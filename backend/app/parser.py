import re
import json
from datetime import datetime
from typing import Optional, Dict, Any
from app.schemas import SecurityEventCreate

# Regular expressions for various log formats
DATE_ISO_REGEX = r'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Syslog auth regexes
SYSLOG_FAILED_LOGIN = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\.\-]+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\w+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port (?P<port>\d+)',
    re.IGNORECASE
)
SYSLOG_SUCCESS_LOGIN = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\.\-]+)\s+sshd\[\d+\]:\s+Accepted password for (?P<user>\w+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port (?P<port>\d+)',
    re.IGNORECASE
)

# Apache / Nginx combined log regex
HTTP_LOG_REGEX = re.compile(
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+[\w\-]+\s+(?P<user>[\w\-]+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>[^\s]+)\s+HTTP/[0-9\.]+"\s+(?P<status>\d{3})\s+(?P<bytes>\d+)',
    re.IGNORECASE
)

def parse_kv_pairs(text: str) -> Dict[str, str]:
    """Parse key=value or key="value" pairs from string."""
    pairs = {}
    matches = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', text)
    for k, v1, v2 in matches:
        pairs[k.lower()] = v1 if v1 else v2
    return pairs

def parse_security_log(raw_line: str) -> SecurityEventCreate:
    """
    Parse a raw log line into a normalized SecurityEventCreate object.
    Supports JSON, standard key-value, syslog auth, HTTP access, and fallback.
    """
    clean_line = raw_line.strip()
    if not clean_line:
        raise ValueError("Empty log line")

    # 1. Check if JSON
    if clean_line.startswith("{") and clean_line.endswith("}"):
        try:
            data = json.loads(clean_line)
            ts = None
            if "timestamp" in data:
                try:
                    ts = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.utcnow()
            else:
                ts = datetime.utcnow()

            return SecurityEventCreate(
                timestamp=ts,
                event_type=data.get("event_type", "GENERIC_EVENT").upper(),
                source_ip=data.get("source_ip") or data.get("ip", "127.0.0.1"),
                destination_ip=data.get("destination_ip") or data.get("dst_ip"),
                port=int(data.get("port")) if data.get("port") else None,
                username=data.get("username") or data.get("user"),
                status=data.get("status", "INFO").upper(),
                raw_log=clean_line,
                metadata_json=json.dumps(data.get("metadata", {}))
            )
        except json.JSONDecodeError:
            pass

    # 2. Check Syslog sshd Failed
    match = SYSLOG_FAILED_LOGIN.search(clean_line)
    if match:
        user = match.group("user")
        ip = match.group("ip")
        port = int(match.group("port"))
        return SecurityEventCreate(
            timestamp=datetime.utcnow(),
            event_type="LOGIN_FAILED",
            source_ip=ip,
            destination_ip="127.0.0.1",
            port=port,
            username=user,
            status="FAILURE",
            raw_log=clean_line,
            metadata_json=json.dumps({"service": "sshd", "host": match.group("host")})
        )

    # 3. Check Syslog sshd Success
    match = SYSLOG_SUCCESS_LOGIN.search(clean_line)
    if match:
        user = match.group("user")
        ip = match.group("ip")
        port = int(match.group("port"))
        return SecurityEventCreate(
            timestamp=datetime.utcnow(),
            event_type="LOGIN_SUCCESS",
            source_ip=ip,
            destination_ip="127.0.0.1",
            port=port,
            username=user,
            status="SUCCESS",
            raw_log=clean_line,
            metadata_json=json.dumps({"service": "sshd", "host": match.group("host")})
        )

    # 4. Check HTTP Access Log
    match = HTTP_LOG_REGEX.search(clean_line)
    if match:
        ip = match.group("ip")
        user = match.group("user") if match.group("user") != "-" else None
        status_code = int(match.group("status"))
        path = match.group("path")
        method = match.group("method")
        
        # Infer event type based on HTTP response / path
        if "login" in path.lower() or "auth" in path.lower():
            event_type = "LOGIN_SUCCESS" if status_code < 400 else "LOGIN_FAILED"
            status = "SUCCESS" if status_code < 400 else "FAILURE"
        elif status_code == 404 or status_code == 403:
            event_type = "PORT_SCAN" if status_code == 404 else "UNAUTHORIZED_ACCESS"
            status = "BLOCKED" if status_code == 403 else "FAILURE"
        else:
            event_type = "NETWORK_CONNECTION"
            status = "SUCCESS"

        return SecurityEventCreate(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            source_ip=ip,
            destination_ip="127.0.0.1",
            port=443 if "https" in clean_line.lower() else 80,
            username=user,
            status=status,
            raw_log=clean_line,
            metadata_json=json.dumps({"method": method, "path": path, "http_status": status_code})
        )

    # 5. Standard SentinelX space/KV format:
    # "2026-08-18 20:15:10 LOGIN_FAILED user=admin ip=192.168.1.22 port=22"
    # Or "LOGIN_FAILED ip=1.2.3.4 user=alice status=FAILURE"
    parts = clean_line.split()
    timestamp = datetime.utcnow()
    event_type = "SECURITY_EVENT"
    
    # Try parsing date at start
    time_offset = 0
    if len(parts) >= 2:
        try:
            # Check YYYY-MM-DD HH:MM:SS
            date_str = f"{parts[0]} {parts[1]}"
            timestamp = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
            time_offset = 2
        except Exception:
            pass

    if len(parts) > time_offset:
        potential_type = parts[time_offset]
        if not "=" in potential_type:
            event_type = potential_type.upper()
            time_offset += 1

    kv = parse_kv_pairs(" ".join(parts[time_offset:]))
    
    source_ip = kv.get("ip") or kv.get("source_ip") or kv.get("src") or kv.get("src_ip")
    if not source_ip:
        # Fallback find first IP regex in the line
        ip_search = re.search(IP_REGEX, clean_line)
        source_ip = ip_search.group(0) if ip_search else "0.0.0.0"

    dest_ip = kv.get("dst_ip") or kv.get("destination_ip") or kv.get("dst") or None
    username = kv.get("user") or kv.get("username") or kv.get("account") or None
    port_val = kv.get("port") or kv.get("dst_port") or kv.get("dport")
    port = int(port_val) if port_val and port_val.isdigit() else None
    
    # Infer default status from event type if missing
    status = kv.get("status")
    if not status:
        if "FAIL" in event_type or "DENY" in event_type or "DROP" in event_type or "BLOCKED" in event_type:
            status = "FAILURE"
        elif "SUCCESS" in event_type or "ALLOW" in event_type or "ACCEPT" in event_type:
            status = "SUCCESS"
        else:
            status = "INFO"
    else:
        status = status.upper()

    return SecurityEventCreate(
        timestamp=timestamp,
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=dest_ip,
        port=port,
        username=username,
        status=status,
        raw_log=clean_line,
        metadata_json=json.dumps(kv)
    )
