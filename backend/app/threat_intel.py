import ipaddress
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from app.models import ThreatFeedItem

# Deterministic simulated GeoIP dataset for realistic threat attribution
KNOWN_GEO_MAPPING = {
    "192.168.": {"country_code": "PRI", "country_name": "Internal Network (RFC1918)", "flag_emoji": "🛡️", "city": "Internal LAN", "asn": "AS-INTERNAL", "isp": "Corporate Intranet", "is_bogon": True},
    "10.": {"country_code": "PRI", "country_name": "Internal VPC (RFC1918)", "flag_emoji": "🏢", "city": "HQ DataCenter", "asn": "AS-INTERNAL", "isp": "Cloud VPC Gateway", "is_bogon": True},
    "172.": {"country_code": "PRI", "country_name": "Internal DMZ", "flag_emoji": "🔐", "city": "DMZ Subnet", "asn": "AS-INTERNAL", "isp": "Internal Firewall", "is_bogon": True},
    "127.0.0.1": {"country_code": "LCL", "country_name": "Localhost Loopback", "flag_emoji": "💻", "city": "Localhost", "asn": "AS-LOOPBACK", "isp": "Local Loopback", "is_bogon": True},
    
    # Common Attack / Public IPs
    "45.33.32.156": {"country_code": "US", "country_name": "United States", "flag_emoji": "🇺🇸", "city": "Fremont, CA", "asn": "AS63949", "isp": "Linode LLC", "is_bogon": False},
    "185.220.101.5": {"country_code": "DE", "country_name": "Germany", "flag_emoji": "🇩🇪", "city": "Frankfurt", "asn": "AS200052", "isp": "Tor Exit Node Network", "is_bogon": False},
    "198.51.100.42": {"country_code": "NL", "country_name": "Netherlands", "flag_emoji": "🇳🇱", "city": "Amsterdam", "asn": "AS13335", "isp": "Cloudflare Bulletproof Proxy", "is_bogon": False},
    "203.0.113.19": {"country_code": "AU", "country_name": "Australia", "flag_emoji": "🇦🇺", "city": "Sydney", "asn": "AS1221", "isp": "Telstra Global", "is_bogon": False},
    "103.235.46.99": {"country_code": "SG", "country_name": "Singapore", "flag_emoji": "🇸🇬", "city": "Singapore", "asn": "AS45102", "isp": "Alibaba Cloud Gateway", "is_bogon": False},
    "91.240.118.12": {"country_code": "RU", "country_name": "Russia", "flag_emoji": "🇷🇺", "city": "Saint Petersburg", "asn": "AS49505", "isp": "Selectel Host", "is_bogon": False},
    "194.26.29.112": {"country_code": "CN", "country_name": "China", "flag_emoji": "🇨🇳", "city": "Beijing", "asn": "AS4134", "isp": "Chinanet Backbone", "is_bogon": False}
}

COUNTRY_POOLS = [
    {"country_code": "US", "country_name": "United States", "flag_emoji": "🇺🇸", "city": "Ashburn, VA", "asn": "AS16509", "isp": "Amazon AWS Cloud"},
    {"country_code": "GB", "country_name": "United Kingdom", "flag_emoji": "🇬🇧", "city": "London", "asn": "AS2856", "isp": "BT Internet Global"},
    {"country_code": "DE", "country_name": "Germany", "flag_emoji": "🇩🇪", "city": "Frankfurt", "asn": "AS24940", "isp": "Hetzner Online GmbH"},
    {"country_code": "JP", "country_name": "Japan", "flag_emoji": "🇯🇵", "city": "Tokyo", "asn": "AS2516", "isp": "KDDI Telecommunications"},
    {"country_code": "FR", "country_name": "France", "flag_emoji": "🇫🇷", "city": "Paris", "asn": "AS16276", "isp": "OVHcloud Roubaix"},
    {"country_code": "IN", "country_name": "India", "flag_emoji": "🇮🇳", "city": "Mumbai", "asn": "AS55836", "isp": "Reliance Jio Infocomm"}
]

class ThreatIntelService:
    """Provides GeoIP resolution, Known Bad IP Blocklist checking, and external threat intel enrichment."""

    @staticmethod
    def resolve_geoip(ip: str) -> Dict[str, Any]:
        """Resolves an IP address into country, flag emoji, city, ASN, and ISP."""
        if not ip:
            return {"ip": "0.0.0.0", "country_code": "UNK", "country_name": "Unknown", "flag_emoji": "❓", "city": "Unknown", "asn": "AS0", "isp": "Unknown", "is_bogon": True}

        # Check explicit mappings first
        if ip in KNOWN_GEO_MAPPING:
            data = KNOWN_GEO_MAPPING[ip].copy()
            data["ip"] = ip
            return data

        # Check prefixes
        for prefix, info in KNOWN_GEO_MAPPING.items():
            if ip.startswith(prefix):
                data = info.copy()
                data["ip"] = ip
                return data

        # Deterministic hashing for arbitrary public IPs
        h = int(hashlib.md5(ip.encode('utf-8')).hexdigest(), 16)
        pool_entry = COUNTRY_POOLS[h % len(COUNTRY_POOLS)].copy()
        pool_entry["ip"] = ip
        pool_entry["is_bogon"] = False
        return pool_entry

    @staticmethod
    def check_threat_blocklist(db: Session, ip: str) -> Optional[ThreatFeedItem]:
        """Checks if a given source IP matches any active Known Bad IP or CIDR range in the database."""
        # 1. Exact IP match
        direct_match = db.query(ThreatFeedItem).filter(
            ThreatFeedItem.ip_or_cidr == ip,
            ThreatFeedItem.is_active == True
        ).first()
        if direct_match:
            return direct_match

        # 2. Check CIDR ranges
        try:
            target_ip_obj = ipaddress.ip_address(ip)
            active_feeds = db.query(ThreatFeedItem).filter(ThreatFeedItem.is_active == True).all()
            for feed in active_feeds:
                if "/" in feed.ip_or_cidr:
                    network = ipaddress.ip_network(feed.ip_or_cidr, strict=False)
                    if target_ip_obj in network:
                        return feed
        except ValueError:
            pass

        return None

    @staticmethod
    def fetch_external_reputation(ip: str) -> Dict[str, Any]:
        """Enriches an IP with simulated external intelligence from AbuseIPDB, VirusTotal, and GreyNoise."""
        geo = ThreatIntelService.resolve_geoip(ip)
        if geo.get("is_bogon"):
            return {
                "ip": ip,
                "abuse_score": 0,
                "reputation": "CLEAN",
                "greynoise_classification": "benign",
                "last_reported": datetime.utcnow(),
                "tags": ["Internal IP", "RFC1918", "Whitelist"]
            }

        # Deterministic rating for public threat actors
        if ip in ["185.220.101.5", "45.33.32.156", "198.51.100.42", "91.240.118.12", "194.26.29.112"]:
            return {
                "ip": ip,
                "abuse_score": 98,
                "reputation": "MALICIOUS",
                "greynoise_classification": "malicious",
                "last_reported": datetime.utcnow(),
                "tags": ["Tor Exit Node", "Known Scanner", "Cobalt Strike C2", "Brute Force Source"]
            }

        h = int(hashlib.md5(ip.encode('utf-8')).hexdigest(), 16)
        score = h % 35
        reputation = "SUSPICIOUS" if score > 20 else "CLEAN"
        classification = "unknown" if score > 20 else "benign"

        return {
            "ip": ip,
            "abuse_score": score,
            "reputation": reputation,
            "greynoise_classification": classification,
            "last_reported": datetime.utcnow(),
            "tags": ["Cloud Hosted", "Crawler" if score > 15 else "Benign ISP"]
        }

threat_intel_service = ThreatIntelService()
