import pytest
from app.parser import parse_security_log

def test_parse_empty_and_whitespace():
    with pytest.raises(ValueError):
        parse_security_log("")

    with pytest.raises(ValueError):
        parse_security_log("   \n\t  ")

def test_parse_malformed_json_fallback():
    # Invalid json should gracefully fallback to standard token parsing
    raw = '{"event_type": "LOGIN_FAILED", "ip": broken_json_here 192.168.1.1}'
    event = parse_security_log(raw)
    assert event.source_ip is not None
    assert event.event_type is not None

def test_parse_sqli_payload_in_log():
    raw = "2026-08-20 14:00:00 SQL_INJECTION_ATTEMPT user=' OR 1=1 -- ip=198.51.100.42 status=BLOCKED"
    event = parse_security_log(raw)
    assert event.source_ip == "198.51.100.42"
    assert event.status == "BLOCKED"
    assert event.event_type == "SQL_INJECTION_ATTEMPT"

def test_parse_truncated_syslog():
    raw = "Aug 20 14:32:10 soc-server sshd[1234]: Failed password for invalid user"
    event = parse_security_log(raw)
    assert event.status == "FAILURE"
    assert event.event_type in ["SSH_FAILED", "LOGIN_FAILED"]

def test_parse_nginx_access_log():
    raw = '192.168.1.55 - - [20/Aug/2026:14:32:10 +0000] "GET /admin/login HTTP/1.1" 401 532 "-" "Mozilla/5.0"'
    event = parse_security_log(raw)
    assert event.source_ip == "192.168.1.55"
    assert event.status == "FAILURE"
    assert event.port == 80
