import pytest
from app.parser import parse_security_log, parse_kv_pairs

def test_parse_sentinelx_standard_log():
    log_line = "2026-08-18 20:15:10 LOGIN_FAILED user=admin ip=192.168.1.22 port=22 status=FAILURE"
    event = parse_security_log(log_line)
    assert event.event_type == "LOGIN_FAILED"
    assert event.source_ip == "192.168.1.22"
    assert event.username == "admin"
    assert event.port == 22
    assert event.status == "FAILURE"

def test_parse_json_log():
    json_line = '{"event_type": "PORT_SCAN", "source_ip": "10.0.0.55", "port": 8080, "status": "BLOCKED"}'
    event = parse_security_log(json_line)
    assert event.event_type == "PORT_SCAN"
    assert event.source_ip == "10.0.0.55"
    assert event.port == 8080
    assert event.status == "BLOCKED"

def test_parse_syslog_failed_ssh():
    syslog_line = "Aug 18 20:15:10 soc-server sshd[1234]: Failed password for root from 192.168.1.105 port 2222 ssh2"
    event = parse_security_log(syslog_line)
    assert event.event_type == "LOGIN_FAILED"
    assert event.source_ip == "192.168.1.105"
    assert event.username == "root"
    assert event.port == 2222
    assert event.status == "FAILURE"

def test_parse_syslog_accepted_ssh():
    syslog_line = "Aug 18 20:15:15 soc-server sshd[1234]: Accepted password for analyst from 192.168.1.50 port 54321 ssh2"
    event = parse_security_log(syslog_line)
    assert event.event_type == "LOGIN_SUCCESS"
    assert event.source_ip == "192.168.1.50"
    assert event.username == "analyst"
    assert event.status == "SUCCESS"
