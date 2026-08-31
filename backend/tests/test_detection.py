import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, SecurityEvent, DetectionRule, Alert
from app.detection import DetectionEngine

@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = TestingSessionLocal()
    rules = [
        DetectionRule(name="Brute Force", code="RULE_BRUTE_FORCE", description="BF", severity="HIGH", threshold=5, window_minutes=5, is_enabled=True, mitre_technique_id="T1110", mitre_tactic="Credential Access"),
        DetectionRule(name="Port Scan", code="RULE_PORT_SCAN", description="PS", severity="HIGH", threshold=5, window_minutes=1, is_enabled=True, mitre_technique_id="T1046", mitre_tactic="Reconnaissance"),
        DetectionRule(name="Suspicious Login", code="RULE_SUSPICIOUS_LOGIN", description="SL", severity="HIGH", threshold=3, window_minutes=5, is_enabled=True, mitre_technique_id="T1078", mitre_tactic="Initial Access"),
        DetectionRule(name="Event Flood", code="RULE_EVENT_FLOOD", description="EF", severity="MEDIUM", threshold=10, window_minutes=1, is_enabled=True, mitre_technique_id="T1498", mitre_tactic="Impact")
    ]
    for r in rules:
        db.add(r)
    db.commit()

    yield db
    db.close()

def test_detect_brute_force(test_db):
    engine = DetectionEngine(test_db)
    ip = "192.168.1.99"
    alerts = []

    for i in range(5):
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type="LOGIN_FAILED",
            source_ip=ip,
            username="admin",
            status="FAILURE"
        )
        test_db.add(event)
        test_db.commit()
        test_db.refresh(event)
        new_alerts = engine.evaluate_event(event)
        alerts.extend(new_alerts)

    assert any(a.alert_type == "BRUTE_FORCE" for a in alerts)
    bf_alert = [a for a in alerts if a.alert_type == "BRUTE_FORCE"][0]
    assert bf_alert.source_ip == ip
    assert bf_alert.mitre_technique_id == "T1110"

def test_detect_port_scan(test_db):
    engine = DetectionEngine(test_db)
    ip = "192.168.1.200"
    alerts = []

    for p in [21, 22, 23, 80, 443, 8080]:
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type="PORT_SCAN",
            source_ip=ip,
            port=p,
            status="BLOCKED"
        )
        test_db.add(event)
        test_db.commit()
        test_db.refresh(event)
        new_alerts = engine.evaluate_event(event)
        alerts.extend(new_alerts)

    assert any(a.alert_type == "PORT_SCAN" for a in alerts)
    ps_alert = [a for a in alerts if a.alert_type == "PORT_SCAN"][0]
    assert ps_alert.source_ip == ip
    assert ps_alert.mitre_technique_id == "T1046"

def test_detect_suspicious_login(test_db):
    engine = DetectionEngine(test_db)
    ip = "10.0.0.77"

    for i in range(3):
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type="LOGIN_FAILED",
            source_ip=ip,
            username="target_user",
            status="FAILURE"
        )
        test_db.add(event)
        test_db.commit()
        test_db.refresh(event)
        engine.evaluate_event(event)

    success_event = SecurityEvent(
        timestamp=datetime.utcnow(),
        event_type="LOGIN_SUCCESS",
        source_ip=ip,
        username="target_user",
        status="SUCCESS"
    )
    test_db.add(success_event)
    test_db.commit()
    test_db.refresh(success_event)
    alerts = engine.evaluate_event(success_event)

    assert any(a.alert_type == "SUSPICIOUS_LOGIN" for a in alerts)
    sl_alert = [a for a in alerts if a.alert_type == "SUSPICIOUS_LOGIN"][0]
    assert sl_alert.source_ip == ip
    assert sl_alert.mitre_technique_id == "T1078"
