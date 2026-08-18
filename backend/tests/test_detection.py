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
    # Add rules
    rules = [
        DetectionRule(name="Brute Force", code="RULE_BRUTE_FORCE", description="BF", severity="HIGH", threshold=5, window_minutes=5, is_enabled=True),
        DetectionRule(name="Port Scan", code="RULE_PORT_SCAN", description="PS", severity="HIGH", threshold=5, window_minutes=1, is_enabled=True),
        DetectionRule(name="Suspicious Login", code="RULE_SUSPICIOUS_LOGIN", description="SL", severity="HIGH", threshold=3, window_minutes=5, is_enabled=True),
        DetectionRule(name="Event Flood", code="RULE_EVENT_FLOOD", description="EF", severity="MEDIUM", threshold=10, window_minutes=1, is_enabled=True)
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

    # Ingest 5 failed logins
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

    assert len(alerts) >= 1
    assert alerts[-1].alert_type == "BRUTE_FORCE"
    assert alerts[-1].source_ip == ip

def test_detect_port_scan(test_db):
    engine = DetectionEngine(test_db)
    ip = "192.168.1.200"
    alerts = []

    # Ingest distinct port scans
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

    assert len(alerts) >= 1
    assert alerts[-1].alert_type == "PORT_SCAN"
    assert alerts[-1].source_ip == ip

def test_detect_suspicious_login(test_db):
    engine = DetectionEngine(test_db)
    ip = "10.0.0.77"

    # 3 failed logins
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

    # Followed by 1 successful login
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

    assert len(alerts) == 1
    assert alerts[0].alert_type == "SUSPICIOUS_LOGIN"
    assert alerts[0].source_ip == ip
