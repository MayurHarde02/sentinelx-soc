import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, SecurityEvent, DetectionRule, Alert
from app.detection import DetectionEngine
from app.routers.ip_intel import _calculate_time_decay_threat_score

@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    rule_bf = DetectionRule(
        name="Brute Force",
        code="RULE_BRUTE_FORCE",
        description="BF",
        severity="HIGH",
        threshold=5,
        window_minutes=5,
        is_enabled=True,
        mitre_technique_id="T1110",
        mitre_tactic="Credential Access"
    )
    db.add(rule_bf)
    db.commit()
    yield db
    db.close()

def test_threshold_boundary_n_minus_one(test_db):
    """Ensure exactly threshold - 1 events does NOT trigger an alert."""
    engine = DetectionEngine(test_db)
    ip = "192.168.1.50"

    # Ingest 4 failed logins (threshold is 5)
    for i in range(4):
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type="LOGIN_FAILED",
            source_ip=ip,
            status="FAILURE"
        )
        test_db.add(event)
        test_db.commit()
        alerts = engine.evaluate_event(event)
        bf_alerts = [a for a in alerts if a.alert_type == "BRUTE_FORCE"]
        assert len(bf_alerts) == 0

def test_sliding_window_expiration(test_db):
    """Ensure events outside the sliding window do NOT contribute to thresholds."""
    engine = DetectionEngine(test_db)
    ip = "192.168.1.60"

    # Ingest 4 failed logins 10 minutes ago (window is 5 minutes)
    old_time = datetime.utcnow() - timedelta(minutes=10)
    for i in range(4):
        event = SecurityEvent(
            timestamp=old_time,
            event_type="LOGIN_FAILED",
            source_ip=ip,
            status="FAILURE"
        )
        test_db.add(event)
    test_db.commit()

    # Ingest 1 current failed login -> Total within 5-min window is 1, so no alert
    current_event = SecurityEvent(
        timestamp=datetime.utcnow(),
        event_type="LOGIN_FAILED",
        source_ip=ip,
        status="FAILURE"
    )
    test_db.add(current_event)
    test_db.commit()

    alerts = engine.evaluate_event(current_event)
    bf_alerts = [a for a in alerts if a.alert_type == "BRUTE_FORCE"]
    assert len(bf_alerts) == 0

def test_time_decay_threat_score_calculation():
    """Verify exponential half-life decay on threat scores."""
    now = datetime.utcnow()
    
    # 1. Fresh Critical Alert
    fresh_alert = Alert(
        timestamp=now,
        alert_type="BRUTE_FORCE",
        source_ip="192.168.1.80",
        severity="CRITICAL",
        description="Fresh attack",
        rule="RULE_BRUTE_FORCE"
    )
    score_fresh, level_fresh = _calculate_time_decay_threat_score(10, now, [fresh_alert])
    assert score_fresh >= 45

    # 2. Same alert 24 hours later (should have decayed by ~50%)
    old_alert = Alert(
        timestamp=now - timedelta(hours=24),
        alert_type="BRUTE_FORCE",
        source_ip="192.168.1.80",
        severity="CRITICAL",
        description="Old attack",
        rule="RULE_BRUTE_FORCE"
    )
    score_old, level_old = _calculate_time_decay_threat_score(10, now - timedelta(hours=24), [old_alert])
    assert score_old < score_fresh
    assert score_old <= 30
