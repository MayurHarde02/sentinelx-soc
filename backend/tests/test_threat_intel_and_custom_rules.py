import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, SecurityEvent, DetectionRule, ThreatFeedItem, Alert
from app.detection import DetectionEngine
from app.threat_intel import threat_intel_service

@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    # Add Threat Feed Item
    feed_item = ThreatFeedItem(
        ip_or_cidr="185.220.101.5",
        feed_name="Tor Exit List",
        threat_category="TOR_EXIT",
        severity="CRITICAL",
        is_active=True
    )
    db.add(feed_item)

    # Add Custom Rule
    custom_rule = DetectionRule(
        name="Custom Data Exfiltration",
        code="RULE_CUSTOM_EXFILTRATION",
        description="Detects suspicious large payload transfers",
        severity="CRITICAL",
        threshold=2,
        window_minutes=5,
        is_enabled=True,
        is_custom=True,
        event_type_filter="DATA_TRANSFER",
        status_filter="BLOCKED",
        mitre_tactic="Exfiltration",
        mitre_technique_id="T1048",
        mitre_technique_name="Exfiltration Over Alternative Protocol"
    )
    db.add(custom_rule)
    db.commit()

    yield db
    db.close()

def test_threat_feed_blocklist_match(test_db):
    engine = DetectionEngine(test_db)
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        event_type="NETWORK_CONNECTION",
        source_ip="185.220.101.5",
        status="ATTEMPT"
    )
    test_db.add(event)
    test_db.commit()

    alerts = engine.evaluate_event(event)
    feed_alerts = [a for a in alerts if a.alert_type == "KNOWN_MALICIOUS_IP"]
    assert len(feed_alerts) == 1
    assert feed_alerts[0].severity == "CRITICAL"
    assert feed_alerts[0].mitre_technique_id == "T1071"

def test_custom_rule_trigger(test_db):
    engine = DetectionEngine(test_db)
    ip = "192.168.1.75"

    # Ingest 2 DATA_TRANSFER events with BLOCKED status
    for i in range(2):
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type="DATA_TRANSFER",
            source_ip=ip,
            status="BLOCKED"
        )
        test_db.add(event)
        test_db.commit()
        alerts = engine.evaluate_event(event)

    custom_alerts = [a for a in alerts if a.rule == "RULE_CUSTOM_EXFILTRATION"]
    assert len(custom_alerts) >= 1
    assert custom_alerts[0].mitre_technique_id == "T1048"

def test_geoip_resolution():
    geo_private = threat_intel_service.resolve_geoip("192.168.1.1")
    assert geo_private["is_bogon"] is True

    geo_public = threat_intel_service.resolve_geoip("45.33.32.156")
    assert geo_public["country_code"] == "US"
    assert "Linode" in geo_public["isp"]
