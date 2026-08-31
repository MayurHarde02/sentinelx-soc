import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.config import settings
from app.models import Base, DetectionRule, User, ThreatFeedItem

# Configure engine for either SQLite or PostgreSQL
if "sqlite" in settings.DATABASE_URL:
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
else:
    # PostgreSQL / MySQL configuration
    engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create tables and seed initial detection rules, users, and threat feed blocklist."""
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        # Seed default detection rules with MITRE ATT&CK taxonomy
        default_rules = [
            {
                "name": "Brute Force Detection",
                "code": "RULE_BRUTE_FORCE",
                "description": "Detects repeated failed login attempts (5+ failed logins from same IP within 5 minutes).",
                "severity": "HIGH",
                "threshold": settings.BRUTE_FORCE_THRESHOLD,
                "window_minutes": settings.BRUTE_FORCE_WINDOW_MINUTES,
                "is_enabled": True,
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1110",
                "mitre_technique_name": "Brute Force"
            },
            {
                "name": "Port Scan Detection",
                "code": "RULE_PORT_SCAN",
                "description": "Detects scanning activity across multiple destination ports (10+ distinct ports from same IP within 1 minute).",
                "severity": "HIGH",
                "threshold": settings.PORT_SCAN_THRESHOLD,
                "window_minutes": settings.PORT_SCAN_WINDOW_MINUTES,
                "is_enabled": True,
                "mitre_tactic": "Reconnaissance",
                "mitre_technique_id": "T1046",
                "mitre_technique_name": "Network Service Discovery"
            },
            {
                "name": "Suspicious Login Sequence",
                "code": "RULE_SUSPICIOUS_LOGIN",
                "description": "Detects multiple failed logins followed by a successful login from the same IP address.",
                "severity": "HIGH",
                "threshold": settings.SUSPICIOUS_LOGIN_FAIL_THRESHOLD,
                "window_minutes": settings.SUSPICIOUS_LOGIN_WINDOW_MINUTES,
                "is_enabled": True,
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1078",
                "mitre_technique_name": "Valid Accounts"
            },
            {
                "name": "High-Frequency Event Flood",
                "code": "RULE_EVENT_FLOOD",
                "description": "Detects abnormal request bursts from a single source IP (100+ requests within 1 minute).",
                "severity": "MEDIUM",
                "threshold": settings.EVENT_FLOOD_THRESHOLD,
                "window_minutes": settings.EVENT_FLOOD_WINDOW_MINUTES,
                "is_enabled": True,
                "mitre_tactic": "Impact",
                "mitre_technique_id": "T1498",
                "mitre_technique_name": "Network Denial of Service"
            },
            {
                "name": "Machine Learning Anomaly Detector",
                "code": "RULE_ML_ANOMALY",
                "description": "Isolation Forest multi-dimensional statistical traffic velocity anomaly detector.",
                "severity": "HIGH",
                "threshold": 1,
                "window_minutes": 2,
                "is_enabled": True,
                "mitre_tactic": "Execution",
                "mitre_technique_id": "T1059",
                "mitre_technique_name": "Command and Scripting Interpreter"
            },
            {
                "name": "Known Threat Feed Blocklist Match",
                "code": "RULE_KNOWN_MALICIOUS_IP",
                "description": "Detects any traffic originating from or targeting an IP on the active Threat Intelligence Blocklist.",
                "severity": "CRITICAL",
                "threshold": 1,
                "window_minutes": 1,
                "is_enabled": True,
                "mitre_tactic": "Command and Control",
                "mitre_technique_id": "T1071",
                "mitre_technique_name": "Application Layer Protocol"
            }
        ]

        for r_data in default_rules:
            existing = db.query(DetectionRule).filter(DetectionRule.code == r_data["code"]).first()
            if not existing:
                rule = DetectionRule(**r_data)
                db.add(rule)
            else:
                # Update existing rule with MITRE metadata if missing
                if not existing.mitre_technique_id:
                    existing.mitre_tactic = r_data["mitre_tactic"]
                    existing.mitre_technique_id = r_data["mitre_technique_id"]
                    existing.mitre_technique_name = r_data["mitre_technique_name"]

        # Seed initial Threat Feed Blocklist items
        default_blocklist = [
            {
                "ip_or_cidr": "185.220.101.5",
                "feed_name": "Emerging Threats / Tor Exit List",
                "threat_category": "TOR_EXIT",
                "severity": "CRITICAL",
                "description": "Active Tor exit relay associated with automated credential stuffing campaigns."
            },
            {
                "ip_or_cidr": "45.33.32.156",
                "feed_name": "AlienVault OTX C2 Feed",
                "threat_category": "C2_BOTNET",
                "severity": "HIGH",
                "description": "Identified Cobalt Strike Command and Control listener endpoint."
            },
            {
                "ip_or_cidr": "198.51.100.42",
                "feed_name": "AbuseIPDB Top Attackers",
                "threat_category": "EXPLOIT_SOURCE",
                "severity": "HIGH",
                "description": "High-volume SSH and web vulnerability brute force scanning host."
            }
        ]

        for b_data in default_blocklist:
            existing_feed = db.query(ThreatFeedItem).filter(ThreatFeedItem.ip_or_cidr == b_data["ip_or_cidr"]).first()
            if not existing_feed:
                feed_item = ThreatFeedItem(**b_data)
                db.add(feed_item)

        # Seed default users if not present
        from app.auth import get_password_hash
        admin_user = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        if not admin_user:
            admin_user = User(
                username=settings.ADMIN_USERNAME,
                full_name="SOC Administrator",
                password_hash=get_password_hash(settings.ADMIN_PASSWORD),
                role="admin",
                is_active=True
            )
            db.add(admin_user)

        analyst_user = db.query(User).filter(User.username == settings.ANALYST_USERNAME).first()
        if not analyst_user:
            analyst_user = User(
                username=settings.ANALYST_USERNAME,
                full_name="Alex Rivera (L2 Analyst)",
                password_hash=get_password_hash(settings.ANALYST_PASSWORD),
                role="analyst",
                is_active=True
            )
            db.add(analyst_user)

        db.commit()
    finally:
        db.close()
