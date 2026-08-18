import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.config import settings
from app.models import Base, DetectionRule, User

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
    """Create tables and seed initial detection rules and users."""
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        # Seed default detection rules if not present
        default_rules = [
            {
                "name": "Brute Force Detection",
                "code": "RULE_BRUTE_FORCE",
                "description": "Detects repeated failed login attempts (5+ failed logins from same IP within 5 minutes).",
                "severity": "HIGH",
                "threshold": settings.BRUTE_FORCE_THRESHOLD,
                "window_minutes": settings.BRUTE_FORCE_WINDOW_MINUTES,
                "is_enabled": True
            },
            {
                "name": "Port Scan Detection",
                "code": "RULE_PORT_SCAN",
                "description": "Detects scanning activity across multiple destination ports (10+ distinct ports from same IP within 1 minute).",
                "severity": "HIGH",
                "threshold": settings.PORT_SCAN_THRESHOLD,
                "window_minutes": settings.PORT_SCAN_WINDOW_MINUTES,
                "is_enabled": True
            },
            {
                "name": "Suspicious Login Sequence",
                "code": "RULE_SUSPICIOUS_LOGIN",
                "description": "Detects multiple failed logins followed by a successful login from the same IP address.",
                "severity": "HIGH",
                "threshold": settings.SUSPICIOUS_LOGIN_FAIL_THRESHOLD,
                "window_minutes": settings.SUSPICIOUS_LOGIN_WINDOW_MINUTES,
                "is_enabled": True
            },
            {
                "name": "High-Frequency Event Flood",
                "code": "RULE_EVENT_FLOOD",
                "description": "Detects abnormal request bursts from a single source IP (100+ requests within 1 minute).",
                "severity": "MEDIUM",
                "threshold": settings.EVENT_FLOOD_THRESHOLD,
                "window_minutes": settings.EVENT_FLOOD_WINDOW_MINUTES,
                "is_enabled": True
            }
        ]

        for r_data in default_rules:
            existing = db.query(DetectionRule).filter(DetectionRule.code == r_data["code"]).first()
            if not existing:
                rule = DetectionRule(**r_data)
                db.add(rule)

        # Seed users if not present
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
