from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Index, Float
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class SecurityEvent(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(64), index=True, nullable=False)
    source_ip = Column(String(45), index=True, nullable=False)
    destination_ip = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)
    username = Column(String(64), index=True, nullable=True)
    status = Column(String(32), nullable=False, default="INFO")  # SUCCESS, FAILURE, ATTEMPT, BLOCKED, etc.
    raw_log = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)  # JSON string

    __table_args__ = (
        Index("idx_events_ip_timestamp", "source_ip", "timestamp"),
        Index("idx_events_type_timestamp", "event_type", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type = Column(String(64), index=True, nullable=False)  # BRUTE_FORCE, PORT_SCAN, SUSPICIOUS_LOGIN, EVENT_FLOOD, ANOMALY_DETECTION, KNOWN_MALICIOUS_IP
    source_ip = Column(String(45), index=True, nullable=False)
    severity = Column(String(16), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    rule = Column(String(64), nullable=False)
    status = Column(String(32), default="Open", index=True)  # Open, Investigating, Resolved, False Positive
    
    # MITRE ATT&CK Mapping
    mitre_tactic = Column(String(64), nullable=True, default="Impact")
    mitre_technique_id = Column(String(32), nullable=True, default="T1498")
    mitre_technique_name = Column(String(128), nullable=True, default="Network Denial of Service")
    
    details_json = Column(Text, nullable=True)  # JSON string of triggers, counts, event IDs, anomaly scores
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    incident_associations = relationship("IncidentAlert", back_populates="alert", cascade="all, delete-orphan")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), default="Open", index=True)  # Open, Investigating, Mitigated, Resolved, Closed
    assigned_to = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Relationships
    alert_associations = relationship("IncidentAlert", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("AnalystNote", back_populates="incident", cascade="all, delete-orphan", order_by="AnalystNote.created_at.asc()")


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)

    incident = relationship("Incident", back_populates="alert_associations")
    alert = relationship("Alert", back_populates="incident_associations")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    author = Column(String(64), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="notes")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    code = Column(String(64), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False, default="HIGH")
    threshold = Column(Integer, nullable=False, default=5)
    window_minutes = Column(Integer, nullable=False, default=5)
    is_enabled = Column(Boolean, default=True)
    
    # Custom Rule Capabilities & MITRE Mapping
    is_custom = Column(Boolean, default=False)
    event_type_filter = Column(String(64), nullable=True)
    status_filter = Column(String(32), nullable=True)
    mitre_tactic = Column(String(64), nullable=True, default="Credential Access")
    mitre_technique_id = Column(String(32), nullable=True, default="T1110")
    mitre_technique_name = Column(String(128), nullable=True, default="Brute Force")
    
    created_at = Column(DateTime, default=datetime.utcnow)


class ThreatFeedItem(Base):
    __tablename__ = "threat_feed_items"

    id = Column(Integer, primary_key=True, index=True)
    ip_or_cidr = Column(String(64), unique=True, index=True, nullable=False)
    feed_name = Column(String(128), nullable=False, default="Internal Threat Blocklist")
    threat_category = Column(String(64), nullable=False, default="C2_BOTNET")  # C2_BOTNET, TOR_EXIT, SCANNER, EXPLOIT_SOURCE
    severity = Column(String(16), nullable=False, default="HIGH")
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor_username = Column(String(64), nullable=False, index=True)
    action_type = Column(String(64), nullable=False, index=True)  # LOGIN, RULE_UPDATE, INCIDENT_UPDATE, ALERT_TRIAGE, FEED_UPDATE, PASSWORD_CHANGE
    entity_type = Column(String(64), nullable=True)
    entity_id = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), default="analyst")  # admin, analyst, student
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
