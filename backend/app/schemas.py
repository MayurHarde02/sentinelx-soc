from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, ConfigDict

# --- User & Auth Schemas ---
class UserBase(BaseModel):
    username: str
    full_name: Optional[str] = None
    role: str = "analyst"

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    is_active: bool
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class TokenData(BaseModel):
    username: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6, description="New password must be at least 6 characters")


# --- Security Event Schemas ---
class SecurityEventBase(BaseModel):
    timestamp: Optional[datetime] = None
    event_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    status: str = "INFO"
    raw_log: Optional[str] = None
    metadata_json: Optional[str] = None

class SecurityEventCreate(SecurityEventBase):
    pass

class SecurityEventResponse(SecurityEventBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime

class RawLogIngestRequest(BaseModel):
    log_line: str

class BatchLogIngestRequest(BaseModel):
    logs: List[str]

class EventStatsResponse(BaseModel):
    total_events: int
    event_types: Dict[str, int]
    events_per_minute: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]


# --- Alert Schemas ---
class AlertBase(BaseModel):
    alert_type: str
    source_ip: str
    severity: str
    description: str
    rule: str
    status: str = "Open"
    mitre_tactic: Optional[str] = "Impact"
    mitre_technique_id: Optional[str] = "T1498"
    mitre_technique_name: Optional[str] = "Network Denial of Service"
    details_json: Optional[str] = None

class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = None

class AlertUpdateStatus(BaseModel):
    status: str = Field(..., description="Open, Investigating, Resolved, False Positive")

class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    created_at: datetime
    updated_at: datetime

class AlertStatsResponse(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    open_alerts: int
    investigating_alerts: int
    resolved_alerts: int
    severity_distribution: Dict[str, int]
    alert_types_distribution: Dict[str, int]
    mitre_tactics_distribution: Dict[str, int] = {}


# --- Incident Schemas ---
class AnalystNoteCreate(BaseModel):
    note: str

class AnalystNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    author: str
    note: str
    created_at: datetime

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "HIGH"
    status: str = "Open"
    assigned_to: Optional[str] = None
    alert_ids: List[int] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None

class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    resolution_notes: Optional[str]
    alerts: List[AlertResponse] = []
    notes: List[AnalystNoteResponse] = []


# --- Detection Rule Schemas ---
class DetectionRuleBase(BaseModel):
    name: str
    code: str
    description: str
    severity: str
    threshold: int
    window_minutes: int
    is_enabled: bool
    is_custom: bool = False
    event_type_filter: Optional[str] = None
    status_filter: Optional[str] = None
    mitre_tactic: Optional[str] = "Credential Access"
    mitre_technique_id: Optional[str] = "T1110"
    mitre_technique_name: Optional[str] = "Brute Force"

class DetectionRuleCreate(BaseModel):
    name: str
    code: str
    description: str
    severity: str = "HIGH"
    threshold: int = 5
    window_minutes: int = 5
    is_enabled: bool = True
    event_type_filter: Optional[str] = "LOGIN_FAILED"
    status_filter: Optional[str] = "FAILURE"
    mitre_tactic: Optional[str] = "Initial Access"
    mitre_technique_id: Optional[str] = "T1078"
    mitre_technique_name: Optional[str] = "Valid Accounts"

class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    threshold: Optional[int] = None
    window_minutes: Optional[int] = None
    is_enabled: Optional[bool] = None
    event_type_filter: Optional[str] = None
    status_filter: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None

class DetectionRuleResponse(DetectionRuleBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


# --- Threat Intel & Known Bad IP Schemas ---
class ThreatFeedItemBase(BaseModel):
    ip_or_cidr: str
    feed_name: str = "Internal Threat Blocklist"
    threat_category: str = "C2_BOTNET"
    severity: str = "HIGH"
    description: Optional[str] = None
    is_active: bool = True

class ThreatFeedItemCreate(ThreatFeedItemBase):
    pass

class ThreatFeedItemResponse(ThreatFeedItemBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime

class GeoIpResponse(BaseModel):
    ip: str
    country_code: str
    country_name: str
    flag_emoji: str
    city: str
    asn: str
    isp: str
    is_bogon: bool = False

class ExternalIntelResponse(BaseModel):
    ip: str
    abuse_score: int
    reputation: str  # CLEAN, SUSPICIOUS, MALICIOUS
    greynoise_classification: str  # benign, malicious, unknown
    last_reported: Optional[datetime] = None
    tags: List[str] = []


# --- IP Intelligence Schemas ---
class IpIntelligenceResponse(BaseModel):
    ip: str
    total_events: int
    total_alerts: int
    threat_score: int  # 0 to 100 (Time-decay calculated)
    threat_level: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    associated_usernames: List[str]
    alert_types: List[str]
    targeted_ports: List[int]
    geoip: Optional[GeoIpResponse] = None
    external_intel: Optional[ExternalIntelResponse] = None
    recent_events: List[SecurityEventResponse] = []
    recent_alerts: List[AlertResponse] = []


# --- Audit Log Schemas ---
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    actor_username: str
    action_type: str
    entity_type: Optional[str]
    entity_id: Optional[str]
    details: Optional[str]
    ip_address: Optional[str]


# --- Simulation Schemas ---
class SimulationRequest(BaseModel):
    scenario: str = Field(..., description="brute_force, port_scan, suspicious_login, flood, anomaly, known_bad, benign")
    target_ip: Optional[str] = None
    intensity: Optional[int] = 1

class SimulationResponse(BaseModel):
    status: str
    scenario: str
    events_generated: int
    alerts_triggered: int
    message: str


# --- Reporting Schemas ---
class TopIpStat(BaseModel):
    ip: str
    event_count: int
    alert_count: int
    threat_score: int
    country: Optional[str] = "US"
    flag: Optional[str] = "🇺🇸"

class AttackVectorStat(BaseModel):
    attack_type: str
    count: int
    percentage: float
    mitre_id: Optional[str] = None

class SecurityReportResponse(BaseModel):
    generated_at: datetime
    time_window: str
    total_events: int
    total_alerts: int
    active_incidents: int
    resolved_incidents: int
    severity_breakdown: Dict[str, int]
    top_suspicious_ips: List[TopIpStat]
    top_attack_vectors: List[AttackVectorStat]
    mitre_tactics_breakdown: Dict[str, int] = {}
    system_health: str


# --- SOAR Schemas ---
class PlaybookBase(BaseModel):
    code: str
    name: str
    description: str
    category: str = "CONTAINMENT"
    target_type: str = "IP"
    trigger_type: str = "MANUAL"
    is_active: bool = True
    actions_json: Optional[str] = None

class PlaybookResponse(PlaybookBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    execution_count: int
    created_at: datetime
    updated_at: datetime

class PlaybookExecuteRequest(BaseModel):
    target_value: str = Field(..., description="IP address, username, or incident identifier")
    incident_id: Optional[int] = None
    alert_id: Optional[int] = None

class PlaybookExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    playbook_code: str
    playbook_name: str
    target_type: str
    target_value: str
    triggered_by: str
    status: str
    incident_id: Optional[int] = None
    alert_id: Optional[int] = None
    execution_log_json: Optional[str] = None
    duration_ms: int
    created_at: datetime

class SoarMetricsResponse(BaseModel):
    mttd_seconds: float
    mttr_seconds: float
    mttd_display: str
    mttr_display: str
    total_playbooks: int
    active_playbooks: int
    total_executions: int
    successful_executions: int
    auto_contained_threats: int

