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

class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    threshold: Optional[int] = None
    window_minutes: Optional[int] = None
    is_enabled: Optional[bool] = None

class DetectionRuleResponse(DetectionRuleBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


# --- IP Intelligence Schemas ---
class IpIntelligenceResponse(BaseModel):
    ip: str
    total_events: int
    total_alerts: int
    threat_score: int  # 0 to 100
    threat_level: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    associated_usernames: List[str]
    alert_types: List[str]
    targeted_ports: List[int]
    recent_events: List[SecurityEventResponse] = []
    recent_alerts: List[AlertResponse] = []


# --- Simulation Schemas ---
class SimulationRequest(BaseModel):
    scenario: str = Field(..., description="brute_force, port_scan, suspicious_login, flood, benign")
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

class AttackVectorStat(BaseModel):
    attack_type: str
    count: int
    percentage: float

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
    system_health: str
