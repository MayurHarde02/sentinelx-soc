import math
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, distinct
from app.database import get_db
from app.models import SecurityEvent, Alert
from app.schemas import IpIntelligenceResponse, SecurityEventResponse, AlertResponse, GeoIpResponse, ExternalIntelResponse
from app.threat_intel import threat_intel_service

router = APIRouter(prefix="/ip-intelligence", tags=["IP Intelligence"])

def _calculate_time_decay_threat_score(total_events: int, last_seen: Optional[datetime], alerts: List[Alert]) -> tuple[int, str]:
    """
    Calculates dynamic threat score (0-100) using mathematical exponential time-decay.
    Alerts decay with a 24-hour half-life so older, non-recurrent alerts fade naturally.
    """
    now = datetime.utcnow()
    decay_constant = 0.0288  # ln(2)/24 hours approx 0.0288 per hour

    accumulated_score = 0.0

    for a in alerts:
        base_weight = 6.0
        if a.severity == "CRITICAL":
            base_weight = 45.0
        elif a.severity == "HIGH":
            base_weight = 28.0
        elif a.severity == "MEDIUM":
            base_weight = 15.0
        elif a.severity == "LOW":
            base_weight = 6.0

        # Calculate hours elapsed since alert
        hours_elapsed = max(0.0, (now - a.timestamp).total_seconds() / 3600.0)
        decay_factor = math.exp(-decay_constant * hours_elapsed)
        accumulated_score += (base_weight * decay_factor)

    # Add modest volume factor based on recency
    if last_seen:
        hours_since_last = max(0.0, (now - last_seen).total_seconds() / 3600.0)
        vol_decay = math.exp(-0.0144 * hours_since_last)  # 48h half-life for raw traffic
        if total_events > 100:
            accumulated_score += (18.0 * vol_decay)
        elif total_events > 30:
            accumulated_score += (10.0 * vol_decay)

    score = int(min(100.0, round(accumulated_score)))

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "SAFE"

    return score, level

@router.get("", response_model=List[IpIntelligenceResponse])
def list_ip_intelligence(
    limit: int = Query(50, le=200),
    offset: int = 0,
    search: Optional[str] = None,
    min_score: Optional[int] = None,
    db: Session = Depends(get_db)
):
    ip_query = db.query(
        SecurityEvent.source_ip,
        func.count(SecurityEvent.id).label("event_count"),
        func.min(SecurityEvent.timestamp).label("first_seen"),
        func.max(SecurityEvent.timestamp).label("last_seen")
    ).group_by(SecurityEvent.source_ip)

    if search:
        ip_query = ip_query.filter(SecurityEvent.source_ip.contains(search))

    results = ip_query.order_by(desc("event_count")).offset(offset).limit(limit).all()
    ip_profiles = []

    for row in results:
        ip = row[0]
        event_count = row[1]
        first_seen = row[2]
        last_seen = row[3]

        alerts = db.query(Alert).filter(Alert.source_ip == ip).all()
        threat_score, threat_level = _calculate_time_decay_threat_score(event_count, last_seen, alerts)

        if min_score is not None and threat_score < min_score:
            continue

        usernames = db.query(distinct(SecurityEvent.username)).filter(
            SecurityEvent.source_ip == ip,
            SecurityEvent.username.isnot(None)
        ).all()
        associated_users = [u[0] for u in usernames if u[0]]

        alert_types = list(set([a.alert_type for a in alerts]))

        ports = db.query(distinct(SecurityEvent.port)).filter(
            SecurityEvent.source_ip == ip,
            SecurityEvent.port.isnot(None)
        ).all()
        targeted_ports = [p[0] for p in ports if p[0]]

        # GeoIP info
        geo_info = threat_intel_service.resolve_geoip(ip)

        ip_profiles.append(IpIntelligenceResponse(
            ip=ip,
            total_events=event_count,
            total_alerts=len(alerts),
            threat_score=threat_score,
            threat_level=threat_level,
            first_seen=first_seen,
            last_seen=last_seen,
            associated_usernames=associated_users,
            alert_types=alert_types,
            targeted_ports=targeted_ports,
            geoip=GeoIpResponse(**geo_info),
            external_intel=None,
            recent_events=[],
            recent_alerts=[]
        ))

    ip_profiles.sort(key=lambda x: (x.threat_score, x.total_events), reverse=True)
    return ip_profiles

@router.get("/{ip}", response_model=IpIntelligenceResponse)
def get_ip_details(ip: str, db: Session = Depends(get_db)):
    event_count = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.source_ip == ip).scalar() or 0
    if event_count == 0:
        raise HTTPException(status_code=404, detail=f"No events found for IP: {ip}")

    first_seen = db.query(func.min(SecurityEvent.timestamp)).filter(SecurityEvent.source_ip == ip).scalar()
    last_seen = db.query(func.max(SecurityEvent.timestamp)).filter(SecurityEvent.source_ip == ip).scalar()

    alerts = db.query(Alert).filter(Alert.source_ip == ip).order_by(desc(Alert.timestamp)).all()
    threat_score, threat_level = _calculate_time_decay_threat_score(event_count, last_seen, alerts)

    usernames = db.query(distinct(SecurityEvent.username)).filter(
        SecurityEvent.source_ip == ip,
        SecurityEvent.username.isnot(None)
    ).all()
    associated_users = [u[0] for u in usernames if u[0]]

    ports = db.query(distinct(SecurityEvent.port)).filter(
        SecurityEvent.source_ip == ip,
        SecurityEvent.port.isnot(None)
    ).all()
    targeted_ports = [p[0] for p in ports if p[0]]

    recent_events = db.query(SecurityEvent).filter(
        SecurityEvent.source_ip == ip
    ).order_by(desc(SecurityEvent.timestamp)).limit(25).all()

    # GeoIP and External Intelligence
    geo_data = threat_intel_service.resolve_geoip(ip)
    ext_intel = threat_intel_service.fetch_external_reputation(ip)

    return IpIntelligenceResponse(
        ip=ip,
        total_events=event_count,
        total_alerts=len(alerts),
        threat_score=threat_score,
        threat_level=threat_level,
        first_seen=first_seen,
        last_seen=last_seen,
        associated_usernames=associated_users,
        alert_types=list(set([a.alert_type for a in alerts])),
        targeted_ports=targeted_ports,
        geoip=GeoIpResponse(**geo_data),
        external_intel=ExternalIntelResponse(**ext_intel),
        recent_events=[SecurityEventResponse.model_validate(e) for e in recent_events],
        recent_alerts=[AlertResponse.model_validate(a) for a in alerts[:15]]
    )
