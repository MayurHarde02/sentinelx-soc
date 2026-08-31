import csv
import io
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.database import get_db
from app.models import SecurityEvent, Alert, Incident
from app.schemas import SecurityReportResponse, TopIpStat, AttackVectorStat
from app.threat_intel import threat_intel_service

router = APIRouter(prefix="/reports", tags=["Reports & Export"])

@router.get("/summary", response_model=SecurityReportResponse)
def get_security_report(
    hours: int = Query(24, description="Time window in hours for report calculations"),
    db: Session = Depends(get_db)
):
    now = datetime.utcnow()
    window_start = now - timedelta(hours=hours)

    total_events = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.timestamp >= window_start).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.timestamp >= window_start).scalar() or 0

    active_incidents = db.query(func.count(Incident.id)).filter(Incident.status.in_(["Open", "Investigating"])).scalar() or 0
    resolved_incidents = db.query(func.count(Incident.id)).filter(Incident.status.in_(["Resolved", "Closed"])).scalar() or 0

    # Severity breakdown
    sev_rows = db.query(Alert.severity, func.count(Alert.id)).filter(Alert.timestamp >= window_start).group_by(Alert.severity).all()
    severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s, c in sev_rows:
        if s in severity_breakdown:
            severity_breakdown[s] = c

    # Top suspicious IPs
    top_ip_rows = db.query(
        SecurityEvent.source_ip,
        func.count(SecurityEvent.id).label("event_count")
    ).filter(SecurityEvent.timestamp >= window_start).group_by(SecurityEvent.source_ip).order_by(desc("event_count")).limit(5).all()

    top_suspicious_ips = []
    for r in top_ip_rows:
        ip = r[0]
        ev_count = r[1]
        al_count = db.query(func.count(Alert.id)).filter(Alert.source_ip == ip, Alert.timestamp >= window_start).scalar() or 0
        geo = threat_intel_service.resolve_geoip(ip)
        
        top_suspicious_ips.append(TopIpStat(
            ip=ip,
            event_count=ev_count,
            alert_count=al_count,
            threat_score=min(100, al_count * 25 + (15 if ev_count > 50 else 5)),
            country=geo.get("country_code", "US"),
            flag=geo.get("flag_emoji", "🌐")
        ))

    # Attack vector breakdown
    alert_type_rows = db.query(Alert.alert_type, func.count(Alert.id)).filter(Alert.timestamp >= window_start).group_by(Alert.alert_type).all()
    top_attack_vectors = []
    for at, count in alert_type_rows:
        pct = round((count / total_alerts * 100.0), 1) if total_alerts > 0 else 0.0
        top_attack_vectors.append(AttackVectorStat(
            attack_type=at,
            count=count,
            percentage=pct,
            mitre_id="T1110" if at == "BRUTE_FORCE" else "T1046" if at == "PORT_SCAN" else "T1078" if at == "SUSPICIOUS_LOGIN" else "T1498"
        ))

    # MITRE ATT&CK Tactics Breakdown
    tactic_rows = db.query(Alert.mitre_tactic, func.count(Alert.id)).filter(Alert.timestamp >= window_start).group_by(Alert.mitre_tactic).all()
    mitre_tactics_breakdown = {t or "Uncategorized": c for t, c in tactic_rows}

    # System health determination
    health = "HEALTHY"
    if severity_breakdown["CRITICAL"] > 0:
        health = "CRITICAL_RISK"
    elif severity_breakdown["HIGH"] > 2:
        health = "ELEVATED_THREAT"
    elif total_alerts > 0:
        health = "GUARDED"

    return SecurityReportResponse(
        generated_at=now,
        time_window=f"Last {hours} Hours",
        total_events=total_events,
        total_alerts=total_alerts,
        active_incidents=active_incidents,
        resolved_incidents=resolved_incidents,
        severity_breakdown=severity_breakdown,
        top_suspicious_ips=top_suspicious_ips,
        top_attack_vectors=top_attack_vectors,
        mitre_tactics_breakdown=mitre_tactics_breakdown,
        system_health=health
    )

@router.get("/export/csv")
def export_csv(
    data_type: str = Query(..., description="'events', 'alerts', or 'incidents'"),
    limit: int = Query(1000, le=10000),
    db: Session = Depends(get_db)
):
    output = io.StringIO()
    writer = csv.writer(output)

    if data_type == "events":
        records = db.query(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit).all()
        writer.writerow(["ID", "Timestamp", "Event Type", "Source IP", "Destination IP", "Port", "Username", "Status", "Raw Log"])
        for r in records:
            writer.writerow([r.id, str(r.timestamp), r.event_type, r.source_ip, r.destination_ip, r.port, r.username, r.status, r.raw_log])
        filename = f"sentinelx_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    elif data_type == "alerts":
        records = db.query(Alert).order_by(desc(Alert.timestamp)).limit(limit).all()
        writer.writerow(["ID", "Timestamp", "Alert Type", "Severity", "Source IP", "Rule", "Status", "MITRE Tactic", "MITRE Technique", "Description"])
        for r in records:
            writer.writerow([r.id, str(r.timestamp), r.alert_type, r.severity, r.source_ip, r.rule, r.status, r.mitre_tactic, r.mitre_technique_id, r.description])
        filename = f"sentinelx_alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    elif data_type == "incidents":
        records = db.query(Incident).order_by(desc(Incident.created_at)).limit(limit).all()
        writer.writerow(["ID", "Title", "Severity", "Status", "Assigned To", "Created At", "Resolved At", "Resolution Notes"])
        for r in records:
            writer.writerow([r.id, r.title, r.severity, r.status, r.assigned_to, str(r.created_at), str(r.resolved_at), r.resolution_notes])
        filename = f"sentinelx_incidents_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    else:
        output.close()
        return Response(content="Invalid data_type parameter. Choose 'events', 'alerts', or 'incidents'.", status_code=400)

    csv_data = output.getvalue()
    output.close()

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
