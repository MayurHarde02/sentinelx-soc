import io
import csv
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.database import get_db
from app.models import SecurityEvent, Alert, Incident
from app.schemas import SecurityReportResponse, TopIpStat, AttackVectorStat
from app.routers.ip_intel import _calculate_threat_score

router = APIRouter(prefix="/reports", tags=["Reporting & Export"])

@router.get("/summary", response_model=SecurityReportResponse)
def get_security_summary(db: Session = Depends(get_db)):
    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    
    active_incidents = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(["Open", "Investigating"])
    ).scalar() or 0

    resolved_incidents = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(["Resolved", "Closed"])
    ).scalar() or 0

    # Severity breakdown
    sev_rows = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_breakdown = {s: c for s, c in sev_rows}

    # Top suspicious IPs
    top_ip_rows = db.query(
        SecurityEvent.source_ip,
        func.count(SecurityEvent.id).label("event_count")
    ).group_by(SecurityEvent.source_ip).order_by(desc("event_count")).limit(5).all()

    top_suspicious_ips = []
    for row in top_ip_rows:
        ip = row[0]
        ev_count = row[1]
        alerts = db.query(Alert).filter(Alert.source_ip == ip).all()
        threat_score, _ = _calculate_threat_score(ev_count, alerts)
        top_suspicious_ips.append(TopIpStat(
            ip=ip,
            event_count=ev_count,
            alert_count=len(alerts),
            threat_score=threat_score
        ))

    # Top attack vectors
    type_rows = db.query(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).all()
    top_attack_vectors = []
    for t_row in type_rows:
        count = t_row[1]
        pct = round((count / total_alerts * 100), 1) if total_alerts > 0 else 0.0
        top_attack_vectors.append(AttackVectorStat(
            attack_type=t_row[0],
            count=count,
            percentage=pct
        ))

    system_health = "HEALTHY" if total_alerts == 0 or (severity_breakdown.get("CRITICAL", 0) == 0 and severity_breakdown.get("HIGH", 0) < 5) else "THREAT_ELEVATED"

    return SecurityReportResponse(
        generated_at=datetime.utcnow(),
        time_window="All Recorded Telemetry",
        total_events=total_events,
        total_alerts=total_alerts,
        active_incidents=active_incidents,
        resolved_incidents=resolved_incidents,
        severity_breakdown=severity_breakdown,
        top_suspicious_ips=top_suspicious_ips,
        top_attack_vectors=top_attack_vectors,
        system_health=system_health
    )

@router.get("/export/csv")
def export_csv(
    data_type: str = Query("alerts", description="events, alerts, incidents"),
    db: Session = Depends(get_db)
):
    output = io.StringIO()
    writer = csv.writer(output)

    if data_type == "events":
        writer.writerow(["ID", "Timestamp", "Event Type", "Source IP", "Dest IP", "Port", "Username", "Status", "Raw Log"])
        events = db.query(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(5000).all()
        for e in events:
            writer.writerow([e.id, e.timestamp, e.event_type, e.source_ip, e.destination_ip or "", e.port or "", e.username or "", e.status, e.raw_log or ""])
        filename = f"sentinelx_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    elif data_type == "alerts":
        writer.writerow(["ID", "Timestamp", "Alert Type", "Source IP", "Severity", "Rule", "Status", "Description"])
        alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(5000).all()
        for a in alerts:
            writer.writerow([a.id, a.timestamp, a.alert_type, a.source_ip, a.severity, a.rule, a.status, a.description])
        filename = f"sentinelx_alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    elif data_type == "incidents":
        writer.writerow(["ID", "Title", "Severity", "Status", "Assigned To", "Created At", "Resolved At", "Description", "Resolution Notes"])
        incidents = db.query(Incident).order_by(desc(Incident.created_at)).all()
        for inc in incidents:
            writer.writerow([inc.id, inc.title, inc.severity, inc.status, inc.assigned_to or "", inc.created_at, inc.resolved_at or "", inc.description or "", inc.resolution_notes or ""])
        filename = f"sentinelx_incidents_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    else:
        raise HTTPException(status_code=400, detail="Invalid data_type. Choose from 'events', 'alerts', 'incidents'")

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
