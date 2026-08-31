from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models import Alert, Incident, IncidentAlert
from app.schemas import AlertResponse, AlertUpdateStatus, AlertStatsResponse, IncidentResponse
from app.alert_manager import AlertManager
from app.audit import audit_logger
from app.websocket_manager import ws_manager

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    manager = AlertManager(db)
    return manager.get_alerts(
        severity=severity,
        alert_type=alert_type,
        source_ip=source_ip,
        status=status,
        limit=limit,
        offset=offset
    )

@router.get("/stats", response_model=AlertStatsResponse)
def get_alert_stats(db: Session = Depends(get_db)):
    manager = AlertManager(db)
    stats = manager.get_stats()
    
    # Calculate MITRE ATT&CK tactic distribution
    tactic_rows = db.query(Alert.mitre_tactic, func.count(Alert.id)).group_by(Alert.mitre_tactic).all()
    stats["mitre_tactics_distribution"] = {t or "Uncategorized": c for t, c in tactic_rows}
    
    return stats

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_details(alert_id: int, db: Session = Depends(get_db)):
    manager = AlertManager(db)
    alert = manager.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    payload: AlertUpdateStatus,
    request: Request,
    actor: str = "analyst",
    db: Session = Depends(get_db)
):
    valid_statuses = ["Open", "Investigating", "Resolved", "False Positive"]
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    manager = AlertManager(db)
    alert = manager.update_alert_status(alert_id, payload.status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="ALERT_STATUS_CHANGE",
        entity_type="Alert",
        entity_id=str(alert_id),
        details=f"Changed status of alert #{alert_id} ({alert.alert_type}) to '{payload.status}'",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    ws_manager.broadcast_sync("ALERT_UPDATED", {
        "id": alert.id,
        "status": alert.status,
        "updated_at": str(alert.updated_at)
    })

    return alert

@router.post("/{alert_id}/escalate", response_model=Dict[str, Any])
def escalate_alert_to_incident(
    alert_id: int,
    request: Request,
    assigned_to: Optional[str] = "analyst",
    db: Session = Depends(get_db)
):
    manager = AlertManager(db)
    alert = manager.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    incident = Incident(
        title=f"Incident: {alert.alert_type} from {alert.source_ip}",
        description=f"Escalated from Alert #{alert.id}: {alert.description}",
        severity=alert.severity,
        status="Investigating",
        assigned_to=assigned_to
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    inc_alert = IncidentAlert(incident_id=incident.id, alert_id=alert.id)
    db.add(inc_alert)
    
    # Mark alert as investigating
    alert.status = "Investigating"
    db.commit()

    audit_logger.log(
        db=db,
        actor_username=assigned_to or "analyst",
        action_type="ALERT_ESCALATED",
        entity_type="Incident",
        entity_id=str(incident.id),
        details=f"Escalated Alert #{alert.id} to Incident #{incident.id}",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    ws_manager.broadcast_sync("NEW_INCIDENT", {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "assigned_to": incident.assigned_to
    })

    return {
        "status": "success",
        "incident_id": incident.id,
        "incident_title": incident.title,
        "assigned_to": incident.assigned_to
    }
