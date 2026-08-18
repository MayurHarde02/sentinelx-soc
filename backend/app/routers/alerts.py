from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Alert, Incident, IncidentAlert
from app.schemas import AlertResponse, AlertUpdateStatus, AlertStatsResponse, IncidentResponse
from app.alert_manager import AlertManager

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
    return manager.get_stats()

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_details(alert_id: int, db: Session = Depends(get_db)):
    manager = AlertManager(db)
    alert = manager.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(alert_id: int, payload: AlertUpdateStatus, db: Session = Depends(get_db)):
    valid_statuses = ["Open", "Investigating", "Resolved", "False Positive"]
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    manager = AlertManager(db)
    alert = manager.update_alert_status(alert_id, payload.status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.post("/{alert_id}/escalate", response_model=Dict[str, Any])
def escalate_alert_to_incident(
    alert_id: int,
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

    return {
        "status": "success",
        "incident_id": incident.id,
        "incident_title": incident.title,
        "assigned_to": incident.assigned_to
    }
