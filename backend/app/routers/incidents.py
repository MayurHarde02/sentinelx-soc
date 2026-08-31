from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db
from app.models import Incident, Alert, IncidentAlert, AnalystNote, SecurityEvent
from app.schemas import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    AnalystNoteCreate,
    AnalystNoteResponse
)
from app.audit import audit_logger
from app.websocket_manager import ws_manager

router = APIRouter(prefix="/incidents", tags=["Incident Management"])

def _format_incident_response(incident: Incident, db: Session) -> Dict[str, Any]:
    alerts = [ia.alert for ia in incident.alert_associations if ia.alert is not None]
    notes = incident.notes

    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "resolved_at": incident.resolved_at,
        "resolution_notes": incident.resolution_notes,
        "alerts": alerts,
        "notes": notes
    }

@router.get("", response_model=List[IncidentResponse])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if assigned_to:
        query = query.filter(Incident.assigned_to == assigned_to)

    incidents = query.order_by(desc(Incident.created_at)).offset(offset).limit(limit).all()
    return [_format_incident_response(inc, db) for inc in incidents]

@router.post("", response_model=IncidentResponse)
def create_incident(payload: IncidentCreate, request: Request, actor: str = "analyst", db: Session = Depends(get_db)):
    incident = Incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status=payload.status,
        assigned_to=payload.assigned_to
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    for alert_id in payload.alert_ids:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            inc_alert = IncidentAlert(incident_id=incident.id, alert_id=alert.id)
            db.add(inc_alert)
            alert.status = "Investigating"

    db.commit()
    db.refresh(incident)

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="INCIDENT_CREATE",
        entity_type="Incident",
        entity_id=str(incident.id),
        details=f"Created incident #{incident.id}: '{incident.title}' ({incident.severity})",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    ws_manager.broadcast_sync("NEW_INCIDENT", {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "assigned_to": incident.assigned_to
    })

    return _format_incident_response(incident, db)

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident_details(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _format_incident_response(incident, db)

@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, payload: IncidentUpdate, request: Request, actor: str = "analyst", db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    if payload.title is not None:
        incident.title = payload.title
    if payload.description is not None:
        incident.description = payload.description
    if payload.severity is not None:
        incident.severity = payload.severity
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to
    if payload.resolution_notes is not None:
        incident.resolution_notes = payload.resolution_notes
    if payload.status is not None:
        incident.status = payload.status
        if payload.status in ["Resolved", "Closed"] and not incident.resolved_at:
            incident.resolved_at = datetime.utcnow()
            for ia in incident.alert_associations:
                if ia.alert:
                    ia.alert.status = "Resolved"

    incident.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(incident)

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="INCIDENT_UPDATE",
        entity_type="Incident",
        entity_id=str(incident.id),
        details=f"Updated incident #{incident.id} (Status: {old_status} -> {incident.status})",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    ws_manager.broadcast_sync("INCIDENT_UPDATED", {
        "id": incident.id,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "updated_at": str(incident.updated_at)
    })

    return _format_incident_response(incident, db)

@router.post("/{incident_id}/notes", response_model=AnalystNoteResponse)
def add_analyst_note(
    incident_id: int,
    payload: AnalystNoteCreate,
    request: Request,
    author: Optional[str] = "analyst",
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    note = AnalystNote(
        incident_id=incident.id,
        author=author or "analyst",
        note=payload.note,
        created_at=datetime.utcnow()
    )
    db.add(note)
    incident.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(note)

    audit_logger.log(
        db=db,
        actor_username=author or "analyst",
        action_type="INCIDENT_NOTE_ADD",
        entity_type="Incident",
        entity_id=str(incident.id),
        details=f"Logged investigation note on incident #{incident.id}",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    ws_manager.broadcast_sync("INCIDENT_NOTE_ADDED", {
        "incident_id": incident.id,
        "author": note.author,
        "note": note.note,
        "created_at": str(note.created_at)
    })

    return note
