import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from app.database import get_db
from app.models import SecurityEvent, Alert, Incident, IncidentAlert, AnalystNote
from app.schemas import (
    SecurityEventCreate,
    SecurityEventResponse,
    RawLogIngestRequest,
    BatchLogIngestRequest,
    EventStatsResponse
)
from app.parser import parse_security_log
from app.detection import DetectionEngine

router = APIRouter(prefix="/events", tags=["Security Events"])

@router.get("", response_model=List[SecurityEventResponse])
def get_events(
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    username: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.upper())
    if source_ip:
        query = query.filter(SecurityEvent.source_ip.contains(source_ip))
    if status:
        query = query.filter(SecurityEvent.status == status.upper())
    if username:
        query = query.filter(SecurityEvent.username.contains(username))
    if search:
        s = f"%{search}%"
        query = query.filter(
            (SecurityEvent.raw_log.ilike(s)) |
            (SecurityEvent.source_ip.ilike(s)) |
            (SecurityEvent.username.ilike(s)) |
            (SecurityEvent.event_type.ilike(s))
        )

    return query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()

@router.post("", response_model=Dict[str, Any])
def ingest_event(event_in: SecurityEventCreate, db: Session = Depends(get_db)):
    event = SecurityEvent(
        timestamp=event_in.timestamp or datetime.utcnow(),
        event_type=event_in.event_type,
        source_ip=event_in.source_ip,
        destination_ip=event_in.destination_ip,
        port=event_in.port,
        username=event_in.username,
        status=event_in.status,
        raw_log=event_in.raw_log or f"{event_in.event_type} {event_in.source_ip} {event_in.username}",
        metadata_json=event_in.metadata_json
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    engine = DetectionEngine(db)
    triggered_alerts = engine.evaluate_event(event)

    return {
        "status": "success",
        "event_id": event.id,
        "event": SecurityEventResponse.model_validate(event),
        "alerts_triggered": len(triggered_alerts)
    }

@router.post("/raw", response_model=Dict[str, Any])
def ingest_raw_log(payload: RawLogIngestRequest, db: Session = Depends(get_db)):
    try:
        parsed_event = parse_security_log(payload.log_line)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Log parsing failed: {str(e)}")

    event = SecurityEvent(
        timestamp=parsed_event.timestamp or datetime.utcnow(),
        event_type=parsed_event.event_type,
        source_ip=parsed_event.source_ip,
        destination_ip=parsed_event.destination_ip,
        port=parsed_event.port,
        username=parsed_event.username,
        status=parsed_event.status,
        raw_log=parsed_event.raw_log,
        metadata_json=parsed_event.metadata_json
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    engine = DetectionEngine(db)
    triggered_alerts = engine.evaluate_event(event)

    return {
        "status": "success",
        "event_id": event.id,
        "event": SecurityEventResponse.model_validate(event),
        "alerts_triggered": len(triggered_alerts)
    }

@router.post("/batch", response_model=Dict[str, Any])
def ingest_batch_logs(payload: BatchLogIngestRequest, db: Session = Depends(get_db)):
    created_count = 0
    alerts_count = 0
    engine = DetectionEngine(db)

    for line in payload.logs:
        if not line.strip():
            continue
        try:
            parsed = parse_security_log(line)
            event = SecurityEvent(
                timestamp=parsed.timestamp or datetime.utcnow(),
                event_type=parsed.event_type,
                source_ip=parsed.source_ip,
                destination_ip=parsed.destination_ip,
                port=parsed.port,
                username=parsed.username,
                status=parsed.status,
                raw_log=parsed.raw_log,
                metadata_json=parsed.metadata_json
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            created_count += 1

            alerts = engine.evaluate_event(event)
            alerts_count += len(alerts)
        except Exception:
            continue

    return {
        "status": "success",
        "events_ingested": created_count,
        "alerts_triggered": alerts_count
    }

@router.post("/upload", response_model=Dict[str, Any])
async def upload_log_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    lines = text.splitlines()

    engine = DetectionEngine(db)
    created_count = 0
    alerts_count = 0

    for line in lines:
        if not line.strip():
            continue
        try:
            parsed = parse_security_log(line)
            event = SecurityEvent(
                timestamp=parsed.timestamp or datetime.utcnow(),
                event_type=parsed.event_type,
                source_ip=parsed.source_ip,
                destination_ip=parsed.destination_ip,
                port=parsed.port,
                username=parsed.username,
                status=parsed.status,
                raw_log=parsed.raw_log,
                metadata_json=parsed.metadata_json
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            created_count += 1

            alerts = engine.evaluate_event(event)
            alerts_count += len(alerts)
        except Exception:
            continue

    return {
        "status": "success",
        "filename": file.filename,
        "events_ingested": created_count,
        "alerts_triggered": alerts_count
    }

@router.get("/stats", response_model=EventStatsResponse)
def get_event_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(SecurityEvent.id)).scalar() or 0

    # Group by event type
    type_rows = db.query(SecurityEvent.event_type, func.count(SecurityEvent.id)).group_by(SecurityEvent.event_type).all()
    event_types = {t: c for t, c in type_rows}

    # Top 5 source IPs
    ip_rows = db.query(
        SecurityEvent.source_ip,
        func.count(SecurityEvent.id).label("count")
    ).group_by(SecurityEvent.source_ip).order_by(desc("count")).limit(5).all()
    
    top_source_ips = [{"ip": r[0], "count": r[1]} for r in ip_rows]

    # Activity over time (e.g. grouped by hour or minute in recent window)
    events_per_minute = []
    recent_events = db.query(
        func.strftime('%Y-%m-%d %H:%M', SecurityEvent.timestamp).label("minute_bucket"),
        func.count(SecurityEvent.id).label("count")
    ).group_by("minute_bucket").order_by(desc("minute_bucket")).limit(20).all()

    for row in reversed(recent_events):
        events_per_minute.append({"time": row[0], "count": row[1]})

    return {
        "total_events": total,
        "event_types": event_types,
        "events_per_minute": events_per_minute,
        "top_source_ips": top_source_ips
    }

@router.delete("/clear")
def clear_all_events(db: Session = Depends(get_db)):
    """Reset all events and alerts for testing."""
    db.query(AnalystNote).delete()
    db.query(IncidentAlert).delete()
    db.query(Incident).delete()
    db.query(Alert).delete()
    db.query(SecurityEvent).delete()
    db.commit()
    return {"status": "success", "message": "All events, alerts, and incidents cleared"}
