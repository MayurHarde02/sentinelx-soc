from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Playbook, PlaybookExecution, User
from app.schemas import (
    PlaybookResponse,
    PlaybookExecuteRequest,
    PlaybookExecutionResponse,
    SoarMetricsResponse
)
from app.auth import get_current_user
from app.playbooks import execute_playbook, calculate_soar_metrics

router = APIRouter(prefix="/soar", tags=["SOAR Automation & Playbooks"])

@router.get("/playbooks", response_model=List[PlaybookResponse])
def list_playbooks(
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all available SOAR security playbooks."""
    query = db.query(Playbook)
    if category:
        query = query.filter(Playbook.category == category)
    return query.order_by(Playbook.id.asc()).all()


@router.patch("/playbooks/{code}/toggle", response_model=PlaybookResponse)
def toggle_playbook(
    code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Enable or disable autonomous execution for a specific playbook."""
    pb = db.query(Playbook).filter(Playbook.code == code).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    pb.is_active = not pb.is_active
    db.commit()
    db.refresh(pb)
    return pb


@router.post("/playbooks/{code}/execute", response_model=PlaybookExecutionResponse)
def run_playbook(
    code: str,
    payload: PlaybookExecuteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually trigger a SOAR security orchestration playbook against a target."""
    pb = db.query(Playbook).filter(Playbook.code == code).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{code}' does not exist")

    execution = execute_playbook(
        db=db,
        playbook_code=code,
        target_value=payload.target_value.strip(),
        incident_id=payload.incident_id,
        alert_id=payload.alert_id,
        triggered_by=current_user.username
    )
    return execution


@router.get("/executions", response_model=List[PlaybookExecutionResponse])
def list_executions(
    limit: int = Query(50, ge=1, le=200),
    target_value: Optional[str] = None,
    playbook_code: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve historical execution logs of SOAR playbooks."""
    query = db.query(PlaybookExecution)
    if target_value:
        query = query.filter(PlaybookExecution.target_value == target_value)
    if playbook_code:
        query = query.filter(PlaybookExecution.playbook_code == playbook_code)
    
    return query.order_by(PlaybookExecution.created_at.desc()).limit(limit).all()


@router.get("/metrics", response_model=SoarMetricsResponse)
def get_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve SOC operational KPIs including MTTD, MTTR, and automation rate."""
    return calculate_soar_metrics(db)
