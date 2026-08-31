from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db
from app.models import AuditLog
from app.schemas import AuditLogResponse

router = APIRouter(prefix="/audit-logs", tags=["SOC Audit Logs"])

@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    action_type: Optional[str] = None,
    actor_username: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if action_type:
        query = query.filter(AuditLog.action_type == action_type.upper())
    if actor_username:
        query = query.filter(AuditLog.actor_username == actor_username)

    return query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()
