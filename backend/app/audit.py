from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models import AuditLog

class AuditLogger:
    """Records audit logs for all security analyst actions across the SOC platform."""

    @staticmethod
    def log(
        db: Session,
        actor_username: str,
        action_type: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> AuditLog:
        audit_entry = AuditLog(
            timestamp=datetime.utcnow(),
            actor_username=actor_username or "system",
            action_type=action_type,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            details=details,
            ip_address=ip_address or "127.0.0.1",
            created_at=datetime.utcnow()
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        return audit_entry

audit_logger = AuditLogger()
