from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.models import Alert, SecurityEvent
from app.schemas import AlertStatsResponse

class AlertManager:
    """Manages Alert lifecycle, metrics aggregation, filtering, and queries."""

    def __init__(self, db: Session):
        self.db = db

    def get_alerts(
        self,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Alert]:
        query = self.db.query(Alert)
        if severity:
            query = query.filter(Alert.severity == severity.upper())
        if alert_type:
            query = query.filter(Alert.alert_type == alert_type.upper())
        if source_ip:
            query = query.filter(Alert.source_ip.contains(source_ip))
        if status:
            query = query.filter(Alert.status == status)

        return query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit).all()

    def get_alert_by_id(self, alert_id: int) -> Optional[Alert]:
        return self.db.query(Alert).filter(Alert.id == alert_id).first()

    def update_alert_status(self, alert_id: int, new_status: str) -> Optional[Alert]:
        alert = self.get_alert_by_id(alert_id)
        if not alert:
            return None
        alert.status = new_status
        alert.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def get_stats(self) -> Dict[str, Any]:
        total_alerts = self.db.query(func.count(Alert.id)).scalar() or 0
        critical_alerts = self.db.query(func.count(Alert.id)).filter(Alert.severity == "CRITICAL").scalar() or 0
        high_alerts = self.db.query(func.count(Alert.id)).filter(Alert.severity == "HIGH").scalar() or 0
        medium_alerts = self.db.query(func.count(Alert.id)).filter(Alert.severity == "MEDIUM").scalar() or 0
        low_alerts = self.db.query(func.count(Alert.id)).filter(Alert.severity == "LOW").scalar() or 0

        open_alerts = self.db.query(func.count(Alert.id)).filter(Alert.status == "Open").scalar() or 0
        investigating_alerts = self.db.query(func.count(Alert.id)).filter(Alert.status == "Investigating").scalar() or 0
        resolved_alerts = self.db.query(func.count(Alert.id)).filter(Alert.status == "Resolved").scalar() or 0

        # Severity breakdown
        sev_counts = self.db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
        severity_distribution = {s: c for s, c in sev_counts}

        # Type breakdown
        type_counts = self.db.query(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).all()
        alert_types_distribution = {t: c for t, c in type_counts}

        return {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts": low_alerts,
            "open_alerts": open_alerts,
            "investigating_alerts": investigating_alerts,
            "resolved_alerts": resolved_alerts,
            "severity_distribution": severity_distribution,
            "alert_types_distribution": alert_types_distribution
        }
