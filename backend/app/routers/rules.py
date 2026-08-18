from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import DetectionRule
from app.schemas import DetectionRuleResponse, DetectionRuleUpdate
from app.config import settings

router = APIRouter(prefix="/rules", tags=["Detection Rules"])

@router.get("", response_model=List[DetectionRuleResponse])
def get_detection_rules(db: Session = Depends(get_db)):
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()

@router.patch("/{rule_id}", response_model=DetectionRuleResponse)
def update_detection_rule(
    rule_id: int,
    payload: DetectionRuleUpdate,
    db: Session = Depends(get_db)
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    if payload.name is not None:
        rule.name = payload.name
    if payload.description is not None:
        rule.description = payload.description
    if payload.severity is not None:
        rule.severity = payload.severity.upper()
    if payload.threshold is not None:
        rule.threshold = max(1, payload.threshold)
    if payload.window_minutes is not None:
        rule.window_minutes = max(1, payload.window_minutes)
    if payload.is_enabled is not None:
        rule.is_enabled = payload.is_enabled

    db.commit()
    db.refresh(rule)
    return rule

@router.post("/reset", response_model=List[DetectionRuleResponse])
def reset_detection_rules(db: Session = Depends(get_db)):
    """Reset rules to default thresholds."""
    defaults = {
        "RULE_BRUTE_FORCE": {"threshold": settings.BRUTE_FORCE_THRESHOLD, "window": settings.BRUTE_FORCE_WINDOW_MINUTES, "sev": "HIGH"},
        "RULE_PORT_SCAN": {"threshold": settings.PORT_SCAN_THRESHOLD, "window": settings.PORT_SCAN_WINDOW_MINUTES, "sev": "HIGH"},
        "RULE_SUSPICIOUS_LOGIN": {"threshold": settings.SUSPICIOUS_LOGIN_FAIL_THRESHOLD, "window": settings.SUSPICIOUS_LOGIN_WINDOW_MINUTES, "sev": "HIGH"},
        "RULE_EVENT_FLOOD": {"threshold": settings.EVENT_FLOOD_THRESHOLD, "window": settings.EVENT_FLOOD_WINDOW_MINUTES, "sev": "MEDIUM"},
    }
    rules = db.query(DetectionRule).all()
    for r in rules:
        if r.code in defaults:
            r.threshold = defaults[r.code]["threshold"]
            r.window_minutes = defaults[r.code]["window"]
            r.severity = defaults[r.code]["sev"]
            r.is_enabled = True
    db.commit()
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()
