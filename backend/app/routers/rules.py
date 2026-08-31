from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import DetectionRule
from app.schemas import DetectionRuleResponse, DetectionRuleUpdate, DetectionRuleCreate
from app.config import settings
from app.audit import audit_logger

router = APIRouter(prefix="/rules", tags=["Detection Rules"])

@router.get("", response_model=List[DetectionRuleResponse])
def get_detection_rules(db: Session = Depends(get_db)):
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()

@router.post("", response_model=DetectionRuleResponse)
def create_custom_rule(
    payload: DetectionRuleCreate,
    request: Request,
    actor: str = "admin",
    db: Session = Depends(get_db)
):
    code = payload.code.upper().strip()
    if not code.startswith("RULE_"):
        code = f"RULE_{code}"

    existing = db.query(DetectionRule).filter(DetectionRule.code == code).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Rule with code '{code}' already exists")

    rule = DetectionRule(
        name=payload.name,
        code=code,
        description=payload.description,
        severity=payload.severity.upper(),
        threshold=max(1, payload.threshold),
        window_minutes=max(1, payload.window_minutes),
        is_enabled=payload.is_enabled,
        is_custom=True,
        event_type_filter=payload.event_type_filter.upper() if payload.event_type_filter else None,
        status_filter=payload.status_filter.upper() if payload.status_filter else None,
        mitre_tactic=payload.mitre_tactic or "Defense Evasion",
        mitre_technique_id=payload.mitre_technique_id or "T1078",
        mitre_technique_name=payload.mitre_technique_name or "Valid Accounts"
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="RULE_CREATE",
        entity_type="DetectionRule",
        entity_id=str(rule.id),
        details=f"Created custom rule '{rule.name}' ({rule.code})",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return rule

@router.patch("/{rule_id}", response_model=DetectionRuleResponse)
def update_detection_rule(
    rule_id: int,
    payload: DetectionRuleUpdate,
    request: Request,
    actor: str = "admin",
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
    if payload.event_type_filter is not None:
        rule.event_type_filter = payload.event_type_filter.upper()
    if payload.status_filter is not None:
        rule.status_filter = payload.status_filter.upper()
    if payload.mitre_tactic is not None:
        rule.mitre_tactic = payload.mitre_tactic
    if payload.mitre_technique_id is not None:
        rule.mitre_technique_id = payload.mitre_technique_id
    if payload.mitre_technique_name is not None:
        rule.mitre_technique_name = payload.mitre_technique_name

    db.commit()
    db.refresh(rule)

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="RULE_UPDATE",
        entity_type="DetectionRule",
        entity_id=str(rule.id),
        details=f"Updated rule '{rule.name}' (threshold={rule.threshold}, window={rule.window_minutes}m, enabled={rule.is_enabled})",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return rule

@router.delete("/{rule_id}")
def delete_detection_rule(
    rule_id: int,
    request: Request,
    actor: str = "admin",
    db: Session = Depends(get_db)
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    if not rule.is_custom:
        raise HTTPException(status_code=400, detail="Core built-in detection rules cannot be deleted. You may disable them instead.")

    rule_name = rule.name
    db.delete(rule)
    db.commit()

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="RULE_DELETE",
        entity_type="DetectionRule",
        entity_id=str(rule_id),
        details=f"Deleted custom rule '{rule_name}'",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return {"status": "success", "message": f"Custom rule '{rule_name}' deleted"}

@router.post("/reset", response_model=List[DetectionRuleResponse])
def reset_detection_rules(db: Session = Depends(get_db)):
    """Reset default rules to baseline thresholds."""
    defaults = {
        "RULE_BRUTE_FORCE": {"threshold": settings.BRUTE_FORCE_THRESHOLD, "window": settings.BRUTE_FORCE_WINDOW_MINUTES, "sev": "HIGH", "tactic": "Credential Access", "tid": "T1110", "tname": "Brute Force"},
        "RULE_PORT_SCAN": {"threshold": settings.PORT_SCAN_THRESHOLD, "window": settings.PORT_SCAN_WINDOW_MINUTES, "sev": "HIGH", "tactic": "Reconnaissance", "tid": "T1046", "tname": "Network Service Discovery"},
        "RULE_SUSPICIOUS_LOGIN": {"threshold": settings.SUSPICIOUS_LOGIN_FAIL_THRESHOLD, "window": settings.SUSPICIOUS_LOGIN_WINDOW_MINUTES, "sev": "HIGH", "tactic": "Initial Access", "tid": "T1078", "tname": "Valid Accounts"},
        "RULE_EVENT_FLOOD": {"threshold": settings.EVENT_FLOOD_THRESHOLD, "window": settings.EVENT_FLOOD_WINDOW_MINUTES, "sev": "MEDIUM", "tactic": "Impact", "tid": "T1498", "tname": "Network Denial of Service"},
        "RULE_ML_ANOMALY": {"threshold": 1, "window": 2, "sev": "HIGH", "tactic": "Execution", "tid": "T1059", "tname": "Command and Scripting Interpreter"},
        "RULE_KNOWN_MALICIOUS_IP": {"threshold": 1, "window": 1, "sev": "CRITICAL", "tactic": "Command and Control", "tid": "T1071", "tname": "Application Layer Protocol"},
    }
    rules = db.query(DetectionRule).all()
    for r in rules:
        if r.code in defaults:
            d = defaults[r.code]
            r.threshold = d["threshold"]
            r.window_minutes = d["window"]
            r.severity = d["sev"]
            r.mitre_tactic = d["tactic"]
            r.mitre_technique_id = d["tid"]
            r.mitre_technique_name = d["tname"]
            r.is_enabled = True
    db.commit()
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()
