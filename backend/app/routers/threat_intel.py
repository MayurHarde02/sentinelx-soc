from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import ThreatFeedItem
from app.schemas import (
    ThreatFeedItemCreate,
    ThreatFeedItemResponse,
    GeoIpResponse,
    ExternalIntelResponse
)
from app.threat_intel import threat_intel_service
from app.audit import audit_logger

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence & Blocklists"])

@router.get("/blocklist", response_model=List[ThreatFeedItemResponse])
def list_threat_feed_items(db: Session = Depends(get_db)):
    return db.query(ThreatFeedItem).order_by(ThreatFeedItem.created_at.desc()).all()

@router.post("/blocklist", response_model=ThreatFeedItemResponse)
def add_threat_feed_item(
    payload: ThreatFeedItemCreate,
    request: Request,
    actor: str = "analyst",
    db: Session = Depends(get_db)
):
    existing = db.query(ThreatFeedItem).filter(ThreatFeedItem.ip_or_cidr == payload.ip_or_cidr).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"IP or CIDR range '{payload.ip_or_cidr}' already exists in blocklist")

    item = ThreatFeedItem(
        ip_or_cidr=payload.ip_or_cidr.strip(),
        feed_name=payload.feed_name,
        threat_category=payload.threat_category,
        severity=payload.severity.upper(),
        description=payload.description,
        is_active=payload.is_active
    )
    db.add(item)
    db.commit()
    db.refresh(item)

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="THREAT_FEED_ADD",
        entity_type="ThreatFeedItem",
        entity_id=str(item.id),
        details=f"Added {item.ip_or_cidr} to blocklist ({item.threat_category})",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return item

@router.delete("/blocklist/{item_id}")
def delete_threat_feed_item(
    item_id: int,
    request: Request,
    actor: str = "analyst",
    db: Session = Depends(get_db)
):
    item = db.query(ThreatFeedItem).filter(ThreatFeedItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Blocklist item not found")

    deleted_ip = item.ip_or_cidr
    db.delete(item)
    db.commit()

    audit_logger.log(
        db=db,
        actor_username=actor,
        action_type="THREAT_FEED_DELETE",
        entity_type="ThreatFeedItem",
        entity_id=str(item_id),
        details=f"Removed {deleted_ip} from threat blocklist",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return {"status": "success", "message": f"Removed {deleted_ip} from blocklist"}

@router.get("/lookup/{ip}", response_model=GeoIpResponse)
def lookup_ip_geoip(ip: str):
    geo = threat_intel_service.resolve_geoip(ip)
    return GeoIpResponse(**geo)

@router.get("/reputation/{ip}", response_model=ExternalIntelResponse)
def lookup_external_reputation(ip: str):
    rep = threat_intel_service.fetch_external_reputation(ip)
    return ExternalIntelResponse(**rep)
