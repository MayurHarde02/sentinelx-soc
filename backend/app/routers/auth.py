from datetime import timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserResponse, Token, LoginRequest, ChangePasswordRequest
from app.auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user,
    require_admin
)
from app.config import settings
from app.rate_limiter import rate_limiter
from app.audit import audit_logger

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=Token)
def login_json(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Rate limit login attempts: max 8 attempts / minute per IP
    rate_limiter.check_rate_limit(request, key_prefix="login_auth", max_tokens=8, refill_rate_per_sec=0.15)

    user = db.query(User).filter(User.username == payload.username).first()
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not user or not verify_password(payload.password, user.password_hash):
        audit_logger.log(
            db=db,
            actor_username=payload.username or "anonymous",
            action_type="LOGIN_FAILED",
            details=f"Failed login attempt for username '{payload.username}'",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="User account is deactivated")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )

    audit_logger.log(
        db=db,
        actor_username=user.username,
        action_type="LOGIN_SUCCESS",
        details=f"Successful SOC authentication as role '{user.role}'",
        ip_address=client_ip
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/change-password", response_model=Dict[str, Any])
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    current_user.password_hash = get_password_hash(payload.new_password)
    db.commit()

    audit_logger.log(
        db=db,
        actor_username=current_user.username,
        action_type="PASSWORD_CHANGE",
        details="User password updated successfully",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return {"status": "success", "message": "Password changed successfully"}

@router.post("/register", response_model=UserResponse)
def register_user(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    existing = db.query(User).filter(User.username == user_in.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    new_user = User(
        username=user_in.username,
        full_name=user_in.full_name,
        password_hash=get_password_hash(user_in.password),
        role=user_in.role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    audit_logger.log(
        db=db,
        actor_username=current_user.username,
        action_type="USER_REGISTER",
        entity_type="User",
        entity_id=str(new_user.id),
        details=f"Admin registered new user '{new_user.username}' with role '{new_user.role}'",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return new_user
