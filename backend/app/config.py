import os
import secrets
from typing import List
from pydantic_settings import BaseSettings
from pydantic import ConfigDict

def _get_cors_origins() -> List[str]:
    env_origins = os.getenv("CORS_ORIGINS")
    if env_origins:
        return [origin.strip() for origin in env_origins.split(",") if origin.strip()]
    
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env == "production":
        # In production without explicit origins, do not allow wildcard '*'
        return ["http://localhost:8000", "http://127.0.0.1:8000"]
    
    # Development defaults
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*"
    ]

def _get_database_url() -> str:
    db_url = os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")
    # Handle older/cloud postgres:// scheme compatibility for SQLAlchemy
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    return db_url

class Settings(BaseSettings):
    model_config = ConfigDict(case_sensitive=True)
    
    PROJECT_NAME: str = "SentinelX SOC Dashboard"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Security & Auth
    SECRET_KEY: str = os.getenv("SECRET_KEY", "sentinelx-super-secret-key-soc-2026-secure-token")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Default Initial Credentials (can be overridden via environment variables)
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "sentinelx123")
    ANALYST_USERNAME: str = os.getenv("ANALYST_USERNAME", "analyst")
    ANALYST_PASSWORD: str = os.getenv("ANALYST_PASSWORD", "analyst123")
    
    # Database (SQLite or PostgreSQL)
    DATABASE_URL: str = _get_database_url()
    
    # Detection Rules Configuration Defaults
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_MINUTES: int = 5
    
    PORT_SCAN_THRESHOLD: int = 10
    PORT_SCAN_WINDOW_MINUTES: int = 1
    
    SUSPICIOUS_LOGIN_FAIL_THRESHOLD: int = 3
    SUSPICIOUS_LOGIN_WINDOW_MINUTES: int = 5
    
    EVENT_FLOOD_THRESHOLD: int = 100
    EVENT_FLOOD_WINDOW_MINUTES: int = 1
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = _get_cors_origins()

settings = Settings()
