import os
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.config import settings
from app.database import init_db
from app.simulator import background_simulation_loop
from app.middleware import SecurityHeadersMiddleware
from app.routers import (
    auth, events, alerts, incidents, ip_intel,
    rules, simulation, reports, ws, threat_intel, audit
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database & Seed data
    init_db()
    sim_task = None
    if not os.environ.get("TESTING"):
        sim_task = asyncio.create_task(background_simulation_loop())
    yield
    if sim_task:
        sim_task.cancel()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="SentinelX: Mini Security Operations Center (SOC) & SIEM API",
    lifespan=lifespan
)

# Attach Security Headers and CSP Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(events.router, prefix=settings.API_V1_STR)
app.include_router(alerts.router, prefix=settings.API_V1_STR)
app.include_router(incidents.router, prefix=settings.API_V1_STR)
app.include_router(ip_intel.router, prefix=settings.API_V1_STR)
app.include_router(threat_intel.router, prefix=settings.API_V1_STR)
app.include_router(rules.router, prefix=settings.API_V1_STR)
app.include_router(simulation.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(audit.router, prefix=settings.API_V1_STR)
app.include_router(ws.router, prefix=settings.API_V1_STR)

@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "online", "service": "SentinelX SOC Engine", "version": settings.PROJECT_VERSION}

# Locate built frontend directory if available (for production single-service deployment)
frontend_candidates = [
    Path(__file__).parent.parent.parent / "frontend" / "dist",
    Path(__file__).parent.parent / "frontend_dist",
    Path("/app/frontend_dist")
]

dist_dir = None
for candidate in frontend_candidates:
    if candidate.exists() and (candidate / "index.html").exists():
        dist_dir = candidate
        break

if dist_dir:
    if (dist_dir / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(dist_dir / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        file_path = dist_dir / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(dist_dir / "index.html")
else:
    @app.get("/", tags=["Root"])
    def root():
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.PROJECT_VERSION,
            "docs_url": "/docs",
            "api_prefix": settings.API_V1_STR
        }
