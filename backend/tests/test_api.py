import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import get_db, init_db
from app.models import Base
import app.database as db_mod
import app.simulator as sim_mod

TEST_DB_FILE = "./test_sentinelx.db"
test_engine = create_engine(f"sqlite:///{TEST_DB_FILE}", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
db_mod.engine = test_engine
db_mod.SessionLocal = TestingSessionLocal
sim_mod.SessionLocal = TestingSessionLocal

@pytest.fixture(autouse=True, scope="module")
def setup_module():
    Base.metadata.create_all(bind=test_engine)
    init_db()
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except Exception:
            pass

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "online"

def test_login_success():
    res = client.post("/api/auth/login", json={"username": "admin", "password": "sentinelx123"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["username"] == "admin"

def test_ingest_event_and_stats():
    payload = {
        "event_type": "LOGIN_FAILED",
        "source_ip": "192.168.1.100",
        "username": "admin",
        "status": "FAILURE"
    }
    res = client.post("/api/events", json=payload)
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    stats_res = client.get("/api/events/stats")
    assert stats_res.status_code == 200
    assert stats_res.json()["total_events"] >= 1

def test_trigger_simulation_and_get_alerts():
    sim_res = client.post("/api/simulation/trigger", json={"scenario": "brute_force", "intensity": 1})
    assert sim_res.status_code == 200
    assert sim_res.json()["events_generated"] >= 5
    assert sim_res.json()["alerts_triggered"] >= 1

    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]

    status_res = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "Investigating"})
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "Investigating"

    esc_res = client.post(f"/api/alerts/{alert_id}/escalate")
    assert esc_res.status_code == 200
    assert "incident_id" in esc_res.json()

def test_security_report_and_csv():
    client.post("/api/simulation/seed-demo")
    
    rep_res = client.get("/api/reports/summary")
    assert rep_res.status_code == 200
    assert rep_res.json()["total_events"] > 0

    csv_res = client.get("/api/reports/export/csv?data_type=alerts")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
