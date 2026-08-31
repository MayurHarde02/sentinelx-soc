import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import get_db, init_db
from app.models import Base, AuditLog
import app.database as db_mod

os.environ["TESTING"] = "1"
TEST_DB_FILE = "./test_security.db"
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

def test_security_headers():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert "Content-Security-Policy" in res.headers

def test_audit_logging_on_login():
    # Login as admin
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "sentinelx123"})
    assert login_res.status_code == 200

    # Query audit logs
    audit_res = client.get("/api/audit-logs")
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert len(logs) >= 1
    assert any(l["action_type"] == "LOGIN_SUCCESS" for l in logs)

def test_create_and_delete_custom_rule_via_api():
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "sentinelx123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    rule_payload = {
        "name": "API Unauthorized Probe",
        "code": "RULE_UNAUTH_PROBE",
        "description": "Flags repeated 401 unauthenticated requests",
        "severity": "HIGH",
        "threshold": 3,
        "window_minutes": 5,
        "is_enabled": True,
        "event_type_filter": "API_REQUEST",
        "status_filter": "UNAUTHORIZED",
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts"
    }

    create_res = client.post("/api/rules", json=rule_payload, headers=headers)
    assert create_res.status_code == 200
    rule_data = create_res.json()
    assert rule_data["code"] == "RULE_UNAUTH_PROBE"
    rule_id = rule_data["id"]

    # Delete custom rule
    del_res = client.delete(f"/api/rules/{rule_id}", headers=headers)
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "success"

def test_threat_feed_blocklist_api():
    add_res = client.post(
        "/api/threat-intel/blocklist",
        json={
            "ip_or_cidr": "91.240.118.12",
            "feed_name": "Custom Incident Blocklist",
            "threat_category": "C2_BOTNET",
            "severity": "CRITICAL",
            "description": "Investigated attack source",
            "is_active": True
        }
    )
    assert add_res.status_code == 200
    item_id = add_res.json()["id"]

    list_res = client.get("/api/threat-intel/blocklist")
    assert list_res.status_code == 200
    assert any(i["ip_or_cidr"] == "91.240.118.12" for i in list_res.json())

    del_res = client.delete(f"/api/threat-intel/blocklist/{item_id}")
    assert del_res.status_code == 200
