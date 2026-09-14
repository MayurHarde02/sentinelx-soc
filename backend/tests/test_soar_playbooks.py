import os
os.environ["TESTING"] = "1"
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import get_db, init_db
from app.models import Base, User, Playbook, PlaybookExecution, ThreatFeedItem, Incident, Alert
from app.auth import get_password_hash
import app.database as db_mod

TEST_DB_FILE = "./test_sentinelx_soar.db"
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

def get_auth_token():
    res = client.post("/api/auth/login", json={"username": "admin", "password": "sentinelx123"})
    assert res.status_code == 200
    return res.json()["access_token"]

def test_list_and_seed_playbooks():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    res = client.get("/api/soar/playbooks", headers=headers)
    assert res.status_code == 200
    playbooks = res.json()
    assert len(playbooks) >= 4
    codes = [p["code"] for p in playbooks]
    assert "PLAYBOOK_CONTAIN_IP" in codes
    assert "PLAYBOOK_QUARANTINE_USER" in codes
    assert "PLAYBOOK_FORENSIC_DOSSIER" in codes
    assert "PLAYBOOK_AUTO_CONTAIN_CRITICAL" in codes

def test_toggle_playbook_active_state():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Toggle off
    res = client.patch("/api/soar/playbooks/PLAYBOOK_AUTO_CONTAIN_CRITICAL/toggle", headers=headers)
    assert res.status_code == 200
    assert res.json()["is_active"] is False

    # Toggle back on
    res2 = client.patch("/api/soar/playbooks/PLAYBOOK_AUTO_CONTAIN_CRITICAL/toggle", headers=headers)
    assert res2.status_code == 200
    assert res2.json()["is_active"] is True

def test_execute_contain_ip_playbook():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    target_ip = "203.0.113.88"
    payload = {
        "target_value": target_ip
    }
    res = client.post("/api/soar/playbooks/PLAYBOOK_CONTAIN_IP/execute", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["target_value"] == target_ip
    assert data["playbook_code"] == "PLAYBOOK_CONTAIN_IP"

    # Verify IP was added to ThreatFeedItem
    db = TestingSessionLocal()
    feed_item = db.query(ThreatFeedItem).filter(ThreatFeedItem.ip_or_cidr == target_ip).first()
    assert feed_item is not None
    assert feed_item.severity == "CRITICAL"
    db.close()

def test_execute_quarantine_user_playbook():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Seed a compromised test user
    db = TestingSessionLocal()
    u = User(
        username="compromised_analyst_test",
        full_name="Compromised User",
        password_hash=get_password_hash("password123"),
        role="analyst",
        is_active=True
    )
    db.add(u)
    db.commit()
    db.close()

    payload = {
        "target_value": "compromised_analyst_test"
    }
    res = client.post("/api/soar/playbooks/PLAYBOOK_QUARANTINE_USER/execute", json=payload, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "SUCCESS"

    # Verify user is deactivated
    db = TestingSessionLocal()
    u_after = db.query(User).filter(User.username == "compromised_analyst_test").first()
    assert u_after.is_active is False
    db.close()

def test_execute_forensic_dossier_playbook():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create an incident to receive the forensic dossier
    db = TestingSessionLocal()
    inc = Incident(title="Test Forensic Incident", description="Testing dossier attachment", severity="HIGH", status="Open")
    db.add(inc)
    db.commit()
    inc_id = inc.id
    db.close()

    payload = {
        "target_value": "198.51.100.22",
        "incident_id": inc_id
    }
    res = client.post("/api/soar/playbooks/PLAYBOOK_FORENSIC_DOSSIER/execute", json=payload, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "SUCCESS"

    # Verify incident received the note
    db = TestingSessionLocal()
    inc_after = db.query(Incident).filter(Incident.id == inc_id).first()
    assert len(inc_after.notes) >= 1
    assert "SOAR Automated Forensic Dossier" in inc_after.notes[0].note
    db.close()

def test_soar_metrics_kpi():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/soar/metrics", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "mttd_seconds" in data
    assert "mttr_seconds" in data
    assert "mttd_display" in data
    assert "mttr_display" in data
    assert data["total_playbooks"] >= 4
    assert data["total_executions"] >= 3
