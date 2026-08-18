# SentinelX: Mini Security Operations Center (SOC) & SIEM Dashboard

**SentinelX** is a lightweight, full-featured Security Operations Center (SOC) and Security Information and Event Management (SIEM) platform designed for cybersecurity analysts, engineers, and learners. It ingests, parses, normalizes, detects cyber threats in real time, alerts analysts, and enables incident investigation and reporting.

---

## 🌟 Key Features

1. **Security Log Collection & Normalization (FR-01, FR-02, FR-03)**
   - Normalizes raw text logs, syslog (auth/sshd), JSON payloads, Apache/Nginx web logs, and standard SentinelX format into a unified structure (`timestamp`, `event_type`, `source_ip`, `destination_ip`, `port`, `username`, `status`, `metadata`).
   - Supports single log ingestion, batch upload, and real-time UI log injection.

2. **Rule-Based Threat Detection Engine (FR-04 to FR-07, Section 16)**
   - **Rule 1 (Brute Force)**: $\ge 5$ failed login attempts from same IP within 5 minutes $\rightarrow$ `HIGH` / `CRITICAL` alert.
   - **Rule 2 (Port Scan)**: $\ge 10$ distinct destination ports probed from same IP within 1 minute $\rightarrow$ `HIGH` alert.
   - **Rule 3 (Suspicious Login)**: Multiple failed logins followed immediately by a successful login $\rightarrow$ `HIGH` alert.
   - **Rule 4 (Event Flood)**: $\ge 100$ requests/events from same source within 1 minute $\rightarrow$ `MEDIUM` / `HIGH` alert.
   - Fully customizable rules with sliding window and activation thresholds.

3. **Alerts Triage Queue & Lifecycle (FR-08 to FR-11)**
   - Real-time alert list with multi-filtering by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), status (`Open`, `Investigating`, `Resolved`, `False Positive`), type, and source IP.
   - One-click status updates and direct escalation to incident response.

4. **Incident Response & Investigation Workspace (FR-16, FR-17)**
   - Convert alerts into formal incidents with assigned analyst, scope, linked alert evidence, and investigation journals/notes.

5. **IP Intelligence & Source Tracking (FR-15)**
   - Tracks unique threat actors and endpoints, calculating dynamic Threat Scores ($0–100$) based on alert severities, event frequencies, targeted ports, and associated usernames.

6. **Interactive Attack Scenario Simulator**
   - Built-in cybersecurity attack launcher:
     - Scenario 1: SSH / Web Brute Force
     - Scenario 2: Nmap Multi-Port Reconnaissance Scan
     - Scenario 3: Credential Stuffing & Suspicious Login
     - Scenario 4: DDoS / Event Flood
     - Scenario 5: Benign Workstation Traffic
   - Continuous background telemetry generator for realistic live SOC monitoring.

7. **SOC Reporting & CSV Export (FR-18)**
   - Executive posture summaries, attack vector distribution, top threat actor rankings, and one-click CSV export for events, alerts, and incidents.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.14, FastAPI, SQLAlchemy, SQLite, Pydantic v2, Uvicorn, Passlib (bcrypt), Python-JOSE (JWT)
- **Frontend**: React 18, Vite, Chart.js, React-Chartjs-2, Lucide Icons, Custom Cyber SOC Design System

---

## 🚀 Quickstart Guide

### 1. Backend Setup & Startup

```bash
# Navigate to the backend directory
cd backend

# Install Python requirements
pip install -r requirements.txt

# Start the FastAPI backend server (http://127.0.0.1:8000)
python run.py
```

FastAPI Interactive API Documentation:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

### 2. Frontend Setup & Startup

```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies (already prepared)
npm install

# Launch Vite development server (http://localhost:5173)
npm run dev
```

---

## 🔐 Default Demo Accounts

| Role | Username | Password | Privileges |
|---|---|---|---|
| **SOC Administrator** | `admin` | `sentinelx123` | Full administrative control, rule configuration, user management |
| **L2 Security Analyst** | `analyst` | `analyst123` | Alert triage, incident response, investigation notes, log injection |

---

## 🧪 Running Automated Tests

```bash
cd backend
python -m pytest tests/
```
All unit tests for log parsing, rule detection heuristics, and API integration are verified.
