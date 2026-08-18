<div align="center">

# 🛡️ SentinelX: Mini Security Operations Center & SIEM

**A high-performance, lightweight SOC & SIEM platform engineered for real-time cyber threat detection, log analysis, alert triage, incident response, and security telemetry visualization.**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)](https://sentinelx-soc-wg93.onrender.com/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.14-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev)
[![SQLite](https://img.shields.io/badge/SQLite%20%2F%20PostgreSQL-Supported-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

[🌐 **Live Demo Dashboard**](https://sentinelx-soc-wg93.onrender.com/) • [Live Architecture](#-system-architecture) • [Key Capabilities](#-key-capabilities) • [Quickstart Guide](#-quickstart-guide) • [Detection Rules](#-threat-detection-heuristics) • [API Reference](#-api-endpoints)


</div>

---

## 📌 Executive Summary

**SentinelX** is a full-stack Security Operations Center (SOC) dashboard and Security Information and Event Management (SIEM) system built for cybersecurity analysts, blue teams, students, and engineers. It collects disparate security events, standardizes and normalizes them, analyzes them with sliding-window detection heuristics, and produces real-time alerts and incident workflows.

```
       LOGS INGESTION
     (Syslog, JSON, HTTP)
              │
              ▼
    ┌───────────────────┐
    │  PARSER & NORMAL  │ ──► Unified Schema (IP, Port, User, Action, Status)
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ DETECTION ENGINE  │ ──► Brute Force, Port Scans, Credential Stuffing, Floods
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │   ALERT MANAGER   │ ──► Deduplication, Severity Scoring, Lifecycle Triage
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │ INCIDENT WORKFLOW │ ──► Evidence Correlation, Analyst Notes, Resolution
    └───────────────────┘
```

---

## 🌟 Key Capabilities

### 1. 📥 Multi-Format Log Ingestion & Normalization (FR-01 - FR-03)
- Ingests standard SentinelX key-value logs, Linux `auth.log` / `sshd` syslog, Apache/Nginx web logs, and raw JSON payloads.
- Standardizes fields into a normalized data model: `timestamp`, `event_type`, `source_ip`, `destination_ip`, `port`, `username`, `status`, `raw_log`, and `metadata_json`.
- Supports single-event API ingestion, batch ingestion, file uploads, and UI-based manual injection.

### 2. ⚡ Heuristic Threat Detection Engine (FR-04 - FR-07)
- Continuous evaluation against active sliding-window detection rules.
- Real-time alert generation with automatic deduplication within active alert windows.
- Dynamic threat severity assignment (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

### 3. 🚨 Alert Triage Queue & Lifecycle (FR-08 - FR-11)
- Comprehensive triage table with multi-criteria filtering by Severity, Alert Type, Source IP, and Status (`Open`, `Investigating`, `Resolved`, `False Positive`).
- 1-click status transitions and direct alert escalation to formal incident response.

### 4. 🔬 Incident Response & Investigation Workspace (FR-16, FR-17)
- Converts one or more correlated alerts into formal security incidents.
- Interactive investigation workspace with timeline correlation, analyst investigation journal / notes, and audit-ready resolution tracking.

### 5. 🌐 Source IP Intelligence & Threat Scoring (FR-15)
- Automated profiling of threat actors and internal hosts.
- Calculates a dynamic **Threat Score (0–100)** and Level (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) based on alert history, scan volume, targeted usernames, and probed ports.

### 6. 🎮 Interactive Attack Scenario Simulator
- Built-in simulation tool to fire on-demand attacks for SOC training and engine verification:
  - **Scenario 1**: SSH / Web Brute Force Attack
  - **Scenario 2**: Nmap Multi-Port Reconnaissance Scan
  - **Scenario 3**: Credential Stuffing & Suspicious Login Sequence
  - **Scenario 4**: High-Frequency Event Flood (DDoS)
  - **Scenario 5**: Benign Workstation Network Traffic
- Background continuous telemetry streaming mode for real-time monitoring demos.

### 7. 📊 SOC Audit Reporting & CSV Export (FR-18)
- Executive security posture summary, attack vector distribution, and top threat actor rankings.
- Instant CSV export for Security Events, Alerts, and Incident records.

---

## 🛠️ System Architecture

```
                                      ┌─────────────────────────────────────────┐
                                      │              SENTINELX SOC              │
                                      └─────────────────────────────────────────┘
                                                           │
                        ┌──────────────────────────────────┴──────────────────────────────────┐
                        │                                                                     │
                 [ FRONTEND ]                                                          [ BACKEND ]
             React 18 + Vite + CSS                                              FastAPI + SQLite / PostgreSQL
                        │                                                                     │
       ┌────────────────┼────────────────┐                                    ┌───────────────┼───────────────┐
       │                │                │                                    │               │               │
  SOC Overview     Live Triage      Rules/Simulator                       Log Parser     Threat Engine   Incident Mgmt
 (Charts & Feed) (Alerts/Incidents) (Config/Triggers)                   (Syslog/JSON)    (4 Core Rules) (Workflow/Notes)
```

---

## 🎯 Threat Detection Heuristics

| Heuristic Rule | Rule Code | Detection Logic | Severity |
|---|---|---|---|
| **Brute Force Detection** | `RULE_BRUTE_FORCE` | $\ge 5$ failed login attempts from the same source IP within **5 minutes** | `HIGH` / `CRITICAL` |
| **Port Scan Detection** | `RULE_PORT_SCAN` | $\ge 10$ distinct destination ports probed from the same IP within **1 minute** | `HIGH` |
| **Suspicious Login Sequence** | `RULE_SUSPICIOUS_LOGIN` | Multiple failed logins immediately followed by a successful login from the same IP | `HIGH` |
| **Event Flood Anomaly** | `RULE_EVENT_FLOOD` | $\ge 100$ requests/events from a single source within **1 minute** | `MEDIUM` / `HIGH` |

---

## 🚀 Quickstart Guide

### Prerequisites
- **Python 3.10+** (Python 3.14 compatible)
- **Node.js 18+** & **npm**

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/MayurHarde02/sentinelx-soc.git
cd sentinelx-soc
```

---

### Step 2: Backend Setup & Launch

```bash
# Navigate to backend directory
cd backend

# Install Python requirements
pip install -r requirements.txt

# Start the FastAPI SOC Engine (http://127.0.0.1:8000)
python run.py
```

- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

### Step 3: Frontend Setup & Launch

Open a new terminal window:

```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite Development Server (http://localhost:5173)
npm run dev
```

Visit **`http://localhost:5173`** in your browser to access the SOC Console.

---

## 🔐 Default Demo Accounts

| Role | Username | Password | Privileges |
|---|---|---|---|
| **L2 Security Analyst** | `analyst` | `analyst123` | Log triage, incident creation, investigation notes, log injection |
| **SOC Administrator** | `admin` | `sentinelx123` | Rule configuration, threshold adjustment, user management |

> [!TIP]
> You can change user passwords at any time using the **Change Password** key icon in the dashboard header or via `POST /api/auth/change-password`.

---

## 🐳 Docker Deployment (Single-Container)

Build and run the entire unified stack (Frontend + Backend + Database) in a single command:

```bash
# Run with Docker Compose
docker compose up -d --build
```
Access the application at **`http://localhost:8000`**.

---

## 📡 API Endpoints

### Authentication & Users
- `POST /api/auth/login` — Authenticate and receive JWT access token.
- `GET /api/auth/me` — Retrieve current authenticated profile.
- `POST /api/auth/change-password` — Securely update user password.
- `POST /api/auth/register` — Register analyst (Admin only).

### Security Events
- `GET /api/events` — Paginated, filtered event list (by IP, type, status, search).
- `POST /api/events` — Ingest single structured JSON event.
- `POST /api/events/raw` — Ingest raw log line (auto-parsed & evaluated).
- `POST /api/events/batch` — Batch ingest multiple log lines.
- `POST /api/events/upload` — Upload raw log text files.
- `GET /api/events/stats` — Ingestion velocity and top source IPs.

### Alerts & Triage
- `GET /api/alerts` — Query alerts filtered by severity, status, or IP.
- `GET /api/alerts/{id}` — Alert details and trigger payload.
- `PATCH /api/alerts/{id}/status` — Update triage status (`Open`, `Investigating`, `Resolved`, `False Positive`).
- `POST /api/alerts/{id}/escalate` — 1-click escalation to formal Incident.

### Incident Management
- `GET /api/incidents` — List active and resolved incidents.
- `POST /api/incidents` — Create incident with linked alerts.
- `GET /api/incidents/{id}` — Incident investigation workspace.
- `PATCH /api/incidents/{id}` — Update incident status and resolution notes.
- `POST /api/incidents/{id}/notes` — Add analyst investigation journal entry.

### IP Intelligence & Heuristics
- `GET /api/ip-intelligence` — List tracked IP profiles and Threat Scores.
- `GET /api/ip-intelligence/{ip}` — Complete historical footprint for an IP.
- `GET /api/rules` — View active detection rules and thresholds.
- `PATCH /api/rules/{id}` — Modify rule thresholds and sliding windows.

### Attack Simulator & Reports
- `POST /api/simulation/trigger` — Launch attack scenarios on demand.
- `POST /api/simulation/stream/toggle` — Toggle continuous background traffic generator.
- `GET /api/reports/summary` — Executive security report summary.
- `GET /api/reports/export/csv` — Download CSV data (`events`, `alerts`, `incidents`).

---

## 🧪 Automated Testing

Run the full automated test suite covering log parsing, detection heuristics, and REST APIs:

```bash
cd backend
python -m pytest tests/ -v
```

---

## 🛡️ Production Hardening

Before deploying to a public server:
1. **Set `SECRET_KEY`**: Set a high-entropy secret string in `.env`.
2. **Restrict CORS**: Configure `CORS_ORIGINS=https://your-domain.com`.
3. **Set Initial Passwords**: Set `ADMIN_PASSWORD` and `ANALYST_PASSWORD` via environment variables.
4. **PostgreSQL Migration**: Point `DATABASE_URL` to a PostgreSQL database and run `python scripts/migrate_db.py`.

---

## 📄 License

This project is open-source and licensed under the [MIT License](LICENSE).