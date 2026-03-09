# ThreeJ Notifier Suite — Project Description

> **Audience:** Human engineers and AI coding agents working on this repository.  
> **Goal:** Provide enough context to safely modify the system without reverse-engineering everything.

---

## 1) AI Quick Command Protocol (Mandatory)

For faster onboarding in new chats, the user may send a short command only.

### Trigger phrase

- `view project description`

### Required AI behavior when trigger is received

1. Read:
   - `/opt/threejnotif/PROJECT_DESCRIPTION.md`
   - `/opt/threejnotif/PROJECT_CHANGELOG.md`
2. Reply with a short acknowledgment in this style:
   - `I reviewed the project description and changelog. I now understand the project scope, features, architecture, and constraints. What is the next task?`
3. Do not start coding yet unless the user gives a task.

This protocol is mandatory for AI assistants used on this repository.

---

## 2) System Purpose

ThreeJ Notifier Suite is an ISP operations portal used to monitor customer connectivity, WAN health, optical signal quality, usage behavior, and offline accounts.  
It combines:

- Live status dashboards
- Historical DB-backed analytics
- Background collectors
- Workflow tracking (Under Surveillance)
- Access control + audit logging

Primary UI style is Tabler-based server-rendered pages (FastAPI + Jinja2).

---

## 3) Deployment / Runtime

- **Repo root:** `/opt/threejnotif`
- **Main app entry:** `app/main.py`
- **Background jobs:** `app/jobs.py`
- **Database layer:** `app/db.py` (+ `app/settings_store.py`)
- **Host URL (current deployment):** `http://10.100.100.87:8000`
- **Docker services:** `threejnotif` (app), `db` (Postgres)

### Standard run commands

```bash
cd /opt/threejnotif
docker compose up -d --build
docker compose ps
docker logs --tail 200 threejnotif-threejnotif-1
```

---

## 4) Tech Stack

- **Backend:** FastAPI
- **Templating:** Jinja2
- **Frontend:** Tabler (local assets) + custom CSS + ApexCharts
- **DB:** Postgres (primary), SQLite-compatible code paths (legacy fallback)
- **Workers:** In-process Python thread loops (`JobsManager`)
- **Auth:** Built-in user/role/permission/session system (DB-backed)

---

## 5) UI / Navigation (Current)

Defined in `app/templates/base.html`:

- Dashboard: `/`
- Under Surveillance: `/surveillance`
- Profile Review: `/profile-review`
- Optical: `/settings/optical`
- Accounts Ping: `/settings/accounts-ping`
- Usage: `/settings/usage`
- Offline: `/settings/offline`
- WAN Ping: `/settings/wan`
- System Settings: `/settings/system`
- Logs: `/logs`

Top header also shows live CPU/RAM/Disk/Uptime from `/system/resources`.

---

## 6) Core Features and Major Modules

## Dashboard
- Template: `app/templates/dashboard.html`
- KPI aggregation logic: `_build_dashboard_kpis` in `app/main.py`
- Latest log cards from `/dashboard/latest-logs`
- Live resource panel from `/system/resources?details=1`

## Under Surveillance
- Template: `app/templates/surveillance.html`
- Main route: `/surveillance` in `app/main.py`
- Workflow tabs:
  - Active Monitoring
  - Needs Manual Fix
  - Post-Fix Observation
  - History
  - Logs Tracking
  - Settings
- Supports split view, timelines, stage movement history, and action-driven workflow transitions

## Accounts Ping
- Page: `app/templates/settings_accounts_ping.html`
- Routes in `app/main.py` under `/settings/accounts-ping` and `/accounts-ping/*`
- Collector loop: `_accounts_ping_loop` in `app/jobs.py`
- Stores raw and rollup samples for account latency/loss availability

## Optical Monitoring
- Page: `app/templates/settings_optical.html`
- Module: `app/notifiers/optical.py`
- Series endpoint: `/optical/series`
- Applies RX/TX classification rules with realistic TX safeguards

## Usage
- Page: `app/templates/settings_usage.html`
- Collector loop: `_usage_loop` in `app/jobs.py`
- Tracks per-account RX/TX rates + totals from MikroTik PPPoE context
- Persists usage samples for trend and anomaly detection

## Offline
- Page: `app/templates/settings_offline.html`
- Collector loop: `_offline_loop` in `app/jobs.py`
- Supports MikroTik and optional Radius-driven basis
- Includes offline history tracking

## WAN Ping
- Page: `app/templates/settings_wan_ping.html`
- Collector loop: `_wan_ping_loop` in `app/jobs.py`
- Uses MikroTik routers + configured targets for WAN/target latency monitoring
- Stores status history and per-target latency history

## System Settings
- Page: `app/templates/settings_system.html`
- Controls branding, routers, ISPs, access management, backup/import-export, danger actions, and other global settings

## Logs
- Page: `app/templates/logs.html`
- User-facing audit trail filters/search
- Category-level permission filtering

---

## 7) Background Architecture

`JobsManager.start()` (`app/jobs.py`) starts these daemon loops:

- `_optical_loop`
- `_telegram_loop`
- `_wan_ping_loop`
- `_accounts_ping_loop`
- `_usage_loop`
- `_offline_loop`

Additional notes:
- CPU attribution per feature is tracked via runtime feature counters.
- Surveillance computation is partially tied to Accounts Ping processing path.

---

## 8) Database Structure (High-level)

Core tables are created in `app/db.py` (Postgres + SQLite-compatible SQL paths).

### Config / State / Job
- `settings`
- `state`
- `job_status`

### Legacy / Ping / Optical / WAN
- `ping_results`, `ping_rollups` (legacy pulsewatch-era structures)
- `speedtest_results`
- `alerts_log`
- `rto_results` (legacy)
- `optical_results`
- `wan_status_history`
- `wan_target_ping_results`

### Accounts Ping / Usage / Offline / Surveillance
- `accounts_ping_results`
- `accounts_ping_rollups`
- `pppoe_usage_samples`
- `offline_history`
- `surveillance_sessions`

### Auth / Access Control / Audit
- `auth_permissions`
- `auth_roles`
- `auth_role_permissions`
- `auth_users`
- `auth_sessions`
- `auth_audit_logs`

---

## 9) Access Control Model

System uses role-based permissions with granular feature/page/tab/action scopes.

- Permission seed + management is in `app/db.py` and `app/main.py`
- Owner/Admin/Viewer base roles exist (Owner is full control)
- Route-level permission checks happen in auth middleware
- Logs visibility can be category-restricted per role

---

## 10) External Integrations

- **MikroTik API**: WAN, usage, and related network operations
- **GenieACS**: Optical/device context retrieval
- **Radius via SSH/DB commands**: Offline/account basis (when configured)
- **SMTP**: Forgot password / account notifications
- **Telegram**: Optional notifier workflows

Do not hardcode credentials. All secrets must remain in settings/DB and not be printed.

---

## 11) Sensitive Data & Security Rules

Sensitive data may exist in:
- `/data/*`
- DB settings/state rows
- Router/API credentials
- SMTP credentials
- Telegram keys/tokens

Rules:
- Never print secrets in logs, commits, or generated reports.
- Never dump full DB contents in support output.
- Keep destructive actions behind danger permissions.

---

## 12) Known Product Constraints

- Time display commonly normalized to **Asia/Manila** for operations workflows.
- RTO feature is considered removed from active UX/flows (legacy schema pieces may still exist).
- Long-retention monitoring data exists; expensive queries must be optimized/cached.

---

## 13) Agent/Engineer Working Instructions

Before coding:
1. Read this file + `README.md`.
2. Locate affected feature route/template/job/db functions.
3. Preserve permission checks and audit logging behavior.
4. Avoid introducing secret leakage.

After coding:
1. Rebuild with `docker compose up -d --build`.
2. Check `docker compose ps`.
3. Check app logs for exceptions.
4. Validate affected page/endpoint behavior.

---

## 14) **Mandatory Documentation Policy**

**When any feature, behavior, route, permission, DB structure, workflow, or architecture is added/changed/removed, updating this `PROJECT_DESCRIPTION.md` and `PROJECT_CHANGELOG.md` is mandatory in the same change set.**

Treat this as part of Definition of Done:

- Code change without project description + changelog update = incomplete change.
- Include what changed, where (file/route/module), and operational impact.
- Use the entry template in `PROJECT_CHANGELOG.md` for each change.

---

## 15) Quick File Map

- App entry + routes: `app/main.py`
- Background collectors/schedulers: `app/jobs.py`
- DB schema + query helpers: `app/db.py`
- Settings/state wrappers: `app/settings_store.py`
- MikroTik helper: `app/mikrotik.py`
- Notifiers: `app/notifiers/*`
- Templates: `app/templates/*`
- Static assets: `app/static/*`
