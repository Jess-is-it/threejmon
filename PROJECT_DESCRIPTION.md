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
- **Host URL (current deployment):** `http://10.100.100.82:8000` (host addresses can change)
- **Docker services:** `threejnotif` (app), `db` (Postgres)
- **Container logs:** both services use Docker's `json-file` driver with `10m` files and three-file rotation
- **Environment model:** this personal deployment currently uses one shared live instance for development validation, staging, and production-like use. Treat rebuilds, migrations, format actions, and permission changes as live-impacting.

### Standard run commands

```bash
cd /opt/threejnotif
THREEJ_VERSION=$(git rev-parse HEAD)
THREEJ_VERSION_DATE=$(git log -1 --format=%cs)
export THREEJ_VERSION THREEJ_VERSION_DATE
printf '%s %s' "$THREEJ_VERSION" "$THREEJ_VERSION_DATE" > .threej_version
docker compose up -d --build
docker compose ps
docker compose logs --tail 200 threejnotif
```

### Standard update commands

```bash
cd /opt/threejnotif
sudo bash update.sh
```

### One-line update command

```bash
curl -fsSL https://raw.githubusercontent.com/Jess-is-it/threejmon/master/update.sh | sudo bash
```

Use the installer only for fresh servers. Existing installs should use the update flow above so the repo is pulled in place and the current data directory is preserved.

---

## 4) Tech Stack

- **Backend:** FastAPI
- **Templating:** Jinja2
- **Frontend:** Tabler (local assets) + custom CSS + ApexCharts
- **DB:** Postgres (primary), SQLite-compatible code paths (legacy fallback)
- **Workers:** In-process Python thread loops (`JobsManager`)
- **Auth:** Built-in user/role/permission/session system (DB-backed)
- **Runtime/deployment:** Python 3.11, Uvicorn, Docker Engine, and Docker Compose

---

## 5) UI / Navigation (Current)

Defined in `app/templates/base.html`:

- Dashboard: `/`
- Dashboard 2: `/dashboard/2`
- Under Surveillance: `/surveillance`
- Profile Review: `/profile-review`
- Optical: `/settings/optical`
- Accounts Ping: `/settings/accounts-ping`
- Accounts Missing: `/settings/accounts-missing`
- Usage: `/settings/usage`
- Offline: `/settings/offline`
- WAN Ping: `/settings/wan`
- ISP Port Status: `/settings/isp-status`
- System Settings: `/settings/system`
- MikroTik Logs: `/logs/mikrotik`
- System Logs: `/logs/system` (`/logs` is a compatible entry route)

Top header also shows live CPU/RAM/Disk/Uptime from `/system/resources`.

---

## 6) Core Features and Major Modules

### Dashboard
- Template: `app/templates/dashboard.html`
- KPI aggregation logic: `_build_dashboard_kpis` in `app/main.py`
- Latest log cards from `/dashboard/latest-logs`
- Live resource panel from `/system/resources?details=1`
- A second operations layout is available at `/dashboard/2` through `app/templates/dashboard_2.html`

### Profile Review
- Template: `app/templates/profile_review.html`
- Main routes: `/profile-review` and `/profile-review/suggest`
- Combines Accounts Ping, Optical, Usage, Offline, and surveillance evidence for account troubleshooting

### Under Surveillance
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

### Accounts Ping
- Page: `app/templates/settings_accounts_ping.html`
- Routes in `app/main.py` under `/settings/accounts-ping` and `/accounts-ping/*`
- Collector loop: `_accounts_ping_loop` in `app/jobs.py`
- Supports `SSH / CSV` source loading or shared MikroTik router `/ppp/active` loading from System Settings
- Stores raw and rollup samples for account latency/loss availability, including router-specific duplicates when MikroTik router mode is used
- In MikroTik router mode, previously seen accounts stay visible and are treated as down when they disappear from the active connections list

### Accounts Missing
- Page: `app/templates/settings_accounts_missing.html`
- Routes in `app/main.py` under `/settings/accounts-missing` and `/accounts-missing/*`
- Collector loop: `_accounts_missing_loop` in `app/jobs.py`
- Tracks accounts that are absent from selected router sources and supports detail review, safe single/bulk cleanup, source tests, and automatic-deletion settings

### Optical Monitoring
- Page: `app/templates/settings_optical.html`
- Module: `app/notifiers/optical.py`
- Series endpoint: `/optical/series`
- Applies RX/TX classification rules with realistic TX safeguards

### Usage
- Page: `app/templates/settings_usage.html`
- Collector loop: `_usage_loop` in `app/jobs.py`
- Tracks per-account RX/TX rates + totals from MikroTik PPPoE context
- Persists usage samples for trend and anomaly detection

### Offline
- Page: `app/templates/settings_offline.html`
- Collector loop: `_offline_loop` in `app/jobs.py`
- Supports MikroTik and optional Radius-driven basis
- Includes offline history tracking

### WAN Ping
- Page: `app/templates/settings_wan_ping.html`
- Collector loop: `_wan_ping_loop` in `app/jobs.py`
- Uses MikroTik routers + configured targets for WAN/target latency monitoring
- Stores status history and per-target latency history
- Routed ISP public addresses are managed manually from System Settings → Routers → Add ISP. A valid public IPv4 address is required and becomes the authoritative RouterOS Netwatch host.
- The system still discovers routed local source IPs, interfaces, and route metadata from the configured core, but route discovery cannot change the saved public WAN address.
- Public-IP provider probes, targeted verification, periodic revalidation, automatic replacement, and verification-state writes are not part of the WAN job.
- Saving a changed WAN IP writes an access-audit event, persists the operator value, and performs Netwatch synchronization with post-write read-back verification. Existing saved addresses are retained when older automatic/manual settings are normalized.

### ISP Port Status
- Page: `app/templates/settings_isp_status.html`
- Collector loop: `_isp_status_loop` in `app/jobs.py`
- Tracks configured ISP interface capacity/utilization, chart history, and optional Telegram reporting
- The configured Poll Interval controls the background collector, persisted history, capacity classification, alerts, current-table refresh, and historical-chart refresh. It does not control the Live chart.
- The Bandwidth Trend opens with a lightweight 5–60 minute Live window (15 minutes by default), seeds it from persisted history, and then appends direct one-second samples from `/isp-status/live`.
- Direct Live sampling is non-persistent and runs only while the browser document is visible, the Status tab and Live range are selected, and the chart is inside the viewport. It stops on tab/range changes, when the chart is scrolled out of view, and on page hide/navigation.
- While a mouse pointer is over the Live plot or its legend, polling and in-memory sample collection continue but visual redraws are held so the shared hover tooltip remains readable. A visible inspection badge counts buffered ticks, and the chart catches up immediately when the pointer leaves. Normal steady-state ticks update only series data; chart options/colors are re-rendered only if the series structure changes.
- Each Live tick normally batches all configured traffic interfaces into one RouterOS `monitor-traffic` command per core, samples cores concurrently off the async request loop, and coalesces near-simultaneous browser requests through a short process cache. If a batch is rejected, per-interface fallback isolates the bad configuration instead of hiding every interface on that core. Partial router results leave the combined All ISP point empty rather than reporting an understated total.
- Historical 1H through 30D chart ranges remain available on demand. The `/isp-status/series` endpoint preserves the older `hours` query parameter for compatibility while the UI uses the explicit `window=live|<hours>` form.
- Page and status-poll rendering uses current collector state first and only reads historical latest rows for ISPs missing from that state. PostgreSQL fallback lookup performs one indexed latest-row probe per requested ISP rather than sorting the complete matching history.
- Capacity classification is evidence-based: `100m` requires a completed recent window whose minimum and maximum observed peaks both remain inside `capacity.hundred_mbps_min` through `capacity.hundred_mbps_max`. A below-minimum sample is insufficient utilization and returns `observing`; a recent above-maximum sample returns `1g`.
- The optional average detector may confirm `100m` only when its average is inside the configured range and the current short window contains no below-floor or above-ceiling reading. It cannot preserve a 100M label while current utilization is below the evidence floor.
- Operators can enable an Asia/Manila non-peak exclusion with `capacity.non_peak_start_time` and `capacity.non_peak_end_time`; overnight intervals are supported and equal start/end values mean no interval. During an active exclusion, possible 100M status and its immediate/daily reporting are suppressed as `observing`, but a recent above-ceiling sample still returns `1g`. Peak-hour evidence restarts after the exclusion ends so overnight samples and elapsed time cannot satisfy the next observation window.

### System Settings
- Page: `app/templates/settings_system.html`
- Controls branding, shared routers for Usage/Offline/Accounts Ping, ISPs, access management, system updates, data retention, the Graphify development view, backup/import-export, danger actions, and other global settings
- Every top-level section uses a stable `/settings/system?tab=<section>` URL and the server renders only the selected top-level pane. This prevents stale Bootstrap tab state after visiting Data Retention and keeps Backup and Danger content isolated.
- Nested Router and Access tabs retain their local Bootstrap tab behavior. The permission-protected Backup pane provides settings plus database export/import controls.

### Data Retention and Storage Guardian
- Module: `app/data_retention.py`
- Protected tab: `/settings/system?tab=data-retention`
- Nested views: Overview & Feature Policies, Settings, and Deletion History. The mandatory guardian policy is isolated in Settings; filters and pagination remain in Deletion History.
- Guardian settings route: `POST /settings/system/data-retention/settings`
- Feature policy route: `POST /settings/system/data-retention/feature/{feature_key}`
- Tracks scheduled feature pruning and emergency guardian cleanup in a durable, filterable, paginated history.
- The mandatory guardian checks the filesystem independently of feature collector enabled/disabled state. At the default 85% trigger it executes one bounded cycle, protects at least the configured recent-data window, and then observes a default six-hour cooldown.
- Emergency percentages are configured per feature; `0%` explicitly excludes a feature. A global maximum-rows-per-dataset cap always limits each deletion transaction.
- Each row in Emergency Deletion by Feature has one Edit action that opens a scoped modal for its normal scheduled retention, scheduled cleanup interval, emergency deletion percentage, and recent-data floor.
- Normal day-based values edit the same settings used by Accounts Ping, Usage, Optical, Offline, WAN, ISP Port Status, MikroTik Logs, and access-audit pruning; saving a policy never runs deletion.
- Scheduled retention uses an age-based batch threshold for every tracked feature. With retention `R` and cleanup interval `I`, deletion waits until data exceeds `R + I`, then removes the accumulated rows older than `R`; the default interval is 30 days.
- Deletion History records every completed scheduled or emergency deletion. Historical rolling-cleanup rows remain as an audit trail, while new scheduled entries appear only when a feature reaches its configured batch threshold.
- Automatic Deletion History displays separate Previous disk and Current disk percentages captured around each new deletion. Historical rows created before snapshot capture show `—`; equal percentages are valid because PostgreSQL row deletion generally makes space reusable internally instead of immediately shrinking filesystem use.
- PostgreSQL uses small BRIN time indexes for the large append-only Accounts Ping, Usage, and Optical datasets, plus ordinary time indexes for smaller Offline and Usage reboot histories, so batch-due checks avoid full-table scans.
- Automated maintenance may run ordinary `VACUUM` to make deleted PostgreSQL pages reusable. It never runs `VACUUM FULL`, never loops until a low-water target is reached, and does not assume that logical row deletion immediately reduces filesystem usage.

### Logs
- Page: `app/templates/logs.html`
- Separate MikroTik and System Logs views with user-facing filters/search
- MikroTik syslog collection and router auto-setup are handled by `_mikrotik_logs_loop` and `app/mikrotik_logs_setup.py`
- Category-level permission filtering

---

## 7) Background Architecture

`JobsManager.start()` (`app/jobs.py`) starts these daemon loops:

- `_optical_loop`
- `_telegram_loop`
- `_wan_ping_loop`
- `_isp_status_loop`
- `_mikrotik_router_health_loop`
- `_mikrotik_logs_loop`
- `_accounts_ping_loop`
- `_accounts_missing_loop`
- `_usage_loop`
- `_offline_loop`
- `_data_retention_loop`

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
- `data_retention_history` (durable per-dataset automatic deletion audit records)

### Legacy / Ping / Optical / WAN
- `ping_results`, `ping_rollups` (legacy pulsewatch-era structures)
- `speedtest_results`
- `alerts_log`
- `rto_results` (legacy)
- `optical_results`
- `wan_status_history`
- `wan_target_ping_results`
- `isp_status_samples`
- `mikrotik_logs`

### Accounts Ping / Usage / Offline / Surveillance
- `accounts_ping_results`
- `accounts_ping_rollups`
- `pppoe_usage_samples`
- `usage_modem_reboot_history`
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
- When a feature, page, tab, route, action, or setting is added, removed, renamed, or moved, the change must include the corresponding permission updates.
- Permission work is not complete unless it covers all of the following:
  - permission catalog / dependencies / route mapping
  - role editor visibility and assignment behavior
  - compatibility grants or migration/backfill for existing roles so current users keep the correct access after the change
- Because users inherit access from roles in this system, updating existing role permissions is mandatory whenever a permissioned feature is introduced or relocated.
- Data Retention uses `system.tab.data_retention.view` for tab/history visibility and `system.data_retention.settings.edit` for policy changes. Built-in roles are synchronized and custom roles with broad System Settings access are backfilled at startup.

---

## 10) External Integrations

- **MikroTik API**: WAN, usage, and related network operations
- **GenieACS**: Optical/device context retrieval
- **Radius via SSH/DB commands**: Offline/account basis (when configured)
- **SMTP**: Forgot password / account notifications
- **Telegram**: Optional notifier workflows

Do not add new hardcoded credentials. User-supplied integration secrets must remain in settings/DB or environment-managed configuration and must not be printed. The repository's default Compose database credentials are suitable only for the trusted personal deployment; override them before broader network exposure.

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
- PostgreSQL row deletion normally makes relation pages reusable rather than returning file blocks to the operating system. Automated retention must remain bounded and must never use `VACUUM FULL` on the shared live instance.

---

## 13) Agent/Engineer Working Instructions

Before coding:
1. Read `AGENTS.md`, this file, `README.md`, and the newest entries in `PROJECT_CHANGELOG.md`.
2. Query the existing Graphify graph before broad source searches.
3. Locate and verify the affected feature route/template/job/DB functions in source.
4. Preserve permission checks and audit logging behavior.
5. Avoid introducing secret leakage.

After coding:
1. Rebuild with the version-aware standard run commands in Section 3, or use `update.sh` for a repository update.
2. Check `docker compose ps`.
3. Check app logs for exceptions.
4. Validate affected page/endpoint behavior.
5. If the change affects permissions or moves a protected feature, update permission seeds/mappings and backfill existing roles so current users inherit the correct access.

---

## 14) **Mandatory Documentation Policy**

**When any feature, behavior, route, permission, DB structure, workflow, or architecture is added/changed/removed, updating this `PROJECT_DESCRIPTION.md` and `PROJECT_CHANGELOG.md` is mandatory in the same change set.**

Treat this as part of Definition of Done:

- Code change without project description + changelog update = incomplete change.
- Include what changed, where (file/route/module), and operational impact.
- Use the entry template in `PROJECT_CHANGELOG.md` for each change.
- Permissioned feature changes are incomplete unless role/permission updates and existing-role backfills are included when needed.

---

## 15) Quick File Map

- App entry + routes: `app/main.py`
- Background collectors/schedulers: `app/jobs.py`
- DB schema + query helpers: `app/db.py`
- Settings/state wrappers: `app/settings_store.py`
- Storage guardian and centralized retention policy: `app/data_retention.py`
- MikroTik helper: `app/mikrotik.py`
- Notifiers: `app/notifiers/*`
- Templates: `app/templates/*`
- Static assets: `app/static/*`
- Deployment: `Dockerfile`, `docker-compose.yml`, `install.sh`, `update.sh`
- AI/engineer onboarding: `AGENTS.md`, `.codex/skills/graphify/*`

---

## 16) Development Knowledge Graph (Graphify)

Graphify is installed as host-only development tooling so AI coding assistants can query the current source architecture before broad file searches.

- **Pinned CLI:** `graphify 0.9.13`
- **CLI path:** `/usr/local/bin/graphify`
- **Isolated environment:** `/home/threejmon/.local/share/graphify-0.9.13`
- **Project Codex skill:** `.codex/skills/graphify/SKILL.md`
- **User-global Codex skill:** `/root/.codex/skills/graphify/SKILL.md`
- **Workspace entry pointer:** `/home/threejmon/AGENTS.md`
- **AI onboarding rules:** `AGENTS.md`
- **Generated local graph:** `graphify-out/graph.json`
- **Protected System Settings tab:** `/settings/system?tab=graphify`
- **Protected interactive graph:** `/settings/system/graphify/graph`
- **Protected architecture report:** `/settings/system/graphify/report`
- **Architecture report:** `graphify-out/GRAPH_REPORT.md`
- **Sensitive/noise exclusions:** `.graphifyignore`

The graph is a local structural extraction of project source and selected project documentation. It does not call an LLM, inspect PostgreSQL, or read runtime databases. Graphify's own `.codex/` skill implementation, generated output, runtime data, credentials, logs, backups, and large vendored assets are excluded to reduce noise and exposure. Generated `graphify-out/` artifacts remain local and Git-ignored. Compose mounts that directory read-only at `/graphify-out`; the application exposes only the reviewed interactive HTML and Markdown report through fixed, authenticated routes. The graph page runs under a restrictive browser sandbox, and raw graph/cache files are not separately web-served. Authorized graph viewers still receive the complete graph content embedded in the interactive HTML.

The `system.tab.graphify.view` permission controls both the tab and direct artifact routes. Built-in roles, including the default read-only Viewer role, receive it through the normal permission sync, and existing custom roles with broad System Settings access are backfilled at startup. Remove that permission from roles that should not inspect source architecture. Graph generation still runs only on the host; Graphify is not installed in the application image.

### Required AI workflow

1. Read `AGENTS.md`, `PROJECT_DESCRIPTION.md`, and the current changelog before coding.
2. For codebase questions, query the existing graph first with `graphify query`, `graphify path`, or `graphify explain` before broad source searches.
3. Verify `INFERRED` and `AMBIGUOUS` relationships against the source before making decisions.
4. After modifying source or project documentation, run `graphify update .` to refresh the graph.
5. Keep graph updates manual. Automatic Git hooks, HTTP MCP, and live PostgreSQL introspection are not enabled.

### Operator view and refresh

Open System Settings → Graphify to view graph statistics, the AI usage guide, and links to the interactive graph/report. After development changes, refresh the host artifacts with:

```bash
cd /opt/threejnotif
graphify update .
graphify cluster-only /opt/threejnotif --no-label
```

The commit shown in the Graphify tab compares the graph's recorded commit with the installed application commit; it cannot prove that every uncommitted working-tree edit is indexed. Run the refresh commands after both source and project-documentation changes.

Graphify is provisioned separately on the current development host. Fresh application installations do not automatically install the CLI or copy generated graph artifacts, so the tab may correctly report that artifacts are unavailable on another host. Graphify is not an application dependency, production service, monitoring feature, test framework, or substitute for source review and validation.
