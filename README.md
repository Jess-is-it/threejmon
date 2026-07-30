# ThreeJ Notifier Suite

ThreeJ is a FastAPI-based ISP operations portal for subscriber reachability, optical levels, usage, offline accounts, WAN health, ISP port capacity, workflow investigation, and audit logging.

The current application includes:

- Operational dashboards and live host/resource status
- Under Surveillance and Profile Review workflows
- Accounts Ping and Accounts Missing
- Optical, Usage, Offline, WAN Ping, and ISP Port Status monitoring
- MikroTik and system audit logs
- Role-based access control, backups, updates, and protected System Settings
- A mandatory storage guardian with per-feature retention controls and paginated automatic-deletion history
- An optional host-side Graphify knowledge graph for development and AI-assisted source navigation

For the detailed architecture, permissions, data model, and engineering rules, read `PROJECT_DESCRIPTION.md`, `PROJECT_CHANGELOG.md`, and `AGENTS.md`.

## Runtime stack

- Python 3.11, FastAPI, Uvicorn, and Jinja2
- Tabler UI with ApexCharts
- PostgreSQL 16 as the Compose database
- Docker Engine with Docker Compose
- In-process background collector threads managed by `JobsManager`

SQLite-compatible code remains for legacy migration/fallback use, but the standard Compose deployment uses PostgreSQL.

## Quick start

Requirements: Git, Docker Engine, and the Docker Compose plugin.

```bash
git clone https://github.com/Jess-is-it/threejmon.git threejnotif
cd threejnotif
THREEJ_VERSION=$(git rev-parse HEAD)
THREEJ_VERSION_DATE=$(git log -1 --format=%cs)
export THREEJ_VERSION THREEJ_VERSION_DATE
printf '%s %s' "$THREEJ_VERSION" "$THREEJ_VERSION_DATE" > .threej_version
docker compose up -d --build
docker compose ps
```

Open `http://<server-ip>:8000`.

The Compose defaults are intended for a trusted personal/test server. Before exposing the service to a broader network, override the PostgreSQL database name, user, password, and application connection URL with environment-managed values.

Persistent application files and PostgreSQL data are stored beneath `./data/`. Do not delete or replace that directory during an update.

Both Compose services use bounded Docker `json-file` logging (`10m` per file, three files per service) to prevent unbounded container-log growth. Application monitoring/history stored in PostgreSQL is separate from Docker's service logs.

Storage protection is configured at System Settings → Data Retention. Overview & Feature Policies provides one modal editor per feature for scheduled and emergency retention, Settings contains the mandatory guardian policy, and Deletion History contains filters, pagination, and separate previous/current disk-usage snapshots for each new deletion. Scheduled cleanup is batched: with retention `R` and interval `I`, data is allowed to reach `R + I` before rows older than `R` are deleted; `I` defaults to 30 days for every feature. The guardian checks filesystem use independently of feature collector status, triggers at 85% by default, deletes only a bounded amount of old eligible data, protects a configurable recent-data window, and observes a cooldown between emergency cycles. Saving a policy never runs deletion. PostgreSQL `DELETE` and ordinary `VACUUM` primarily make database space reusable; they do not guarantee an immediate reduction in filesystem usage, so before/after percentages can legitimately be equal. The automated workflow never runs `VACUUM FULL`.

Every top-level System Settings tab uses a stable `/settings/system?tab=<section>` URL and renders only its selected pane. This keeps navigation reliable after Data Retention, reduces unused page content, and prevents Backup and Danger controls from appearing together. Nested tabs inside sections remain local browser tabs. The permission-protected Backup pane contains settings and database export/import controls.

Routed WAN addresses are managed manually at System Settings → Routers → Add ISP. The application still discovers the routed local source IP and route metadata from RouterOS, but it never probes, verifies, or automatically replaces the public WAN IPv4 address. The operator-entered address is validated, audited when changed, persisted as the authoritative Netwatch host, and synchronized to RouterOS when the ISP list is saved. Existing saved WAN addresses are retained during migration.

ISP Port Status opens its Bandwidth Trend in a lightweight Live view covering the latest 15 minutes by default. The live window is configurable from 5 to 60 minutes, seeds from stored history, then samples configured MikroTik traffic interfaces once per second only while the Live chart is visible. These direct points are display-only; background history, capacity checks, alerts, the current table, and historical chart refreshes continue to use the configured Poll Interval. Hovering the Live plot or legend holds visual redraws so tooltip details stay readable while samples continue buffering; the chart catches up when the pointer leaves. Live polling stops when the browser/page is hidden, Settings or a historical range is selected, the chart leaves the viewport, or the user navigates away. Longer 1H through 30D history is fetched only when selected.

Capacity tagging treats observed traffic as evidence, not negotiated link speed. A possible 100M circuit requires every recent peak in the completed detection window to remain between the configured minimum and maximum; any below-minimum reading keeps the ISP in Observing, while an above-maximum reading proves the circuit can exceed the 100M ceiling and is tagged 1G. The optional long-average rule cannot override a below-minimum reading in the current detection window. Operators can also pause 100M tagging and reporting during a configurable non-peak interval in Asia/Manila time (overnight ranges are supported); above-ceiling 1G evidence is still honored.

## Fresh-server installer

For a public repository:

```bash
curl -fsSL https://raw.githubusercontent.com/Jess-is-it/threejmon/master/install.sh \
  | sudo THREEJ_REPO_URL=https://github.com/Jess-is-it/threejmon.git bash
```

Supported installer overrides:

- `THREEJ_REPO_URL`: required Git clone URL
- `THREEJ_INSTALL_DIR`: installation directory; default `/opt/threejnotif`
- `THREEJ_APP_USER`: service user; default `threejnotif`

The application currently listens on port 8000. `THREEJ_PORT` is not a supported listener override.

## Updating an existing server

Use the updater instead of rerunning the fresh-server installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Jess-is-it/threejmon/master/update.sh | sudo bash
```

Supported update overrides:

- `THREEJ_INSTALL_DIR`: existing installation directory; default `/opt/threejnotif`
- `THREEJ_BRANCH`: branch to update; default is the current branch, falling back to `master`
- `THREEJ_REPO_URL`: temporary fetch/pull source
- `THREEJ_SKIP_REBUILD=1`: update the repository without rebuilding services
- `THREEJ_FORCE_REBUILD=1`: rebuild even when the Git commit has not changed
- `THREEJ_TARGET_COMMIT`: deploy a specific fetched commit

The updater stops on tracked local changes unless the application explicitly invokes its controlled dirty-worktree update flow. Back up and review local changes before any update.

## Private repository bootstrap

On a fresh server, this helper creates a read-only deploy key and pauses while it is added in GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/Jess-is-it/threejmon/master/scripts/bootstrap_deploy_and_install.sh | bash
```

For a public repository through the same bootstrap helper:

```bash
curl -fsSL https://raw.githubusercontent.com/Jess-is-it/threejmon/master/scripts/bootstrap_deploy_and_install.sh | PUBLIC_REPO=1 bash
```

## Operations

```bash
cd /opt/threejnotif
docker compose ps
docker compose logs --tail 200 threejnotif
docker compose logs --tail 100 db
```

The server must be able to reach the configured MikroTik routers, GenieACS service, SSH/Radius sources, SMTP server, Telegram API, and any other enabled integration.

## Graphify development graph

Graphify is optional host-side development tooling. It is not installed in the application image and does not run as a Compose service. When provisioned, generated artifacts live in `graphify-out/`, are mounted read-only into the app, and are available to authorized users at System Settings → Graphify.

On the provisioned development host, refresh the graph after source or project-documentation changes:

```bash
cd /opt/threejnotif
graphify update .
graphify cluster-only /opt/threejnotif --no-label
```

See `PROJECT_DESCRIPTION.md` for Graphify scope, access control, exclusions, and the required AI workflow.
