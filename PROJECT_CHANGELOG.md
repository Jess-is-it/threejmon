# ThreeJ Notifier Suite — Project Changelog

Use this file to record every meaningful system change in reverse-chronological order.

## Changelog Rules (Mandatory)

1. Any feature/function/behavior/schema/permission/architecture change must add a new entry.
2. Each entry must be added **in the same commit/PR** as the code change.
3. Keep entries factual and operation-focused (what changed, impact, rollback path).
4. Do not include secrets, tokens, passwords, or sensitive data.

---

## Entry Template

```md
## YYYY-MM-DD HH:MM UTC — <Short Change Title>
- Type: feature | fix | refactor | perf | security | docs | migration
- Scope: <feature/page/module names>
- Summary:
  - <what changed>
  - <what changed>
- Files:
  - <path>
  - <path>
- DB/Config Impact:
  - Schema: none | <details>
  - Settings/State keys: none | <details>
- Runtime Impact:
  - <performance/behavior/user-visible impact>
- Validation:
  - <commands/tests/run checks performed>
- Rollback:
  - <commit hash or exact rollback steps>
```

---

## Entries

## 2026-03-25 06:30 UTC — Added dedicated one-line updater for existing servers
- Type: feature
- Scope: Deployment tooling / update workflow / project docs
- Summary:
  - Added a dedicated `update.sh` script for already-installed servers so operators can pull the latest branch and rebuild without re-running the fresh-install logic.
  - Made the updater stop on tracked local changes, support branch and repo URL overrides, and allow Git fetches to run under a specified local user when SSH-based remotes are in use.
  - Documented the standard update flow and the new one-line update command in the repository docs.
- Files:
  - `update.sh`
  - `README.md`
  - `PROJECT_DESCRIPTION.md`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Existing servers can now be updated with a single raw-script command without hitting the install script's fresh-server checks.
- Validation:
  - `bash -n /opt/threejnotif/update.sh`
  - `git -C /opt/threejnotif diff --check -- update.sh README.md PROJECT_DESCRIPTION.md PROJECT_CHANGELOG.md`
  - `THREEJ_INSTALL_DIR=/tmp/threej-update-test THREEJ_GIT_USER=root THREEJ_REPO_URL=https://github.com/Jess-is-it/threejmon.git THREEJ_SKIP_REBUILD=1 bash /opt/threejnotif/update.sh`
- Rollback:
  - Revert the files listed above.

## 2026-03-13 07:59 UTC — Added MikroTik router source mode to Accounts Ping
- Type: feature
- Scope: Accounts Ping / shared MikroTik routers / surveillance compatibility / project docs
- Summary:
  - Added a selectable Accounts Ping source mode so operators can load targets from either the SSH ShapedDevices CSV or the shared MikroTik routers defined in System Settings.
  - Reused the Usage-style per-router enablement model for Accounts Ping and pulled `/ppp/active` addresses from the selected routers while preserving router-specific duplicate rows.
  - Kept previously seen MikroTik accounts visible and treated them as down when they disappear from the active connections list, instead of removing them from Accounts Ping.
  - Updated Accounts Ping-related aggregation paths so router-specific account identities continue to work with the page, profile lookups, and surveillance diagnostics.
- Files:
  - `app/accounts_ping_sources.py`
  - `app/main.py`
  - `app/jobs.py`
  - `app/settings_defaults.py`
  - `app/db.py`
  - `app/templates/settings_accounts_ping.html`
  - `PROJECT_DESCRIPTION.md`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: adds `accounts_ping.source.mode`, `accounts_ping.source.mikrotik.router_enabled`, and state field `accounts_ping_state.router_status`
- Runtime Impact:
  - Accounts Ping can now track router-loaded active sessions in addition to the SSH CSV source, and disconnected MikroTik sessions remain visible as down for operators.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py /opt/threejnotif/app/jobs.py /opt/threejnotif/app/accounts_ping_sources.py /opt/threejnotif/app/db.py /opt/threejnotif/app/settings_defaults.py`
  - `python3 - <<'PY'` with `jinja2.Environment().parse(Path('/opt/threejnotif/app/templates/settings_accounts_ping.html').read_text())`
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-13 06:08 UTC — Documented mandatory permission backfills for moved or new features
- Type: docs
- Scope: Project description / Access control maintenance rules
- Summary:
  - Added an explicit project rule that any new, changed, renamed, or moved permissioned feature must update the permission catalog, dependencies, route mapping, and role editor behavior.
  - Added a mandatory requirement to backfill existing role permissions when protected features are relocated or introduced, so current users inherit the correct access without manual repair.
  - Extended the Definition of Done to treat permission maintenance and existing-role compatibility as part of a complete change.
- Files:
  - `PROJECT_DESCRIPTION.md`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - No runtime behavior change; this strengthens the documented engineering rules for future permissioned feature work.
- Validation:
  - `git -C /opt/threejnotif diff --check -- PROJECT_DESCRIPTION.md PROJECT_CHANGELOG.md`
- Rollback:
  - Revert the files listed above.

## 2026-03-13 05:40 UTC — Added per-user new-entry markers for Active Monitoring
- Type: feature
- Scope: Under Surveillance / Sidebar navigation
- Summary:
  - Sorted the Under Surveillance tables by newest workflow entry first so newly added Active Monitoring rows appear at the top instead of alphabetical order.
  - Added a per-user `New` marker for Active Monitoring accounts, including a highlighted row state and a 10-second viewed timer that clears only for the logged-in user after they keep the tab open.
  - Moved the Under Surveillance sidebar badge to server-side per-user tracking so the navigation count now follows the same user-specific `new` state as the table.
- Files:
  - `app/main.py`
  - `app/templates/base.html`
  - `app/templates/surveillance.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: adds state key `surveillance_new_seen_by_user_v1`
- Runtime Impact:
  - Active Monitoring rows now open newest-first and show `New` only until each user has viewed them for 10 seconds.
  - The Under Surveillance navigation badge is now user-aware instead of browser-local.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py`
  - `python3 - <<'PY'` with `jinja2.Environment(...).get_template('surveillance.html')` and `get_template('base.html')`
  - `python3 - <<'PY'` extracting inline `<script>` blocks from `app/templates/surveillance.html` and `app/templates/base.html` and running `node --check`
  - `git -C /opt/threejnotif diff --check -- app/main.py app/templates/surveillance.html app/templates/base.html`
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-13 04:04 UTC — Added Offline tab counts and sidebar new-item badges
- Type: feature
- Scope: Offline Status / Sidebar navigation / Under Surveillance navigation
- Summary:
  - Added per-rule badge counts to the Offline status tabs so each enabled Offline threshold tab shows how many current accounts match that rule.
  - Added sidebar `new` badges for Offline and Under Surveillance that track newly seen Offline accounts and newly added Active Monitoring accounts per browser using local storage.
  - Added a lightweight navigation summary endpoint so sidebar badges update live without loading the full feature pages.
- Files:
  - `app/main.py`
  - `app/templates/base.html`
  - `app/templates/settings_offline.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Offline tabs now display live counts per rule.
  - Sidebar badges update automatically and clear once the related page is opened in that browser.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py`
  - `python3 - <<'PY'` with `jinja2.Environment(...).get_template('base.html')` and `get_template('settings_offline.html')`
  - `node - <<'NODE'` stripped-template JS syntax checks for `app/templates/base.html` and `app/templates/settings_offline.html`
  - `git -C /opt/threejnotif diff --check -- app/main.py app/templates/base.html app/templates/settings_offline.html PROJECT_CHANGELOG.md`
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-13 03:35 UTC — Added ordered multi-threshold Offline tracking tabs
- Type: feature
- Scope: Offline Status / Offline Settings / Offline collector
- Summary:
  - Replaced the old single Offline threshold with an ordered tracking-rule list so users can create multiple thresholds like `12H` and `3D`, and each enabled rule now appears as its own Offline Status tab.
  - Updated the Offline collector and summary payload to reuse one live tracker for all enabled thresholds, while keeping history and profile logic anchored to the earliest enabled rule for compatibility.
  - Added a rule editor in Offline Settings so thresholds can be added, removed, enabled, and reordered to control which tab appears first, second, third, and so on.
- Files:
  - `app/offline_rules.py`
  - `app/main.py`
  - `app/jobs.py`
  - `app/settings_defaults.py`
  - `app/templates/settings_offline.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: adds `offline.general.tracking_rules`; `offline.general.min_offline_value` and `offline.general.min_offline_unit` remain as compatibility mirrors of the earliest enabled rule
- Runtime Impact:
  - Offline Status can now switch between multiple live offline windows without extra router polling.
  - Offline History and profile threshold messaging continue to use the earliest enabled threshold to avoid breaking existing behavior.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py /opt/threejnotif/app/jobs.py /opt/threejnotif/app/offline_rules.py`
  - `python3 - <<'PY'` with `jinja2.Environment(...).get_template('settings_offline.html')`
  - `node - <<'NODE'` stripped-template JS syntax check for `app/templates/settings_offline.html`
  - `git -C /opt/threejnotif diff --check -- app/main.py app/jobs.py app/settings_defaults.py app/templates/settings_offline.html app/offline_rules.py PROJECT_CHANGELOG.md`
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-13 03:13 UTC — Backfilled centralized danger permissions and fixed danger modal confirmation UI
- Type: fix
- Scope: System Settings Danger tab / Auth roles / Danger confirmation modal
- Summary:
  - Added a startup migration that backfills centralized danger access onto existing roles that already had danger permissions, so those users can open the new System Settings danger location without manual role repair.
  - Updated danger permission dependencies so newly created or edited roles auto-add the required System Settings view and danger-tab access when danger actions are assigned.
  - Fixed the System Settings danger modal so the typed confirmation field only appears for actions that require it and the label now shows the actual expected text instead of an empty `Type to continue.` message.
- Files:
  - `app/main.py`
  - `app/templates/settings_system.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Existing users inherit the corrected centralized danger access through their roles automatically after startup.
  - The danger modal now hides the confirm-text field for normal format actions and labels uninstall confirmation correctly.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py`
  - `python3 - <<'PY'` with `jinja2.Environment().parse(...)` for `app/templates/settings_system.html`
  - `git -C /opt/threejnotif diff --check -- app/main.py app/templates/settings_system.html PROJECT_CHANGELOG.md`
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-13 02:44 UTC — Centralized feature danger actions under System Settings
- Type: feature
- Scope: System Settings Danger tab / Under Surveillance / Optical / Accounts Ping / Usage / Offline / WAN Ping
- Summary:
  - Moved the per-feature danger actions out of Under Surveillance, Optical, Accounts Ping, Usage, and WAN Ping settings and centralized them under System Settings -> Danger with grouped feature cards.
  - Added password-confirmed danger actions for each feature, a one-click `Format All Features` action, Offline format support, and kept uninstall under the same centralized confirmation flow.
  - Added a compatibility permission grant so existing danger-enabled roles can open the centralized System Settings danger page without a separate manual permission update.
  - Converted the old per-feature format endpoints into compatibility shims so destructive actions no longer bypass the new System Settings confirmation flow.
- Files:
  - `app/main.py`
  - `app/db.py`
  - `app/templates/settings_system.html`
  - `app/templates/surveillance.html`
  - `app/templates/settings_optical.html`
  - `app/templates/settings_accounts_ping.html`
  - `app/templates/settings_usage.html`
  - `app/templates/settings_wan_ping.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: added centralized Offline clear support; danger actions now reset feature state through System Settings
- Runtime Impact:
  - Destructive reset actions are now consolidated into one authenticated flow and require current-password confirmation when auth is enabled.
  - Feature settings pages no longer expose their own danger tabs, reducing duplicate destructive UI.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py /opt/threejnotif/app/db.py`
  - `python3 - <<'PY'` with `jinja2.Environment().parse(...)` for the updated danger-related templates
  - `docker exec threejnotif-threejnotif-1 python -c ...` to render the System Settings danger page with danger permissions and confirm the centralized cards render without template errors
  - `git -C /opt/threejnotif diff --check -- app/main.py app/db.py app/templates/settings_system.html app/templates/surveillance.html app/templates/settings_optical.html app/templates/settings_accounts_ping.html app/templates/settings_usage.html app/templates/settings_wan_ping.html PROJECT_CHANGELOG.md`
  - `docker compose -f /opt/threejnotif/docker-compose.yml up -d --build threejnotif`
  - Verified `/settings/system` and `/settings/usage` returned `401 Unauthorized` after startup and confirmed `0.0.0.0:8000` is listening
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-13 00:20 UTC — Fixed Dashboard Latest Logs card stretching to full column height
- Type: fix
- Scope: Dashboard layout / Latest Logs panel
- Summary:
  - Removed the forced full-height behavior from the Dashboard Latest Logs card so it no longer stretches to match the taller left-side Dashboard panels.
  - Anchored the Dashboard right-side column to its content height, which keeps the Latest Logs card background aligned to the actual log list instead of leaving a large empty card area.
- Files:
  - `app/templates/dashboard.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - The Dashboard Latest Logs panel now sizes to its content instead of visually stretching through the full sidebar column height.
- Validation:
  - `python3 - <<'PY'` with `jinja2.Environment().parse(...)` for `app/templates/dashboard.html`
  - `git -C /opt/threejnotif diff --check -- app/templates/dashboard.html PROJECT_CHANGELOG.md`
  - `docker compose -f /opt/threejnotif/docker-compose.yml up -d --build threejnotif`
  - Verified `/` returned `401 Unauthorized` after startup, confirming the updated authenticated Dashboard is serving
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-13 00:10 UTC — Fixed Dashboard Under Surveillance KPI state label
- Type: fix
- Scope: Dashboard KPI status badges / Under Surveillance summary
- Summary:
  - Replaced the Dashboard Under Surveillance KPI’s generic job-health fallback with surveillance-specific state logic so it no longer shows `Idle` just because it has no job status row.
  - The Under Surveillance KPI now shows `Disabled` when the feature is off, `Ready` when enabled with no active entries, and `Active` when surveillance accounts exist.
  - Updated Dashboard KPI badge rendering to use the computed `tone` value, so KPI badge colors now follow the backend health state instead of defaulting to the card theme.
- Files:
  - `app/main.py`
  - `app/templates/dashboard.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Dashboard KPI badges now reflect actual surveillance state, and KPI badge colors match the backend health classification consistently.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py`
  - `python3 - <<'PY'` with `jinja2.Environment().parse(...)` for `app/templates/dashboard.html`
  - `git -C /opt/threejnotif diff --check -- app/main.py app/templates/dashboard.html PROJECT_CHANGELOG.md`
  - `docker compose -f /opt/threejnotif/docker-compose.yml up -d --build threejnotif`
  - Verified `/` returned `401 Unauthorized` after startup, confirming the updated authenticated Dashboard is serving
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-12 10:25 UTC — Fixed Accounts Ping action badge shrink at responsive widths
- Type: fix
- Scope: Accounts Ping status table / responsive actions
- Summary:
  - Increased the Accounts Ping action-column width so the Profile Review and Surveillance icon badges fit without compressing each other.
  - Locked the action wrapper children to `flex: 0 0 auto` so the Profile Review anchor no longer shrinks narrower than the surveillance icon under tighter layouts.
- Files:
  - `app/templates/settings_accounts_ping.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Accounts Ping action icons keep a consistent badge size across normal and responsive breakpoints.
- Validation:
  - `python3 - <<'PY'` with `jinja2.Environment().parse(...)` for `app/templates/settings_accounts_ping.html`
  - `python3 - <<'PY'` extracting the inline `<script>` block from `app/templates/settings_accounts_ping.html` and running `node --check`
  - `git -C /opt/threejnotif diff --check -- app/templates/settings_accounts_ping.html PROJECT_CHANGELOG.md`
  - `docker compose -f /opt/threejnotif/docker-compose.yml up -d --build threejnotif`
  - Verified `/settings/accounts-ping` returned `401 Unauthorized` after startup, confirming the updated authenticated page is serving
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-12 10:05 UTC — Made Optical, Accounts Ping, Usage, and Offline status tables collapse responsively
- Type: fix
- Scope: Optical / Accounts Ping / Usage / Offline status tables
- Summary:
  - Added fixed-layout responsive column priorities so the status tables progressively hide lower-priority columns as the viewport gets tighter or the browser is zoomed in.
  - Updated Optical, Usage, and Offline row rendering so long PPPoE or customer names truncate cleanly and the action buttons remain visible instead of being pushed off-screen.
  - Tightened the Accounts Ping table so the final mobile breakpoint now leaves only the customer and action columns, matching the intended Under Surveillance behavior.
- Files:
  - `app/templates/settings_optical.html`
  - `app/templates/settings_accounts_ping.html`
  - `app/templates/settings_usage.html`
  - `app/templates/settings_offline.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Monitoring tables stay usable on smaller screens and under browser zoom because the action icons remain accessible at every breakpoint.
- Validation:
  - `python3 - <<'PY'` with `jinja2.Environment().parse(...)` for `app/templates/settings_accounts_ping.html`, `app/templates/settings_optical.html`, `app/templates/settings_usage.html`, and `app/templates/settings_offline.html`
  - `python3 - <<'PY'` extracting inline `<script>` blocks, replacing Jinja placeholders in-memory, and running `node --check` against the resulting JS for the same four templates
  - `git -C /opt/threejnotif diff --check -- app/templates/settings_accounts_ping.html app/templates/settings_optical.html app/templates/settings_usage.html app/templates/settings_offline.html PROJECT_CHANGELOG.md`
  - `docker compose -f /opt/threejnotif/docker-compose.yml up -d --build threejnotif`
  - Verified `/settings/optical`, `/settings/accounts-ping`, `/settings/usage`, and `/settings/offline` returned `401 Unauthorized` after startup, confirming the updated authenticated pages are serving
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-12 09:30 UTC — Hardened Optical TX collection and fallback for intermittent null polls
- Type: fix
- Scope: Optical collector / Optical status queries / Profile Review optical lookups / Dashboard optical candidates
- Summary:
  - Added a targeted GenieACS device refetch when the bulk Optical poll misses TX so devices that expose `TXPower` a few seconds later no longer get stored as `n/a` for the whole poll cycle.
  - Added an explicit GenieACS `getParameterValues` refresh for TX when the parameter node exists but the cached `_value` is missing, so the collector can populate live TX instead of accepting object-only responses.
  - Added latest-row TX fallback logic so Optical pages reuse the most recent non-null TX sample for a device instead of treating one null collector row as `Missing/Unrealistic TX`.
  - Applied the fallback path to Optical status, dashboard Optical candidates, search lookups, and PPPoE-based optical lookups used elsewhere in the app.
- Files:
  - `app/notifiers/optical.py`
  - `app/db.py`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Optical TX values stay populated across intermittent GenieACS null polls, and the Optical page no longer flips valid accounts to `n/a` when a recent TX reading already exists.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/db.py /opt/threejnotif/app/notifiers/optical.py /opt/threejnotif/app/main.py`
- Rollback:
  - Revert the files listed above and rebuild the `threejnotif` service.

## 2026-03-12 07:35 UTC — Reverted Optical no-data overlay and normalized raw power values
- Type: fix
- Scope: Optical collector / Optical modal charts / Optical history data
- Summary:
  - Reverted the temporary Optical modal no-data overlay so the chart returns to showing only the real RX/TX series.
  - Normalized raw GenieACS optical power integers into dBm during Optical collection using the vendor power scale, fixing cases where values like `326` or `15563` were being stored directly.
  - Applied a live 30-day Optical history backfill in Postgres so existing raw `rx` and `tx` values already stored in the active chart windows are corrected for the Optical page and modal charts.
- Files:
  - `app/notifiers/optical.py`
  - `app/templates/settings_optical.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Optical tables and sparkline modals will render dBm values on-axis again instead of plotting raw vendor integers off-scale.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/notifiers/optical.py`
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/settings_optical.html').read_text())"`
  - `node -e "const fs=require('fs'); const path='/opt/threejnotif/app/templates/settings_optical.html'; const s=fs.readFileSync(path,'utf8'); const scripts=[...s.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)]; for (const m of scripts) { const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'true').replace(/\\{%[\\s\\S]*?%\\}/g,''); new Function(js); }"`
  - `docker compose -f /opt/threejnotif/docker-compose.yml up -d --build threejnotif`
  - Verified `/settings/optical` returned `401 Unauthorized` after restart and confirmed `AnnaronanN3S2MateoRJr` was stored as about `-14.87 dBm` instead of raw `326`.
- Rollback:
  - Revert the files listed above and restore the previous Optical parser behavior.

## 2026-03-12 07:19 UTC — Marked trailing Optical chart gaps as no-data ranges
- Type: fix
- Scope: Optical modal charts / tooltip behavior
- Summary:
  - Detected trailing gaps in the Optical sparkline modal when no newer RX/TX readings exist inside the selected window and marked that tail as a black `No data` range.
  - Added synthetic no-data hover points so the modal tooltip stops implying stale optical readings are still present in the blank tail of the chart.
  - Preserved the real RX/TX line colors while using the black range label to indicate that the ONU has no fresh optical samples for that part of the window.
- Files:
  - `app/templates/settings_optical.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Operators can distinguish between actual optical readings and time ranges with no fresh telemetry in the Optical trend modal.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/settings_optical.html').read_text())"`
  - `node -e "const fs=require('fs'); const path='/opt/threejnotif/app/templates/settings_optical.html'; const s=fs.readFileSync(path,'utf8'); const scripts=[...s.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)]; for (const m of scripts) { const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'true').replace(/\\{%[\\s\\S]*?%\\}/g,''); new Function(js); }"`
- Rollback:
  - Revert the files listed above.

## 2026-03-12 07:05 UTC — Fixed sparkline modal x-axis labels for multi-day filters
- Type: fix
- Scope: Optical modal charts / Accounts Ping modal charts / Usage modal charts
- Summary:
  - Updated sparkline modal x-axis formatting so longer windows like `7D`, `15D`, and `30D` show date-based labels instead of time-only tick labels.
  - Added window-based tick density and fixed chart ranges so the modal axis follows the selected filter more accurately across Optical, Accounts Ping, and Usage.
  - Preserved full date-time detail in tooltips while making the labels under the line chart match the active modal filter.
- Files:
  - `app/templates/settings_optical.html`
  - `app/templates/settings_accounts_ping.html`
  - `app/templates/settings_usage.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Operators can now tell at a glance whether a sparkline modal is showing hourly or multi-day data because the x-axis labels reflect the selected filter.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; files=['/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html','/opt/threejnotif/app/templates/settings_usage.html']; env=Environment(); [env.parse(Path(f).read_text()) for f in files]"`
  - `node -e "const fs=require('fs'); const files=['/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html','/opt/threejnotif/app/templates/settings_usage.html']; for (const path of files) { const s=fs.readFileSync(path,'utf8'); const scripts=[...s.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)]; for (const m of scripts) { const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'true').replace(/\\{%[\\s\\S]*?%\\}/g,''); new Function(js); } }"`
- Rollback:
  - Revert the files listed above.

## 2026-03-12 06:55 UTC — Replaced custom status loading banners with Tabler cards
- Type: fix
- Scope: Optical status / Accounts Ping status / loading UI
- Summary:
  - Replaced the custom CSS top-center loading banners on Optical and Accounts Ping with Tabler-native fixed cards and spinner components.
  - Kept the same loading behavior for filter, search, sort, limit, and pagination changes while aligning the visuals with the existing project UI patterns.
- Files:
  - `app/templates/settings_optical.html`
  - `app/templates/settings_accounts_ping.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - The status-page loading state now uses the same Tabler card/spinner language already used elsewhere in the app instead of a custom banner treatment.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; files=['/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html']; env=Environment(); [env.parse(Path(f).read_text()) for f in files]"`
  - `node -e "const fs=require('fs'); const files=['/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html']; for (const path of files) { const s=fs.readFileSync(path,'utf8'); const scripts=[...s.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)]; for (const m of scripts) { const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'true').replace(/\\{%[\\s\\S]*?%\\}/g,''); new Function(js); } }"`
- Rollback:
  - Revert the files listed above.

## 2026-03-12 06:48 UTC — Fixed Optical filter navigation and added status loading banners
- Type: fix
- Scope: Optical status / Accounts Ping status
- Summary:
  - Fixed the Optical status filter handler so selecting a new filter window reliably updates the page again.
  - Added a noticeable top-center loading banner for Optical and Accounts Ping while filter, search, sort, limit, and pagination changes reload the status tables.
  - Kept the loading effect scoped to the status pages so modal trend charts and settings forms continue to behave as before.
- Files:
  - `app/templates/settings_optical.html`
  - `app/templates/settings_accounts_ping.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Operators now get immediate visual feedback during slow Optical and Accounts Ping status refreshes, and the Optical filter no longer stalls on selection.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; files=['/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html']; env=Environment(); [env.parse(Path(f).read_text()) for f in files]"`
  - `node -e "const fs=require('fs'); const files=['/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html']; for (const path of files) { const s=fs.readFileSync(path,'utf8'); const scripts=[...s.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)]; for (const m of scripts) { const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'true').replace(/\\{%[\\s\\S]*?%\\}/g,''); new Function(js); } }"`
- Rollback:
  - Revert the files listed above.

## 2026-03-11 04:40 UTC — Replaced obsolete level-two labels with Needs Manual Fix
- Type: fix
- Scope: Profile Review / surveillance labels / Optical / Accounts Ping
- Summary:
  - Replaced the remaining user-facing legacy level-two surveillance labels with `Needs Manual Fix`.
  - Updated Profile Review recommendation text, surveillance KPI labels, and reason/baseline captions to use the current workflow terminology.
  - Updated shared surveillance badge text so the same label appears consistently across Profile Review, Optical, and Accounts Ping.
- Files:
  - `app/main.py`
  - `app/templates/base.html`
  - `app/templates/profile_review.html`
  - `app/templates/settings_optical.html`
  - `app/templates/settings_accounts_ping.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Operators now see the current `Needs Manual Fix` terminology anywhere the `level2` surveillance state is surfaced in the UI.
- Validation:
  - Repo-wide legacy-label search returned no remaining matches outside historical notes before this entry was normalized.
  - `python3 -m py_compile /opt/threejnotif/app/main.py`
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; files=['/opt/threejnotif/app/templates/base.html','/opt/threejnotif/app/templates/profile_review.html','/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html']; env=Environment(); [env.parse(Path(f).read_text()) for f in files]"`
- Rollback:
  - Revert the files listed above.

## 2026-03-11 04:25 UTC — Added Profile Review action buttons across monitoring tables
- Type: feature
- Scope: Optical / Accounts Ping / Usage / Offline table actions
- Summary:
  - Added Profile Review icon actions to the account/customer rows in Optical, Accounts Ping, Usage, and Offline tables.
  - Configured the new action to open `/profile-review` in a new tab and prefill the best available account context from each row (PPPoE, IP, and device ID when available).
  - Preserved existing action buttons such as Under Surveillance controls and kept the new Profile Review action gated by `profile_review.view`.
- Files:
  - `app/templates/settings_optical.html`
  - `app/templates/settings_accounts_ping.html`
  - `app/templates/settings_usage.html`
  - `app/templates/settings_offline.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Operators can jump directly from monitoring tables into Profile Review without losing the current page.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; files=['/opt/threejnotif/app/templates/settings_optical.html','/opt/threejnotif/app/templates/settings_accounts_ping.html','/opt/threejnotif/app/templates/settings_usage.html','/opt/threejnotif/app/templates/settings_offline.html']; env=Environment(); [env.parse(Path(f).read_text()) for f in files]"`
  - `node -e "const fs=require('fs'); const path='/opt/threejnotif/app/templates/settings_usage.html'; const s=fs.readFileSync(path,'utf8'); const m=s.match(/<script>([\\s\\S]*?)<\\/script>/); const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'true').replace(/\\{%[\\s\\S]*?%\\}/g,''); new Function(js);"`
  - `node -e "const fs=require('fs'); const path='/opt/threejnotif/app/templates/settings_offline.html'; const s=fs.readFileSync(path,'utf8'); const m=s.match(/<script>([\\s\\S]*?)<\\/script>/); const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'true').replace(/\\{%[\\s\\S]*?%\\}/g,''); new Function(js);"`
- Rollback:
  - Revert the Profile Review action changes in the files listed above.

## 2026-03-10 18:25 UTC — Added Offline router scope toggles and per-router status
- Type: feature
- Scope: Offline settings / router selection / collector scope
- Summary:
  - Added Offline router-level enable toggles under Settings → Routers so operators can limit polling to selected MikroTik routers, matching the Usage router-scope workflow.
  - Added a Status column on the Offline routers table that shows each selected router's collector state and retrieved active-user count.
  - Updated the Offline collector to honor the new router selection in both direct RouterOS polling and Usage-cache reuse paths.
- Files:
  - `app/settings_defaults.py`
  - `app/main.py`
  - `app/jobs.py`
  - `app/templates/settings_offline.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: adds `offline.mikrotik.router_enabled`; adds `offline_state.enabled_router_ids`
- Runtime Impact:
  - Offline polling can now be limited to selected routers, and the settings page shows per-router activity counts from the latest collector state.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py /opt/threejnotif/app/jobs.py /opt/threejnotif/app/settings_defaults.py`
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/settings_offline.html').read_text())"`
- Rollback:
  - Revert the Offline router-scope changes in the files listed above.

## 2026-03-09 05:54 UTC — Exposed core Profile Review diagnostics to page viewers
- Type: fix
- Scope: Profile Review / access behavior
- Summary:
  - Updated Profile Review so the core diagnostic cards are shown to users with normal `profile_review.view` access, instead of requiring the extra `profile_review.details.view` permission.
  - This restores visibility of Account Details, Testing Focus, Under Surveillance, Offline, and the new Inspect Activity panel for operators who could already open the page.
- Files:
  - `app/templates/profile_review.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Profile Review now exposes the main diagnostic section consistently for standard page viewers.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/profile_review.html').read_text())"`
  - `node -e "const fs=require('fs'); const s=fs.readFileSync('/opt/threejnotif/app/templates/profile_review.html','utf8'); const m=s.match(/<script>([\\s\\S]*?)<\\/script>/); if(!m) throw new Error('script block not found'); const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'null'); new Function(js);"`
- Rollback:
  - Revert the `can_core_details` access change in `app/templates/profile_review.html`.

## 2026-03-09 05:22 UTC — Added Inspect Activity panel to Profile Review
- Type: feature
- Scope: Profile Review / surveillance baseline diagnostics
- Summary:
  - Added an inline Inspect Activity card on Profile Review so operators can see the same ACC-Ping latency/loss baseline used in Surveillance without leaving the page.
  - Reused the existing `/surveillance/inspect_activity` endpoint and surfaced its KPI set, zoomable chart, range label, and baseline anchor text directly in the profile workflow.
- Files:
  - `app/templates/profile_review.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Profile Review now exposes surveillance-style inspection data inline for faster account testing and tagging decisions.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/profile_review.html').read_text())"`
- Rollback:
  - Revert the Inspect Activity additions in `app/templates/profile_review.html`.

## 2026-03-09 04:46 UTC — Expanded Profile Review into full account diagnostics
- Type: feature
- Scope: Profile Review / account lookup / surveillance-offline account context
- Summary:
  - Reworked Profile Review search and profile context so account lookups can surface surveillance, offline, usage, optical, and ACC-Ping data together.
  - Added consolidated account KPIs, testing-focus guidance, surveillance details, and offline history/status to help operators decide when to tag an account for Under Surveillance.
  - Added exact account helpers for offline history and active surveillance session lookups to avoid broad scans for profile pages.
- Files:
  - `app/main.py`
  - `app/db.py`
  - `app/templates/profile_review.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Profile Review now renders richer cross-module diagnostics and broader search results for account troubleshooting.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py /opt/threejnotif/app/db.py`
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/profile_review.html').read_text())"`
- Rollback:
  - Revert the Profile Review changes in `app/main.py`, `app/db.py`, and `app/templates/profile_review.html`.

## 2026-03-09 03:41 UTC — Added AI short-command onboarding protocol
- Type: docs
- Scope: AI collaboration workflow / repository docs
- Summary:
  - Added mandatory quick-command protocol to `PROJECT_DESCRIPTION.md` so user can say `view project description`.
  - Defined required AI behavior: read project description + changelog, then return a standard acknowledgment before coding.
  - Renumbered section headers in `PROJECT_DESCRIPTION.md` after inserting new onboarding section.
- Files:
  - `PROJECT_DESCRIPTION.md`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - No runtime impact.
- Validation:
  - Verified cross-reference and protocol text is present.
- Rollback:
  - Revert latest docs commit or remove onboarding section and changelog entry.

## 2026-03-09 03:33 UTC — Added project-level AI onboarding documentation
- Type: docs
- Scope: repository documentation
- Summary:
  - Added `PROJECT_DESCRIPTION.md` with architecture, feature map, DB overview, runtime instructions, and security rules.
  - Added mandatory documentation policy requiring updates whenever system behavior changes.
- Files:
  - `PROJECT_DESCRIPTION.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - No runtime impact.
- Validation:
  - Verified file exists and content is readable.
- Rollback:
  - Remove `PROJECT_DESCRIPTION.md`.

## 2026-03-09 03:36 UTC — Added formal project changelog system
- Type: docs
- Scope: repository documentation governance
- Summary:
  - Added `PROJECT_CHANGELOG.md` with mandatory rules and reusable entry template.
  - Linked changelog requirement from `PROJECT_DESCRIPTION.md`.
- Files:
  - `PROJECT_CHANGELOG.md`
  - `PROJECT_DESCRIPTION.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - No runtime impact.
- Validation:
  - Verified both markdown files and cross-reference.
- Rollback:
  - Remove `PROJECT_CHANGELOG.md` and revert `PROJECT_DESCRIPTION.md` changelog references.
