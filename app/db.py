import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta

DB_PATH = os.environ.get("THREEJ_DB_PATH", "/data/threejnotif.db")
DB_URL = (os.environ.get("THREEJ_DATABASE_URL") or os.environ.get("DATABASE_URL") or "").strip()

_pg_pool = None
_pg_pool_lock = threading.Lock()
_retention_prune_lock = threading.Lock()
_retention_prune_last = {}


AUTH_DEFAULT_PERMISSIONS = [
    {"code": "dashboard.view", "label": "Dashboard View", "description": "View dashboard and summary KPIs."},
    {"code": "dashboard.kpi.wan.view", "label": "Dashboard · WAN Ping KPI", "description": "View WAN Ping KPI card on Dashboard."},
    {"code": "dashboard.kpi.accounts_ping.view", "label": "Dashboard · Accounts Ping KPI", "description": "View Accounts Ping KPI card on Dashboard."},
    {"code": "dashboard.kpi.under_surveillance.view", "label": "Dashboard · Under Surveillance KPI", "description": "View Under Surveillance KPI card on Dashboard."},
    {"code": "dashboard.kpi.usage.view", "label": "Dashboard · Usage KPI", "description": "View Usage KPI card on Dashboard."},
    {"code": "dashboard.kpi.offline.view", "label": "Dashboard · Offline KPI", "description": "View Offline KPI card on Dashboard."},
    {"code": "dashboard.kpi.optical.view", "label": "Dashboard · Optical KPI", "description": "View Optical Monitoring KPI card on Dashboard."},
    {"code": "dashboard.needs_attention.view", "label": "Dashboard · Needs Attention", "description": "View Needs Attention panel on Dashboard."},
    {"code": "dashboard.resources.view", "label": "Dashboard · Live Resources", "description": "View Live System Resource Usage panel on Dashboard."},
    {"code": "dashboard.logs.view", "label": "Dashboard · Latest Logs", "description": "View Latest Logs panel on Dashboard."},
    {"code": "profile_review.view", "label": "Profile Review View", "description": "View profile review page and lookups."},
    {"code": "surveillance.view", "label": "Surveillance View", "description": "View Under Surveillance page and analytics."},
    {"code": "surveillance.edit", "label": "Surveillance Edit", "description": "Update surveillance records and actions."},
    {"code": "optical.view", "label": "Optical View", "description": "View optical monitoring page and charts."},
    {"code": "optical.edit", "label": "Optical Edit", "description": "Edit optical settings and run checks."},
    {"code": "accounts_ping.view", "label": "Accounts Ping View", "description": "View Accounts Ping page and data."},
    {"code": "accounts_ping.edit", "label": "Accounts Ping Edit", "description": "Edit Accounts Ping settings and actions."},
    {"code": "usage.view", "label": "Usage View", "description": "View Usage page and usage status."},
    {"code": "usage.edit", "label": "Usage Edit", "description": "Edit Usage settings and collectors."},
    {"code": "offline.view", "label": "Offline View", "description": "View Offline page and history."},
    {"code": "offline.edit", "label": "Offline Edit", "description": "Edit Offline settings and actions."},
    {"code": "wan.view", "label": "WAN View", "description": "View WAN Ping status and charts."},
    {"code": "wan.edit", "label": "WAN Edit", "description": "Edit WAN settings, targets, and actions."},
    {"code": "system.view", "label": "System View", "description": "View system settings pages."},
    {"code": "system.edit", "label": "System Edit", "description": "Edit system settings pages."},
    {"code": "system.general.branding.view", "label": "System General · Branding View", "description": "View Branding section under System Settings → General."},
    {"code": "system.general.branding.edit", "label": "System General · Branding Edit", "description": "Edit Branding section under System Settings → General."},
    {"code": "system.general.telegram.view", "label": "System General · Telegram Commands View", "description": "View Telegram Commands section under System Settings → General."},
    {"code": "system.general.telegram.edit", "label": "System General · Telegram Commands Edit", "description": "Edit Telegram Commands section under System Settings → General."},
    {"code": "tools.test", "label": "Run Tests", "description": "Run module test actions (Router/API/Radius/etc)."},
    {"code": "settings.import_export", "label": "Settings Import/Export", "description": "Export/import settings or DB payloads."},
    {"code": "settings.danger", "label": "Danger Actions", "description": "Run format/reset destructive actions."},
    {"code": "auth.manage", "label": "Access Management", "description": "Manage users, roles, permissions, and auth settings."},
    {"code": "profile_review.search.view", "label": "Profile Review · Search", "description": "Search/select accounts in Profile Review."},
    {"code": "profile_review.details.view", "label": "Profile Review · Details", "description": "View profile details panels in Profile Review."},
    {"code": "profile_review.usage_panel.view", "label": "Profile Review · Usage Panel", "description": "View Usage panel in Profile Review."},
    {"code": "profile_review.accounts_ping_panel.view", "label": "Profile Review · Accounts Ping Panel", "description": "View Accounts Ping panel in Profile Review."},
    {"code": "profile_review.optical_panel.view", "label": "Profile Review · Optical Panel", "description": "View Optical panel in Profile Review."},
    {"code": "profile_review.action.add_surveillance.edit", "label": "Profile Review · Add To Surveillance", "description": "Add selected account from Profile Review to Under Surveillance."},
    {"code": "surveillance.tab.active.view", "label": "Under Surveillance · Active Monitoring Tab", "description": "View Active Monitoring tab."},
    {"code": "surveillance.tab.manual_fix.view", "label": "Under Surveillance · Needs Manual Fix Tab", "description": "View Needs Manual Fix tab."},
    {"code": "surveillance.tab.post_fix.view", "label": "Under Surveillance · Post-Fix Observation Tab", "description": "View Post-Fix Observation tab."},
    {"code": "surveillance.tab.history.view", "label": "Under Surveillance · History Tab", "description": "View surveillance History tab."},
    {"code": "surveillance.tab.logs.view", "label": "Under Surveillance · Logs Tracking Tab", "description": "View surveillance logs tracking tab."},
    {"code": "surveillance.tab.settings.view", "label": "Under Surveillance · Settings Tab", "description": "View surveillance settings tab."},
    {"code": "surveillance.split_view.view", "label": "Under Surveillance · Split View", "description": "Open and view account split panel."},
    {"code": "surveillance.split_view.inspection.view", "label": "Under Surveillance · Inspect Activity", "description": "View 7-day pre-surveillance inspection modal."},
    {"code": "surveillance.split_view.timeline.view", "label": "Under Surveillance · Healing Timelines", "description": "View healing timelines in split panel."},
    {"code": "surveillance.split_view.baseline.view", "label": "Under Surveillance · Baseline Metrics", "description": "View baseline KPIs and charts in split panel."},
    {"code": "surveillance.action.add_manual.edit", "label": "Under Surveillance · Add Manual", "description": "Manually add accounts into Active Monitoring."},
    {"code": "surveillance.action.mark_false.edit", "label": "Under Surveillance · Mark False", "description": "Mark accounts as false and close session."},
    {"code": "surveillance.action.move_to_manual_fix.edit", "label": "Under Surveillance · Move To Needs Manual Fix", "description": "Move accounts from Active Monitoring to Needs Manual Fix."},
    {"code": "surveillance.action.account_fixed.edit", "label": "Under Surveillance · Account Fixed", "description": "Mark accounts as fixed from Needs Manual Fix."},
    {"code": "surveillance.action.mark_recovered.edit", "label": "Under Surveillance · Mark Fully Recovered", "description": "Mark accounts as fully recovered in Post-Fix Observation."},
    {"code": "surveillance.action.bulk.edit", "label": "Under Surveillance · Bulk Actions", "description": "Use multi-select/bulk workflow actions."},
    {"code": "surveillance.settings.checkers.edit", "label": "Under Surveillance · Settings · Checkers", "description": "Edit checker thresholds and readiness logic."},
    {"code": "surveillance.settings.auto_add.edit", "label": "Under Surveillance · Settings · Auto Add", "description": "Edit auto-add scan rules and lookback."},
    {"code": "surveillance.settings.danger.run", "label": "Under Surveillance · Settings · Danger", "description": "Run destructive surveillance format actions."},
    {"code": "optical.tab.status.view", "label": "Optical · Status Tab", "description": "View optical status tab and table."},
    {"code": "optical.tab.settings.view", "label": "Optical · Settings Tab", "description": "View optical settings tab."},
    {"code": "optical.chart.series.view", "label": "Optical · Chart Series", "description": "View optical RX/TX chart series and modal."},
    {"code": "optical.settings.thresholds.edit", "label": "Optical · Settings · Thresholds", "description": "Edit stable/issue RX/TX thresholds."},
    {"code": "optical.settings.datasource.edit", "label": "Optical · Settings · Data Source", "description": "Edit GenieACS data source and parameter paths."},
    {"code": "optical.settings.telegram.edit", "label": "Optical · Settings · Telegram", "description": "Edit optical Telegram notification behavior."},
    {"code": "optical.settings.retention.edit", "label": "Optical · Settings · Retention", "description": "Edit optical data retention settings."},
    {"code": "optical.settings.danger.run", "label": "Optical · Settings · Danger", "description": "Run optical destructive format actions."},
    {"code": "optical.action.test_source.run", "label": "Optical · Test Data Source", "description": "Run optical source/API test actions."},
    {"code": "accounts_ping.tab.status.view", "label": "Accounts Ping · Status Tab", "description": "View accounts ping status tab and table."},
    {"code": "accounts_ping.tab.settings.view", "label": "Accounts Ping · Settings Tab", "description": "View accounts ping settings tab."},
    {"code": "accounts_ping.chart.series.view", "label": "Accounts Ping · Chart Series", "description": "View accounts ping line chart data and modal."},
    {"code": "accounts_ping.settings.datasource.edit", "label": "Accounts Ping · Settings · Data Source", "description": "Edit Accounts Ping source (SSH/CSV) settings."},
    {"code": "accounts_ping.settings.checkers.edit", "label": "Accounts Ping · Settings · Checkers", "description": "Edit latency/loss checker settings."},
    {"code": "accounts_ping.settings.performance.edit", "label": "Accounts Ping · Settings · Performance", "description": "Edit collector performance settings (parallelism/interval)."},
    {"code": "accounts_ping.settings.retention.edit", "label": "Accounts Ping · Settings · Retention", "description": "Edit accounts ping retention settings."},
    {"code": "accounts_ping.settings.danger.run", "label": "Accounts Ping · Settings · Danger", "description": "Run accounts ping destructive format actions."},
    {"code": "accounts_ping.action.test_source.run", "label": "Accounts Ping · Test Data Source", "description": "Run Accounts Ping source and connectivity test actions."},
    {"code": "accounts_ping.action.run_now.run", "label": "Accounts Ping · Run Now", "description": "Run accounts ping collection manually."},
    {"code": "usage.tab.status.view", "label": "Usage · Status Tab", "description": "View usage status tab."},
    {"code": "usage.tab.settings.view", "label": "Usage · Settings Tab", "description": "View usage settings tab."},
    {"code": "usage.status.issues.view", "label": "Usage · Issues Tab", "description": "View usage issues table."},
    {"code": "usage.status.stable.view", "label": "Usage · Stable Tab", "description": "View stable usage table."},
    {"code": "usage.table.devices.view", "label": "Usage · Devices Column", "description": "View per-account device details/panel."},
    {"code": "usage.chart.series.view", "label": "Usage · Chart Series", "description": "View usage rate/total charts and modal."},
    {"code": "usage.settings.general.edit", "label": "Usage · Settings · General", "description": "Edit general usage settings and intervals."},
    {"code": "usage.settings.datasource.edit", "label": "Usage · Settings · Data Source", "description": "Edit Usage data source and GenieACS host parameters."},
    {"code": "usage.settings.routers.view", "label": "Usage · Settings · Routers View", "description": "View router reference list under Usage settings."},
    {"code": "usage.settings.routers.edit", "label": "Usage · Settings · Routers Scope", "description": "Enable/disable router scope used by Usage."},
    {"code": "usage.settings.rules.edit", "label": "Usage · Settings · Detection Rules", "description": "Edit usage issue detection rules and working hours."},
    {"code": "usage.settings.retention.edit", "label": "Usage · Settings · Retention", "description": "Edit usage data retention settings."},
    {"code": "usage.settings.danger.run", "label": "Usage · Settings · Danger", "description": "Run usage destructive format actions."},
    {"code": "usage.action.test_source.run", "label": "Usage · Test Data Source", "description": "Run Usage data source and router test actions."},
    {"code": "offline.tab.status.view", "label": "Offline · Status Tab", "description": "View offline status tab."},
    {"code": "offline.tab.history.view", "label": "Offline · History Tab", "description": "View offline history tab."},
    {"code": "offline.tab.settings.view", "label": "Offline · Settings Tab", "description": "View offline settings tab."},
    {"code": "offline.status.current.view", "label": "Offline · Current Offline List", "description": "View current offline accounts list."},
    {"code": "offline.history.view", "label": "Offline · History Records", "description": "View historical offline-to-active records."},
    {"code": "offline.settings.mode.edit", "label": "Offline · Settings · Mode", "description": "Edit offline mode (MikroTik-only vs MikroTik+Radius)."},
    {"code": "offline.settings.radius.view", "label": "Offline · Settings · Radius View", "description": "View radius settings and accounts viewer."},
    {"code": "offline.settings.radius.edit", "label": "Offline · Settings · Radius Edit", "description": "Edit radius server connection and list command."},
    {"code": "offline.settings.window.edit", "label": "Offline · Settings · Window", "description": "Edit offline detection time/day window."},
    {"code": "offline.settings.danger.run", "label": "Offline · Settings · Danger", "description": "Run offline destructive format actions."},
    {"code": "offline.action.radius_test.run", "label": "Offline · Test Radius", "description": "Run radius connection test action."},
    {"code": "wan.tab.status.view", "label": "WAN Ping · Status Tab", "description": "View WAN status tab."},
    {"code": "wan.tab.settings.view", "label": "WAN Ping · Settings Tab", "description": "View WAN settings tab."},
    {"code": "wan.status.netwatch.view", "label": "WAN Ping · Netwatch Overview", "description": "View Netwatch up/down overview and cards."},
    {"code": "wan.status.target_latency.view", "label": "WAN Ping · Target Latency", "description": "View target latency line charts."},
    {"code": "wan.status.live_ping.run", "label": "WAN Ping · Run Ping All", "description": "Run live ping-all modal action."},
    {"code": "wan.settings.general.edit", "label": "WAN Ping · Settings · General", "description": "Edit WAN polling intervals and defaults."},
    {"code": "wan.settings.isp_reference.view", "label": "WAN Ping · Settings · ISP Reference View", "description": "View read-only ISP reference table."},
    {"code": "wan.settings.targets.edit", "label": "WAN Ping · Settings · Targets", "description": "Add/edit/delete WAN ping targets."},
    {"code": "wan.settings.polling.edit", "label": "WAN Ping · Settings · Polling", "description": "Edit target latency polling behavior."},
    {"code": "wan.settings.sync.run", "label": "WAN Ping · Settings · Sync Netwatch", "description": "Run WAN-to-router netwatch synchronization actions."},
    {"code": "wan.settings.danger.run", "label": "WAN Ping · Settings · Danger", "description": "Run WAN destructive format actions."},
    {"code": "wan.action.test_router.run", "label": "WAN Ping · Test Router", "description": "Run WAN router/API connectivity tests."},
    {"code": "system.tab.general.view", "label": "System Settings · General Tab", "description": "View System Settings general tab."},
    {"code": "system.tab.routers.view", "label": "System Settings · Routers Tab", "description": "View System Settings routers tab."},
    {"code": "system.tab.access.view", "label": "System Settings · Access Tab", "description": "View System Settings access tab."},
    {"code": "system.backup.import_export.run", "label": "System Backup · Import / Export", "description": "Use backup and restore actions under System Settings → Backup."},
    {"code": "system.tab.danger.view", "label": "System Settings · Danger Tab", "description": "View System Settings danger tab."},
    {"code": "system.routers.mikrotik.view", "label": "System Routers · MikroTik View", "description": "View MikroTik routers section."},
    {"code": "system.routers.mikrotik.edit", "label": "System Routers · MikroTik Edit", "description": "Edit MikroTik routers section."},
    {"code": "system.routers.cores.view", "label": "System Routers · Cores View", "description": "View router cores section."},
    {"code": "system.routers.cores.edit", "label": "System Routers · Cores Edit", "description": "Edit router cores section."},
    {"code": "system.routers.test.run", "label": "System Routers · Test Connections", "description": "Run router/core connectivity test actions under System Settings → Routers."},
    {"code": "system.routers.isp.view", "label": "System Routers · ISPs View", "description": "View Add ISP section."},
    {"code": "system.routers.isp.edit", "label": "System Routers · ISPs Edit", "description": "Edit Add ISP section."},
    {"code": "system.targets.view", "label": "System Settings · Targets View", "description": "View shared ping targets settings."},
    {"code": "system.targets.edit", "label": "System Settings · Targets Edit", "description": "Edit shared ping targets settings."},
    {"code": "system.access.auth.view", "label": "System Access · Auth Config View", "description": "View authentication settings under Access."},
    {"code": "system.access.auth.edit", "label": "System Access · Auth Config Edit", "description": "Edit authentication settings under Access."},
    {"code": "system.access.permissions.view", "label": "System Access · Permissions View", "description": "View permission catalog."},
    {"code": "system.access.roles.view", "label": "System Access · Roles View", "description": "View roles list and assigned permissions."},
    {"code": "system.access.roles.edit", "label": "System Access · Roles Edit", "description": "Add/edit/delete roles and role permissions."},
    {"code": "system.access.users.view", "label": "System Access · Users View", "description": "View users list."},
    {"code": "system.access.users.edit", "label": "System Access · Users Edit", "description": "Add/edit/delete users and reset passwords."},
    {"code": "system.danger.uninstall.run", "label": "System Danger · Uninstall", "description": "Run system uninstall action."},
    {"code": "logs.category.surveillance.view", "label": "Logs · Category · Surveillance", "description": "View Surveillance logs on the Logs page."},
    {"code": "logs.category.access.view", "label": "Logs · Category · Access", "description": "View Access logs on the Logs page."},
    {"code": "logs.category.user_action.view", "label": "Logs · Category · User Action", "description": "View User Action logs on the Logs page."},
    {"code": "logs.category.settings.view", "label": "Logs · Category · Settings", "description": "View Settings logs on the Logs page."},
    {"code": "logs.category.system.view", "label": "Logs · Category · System", "description": "View System logs on the Logs page."},
    {"code": "logs.search.view", "label": "Logs · Search", "description": "Use logs search on logs page."},
    {"code": "logs.filter.view", "label": "Logs · Filters", "description": "Use logs filters/date/category controls."},
    {"code": "logs.timeline.view", "label": "Logs · Timeline", "description": "View detailed logs timeline table/cards."},
    {"code": "VIEW_Dashboard", "label": "VIEW_Dashboard", "description": "View dashboard KPIs and overview."},
    {"code": "VIEW_ProfileReview", "label": "VIEW_ProfileReview", "description": "View Profile Review page."},
    {"code": "VIEW_UnderSurveillance", "label": "VIEW_UnderSurveillance", "description": "View Under Surveillance workflow page."},
    {"code": "EDIT_UnderSurveillance", "label": "EDIT_UnderSurveillance", "description": "Edit surveillance records and workflow states."},
    {"code": "ADD_AccessMonitoring_UnderSurveillance", "label": "ADD_AccessMonitoring_UnderSurveillance", "description": "Add an account into Active Monitoring."},
    {"code": "MARKFALSE_AccessMonitoring_UnderSurveillance", "label": "MARKFALSE_AccessMonitoring_UnderSurveillance", "description": "Mark Active Monitoring entries as false."},
    {"code": "MOVE_AccessMonitoring_ToNeedsManualFix", "label": "MOVE_AccessMonitoring_ToNeedsManualFix", "description": "Move Active Monitoring accounts to Needs Manual Fix."},
    {"code": "FIX_NeedsManualFix_Account", "label": "FIX_NeedsManualFix_Account", "description": "Mark Needs Manual Fix entries as fixed."},
    {"code": "RECOVER_PostFixObservation_Account", "label": "RECOVER_PostFixObservation_Account", "description": "Mark Post-Fix Observation entries as fully recovered."},
    {"code": "VIEW_Optical", "label": "VIEW_Optical", "description": "View Optical Monitoring."},
    {"code": "EDIT_Optical", "label": "EDIT_Optical", "description": "Edit Optical Monitoring settings."},
    {"code": "VIEW_AccountsPing", "label": "VIEW_AccountsPing", "description": "View Accounts Ping."},
    {"code": "EDIT_AccountsPing", "label": "EDIT_AccountsPing", "description": "Edit Accounts Ping settings/actions."},
    {"code": "VIEW_Usage", "label": "VIEW_Usage", "description": "View Usage module."},
    {"code": "EDIT_Usage", "label": "EDIT_Usage", "description": "Edit Usage module settings/actions."},
    {"code": "VIEW_Offline", "label": "VIEW_Offline", "description": "View Offline module."},
    {"code": "EDIT_Offline", "label": "EDIT_Offline", "description": "Edit Offline module settings/actions."},
    {"code": "VIEW_WanPing", "label": "VIEW_WanPing", "description": "View WAN Ping module."},
    {"code": "EDIT_WanPing", "label": "EDIT_WanPing", "description": "Edit WAN Ping module settings/actions."},
    {"code": "VIEW_SystemSettings", "label": "VIEW_SystemSettings", "description": "View System Settings page."},
    {"code": "EDIT_SystemSettings", "label": "EDIT_SystemSettings", "description": "Edit System Settings."},
    {"code": "RUN_TestTools", "label": "RUN_TestTools", "description": "Execute module test actions."},
    {"code": "MANAGE_BackupImportExport", "label": "MANAGE_BackupImportExport", "description": "Run settings/database backup import-export actions."},
    {"code": "RUN_DangerActions", "label": "RUN_DangerActions", "description": "Execute destructive format/uninstall actions."},
    {"code": "MANAGE_AccessControl", "label": "MANAGE_AccessControl", "description": "Manage users, roles, permissions, and auth settings."},
]


AUTH_DEFAULT_ROLES = [
    {"name": "owner", "description": "System owner. Full access and immutable permissions."},
    {"name": "admin", "description": "Full module access except danger/format actions."},
    {"name": "viewer", "description": "Read-only user for dashboards and status pages."},
]


def _is_danger_permission_code(code: str) -> bool:
    lowered = str(code or "").strip().lower()
    if not lowered:
        return False
    if lowered == "settings.danger" or lowered == "run_dangeractions":
        return True
    if ".danger." in lowered:
        return True
    if lowered.endswith(".danger"):
        return True
    return False


def _is_view_permission_code(code: str) -> bool:
    lowered = str(code or "").strip().lower()
    if not lowered:
        return False
    return lowered.endswith(".view") or lowered.startswith("view_")


AUTH_DEFAULT_ROLE_PERMS = {
    "owner": [perm["code"] for perm in AUTH_DEFAULT_PERMISSIONS],
    "admin": [perm["code"] for perm in AUTH_DEFAULT_PERMISSIONS if not _is_danger_permission_code(perm.get("code"))],
    "viewer": [
        perm["code"]
        for perm in AUTH_DEFAULT_PERMISSIONS
        if _is_view_permission_code(perm.get("code")) and not _is_danger_permission_code(perm.get("code"))
    ],
}


def _should_run_retention_prune(key, interval_seconds):
    interval = max(int(interval_seconds or 0), 0)
    if interval <= 0:
        return True
    now = time.monotonic()
    with _retention_prune_lock:
        last = float(_retention_prune_last.get(key) or 0.0)
        if now - last < interval:
            return False
        _retention_prune_last[key] = now
        return True


def _use_postgres():
    url = (DB_URL or "").lower()
    return url.startswith("postgres://") or url.startswith("postgresql://")


def _translate_qmarks(sql):
    # sqlite uses "?" params; psycopg2 expects "%s".
    # Replace only outside single-quoted string literals.
    out = []
    in_single = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            out.append(ch)
            if in_single and i + 1 < len(sql) and sql[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            in_single = not in_single
            i += 1
            continue
        if ch == "?" and not in_single:
            out.append("%s")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _row_get(row, key, default=None):
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default


def _seed_auth_defaults(conn):
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    permission_ids = {}
    for item in AUTH_DEFAULT_PERMISSIONS:
        code = (item.get("code") or "").strip()
        if not code:
            continue
        label = (item.get("label") or code).strip()
        description = (item.get("description") or "").strip()
        row = conn.execute("SELECT id FROM auth_permissions WHERE code = ? LIMIT 1", (code,)).fetchone()
        if not row:
            conn.execute(
                """
                INSERT INTO auth_permissions (code, label, description, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (code, label, description, now),
            )
            row = conn.execute("SELECT id FROM auth_permissions WHERE code = ? LIMIT 1", (code,)).fetchone()
        permission_id = _row_get(row, "id")
        if permission_id is not None:
            try:
                permission_ids[code] = int(permission_id)
            except Exception:
                pass

    canonical_roles = {}
    role_ids = {}
    role_created = {}
    for role in AUTH_DEFAULT_ROLES:
        name = (role.get("name") or "").strip().lower()
        if not name:
            continue
        canonical_roles[name] = (role.get("description") or "").strip()
        row = conn.execute("SELECT id FROM auth_roles WHERE lower(name) = lower(?) LIMIT 1", (name,)).fetchone()
        created_now = False
        if not row:
            conn.execute(
                """
                INSERT INTO auth_roles (name, description, is_builtin, created_at, updated_at)
                VALUES (?, ?, 1, ?, ?)
                """,
                (name, canonical_roles[name], now, now),
            )
            row = conn.execute("SELECT id FROM auth_roles WHERE lower(name) = lower(?) LIMIT 1", (name,)).fetchone()
            created_now = True
        else:
            conn.execute(
                """
                UPDATE auth_roles
                SET description = ?, is_builtin = 1, updated_at = ?
                WHERE id = ?
                """,
                (canonical_roles[name], now, _row_get(row, "id")),
            )
        role_id = _row_get(row, "id")
        if role_id is None:
            continue
        try:
            role_ids[name] = int(role_id)
            role_created[name] = created_now
        except Exception:
            continue

    fallback_role_id = role_ids.get("viewer") or role_ids.get("admin") or role_ids.get("owner") or 0

    legacy_builtin_rows = conn.execute(
        """
        SELECT id, name
        FROM auth_roles
        WHERE is_builtin = 1
        """
    ).fetchall()
    for row in legacy_builtin_rows or []:
        role_name = str(_row_get(row, "name", "") or "").strip().lower()
        role_id = int(_row_get(row, "id", 0) or 0)
        if role_id <= 0:
            continue
        if role_name in canonical_roles:
            continue
        if fallback_role_id > 0:
            conn.execute("UPDATE auth_users SET role_id = ? WHERE role_id = ?", (fallback_role_id, role_id))
        conn.execute("DELETE FROM auth_role_permissions WHERE role_id = ?", (role_id,))
        conn.execute("DELETE FROM auth_roles WHERE id = ?", (role_id,))

    for role_name, perm_codes in (AUTH_DEFAULT_ROLE_PERMS or {}).items():
        normalized_role_name = str(role_name or "").strip().lower()
        role_id = role_ids.get(normalized_role_name)
        if not role_id:
            continue
        should_seed_perms = normalized_role_name == "owner"
        if not should_seed_perms:
            if role_created.get(normalized_role_name):
                should_seed_perms = True
            else:
                count_row = conn.execute(
                    "SELECT COUNT(*) AS count_value FROM auth_role_permissions WHERE role_id = ?",
                    (role_id,),
                ).fetchone()
                try:
                    current_count = int(_row_get(count_row, "count_value", 0) or 0)
                except Exception:
                    current_count = 0
                should_seed_perms = current_count <= 0
        if not should_seed_perms:
            continue
        conn.execute("DELETE FROM auth_role_permissions WHERE role_id = ?", (role_id,))
        for code in perm_codes or []:
            perm_id = permission_ids.get(code)
            if not perm_id:
                continue
            conn.execute(
                """
                INSERT INTO auth_role_permissions (role_id, permission_id)
                VALUES (?, ?)
                """,
                (role_id, perm_id),
            )


class _NoResult:
    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _PGCursorResult:
    def __init__(self, owner, cursor):
        self._owner = owner
        self._cursor = cursor

    def _close(self):
        if not self._cursor:
            return
        try:
            self._cursor.close()
        finally:
            self._owner._discard_cursor(self._cursor)
            self._cursor = None

    def fetchone(self):
        try:
            return self._cursor.fetchone()
        finally:
            self._close()

    def fetchall(self):
        try:
            return self._cursor.fetchall()
        finally:
            self._close()


class _PGConn:
    def __init__(self, pool, conn):
        self._pool = pool
        self._conn = conn
        self._open_cursors = []

    def _discard_cursor(self, cursor):
        try:
            self._open_cursors.remove(cursor)
        except ValueError:
            pass

    def __enter__(self):
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._conn.__exit__(exc_type, exc, tb)

    def execute(self, sql, params=None):
        from psycopg2.extras import RealDictCursor

        q = _translate_qmarks(str(sql))
        cur = self._conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute(q, tuple(params or ()))
            if cur.description is None:
                cur.close()
                return _NoResult()
            self._open_cursors.append(cur)
            return _PGCursorResult(self, cur)
        except Exception:
            try:
                cur.close()
            except Exception:
                pass
            raise

    def close(self):
        # Return to pool, ensuring the connection is clean.
        for cur in list(self._open_cursors):
            try:
                cur.close()
            except Exception:
                pass
        self._open_cursors.clear()
        try:
            try:
                self._conn.rollback()
            except Exception:
                pass
        finally:
            self._pool.putconn(self._conn)


def _get_pg_pool():
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    with _pg_pool_lock:
        if _pg_pool is not None:
            return _pg_pool
        from psycopg2.pool import ThreadedConnectionPool

        minconn = max(int(os.environ.get("THREEJ_PG_POOL_MIN", 1) or 1), 1)
        # Default higher to avoid pool exhaustion with multiple background loops + UI polling.
        maxconn = max(int(os.environ.get("THREEJ_PG_POOL_MAX", 30) or 30), minconn)
        _pg_pool = ThreadedConnectionPool(minconn, maxconn, dsn=DB_URL)
        return _pg_pool


def _pg_prepare_conn(pool, conn):
    try:
        conn.autocommit = False
        cur = conn.cursor()
        try:
            cur.execute("SELECT 1")
            cur.fetchone()
        finally:
            cur.close()
        try:
            conn.rollback()
        except Exception:
            pass
        return _PGConn(pool, conn)
    except Exception:
        try:
            pool.putconn(conn, close=True)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
        raise


def get_conn():
    if _use_postgres():
        from psycopg2.pool import PoolError

        pool = _get_pg_pool()
        wait_seconds = float(os.environ.get("THREEJ_PG_POOL_WAIT_SECONDS", 5) or 5)
        deadline = time.monotonic() + max(wait_seconds, 0.0)
        backoff = 0.05
        while True:
            try:
                conn = pool.getconn()
                return _pg_prepare_conn(pool, conn)
            except PoolError:
                if wait_seconds <= 0 or time.monotonic() >= deadline:
                    raise
                time.sleep(backoff)
                backoff = min(backoff * 2, 0.5)
            except Exception:
                if wait_seconds <= 0 or time.monotonic() >= deadline:
                    raise
                time.sleep(backoff)
                backoff = min(backoff * 2, 0.5)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    with conn:
        if _use_postgres():
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS job_status (
                    job_name TEXT PRIMARY KEY,
                    last_run_at TEXT,
                    last_success_at TEXT,
                    last_error TEXT,
                    last_error_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ping_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    loss DOUBLE PRECISION,
                    min_ms DOUBLE PRECISION,
                    avg_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
                    raw_output TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ping_rollups (
                    bucket_ts TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    avg_sum DOUBLE PRECISION NOT NULL,
                    avg_count INTEGER NOT NULL,
                    loss_sum DOUBLE PRECISION NOT NULL,
                    loss_count INTEGER NOT NULL,
                    min_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
                    max_avg_ms DOUBLE PRECISION,
                    PRIMARY KEY (bucket_ts, isp_id, target)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS speedtest_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    download_mbps DOUBLE PRECISION,
                    upload_mbps DOUBLE PRECISION,
                    latency_ms DOUBLE PRECISION,
                    server_name TEXT,
                    server_id TEXT,
                    public_ip TEXT,
                    raw_output TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts_log (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    cooldown_until TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rto_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    name TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS optical_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    pppoe TEXT,
                    ip TEXT,
                    rx DOUBLE PRECISION,
                    tx DOUBLE PRECISION,
                    priority INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wan_status_history (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    wan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    up_pct DOUBLE PRECISION,
                    target TEXT,
                    core_id TEXT,
                    label TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wan_target_ping_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    wan_id TEXT NOT NULL,
                    core_id TEXT,
                    label TEXT,
                    target_id TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    src_address TEXT,
                    ok INTEGER NOT NULL,
                    rtt_ms DOUBLE PRECISION
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_wan_target_ping_results_target_ts
                ON wan_target_ping_results (target_id, timestamp)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_wan_target_ping_results_wan_target_ts
                ON wan_target_ping_results (wan_id, target_id, timestamp)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    name TEXT,
                    ip TEXT NOT NULL,
                    loss DOUBLE PRECISION,
                    min_ms DOUBLE PRECISION,
                    avg_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
                    mode TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_rollups (
                    bucket_ts TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    ok_count INTEGER NOT NULL,
                    avg_sum DOUBLE PRECISION NOT NULL,
                    avg_count INTEGER NOT NULL,
                    loss_sum DOUBLE PRECISION NOT NULL,
                    loss_count INTEGER NOT NULL,
                    min_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
                    max_avg_ms DOUBLE PRECISION,
                    PRIMARY KEY (bucket_ts, account_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pppoe_usage_samples (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    pppoe TEXT NOT NULL,
                    address TEXT,
                    session_id TEXT,
                    uptime TEXT,
                    bytes_in BIGINT,
                    bytes_out BIGINT,
                    host_count INTEGER,
                    rx_bps DOUBLE PRECISION,
                    tx_bps DOUBLE PRECISION
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS surveillance_sessions (
                    id BIGSERIAL PRIMARY KEY,
                    pppoe TEXT NOT NULL,
                    source TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    end_reason TEXT,
                    end_note TEXT,
                    under_seconds INTEGER NOT NULL DEFAULT 0,
                    level2_seconds INTEGER NOT NULL DEFAULT 0,
                    observe_seconds INTEGER NOT NULL DEFAULT 0,
                    observed_count INTEGER NOT NULL DEFAULT 0,
                    last_state TEXT NOT NULL DEFAULT 'under',
                    last_ip TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_history (
                    id BIGSERIAL PRIMARY KEY,
                    pppoe TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    mode TEXT NOT NULL,
                    offline_started_at TEXT NOT NULL,
                    offline_ended_at TEXT NOT NULL,
                    duration_seconds INTEGER,
                    radius_status TEXT,
                    disabled BOOLEAN,
                    profile TEXT,
                    last_logged_out TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_permissions (
                    id BIGSERIAL PRIMARY KEY,
                    code TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_roles (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    is_builtin INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_role_permissions (
                    role_id BIGINT NOT NULL,
                    permission_id BIGINT NOT NULL,
                    PRIMARY KEY (role_id, permission_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT,
                    full_name TEXT,
                    role_id BIGINT NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    last_login_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    id BIGSERIAL PRIMARY KEY,
                    session_token_hash TEXT NOT NULL UNIQUE,
                    user_id BIGINT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    expires_at TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    revoked_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_audit_logs (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    user_id BIGINT,
                    username TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    details TEXT,
                    ip_address TEXT
                )
                """
            )
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS job_status (
                    job_name TEXT PRIMARY KEY,
                    last_run_at TEXT,
                    last_success_at TEXT,
                    last_error TEXT,
                    last_error_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ping_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    loss REAL,
                    min_ms REAL,
                    avg_ms REAL,
                    max_ms REAL,
                    raw_output TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ping_rollups (
                    bucket_ts TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    avg_sum REAL NOT NULL,
                    avg_count INTEGER NOT NULL,
                    loss_sum REAL NOT NULL,
                    loss_count INTEGER NOT NULL,
                    min_ms REAL,
                    max_ms REAL,
                    max_avg_ms REAL,
                    PRIMARY KEY (bucket_ts, isp_id, target)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS speedtest_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    download_mbps REAL,
                    upload_mbps REAL,
                    latency_ms REAL,
                    server_name TEXT,
                    server_id TEXT,
                    public_ip TEXT,
                    raw_output TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    cooldown_until TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rto_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    name TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS optical_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    pppoe TEXT,
                    ip TEXT,
                    rx REAL,
                    tx REAL,
                    priority INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wan_status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    wan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    up_pct REAL,
                    target TEXT,
                    core_id TEXT,
                    label TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wan_target_ping_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    wan_id TEXT NOT NULL,
                    core_id TEXT,
                    label TEXT,
                    target_id TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    src_address TEXT,
                    ok INTEGER NOT NULL,
                    rtt_ms REAL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_wan_target_ping_results_target_ts
                ON wan_target_ping_results (target_id, timestamp)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_wan_target_ping_results_wan_target_ts
                ON wan_target_ping_results (wan_id, target_id, timestamp)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    name TEXT,
                    ip TEXT NOT NULL,
                    loss REAL,
                    min_ms REAL,
                    avg_ms REAL,
                    max_ms REAL,
                    mode TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_rollups (
                    bucket_ts TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    ok_count INTEGER NOT NULL,
                    avg_sum REAL NOT NULL,
                    avg_count INTEGER NOT NULL,
                    loss_sum REAL NOT NULL,
                    loss_count INTEGER NOT NULL,
                    min_ms REAL,
                    max_ms REAL,
                    max_avg_ms REAL,
                    PRIMARY KEY (bucket_ts, account_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pppoe_usage_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    pppoe TEXT NOT NULL,
                    address TEXT,
                    session_id TEXT,
                    uptime TEXT,
                    bytes_in INTEGER,
                    bytes_out INTEGER,
                    host_count INTEGER,
                    rx_bps REAL,
                    tx_bps REAL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS surveillance_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pppoe TEXT NOT NULL,
                    source TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    end_reason TEXT,
                    end_note TEXT,
                    under_seconds INTEGER NOT NULL DEFAULT 0,
                    level2_seconds INTEGER NOT NULL DEFAULT 0,
                    observe_seconds INTEGER NOT NULL DEFAULT 0,
                    observed_count INTEGER NOT NULL DEFAULT 0,
                    last_state TEXT NOT NULL DEFAULT 'under',
                    last_ip TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pppoe TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    mode TEXT NOT NULL,
                    offline_started_at TEXT NOT NULL,
                    offline_ended_at TEXT NOT NULL,
                    duration_seconds INTEGER,
                    radius_status TEXT,
                    disabled INTEGER,
                    profile TEXT,
                    last_logged_out TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    is_builtin INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_role_permissions (
                    role_id INTEGER NOT NULL,
                    permission_id INTEGER NOT NULL,
                    PRIMARY KEY (role_id, permission_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT,
                    full_name TEXT,
                    role_id INTEGER NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    last_login_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_token_hash TEXT NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    expires_at TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    revoked_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    details TEXT,
                    ip_address TEXT
                )
                """
            )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_wan_status_history_wan_ts
            ON wan_status_history (wan_id, timestamp)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_wan_status_history_ts
            ON wan_status_history (timestamp)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_wan_target_ping_results_ts
            ON wan_target_ping_results (timestamp)
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rto_results_ip_ts ON rto_results (ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_optical_results_device_ts ON optical_results (device_id, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_optical_results_ip_ts ON optical_results (ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_optical_results_pppoe_ts ON optical_results (pppoe, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ping_results_isp_ts ON ping_results (isp_id, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ping_rollups_isp_bucket ON ping_rollups (isp_id, bucket_ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_ping_results_acct_ts ON accounts_ping_results (account_id, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_ping_results_ip_ts ON accounts_ping_results (ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_ping_rollups_acct_bucket ON accounts_ping_rollups (account_id, bucket_ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pppoe_usage_samples_pppoe_ts ON pppoe_usage_samples (pppoe, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pppoe_usage_samples_router_ts ON pppoe_usage_samples (router_id, timestamp)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_surveillance_sessions_pppoe_started ON surveillance_sessions (pppoe, started_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_surveillance_sessions_active ON surveillance_sessions (ended_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_offline_history_pppoe_ended ON offline_history (pppoe, offline_ended_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_offline_history_router_ended ON offline_history (router_id, offline_ended_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_users_role_active ON auth_users (role_id, is_active)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_active ON auth_sessions (user_id, revoked_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_sessions_last_seen ON auth_sessions (last_seen_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_ts ON auth_audit_logs (timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_user_ts ON auth_audit_logs (user_id, timestamp)"
        )
        # Lightweight schema upgrade for existing installs.
        try:
            if _use_postgres():
                conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN IF NOT EXISTS end_note TEXT")
                conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN IF NOT EXISTS under_seconds INTEGER NOT NULL DEFAULT 0")
                conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN IF NOT EXISTS level2_seconds INTEGER NOT NULL DEFAULT 0")
                conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN IF NOT EXISTS observe_seconds INTEGER NOT NULL DEFAULT 0")
                conn.execute("ALTER TABLE pppoe_usage_samples ADD COLUMN IF NOT EXISTS host_count INTEGER")
                conn.execute("ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS email TEXT")
                conn.execute("ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS full_name TEXT")
                conn.execute("ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0")
                conn.execute("ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS is_active INTEGER NOT NULL DEFAULT 1")
                conn.execute("ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS last_login_at TEXT")
                conn.execute("ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS updated_at TEXT")
            else:
                cols = []
                try:
                    info = conn.execute("PRAGMA table_info(surveillance_sessions)").fetchall()
                    cols = [row["name"] for row in info] if info else []
                except Exception:
                    cols = []
                if "end_note" not in cols:
                    conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN end_note TEXT")
                if "under_seconds" not in cols:
                    conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN under_seconds INTEGER NOT NULL DEFAULT 0")
                if "level2_seconds" not in cols:
                    conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN level2_seconds INTEGER NOT NULL DEFAULT 0")
                if "observe_seconds" not in cols:
                    conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN observe_seconds INTEGER NOT NULL DEFAULT 0")
                try:
                    info = conn.execute("PRAGMA table_info(pppoe_usage_samples)").fetchall()
                    cols = [row["name"] for row in info] if info else []
                except Exception:
                    cols = []
                if "host_count" not in cols:
                    conn.execute("ALTER TABLE pppoe_usage_samples ADD COLUMN host_count INTEGER")
                try:
                    info = conn.execute("PRAGMA table_info(auth_users)").fetchall()
                    cols = [row["name"] for row in info] if info else []
                except Exception:
                    cols = []
                if "email" not in cols:
                    conn.execute("ALTER TABLE auth_users ADD COLUMN email TEXT")
                if "full_name" not in cols:
                    conn.execute("ALTER TABLE auth_users ADD COLUMN full_name TEXT")
                if "must_change_password" not in cols:
                    conn.execute("ALTER TABLE auth_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
                if "is_active" not in cols:
                    conn.execute("ALTER TABLE auth_users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
                if "last_login_at" not in cols:
                    conn.execute("ALTER TABLE auth_users ADD COLUMN last_login_at TEXT")
                if "updated_at" not in cols:
                    conn.execute("ALTER TABLE auth_users ADD COLUMN updated_at TEXT")
        except Exception:
            pass
        try:
            _seed_auth_defaults(conn)
        except Exception:
            pass
    conn.close()


def insert_offline_history_event(
    pppoe,
    router_id,
    router_name,
    mode,
    offline_started_at,
    offline_ended_at,
    duration_seconds=None,
    radius_status=None,
    disabled=None,
    profile=None,
    last_logged_out=None,
):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO offline_history (
                    pppoe, router_id, router_name, mode,
                    offline_started_at, offline_ended_at, duration_seconds,
                    radius_status, disabled, profile, last_logged_out
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pppoe,
                    (router_id or "").strip(),
                    (router_name or "").strip(),
                    (mode or "").strip(),
                    (offline_started_at or "").strip(),
                    (offline_ended_at or "").strip(),
                    int(duration_seconds) if duration_seconds is not None else None,
                    (radius_status or "").strip() if radius_status is not None else None,
                    bool(disabled) if disabled is not None else None,
                    (profile or "").strip() if profile is not None else None,
                    (last_logged_out or "").strip() if last_logged_out is not None else None,
                ),
            )
    finally:
        conn.close()


def get_offline_history_since(since_iso, limit=500):
    since_iso = (since_iso or "").strip()
    limit = max(min(int(limit or 500), 2000), 1)
    if not since_iso:
        return []
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                id, pppoe, router_id, router_name, mode,
                offline_started_at, offline_ended_at, duration_seconds,
                radius_status, disabled, profile, last_logged_out
            FROM offline_history
            WHERE offline_ended_at >= ?
            ORDER BY offline_ended_at DESC
            LIMIT ?
            """,
            (since_iso, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_offline_history_for_pppoe(pppoe, since_iso="", limit=20):
    pppoe = (pppoe or "").strip()
    since_iso = (since_iso or "").strip()
    limit = max(min(int(limit or 20), 200), 1)
    if not pppoe:
        return []
    conn = get_conn()
    try:
        if since_iso:
            rows = conn.execute(
                """
                SELECT
                    id, pppoe, router_id, router_name, mode,
                    offline_started_at, offline_ended_at, duration_seconds,
                    radius_status, disabled, profile, last_logged_out
                FROM offline_history
                WHERE lower(pppoe) = lower(?)
                  AND offline_ended_at >= ?
                ORDER BY offline_ended_at DESC
                LIMIT ?
                """,
                (pppoe, since_iso, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT
                    id, pppoe, router_id, router_name, mode,
                    offline_started_at, offline_ended_at, duration_seconds,
                    radius_status, disabled, profile, last_logged_out
                FROM offline_history
                WHERE lower(pppoe) = lower(?)
                ORDER BY offline_ended_at DESC
                LIMIT ?
                """,
                (pppoe, limit),
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def delete_offline_history_older_than(cutoff_iso):
    cutoff_iso = (cutoff_iso or "").strip()
    if not cutoff_iso:
        return
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM offline_history WHERE offline_ended_at < ?", (cutoff_iso,))
    finally:
        conn.close()


def clear_offline_history():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM offline_history")
    finally:
        conn.close()


def get_json(table, key, default):
    conn = get_conn()
    try:
        row = conn.execute(
            f"SELECT value FROM {table} WHERE key = ?",
            (key,),
        ).fetchone()
        if not row:
            return default
        return json.loads(row["value"])
    finally:
        conn.close()


def _get_active_surveillance_session(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT id, pppoe, source, started_at, ended_at, end_reason, end_note,
                   under_seconds, level2_seconds, observe_seconds,
                   observed_count, last_state, last_ip, updated_at
            FROM surveillance_sessions
            WHERE pppoe = ? AND ended_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (pppoe,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_active_surveillance_session(pppoe):
    return _get_active_surveillance_session(pppoe)


def _get_surveillance_observed_total(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return 0
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(observed_count), 0) AS c FROM surveillance_sessions WHERE pppoe = ?",
            (pppoe,),
        ).fetchone()
        if isinstance(row, dict):
            return int(row.get("c") or 0)
        return int(row["c"] or 0)
    except Exception:
        return 0
    finally:
        conn.close()


def ensure_surveillance_session(pppoe, started_at=None, source="", ip="", state="under"):
    """
    Ensures there is an active (non-ended) session for this PPPoE.
    Returns the active session row as a dict.
    """
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return None
    existing = _get_active_surveillance_session(pppoe)
    if existing:
        return existing
    now_iso = utc_now_iso()
    started_at = (started_at or "").strip() or now_iso
    state = (state or "under").strip().lower() or "under"
    if state not in ("under", "level2"):
        state = "under"
    observed_total = _get_surveillance_observed_total(pppoe)
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO surveillance_sessions (
                    pppoe, source, started_at, ended_at, end_reason, end_note,
                    under_seconds, level2_seconds, observe_seconds,
                    observed_count, last_state, last_ip, updated_at
                )
                VALUES (?, ?, ?, NULL, NULL, NULL, 0, 0, 0, ?, ?, ?, ?)
                """,
                (
                    pppoe,
                    (source or "").strip(),
                    started_at,
                    observed_total,
                    state,
                    (ip or "").strip(),
                    now_iso,
                ),
            )
    finally:
        conn.close()
    return _get_active_surveillance_session(pppoe)


def touch_surveillance_session(pppoe, source="", ip="", state=None):
    """
    Updates the active session's last_state/last_ip/source/updated_at.
    If no active session exists, it is created using now as started_at.
    """
    session = ensure_surveillance_session(pppoe, source=source, ip=ip, state=state or "under")
    if not session:
        return None
    session_id = session.get("id")
    if not session_id:
        return session
    now_iso = utc_now_iso()
    state = (state or session.get("last_state") or "under").strip().lower() or "under"
    if state not in ("under", "level2"):
        state = "under"
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE surveillance_sessions
                SET source = ?,
                    last_state = ?,
                    last_ip = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    (source or session.get("source") or "").strip(),
                    state,
                    (ip or session.get("last_ip") or "").strip(),
                    now_iso,
                    session_id,
                ),
            )
    finally:
        conn.close()
    return _get_active_surveillance_session(pppoe)


def increment_surveillance_observed(pppoe, started_at=None, source="", ip=""):
    """
    Increments observed_count for the active session and sets last_state to level2.
    If no active session exists, it is created using started_at (or now).
    """
    session = ensure_surveillance_session(pppoe, started_at=started_at, source=source, ip=ip, state="under")
    if not session:
        return None
    session_id = session.get("id")
    if not session_id:
        return session
    now_iso = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE surveillance_sessions
                SET observed_count = COALESCE(observed_count, 0) + 1,
                    source = ?,
                    last_state = 'level2',
                    last_ip = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    (source or session.get("source") or "").strip(),
                    (ip or session.get("last_ip") or "").strip(),
                    now_iso,
                    session_id,
                ),
            )
    finally:
        conn.close()
    return _get_active_surveillance_session(pppoe)


def end_surveillance_session(
    pppoe,
    end_reason,
    started_at=None,
    source="",
    ip="",
    state=None,
    note="",
    under_seconds=None,
    level2_seconds=None,
    observe_seconds=None,
):
    """
    Ends the active session, setting ended_at + end_reason.
    If no active session exists, it is created first (using started_at or now) then ended.
    """
    end_reason = (end_reason or "").strip().lower()
    if end_reason not in ("healed", "removed", "fixed", "false", "recovered"):
        end_reason = "removed"
    session = ensure_surveillance_session(pppoe, started_at=started_at, source=source, ip=ip, state="under")
    if not session:
        return None
    session_id = session.get("id")
    if not session_id:
        return session
    now_iso = utc_now_iso()
    state = (state or session.get("last_state") or "under").strip().lower() or "under"
    if state not in ("under", "level2"):
        state = session.get("last_state") or "under"
    try:
        under_seconds = int(session.get("under_seconds") if under_seconds is None else under_seconds)
    except Exception:
        under_seconds = 0
    try:
        level2_seconds = int(session.get("level2_seconds") if level2_seconds is None else level2_seconds)
    except Exception:
        level2_seconds = 0
    try:
        observe_seconds = int(session.get("observe_seconds") if observe_seconds is None else observe_seconds)
    except Exception:
        observe_seconds = 0
    under_seconds = max(0, under_seconds)
    level2_seconds = max(0, level2_seconds)
    observe_seconds = max(0, observe_seconds)
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE surveillance_sessions
                SET ended_at = ?,
                    end_reason = ?,
                    last_state = ?,
                    last_ip = ?,
                    source = ?,
                    end_note = ?,
                    under_seconds = ?,
                    level2_seconds = ?,
                    observe_seconds = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    now_iso,
                    end_reason,
                    state,
                    (ip or session.get("last_ip") or "").strip(),
                    (source or session.get("source") or "").strip(),
                    (note or "").strip(),
                    under_seconds,
                    level2_seconds,
                    observe_seconds,
                    now_iso,
                    session_id,
                ),
            )
    finally:
        conn.close()
    return None


def list_surveillance_sessions(query="", page=1, limit=50):
    try:
        page = int(page or 1)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    try:
        limit = int(limit or 50)
    except Exception:
        limit = 50
    if limit < 1:
        limit = 50
    if limit > 500:
        limit = 500
    query = (query or "").strip().lower()
    params = []
    where = ""
    if query:
        where = "WHERE lower(pppoe) LIKE ?"
        params.append(f"%{query}%")
    offset = (page - 1) * limit
    conn = get_conn()
    try:
        count_row = conn.execute(
            f"SELECT COUNT(*) AS c FROM surveillance_sessions {where}",
            tuple(params),
        ).fetchone()
        if isinstance(count_row, dict):
            total = int(count_row.get("c") or 0)
        else:
            total = int(count_row["c"] or 0)
        rows = conn.execute(
            f"""
            SELECT id, pppoe, source, started_at, ended_at, end_reason, end_note,
                   under_seconds, level2_seconds, observe_seconds,
                   observed_count, last_state, last_ip, updated_at
            FROM surveillance_sessions
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit, offset]),
        ).fetchall()
        out = [dict(row) for row in rows] if rows else []
        return {"rows": out, "total": total, "page": page, "limit": limit}
    finally:
        conn.close()


def list_surveillance_history(query="", page=1, limit=50, end_reason=""):
    """
    History is only sessions that have ended (removed/healed/fixed/false/recovered).
    """
    try:
        page = int(page or 1)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    try:
        limit = int(limit or 50)
    except Exception:
        limit = 50
    if limit < 1:
        limit = 50
    if limit > 500:
        limit = 500
    query = (query or "").strip().lower()
    end_reason = (end_reason or "").strip().lower()
    if end_reason in ("all", "any"):
        end_reason = ""
    if end_reason and end_reason not in ("healed", "removed", "fixed", "false", "recovered"):
        end_reason = ""
    params = []
    where_parts = ["ended_at IS NOT NULL"]
    if query:
        where_parts.append("lower(pppoe) LIKE ?")
        params.append(f"%{query}%")
    if end_reason:
        where_parts.append("end_reason = ?")
        params.append(end_reason)
    where = "WHERE " + " AND ".join(where_parts)
    offset = (page - 1) * limit
    conn = get_conn()
    try:
        count_row = conn.execute(
            f"SELECT COUNT(*) AS c FROM surveillance_sessions {where}",
            tuple(params),
        ).fetchone()
        if isinstance(count_row, dict):
            total = int(count_row.get("c") or 0)
        else:
            total = int(count_row["c"] or 0)
        rows = conn.execute(
            f"""
            SELECT id, pppoe, source, started_at, ended_at, end_reason, end_note,
                   under_seconds, level2_seconds, observe_seconds,
                   observed_count, last_state, last_ip, updated_at
            FROM surveillance_sessions
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit, offset]),
        ).fetchall()
        out = [dict(row) for row in rows] if rows else []
        return {"rows": out, "total": total, "page": page, "limit": limit}
    finally:
        conn.close()


def get_surveillance_session_by_id(session_id):
    try:
        session_id = int(session_id or 0)
    except Exception:
        session_id = 0
    if session_id <= 0:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT id, pppoe, source, started_at, ended_at, end_reason, end_note,
                   under_seconds, level2_seconds, observe_seconds,
                   observed_count, last_state, last_ip, updated_at
            FROM surveillance_sessions
            WHERE id = ?
            LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_surveillance_fixed_cycles_map(pppoes, limit_per_pppoe=0):
    values = []
    seen = set()
    for raw in pppoes or []:
        pppoe = (raw or "").strip()
        if not pppoe:
            continue
        key = pppoe.lower()
        if key in seen:
            continue
        seen.add(key)
        values.append(pppoe)
    if not values:
        return {}

    try:
        limit_per_pppoe = int(limit_per_pppoe or 0)
    except Exception:
        limit_per_pppoe = 0
    if limit_per_pppoe < 0:
        limit_per_pppoe = 0

    conn = get_conn()
    try:
        placeholders = ",".join(["?"] * len(values))
        rows = conn.execute(
            f"""
            SELECT pppoe, started_at, ended_at, end_note
            FROM surveillance_sessions
            WHERE ended_at IS NOT NULL
              AND end_reason = 'fixed'
              AND pppoe IN ({placeholders})
            ORDER BY pppoe ASC, ended_at DESC, id DESC
            """,
            tuple(values),
        ).fetchall()
        out = {}
        for row in rows or []:
            item = dict(row)
            pppoe = (item.get("pppoe") or "").strip()
            if not pppoe:
                continue
            bucket = out.setdefault(pppoe, [])
            if limit_per_pppoe > 0 and len(bucket) >= limit_per_pppoe:
                continue
            bucket.append(item)
        return out
    finally:
        conn.close()


def get_latest_surveillance_fixed_cycle_map(pppoes):
    cycles_map = get_surveillance_fixed_cycles_map(pppoes, limit_per_pppoe=1)
    out = {}
    for pppoe, rows in (cycles_map or {}).items():
        if not rows:
            continue
        row = rows[0] or {}
        out[pppoe] = {
            "started_at": (row.get("started_at") or "").strip(),
            "ended_at": (row.get("ended_at") or "").strip(),
        }
    return out


def set_json(table, key, value):
    payload = json.dumps(value, ensure_ascii=True)
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                f"INSERT INTO {table} (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, payload),
            )
    finally:
        conn.close()


def update_job_status(job_name, last_run_at=None, last_success_at=None, last_error=None, last_error_at=None):
    conn = get_conn()
    try:
        existing = conn.execute(
            "SELECT * FROM job_status WHERE job_name = ?",
            (job_name,),
        ).fetchone()
        payload = {
            "last_run_at": existing["last_run_at"] if existing else None,
            "last_success_at": existing["last_success_at"] if existing else None,
            "last_error": existing["last_error"] if existing else None,
            "last_error_at": existing["last_error_at"] if existing else None,
        }
        if last_run_at is not None:
            payload["last_run_at"] = last_run_at
        if last_success_at is not None:
            payload["last_success_at"] = last_success_at
        if last_error is not None:
            payload["last_error"] = last_error
        if last_error_at is not None:
            payload["last_error_at"] = last_error_at

        with conn:
            conn.execute(
                """
                INSERT INTO job_status (job_name, last_run_at, last_success_at, last_error, last_error_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(job_name) DO UPDATE SET
                    last_run_at = excluded.last_run_at,
                    last_success_at = excluded.last_success_at,
                    last_error = excluded.last_error,
                    last_error_at = excluded.last_error_at
                """,
                (
                    job_name,
                    payload["last_run_at"],
                    payload["last_success_at"],
                    payload["last_error"],
                    payload["last_error_at"],
                ),
            )
    finally:
        conn.close()


def get_job_status():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM job_status").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _bucket_ts_iso(timestamp, bucket_seconds=60):
    raw = str(timestamp).strip()
    if raw.endswith("Z"):
        raw = raw[:-1]
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    bucket = int(dt.timestamp() // max(int(bucket_seconds), 1)) * max(int(bucket_seconds), 1)
    return datetime.fromtimestamp(bucket, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_all_settings():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}
    finally:
        conn.close()


def fetch_all_state():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT key, value FROM state").fetchall()
        return {row["key"]: row["value"] for row in rows}
    finally:
        conn.close()


def _parse_iso_utc(value):
    text = (value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None


def count_auth_users():
    conn = get_conn()
    try:
        row = conn.execute("SELECT COUNT(*) AS c FROM auth_users").fetchone()
        return int(_row_get(row, "c", 0) or 0)
    finally:
        conn.close()


def list_auth_permissions():
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT id, code, label, description, created_at
            FROM auth_permissions
            ORDER BY lower(code) ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def create_auth_permission(code, label="", description=""):
    code = (code or "").strip()
    if not code:
        raise ValueError("Permission code is required.")
    if len(code) > 120:
        raise ValueError("Permission code is too long.")
    label = (label or code).strip()
    description = (description or "").strip()
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            row = conn.execute("SELECT id FROM auth_permissions WHERE lower(code) = lower(?) LIMIT 1", (code,)).fetchone()
            if row:
                raise ValueError("Permission already exists.")
            conn.execute(
                """
                INSERT INTO auth_permissions (code, label, description, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (code, label, description, now),
            )
    finally:
        conn.close()


def get_auth_role_by_name(name):
    name = (name or "").strip()
    if not name:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT id, name, description, is_builtin, created_at, updated_at
            FROM auth_roles
            WHERE lower(name) = lower(?)
            LIMIT 1
            """,
            (name,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_auth_role_by_id(role_id):
    try:
        role_id = int(role_id or 0)
    except Exception:
        role_id = 0
    if role_id <= 0:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT id, name, description, is_builtin, created_at, updated_at
            FROM auth_roles
            WHERE id = ?
            LIMIT 1
            """,
            (role_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_auth_role_permission_codes(role_id):
    try:
        role_id = int(role_id or 0)
    except Exception:
        role_id = 0
    if role_id <= 0:
        return set()
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT p.code
            FROM auth_role_permissions rp
            JOIN auth_permissions p ON p.id = rp.permission_id
            WHERE rp.role_id = ?
            """,
            (role_id,),
        ).fetchall()
        return {str(_row_get(row, "code", "") or "").strip() for row in rows if str(_row_get(row, "code", "") or "").strip()}
    finally:
        conn.close()


def list_auth_roles(include_permissions=True):
    conn = get_conn()
    try:
        roles = conn.execute(
            """
            SELECT id, name, description, is_builtin, created_at, updated_at
            FROM auth_roles
            ORDER BY lower(name) ASC
            """
        ).fetchall()
        out = []
        for role in roles:
            item = dict(role)
            if include_permissions:
                item["permission_codes"] = sorted(get_auth_role_permission_codes(item.get("id")))
            out.append(item)
        return out
    finally:
        conn.close()


def create_auth_role(name, description="", permission_codes=None):
    name = (name or "").strip().lower()
    if not name:
        raise ValueError("Role name is required.")
    if len(name) > 80:
        raise ValueError("Role name is too long.")
    description = (description or "").strip()
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            exists = conn.execute("SELECT 1 AS ok FROM auth_roles WHERE lower(name) = lower(?) LIMIT 1", (name,)).fetchone()
            if exists:
                raise ValueError("Role already exists.")
            conn.execute(
                """
                INSERT INTO auth_roles (name, description, is_builtin, created_at, updated_at)
                VALUES (?, ?, 0, ?, ?)
                """,
                (name, description, now, now),
            )
            row = conn.execute("SELECT id FROM auth_roles WHERE lower(name) = lower(?) LIMIT 1", (name,)).fetchone()
            role_id = int(_row_get(row, "id", 0) or 0)
            if role_id > 0:
                _set_auth_role_permissions_with_conn(conn, role_id, permission_codes or [])
            return role_id
    finally:
        conn.close()


def update_auth_role(role_id, name, description=""):
    try:
        role_id = int(role_id or 0)
    except Exception:
        role_id = 0
    if role_id <= 0:
        raise ValueError("Invalid role.")
    name = (name or "").strip().lower()
    if not name:
        raise ValueError("Role name is required.")
    description = (description or "").strip()
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            role = conn.execute(
                "SELECT id, name, is_builtin FROM auth_roles WHERE id = ? LIMIT 1",
                (role_id,),
            ).fetchone()
            if not role:
                raise ValueError("Role not found.")
            role_name = str(_row_get(role, "name", "") or "").strip().lower()
            if role_name == "owner":
                raise ValueError("Owner role is locked and cannot be edited.")
            existing = conn.execute(
                "SELECT id FROM auth_roles WHERE lower(name) = lower(?) AND id <> ? LIMIT 1",
                (name, role_id),
            ).fetchone()
            if existing:
                raise ValueError("Role name already in use.")
            conn.execute(
                """
                UPDATE auth_roles
                SET name = ?, description = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, description, now, role_id),
            )
    finally:
        conn.close()


def _set_auth_role_permissions_with_conn(conn, role_id, permission_codes):
    try:
        role_id = int(role_id or 0)
    except Exception:
        role_id = 0
    if role_id <= 0:
        return
    cleaned = []
    seen = set()
    for code in permission_codes or []:
        value = (code or "").strip()
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        cleaned.append(value)
    conn.execute("DELETE FROM auth_role_permissions WHERE role_id = ?", (role_id,))
    if not cleaned:
        return
    rows = conn.execute("SELECT id, code FROM auth_permissions").fetchall()
    by_lower = {}
    for row in rows or []:
        code = str(_row_get(row, "code", "") or "").strip()
        permission_id = _row_get(row, "id")
        if not code or permission_id is None:
            continue
        by_lower[code.lower()] = int(permission_id)
    for value in cleaned:
        permission_id = by_lower.get(value.lower())
        if permission_id is None:
            continue
        conn.execute(
            """
            INSERT INTO auth_role_permissions (role_id, permission_id)
            VALUES (?, ?)
            """,
            (role_id, int(permission_id)),
        )


def set_auth_role_permissions(role_id, permission_codes):
    conn = get_conn()
    try:
        with conn:
            role = conn.execute(
                "SELECT id, name FROM auth_roles WHERE id = ? LIMIT 1",
                (int(role_id or 0),),
            ).fetchone()
            if not role:
                raise ValueError("Role not found.")
            role_name = str(_row_get(role, "name", "") or "").strip().lower()
            if role_name == "owner":
                raise ValueError("Owner role permissions are locked.")
            _set_auth_role_permissions_with_conn(conn, int(_row_get(role, "id", 0) or 0), permission_codes)
    finally:
        conn.close()


def delete_auth_role(role_id):
    try:
        role_id = int(role_id or 0)
    except Exception:
        role_id = 0
    if role_id <= 0:
        raise ValueError("Invalid role.")
    conn = get_conn()
    try:
        with conn:
            role = conn.execute(
                "SELECT id, name, is_builtin FROM auth_roles WHERE id = ? LIMIT 1",
                (role_id,),
            ).fetchone()
            if not role:
                raise ValueError("Role not found.")
            if str(_row_get(role, "name", "") or "").strip().lower() == "owner":
                raise ValueError("Owner role cannot be deleted.")
            if int(_row_get(role, "is_builtin", 0) or 0) == 1:
                raise ValueError("Built-in roles cannot be deleted.")
            users_row = conn.execute(
                "SELECT COUNT(*) AS c FROM auth_users WHERE role_id = ?",
                (role_id,),
            ).fetchone()
            if int(_row_get(users_row, "c", 0) or 0) > 0:
                raise ValueError("Role is assigned to one or more users.")
            conn.execute("DELETE FROM auth_role_permissions WHERE role_id = ?", (role_id,))
            conn.execute("DELETE FROM auth_roles WHERE id = ?", (role_id,))
    finally:
        conn.close()


def list_auth_users():
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                u.id, u.username, u.email, u.full_name, u.role_id,
                u.must_change_password, u.is_active, u.last_login_at,
                u.created_at, u.updated_at,
                r.name AS role_name
            FROM auth_users u
            LEFT JOIN auth_roles r ON r.id = u.role_id
            ORDER BY lower(u.username) ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_auth_user_by_id(user_id):
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT
                u.id, u.username, u.email, u.full_name, u.role_id,
                u.password_hash, u.password_salt,
                u.must_change_password, u.is_active, u.last_login_at,
                u.created_at, u.updated_at,
                r.name AS role_name
            FROM auth_users u
            LEFT JOIN auth_roles r ON r.id = u.role_id
            WHERE u.id = ?
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_auth_user_by_username(username):
    username = (username or "").strip()
    if not username:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT
                u.id, u.username, u.email, u.full_name, u.role_id,
                u.password_hash, u.password_salt,
                u.must_change_password, u.is_active, u.last_login_at,
                u.created_at, u.updated_at,
                r.name AS role_name
            FROM auth_users u
            LEFT JOIN auth_roles r ON r.id = u.role_id
            WHERE lower(u.username) = lower(?)
            LIMIT 1
            """,
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_auth_user_by_email(email):
    email = (email or "").strip().lower()
    if not email:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT
                u.id, u.username, u.email, u.full_name, u.role_id,
                u.password_hash, u.password_salt,
                u.must_change_password, u.is_active, u.last_login_at,
                u.created_at, u.updated_at,
                r.name AS role_name
            FROM auth_users u
            LEFT JOIN auth_roles r ON r.id = u.role_id
            WHERE lower(u.email) = lower(?)
            LIMIT 1
            """,
            (email,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_auth_user(
    username,
    email,
    full_name,
    role_id,
    password_hash,
    password_salt,
    must_change_password=False,
    is_active=True,
):
    username = (username or "").strip()
    if not username:
        raise ValueError("Username is required.")
    email = (email or "").strip().lower()
    full_name = (full_name or "").strip()
    try:
        role_id = int(role_id or 0)
    except Exception:
        role_id = 0
    if role_id <= 0:
        raise ValueError("Role is required.")
    password_hash = (password_hash or "").strip()
    password_salt = (password_salt or "").strip()
    if not password_hash or not password_salt:
        raise ValueError("Password hash is required.")
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            role = conn.execute("SELECT id FROM auth_roles WHERE id = ? LIMIT 1", (role_id,)).fetchone()
            if not role:
                raise ValueError("Role not found.")
            if conn.execute("SELECT 1 AS ok FROM auth_users WHERE lower(username) = lower(?) LIMIT 1", (username,)).fetchone():
                raise ValueError("Username already exists.")
            if email and conn.execute("SELECT 1 AS ok FROM auth_users WHERE lower(email) = lower(?) LIMIT 1", (email,)).fetchone():
                raise ValueError("Email already exists.")
            conn.execute(
                """
                INSERT INTO auth_users (
                    username, email, full_name, role_id,
                    password_hash, password_salt,
                    must_change_password, is_active,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    email,
                    full_name,
                    role_id,
                    password_hash,
                    password_salt,
                    1 if must_change_password else 0,
                    1 if is_active else 0,
                    now,
                    now,
                ),
            )
            row = conn.execute("SELECT id FROM auth_users WHERE lower(username) = lower(?) LIMIT 1", (username,)).fetchone()
            return int(_row_get(row, "id", 0) or 0)
    finally:
        conn.close()


def update_auth_user(user_id, email, full_name, role_id, is_active=True):
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        raise ValueError("Invalid user.")
    email = (email or "").strip().lower()
    full_name = (full_name or "").strip()
    try:
        role_id = int(role_id or 0)
    except Exception:
        role_id = 0
    if role_id <= 0:
        raise ValueError("Role is required.")
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            user = conn.execute("SELECT id FROM auth_users WHERE id = ? LIMIT 1", (user_id,)).fetchone()
            if not user:
                raise ValueError("User not found.")
            role = conn.execute("SELECT id FROM auth_roles WHERE id = ? LIMIT 1", (role_id,)).fetchone()
            if not role:
                raise ValueError("Role not found.")
            if email:
                exists = conn.execute(
                    "SELECT id FROM auth_users WHERE lower(email) = lower(?) AND id <> ? LIMIT 1",
                    (email, user_id),
                ).fetchone()
                if exists:
                    raise ValueError("Email already used by another user.")
            conn.execute(
                """
                UPDATE auth_users
                SET email = ?, full_name = ?, role_id = ?, is_active = ?, updated_at = ?
                WHERE id = ?
                """,
                (email, full_name, role_id, 1 if is_active else 0, now, user_id),
            )
    finally:
        conn.close()


def delete_auth_user(user_id):
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        raise ValueError("Invalid user.")
    conn = get_conn()
    try:
        with conn:
            user = conn.execute("SELECT id FROM auth_users WHERE id = ? LIMIT 1", (user_id,)).fetchone()
            if not user:
                raise ValueError("User not found.")
            conn.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM auth_users WHERE id = ?", (user_id,))
    finally:
        conn.close()


def set_auth_user_password(user_id, password_hash, password_salt, must_change_password=False):
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        raise ValueError("Invalid user.")
    password_hash = (password_hash or "").strip()
    password_salt = (password_salt or "").strip()
    if not password_hash or not password_salt:
        raise ValueError("Password hash is required.")
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE auth_users
                SET password_hash = ?, password_salt = ?, must_change_password = ?, updated_at = ?
                WHERE id = ?
                """,
                (password_hash, password_salt, 1 if must_change_password else 0, now, user_id),
            )
    finally:
        conn.close()


def touch_auth_user_login(user_id, at_iso=None):
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        return
    at_iso = (at_iso or "").strip() or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE auth_users
                SET last_login_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (at_iso, at_iso, user_id),
            )
    finally:
        conn.close()


def create_auth_session(token_hash, user_id, created_at=None, expires_at=None, ip_address="", user_agent=""):
    token_hash = (token_hash or "").strip()
    if not token_hash:
        raise ValueError("Session token hash is required.")
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        raise ValueError("Invalid user.")
    created_at = (created_at or "").strip() or utc_now_iso()
    expires_at = (expires_at or "").strip()
    ip_address = (ip_address or "").strip()
    user_agent = (user_agent or "").strip()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO auth_sessions (
                    session_token_hash, user_id, created_at, last_seen_at, expires_at, ip_address, user_agent, revoked_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (token_hash, user_id, created_at, created_at, expires_at or None, ip_address, user_agent),
            )
    finally:
        conn.close()


def revoke_auth_session(token_hash):
    token_hash = (token_hash or "").strip()
    if not token_hash:
        return
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE session_token_hash = ? AND revoked_at IS NULL
                """,
                (now, token_hash),
            )
    finally:
        conn.close()


def revoke_auth_sessions_for_user(user_id):
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        return
    now = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (now, user_id),
            )
    finally:
        conn.close()


def get_auth_session(token_hash):
    token_hash = (token_hash or "").strip()
    if not token_hash:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT
                s.id AS session_id,
                s.session_token_hash,
                s.user_id,
                s.created_at,
                s.last_seen_at,
                s.expires_at,
                s.ip_address,
                s.user_agent,
                s.revoked_at,
                u.username,
                u.email,
                u.full_name,
                u.role_id,
                u.password_hash,
                u.password_salt,
                u.must_change_password,
                u.is_active,
                u.last_login_at,
                r.name AS role_name
            FROM auth_sessions s
            JOIN auth_users u ON u.id = s.user_id
            LEFT JOIN auth_roles r ON r.id = u.role_id
            WHERE s.session_token_hash = ?
              AND s.revoked_at IS NULL
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def touch_auth_session(session_id, at_iso=None, ip_address=None, user_agent=None):
    try:
        session_id = int(session_id or 0)
    except Exception:
        session_id = 0
    if session_id <= 0:
        return
    at_iso = (at_iso or "").strip() or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            if ip_address is None and user_agent is None:
                conn.execute(
                    "UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?",
                    (at_iso, session_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE auth_sessions
                    SET last_seen_at = ?,
                        ip_address = COALESCE(?, ip_address),
                        user_agent = COALESCE(?, user_agent)
                    WHERE id = ?
                    """,
                    (
                        at_iso,
                        (ip_address or "").strip() if ip_address is not None else None,
                        (user_agent or "").strip() if user_agent is not None else None,
                        session_id,
                    ),
                )
    finally:
        conn.close()


def get_auth_user_permission_codes(user_id):
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        return set()
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT DISTINCT p.code
            FROM auth_users u
            JOIN auth_role_permissions rp ON rp.role_id = u.role_id
            JOIN auth_permissions p ON p.id = rp.permission_id
            WHERE u.id = ?
            """,
            (user_id,),
        ).fetchall()
        return {str(_row_get(row, "code", "") or "").strip() for row in rows if str(_row_get(row, "code", "") or "").strip()}
    finally:
        conn.close()


def insert_auth_audit_log(timestamp, user_id, username, action, resource="", details="", ip_address=""):
    timestamp = (timestamp or "").strip() or utc_now_iso()
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0
    username = (username or "").strip()
    action = (action or "").strip()
    if not action:
        return
    resource = (resource or "").strip()
    details = (details or "").strip()
    ip_address = (ip_address or "").strip()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO auth_audit_logs (timestamp, user_id, username, action, resource, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, user_id if user_id > 0 else None, username or None, action, resource or None, details or None, ip_address or None),
            )
    finally:
        conn.close()


def list_auth_audit_logs(limit=200):
    try:
        limit = int(limit or 200)
    except Exception:
        limit = 200
    limit = max(1, min(limit, 20000))
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT id, timestamp, user_id, username, action, resource, details, ip_address
            FROM auth_audit_logs
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def delete_auth_audit_logs_older_than(cutoff_iso):
    cutoff_iso = (cutoff_iso or "").strip()
    if not cutoff_iso:
        return
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM auth_audit_logs WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def insert_accounts_ping_result(
    account_id,
    name,
    ip,
    loss,
    min_ms,
    avg_ms,
    max_ms,
    ok,
    mode="normal",
    timestamp=None,
    bucket_seconds=60,
):
    stamp = timestamp or utc_now_iso()
    bucket_ts = _bucket_ts_iso(stamp, bucket_seconds=bucket_seconds)
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO accounts_ping_results (timestamp, account_id, name, ip, loss, min_ms, avg_ms, max_ms, mode, ok)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (stamp, account_id, name, ip, loss, min_ms, avg_ms, max_ms, mode, 1 if ok else 0),
            )
            avg_sum = float(avg_ms) if avg_ms is not None else 0.0
            avg_count = 1 if avg_ms is not None else 0
            loss_sum = float(loss) if loss is not None else 0.0
            loss_count = 1 if loss is not None else 0
            ok_count = 1 if ok else 0
            if _use_postgres():
                conn.execute(
                    """
                    INSERT INTO accounts_ping_rollups (
                        bucket_ts, account_id, ip, sample_count, ok_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket_ts, account_id) DO UPDATE SET
                        ip = excluded.ip,
                        sample_count = accounts_ping_rollups.sample_count + 1,
                        ok_count = accounts_ping_rollups.ok_count + excluded.ok_count,
                        avg_sum = accounts_ping_rollups.avg_sum + excluded.avg_sum,
                        avg_count = accounts_ping_rollups.avg_count + excluded.avg_count,
                        loss_sum = accounts_ping_rollups.loss_sum + excluded.loss_sum,
                        loss_count = accounts_ping_rollups.loss_count + excluded.loss_count,
                        min_ms = CASE
                            WHEN accounts_ping_rollups.min_ms IS NULL THEN excluded.min_ms
                            WHEN excluded.min_ms IS NULL THEN accounts_ping_rollups.min_ms
                            ELSE LEAST(accounts_ping_rollups.min_ms, excluded.min_ms)
                        END,
                        max_ms = CASE
                            WHEN accounts_ping_rollups.max_ms IS NULL THEN excluded.max_ms
                            WHEN excluded.max_ms IS NULL THEN accounts_ping_rollups.max_ms
                            ELSE GREATEST(accounts_ping_rollups.max_ms, excluded.max_ms)
                        END,
                        max_avg_ms = CASE
                            WHEN accounts_ping_rollups.max_avg_ms IS NULL THEN excluded.max_avg_ms
                            WHEN excluded.max_avg_ms IS NULL THEN accounts_ping_rollups.max_avg_ms
                            ELSE GREATEST(accounts_ping_rollups.max_avg_ms, excluded.max_avg_ms)
                        END
                    """,
                    (
                        bucket_ts,
                        account_id,
                        ip,
                        ok_count,
                        avg_sum,
                        avg_count,
                        loss_sum,
                        loss_count,
                        min_ms,
                        max_ms,
                        avg_ms,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO accounts_ping_rollups (
                        bucket_ts, account_id, ip, sample_count, ok_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket_ts, account_id) DO UPDATE SET
                        sample_count = sample_count + 1,
                        ok_count = ok_count + excluded.ok_count,
                        avg_sum = avg_sum + excluded.avg_sum,
                        avg_count = avg_count + excluded.avg_count,
                        loss_sum = loss_sum + excluded.loss_sum,
                        loss_count = loss_count + excluded.loss_count,
                        min_ms = CASE
                            WHEN min_ms IS NULL THEN excluded.min_ms
                            WHEN excluded.min_ms IS NULL THEN min_ms
                            ELSE MIN(min_ms, excluded.min_ms)
                        END,
                        max_ms = CASE
                            WHEN max_ms IS NULL THEN excluded.max_ms
                            WHEN excluded.max_ms IS NULL THEN max_ms
                            ELSE MAX(max_ms, excluded.max_ms)
                        END,
                        max_avg_ms = CASE
                            WHEN max_avg_ms IS NULL THEN excluded.max_avg_ms
                            WHEN excluded.max_avg_ms IS NULL THEN max_avg_ms
                            ELSE MAX(max_avg_ms, excluded.max_avg_ms)
                        END
                    """,
                    (
                        bucket_ts,
                        account_id,
                        ip,
                        ok_count,
                        avg_sum,
                        avg_count,
                        loss_sum,
                        loss_count,
                        min_ms,
                        max_ms,
                        avg_ms,
                    ),
                )
    finally:
        conn.close()


def delete_accounts_ping_raw_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM accounts_ping_results WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def delete_accounts_ping_rollups_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM accounts_ping_rollups WHERE bucket_ts < ?", (cutoff_iso,))
    finally:
        conn.close()


def get_accounts_ping_series(account_id, since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, ip, loss, min_ms, avg_ms, max_ms, ok, mode
            FROM accounts_ping_results
            WHERE account_id = ? AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (account_id, since_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_series_range(account_id, since_iso, until_iso):
    if not account_id:
        return []
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, ip, loss, min_ms, avg_ms, max_ms, ok, mode
            FROM accounts_ping_results
            WHERE account_id = ? AND timestamp >= ? AND timestamp < ?
            ORDER BY timestamp ASC
            """,
            (account_id, since_iso, until_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_latest_ip_since(account_id, since_iso):
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT ip
            FROM accounts_ping_results
            WHERE account_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (account_id, since_iso),
        ).fetchone()
        return row["ip"] if row and row.get("ip") else ""
    finally:
        conn.close()


def get_accounts_ping_results_since(since_iso, account_ids=None):
    conn = get_conn()
    try:
        params = [since_iso]
        account_clause = ""
        if account_ids:
            placeholders = ",".join("?" for _ in account_ids)
            account_clause = f"AND account_id IN ({placeholders})"
            params.extend(list(account_ids))
        rows = conn.execute(
            f"""
            SELECT timestamp, account_id, ip, ok
            FROM accounts_ping_results
            WHERE timestamp >= ? {account_clause}
            ORDER BY timestamp ASC
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_rollups_since(since_iso, account_ids=None):
    conn = get_conn()
    try:
        params = [since_iso]
        account_clause = ""
        if account_ids:
            if _use_postgres():
                rows = conn.execute(
                    """
                    SELECT bucket_ts, account_id, ip, sample_count, ok_count
                    FROM accounts_ping_rollups
                    WHERE bucket_ts >= ? AND account_id = ANY(?)
                    ORDER BY bucket_ts ASC
                    """,
                    (since_iso, list(account_ids)),
                ).fetchall()
                return [dict(row) for row in rows]
            placeholders = ",".join("?" for _ in account_ids)
            account_clause = f"AND account_id IN ({placeholders})"
            params.extend(list(account_ids))
        rows = conn.execute(
            f"""
            SELECT bucket_ts, account_id, ip, sample_count, ok_count
            FROM accounts_ping_rollups
            WHERE bucket_ts >= ? {account_clause}
            ORDER BY bucket_ts ASC
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_rollups_range(account_id, since_iso, until_iso):
    if not account_id:
        return []
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT bucket_ts, account_id, ip, sample_count, ok_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
            FROM accounts_ping_rollups
            WHERE account_id = ? AND bucket_ts >= ? AND bucket_ts < ?
            ORDER BY bucket_ts ASC
            """,
            (account_id, since_iso, until_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_downtime_minutes_map(account_ids, since_iso, until_iso):
    """
    Returns a map of account_id -> downtime_minutes within the given window.

    Downtime minutes are counted from minute rollups where Loss% is 100%.
    (loss_pct = loss_sum / loss_count >= 99.999)
    """
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            SELECT
                account_id,
                SUM(CASE
                    WHEN loss_count > 0 AND (loss_sum / loss_count) >= 99.999 THEN 1
                    ELSE 0
                END) AS downtime_minutes
            FROM accounts_ping_rollups
            WHERE bucket_ts >= ? AND bucket_ts < ? AND account_id IN ({placeholders})
            GROUP BY account_id
            """,
            tuple([since_iso, until_iso] + list(account_ids)),
        ).fetchall()
        out = {}
        for row in rows or []:
            d = dict(row) if not isinstance(row, dict) else row
            aid = (d.get("account_id") or "").strip()
            if not aid:
                continue
            try:
                out[aid] = int(d.get("downtime_minutes") or 0)
            except Exception:
                out[aid] = 0
        return out
    finally:
        conn.close()


def get_accounts_ping_down_events_map(account_ids, since_iso, until_iso):
    """
    Returns a map of account_id -> down_events within the given window.

    A down event is counted at the start of a contiguous down streak:
    - current minute bucket has Loss% = 100% (>= 99.999)
    - previous minute bucket was not 100% (or does not exist)
    """
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            WITH w AS (
              SELECT
                account_id,
                bucket_ts,
                CASE
                  WHEN loss_count > 0 AND (loss_sum / loss_count) >= 99.999 THEN 1
                  ELSE 0
                END AS is_down,
                LAG(
                  CASE
                    WHEN loss_count > 0 AND (loss_sum / loss_count) >= 99.999 THEN 1
                    ELSE 0
                  END
                ) OVER (PARTITION BY account_id ORDER BY bucket_ts) AS prev_down
              FROM accounts_ping_rollups
              WHERE bucket_ts >= ? AND bucket_ts < ? AND account_id IN ({placeholders})
            )
            SELECT
              account_id,
              SUM(CASE WHEN is_down = 1 AND COALESCE(prev_down, 0) = 0 THEN 1 ELSE 0 END) AS down_events
            FROM w
            GROUP BY account_id
            """,
            tuple([since_iso, until_iso] + list(account_ids)),
        ).fetchall()
        out = {}
        for row in rows or []:
            d = dict(row) if not isinstance(row, dict) else row
            aid = (d.get("account_id") or "").strip()
            if not aid:
                continue
            try:
                out[aid] = int(d.get("down_events") or 0)
            except Exception:
                out[aid] = 0
        return out
    finally:
        conn.close()


def get_latest_accounts_ping_map(account_ids):
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            unique_account_ids = []
            seen = set()
            for account_id in account_ids:
                account_id = (account_id or "").strip()
                if not account_id or account_id in seen:
                    continue
                seen.add(account_id)
                unique_account_ids.append(account_id)
            if not unique_account_ids:
                return {}

            placeholders = ",".join("(?)" for _ in unique_account_ids)
            rows = conn.execute(
                f"""
                SELECT
                    a.account_id,
                    r.timestamp,
                    r.name,
                    r.ip,
                    r.loss,
                    r.min_ms,
                    r.avg_ms,
                    r.max_ms,
                    r.mode,
                    r.ok
                FROM (VALUES {placeholders}) AS a(account_id)
                JOIN LATERAL (
                    SELECT timestamp, name, ip, loss, min_ms, avg_ms, max_ms, mode, ok
                    FROM accounts_ping_results
                    WHERE account_id = a.account_id
                    ORDER BY timestamp DESC
                    LIMIT 1
                ) AS r ON TRUE
                """,
                unique_account_ids,
            ).fetchall()
            return {row["account_id"]: dict(row) for row in rows}

        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            SELECT r.*
            FROM accounts_ping_results r
            JOIN (
                SELECT account_id, MAX(timestamp) AS max_ts
                FROM accounts_ping_results
                WHERE account_id IN ({placeholders})
                GROUP BY account_id
            ) latest
              ON r.account_id = latest.account_id AND r.timestamp = latest.max_ts
            """,
            list(account_ids),
        ).fetchall()
        return {row["account_id"]: dict(row) for row in rows}
    finally:
        conn.close()


def has_surveillance_session(pppoe: str) -> bool:
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return False
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT 1 AS ok FROM surveillance_sessions WHERE pppoe = ? LIMIT 1",
            (pppoe,),
        ).fetchone()
        if isinstance(row, dict):
            return bool(row.get("ok"))
        return bool(row)
    finally:
        conn.close()


def get_accounts_ping_window_stats(account_ids, since_iso):
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT
                  account_id,
                  SUM(sample_count) AS total,
                  SUM(sample_count - ok_count) AS failures,
                  CASE
                    WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                    ELSE NULL
                  END AS loss_avg,
                  CASE
                    WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                    ELSE NULL
                  END AS avg_ms_avg
                FROM accounts_ping_rollups
                WHERE bucket_ts >= ? AND account_id = ANY(?)
                GROUP BY account_id
                """,
                (since_iso, list(account_ids)),
            ).fetchall()
            return {row["account_id"]: dict(row) for row in rows}

        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            SELECT
              account_id,
              SUM(sample_count) AS total,
              SUM(sample_count - ok_count) AS failures,
              CASE
                WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                ELSE NULL
              END AS loss_avg,
              CASE
                WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                ELSE NULL
              END AS avg_ms_avg
            FROM accounts_ping_rollups
            WHERE bucket_ts >= ? AND account_id IN ({placeholders})
            GROUP BY account_id
            """,
            [since_iso] + list(account_ids),
        ).fetchall()
        return {row["account_id"]: dict(row) for row in rows}
    finally:
        conn.close()


def get_accounts_ping_checker_stats_map(account_since_map, until_iso=None):
    """
    Returns checker stats per account_id for account-specific windows.

    account_since_map: {account_id: since_iso}
    until_iso: optional window end (exclusive). Defaults to utc now.
    """
    if not isinstance(account_since_map, dict) or not account_since_map:
        return {}

    pairs = []
    seen = set()
    for account_id, since_iso in (account_since_map or {}).items():
        aid = (account_id or "").strip()
        since = (since_iso or "").strip()
        if not aid or not since or aid in seen:
            continue
        seen.add(aid)
        pairs.append((aid, since))
    if not pairs:
        return {}

    end_iso = (until_iso or "").strip()
    if not end_iso:
        end_iso = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    conn = get_conn()
    try:
        values_clause = ",".join("(?, ?)" for _ in pairs)
        params = []
        for account_id, since_iso in pairs:
            params.extend([account_id, since_iso])
        params.append(end_iso)

        rows = conn.execute(
            f"""
            WITH anchors(account_id, since_iso) AS (
              VALUES {values_clause}
            ),
            filtered AS (
              SELECT
                r.account_id,
                r.bucket_ts,
                r.sample_count,
                r.ok_count,
                r.avg_sum,
                r.avg_count,
                r.loss_sum,
                r.loss_count,
                CASE
                  WHEN r.loss_count > 0 AND (r.loss_sum / r.loss_count) >= 99.999 THEN 1
                  ELSE 0
                END AS is_down
              FROM accounts_ping_rollups r
              JOIN anchors a ON a.account_id = r.account_id
              WHERE r.bucket_ts >= a.since_iso AND r.bucket_ts < ?
            ),
            w AS (
              SELECT
                account_id,
                bucket_ts,
                sample_count,
                ok_count,
                avg_sum,
                avg_count,
                loss_sum,
                loss_count,
                is_down,
                LAG(is_down) OVER (PARTITION BY account_id ORDER BY bucket_ts) AS prev_down
              FROM filtered
            )
            SELECT
              account_id,
              SUM(sample_count) AS total,
              SUM(sample_count - ok_count) AS failures,
              CASE
                WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                ELSE NULL
              END AS loss_avg,
              CASE
                WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                ELSE NULL
              END AS avg_ms_avg,
              SUM(
                CASE
                  WHEN loss_count > 0 THEN ((loss_sum / loss_count) / 100.0) * 60.0
                  ELSE 0.0
                END
              ) AS downtime_seconds,
              SUM(
                CASE
                  WHEN is_down = 1 AND COALESCE(prev_down, 0) = 0 THEN 1
                  ELSE 0
                END
              ) AS loss_events
            FROM w
            GROUP BY account_id
            """,
            params,
        ).fetchall()

        out = {}
        for row in rows or []:
            d = dict(row) if not isinstance(row, dict) else row
            aid = (d.get("account_id") or "").strip()
            if not aid:
                continue
            out[aid] = {
                "total": int(d.get("total") or 0),
                "failures": int(d.get("failures") or 0),
                "loss_avg": d.get("loss_avg"),
                "avg_ms_avg": d.get("avg_ms_avg"),
                "downtime_seconds": int(round(float(d.get("downtime_seconds") or 0.0))),
                "loss_events": int(d.get("loss_events") or 0),
            }
        return out
    finally:
        conn.close()


def get_accounts_ping_window_stats_by_ip(account_ids, since_iso):
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT
                  account_id,
                  ip,
                  SUM(sample_count) AS total,
                  SUM(sample_count - ok_count) AS failures,
                  CASE
                    WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                    ELSE NULL
                  END AS loss_avg,
                  CASE
                    WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                    ELSE NULL
                  END AS avg_ms_avg
                FROM accounts_ping_rollups
                WHERE bucket_ts >= ? AND account_id = ANY(?)
                GROUP BY account_id, ip
                """,
                (since_iso, list(account_ids)),
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in account_ids)
            rows = conn.execute(
                f"""
                SELECT
                  account_id,
                  ip,
                  SUM(sample_count) AS total,
                  SUM(sample_count - ok_count) AS failures,
                  CASE
                    WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                    ELSE NULL
                  END AS loss_avg,
                  CASE
                    WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                    ELSE NULL
                  END AS avg_ms_avg
                FROM accounts_ping_rollups
                WHERE bucket_ts >= ? AND account_id IN ({placeholders})
                GROUP BY account_id, ip
                """,
                [since_iso] + list(account_ids),
            ).fetchall()
        out = {}
        for row in rows:
            acct = row["account_id"]
            ip = row["ip"]
            out.setdefault(acct, {})[ip] = dict(row)
        return out
    finally:
        conn.close()


def get_optical_latest_results_since(since_iso):
    rows = []
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT DISTINCT ON (device_id)
                  timestamp, device_id, pppoe, ip, rx, tx, priority
                FROM optical_results
                WHERE timestamp >= ?
                ORDER BY device_id, timestamp DESC
                """,
                (since_iso,),
            ).fetchall()
            rows = [dict(row) for row in rows]
        else:
            rows = conn.execute(
                """
                SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
                FROM optical_results o
                JOIN (
                  SELECT device_id, MAX(timestamp) AS max_ts
                  FROM optical_results
                  WHERE timestamp >= ?
                  GROUP BY device_id
                ) latest
                  ON o.device_id = latest.device_id AND o.timestamp = latest.max_ts
                """,
                (since_iso,),
            ).fetchall()
            rows = [dict(row) for row in rows]
        return _apply_optical_tx_fallback(rows)
    finally:
        conn.close()

OPTICAL_TX_FALLBACK_LOOKBACK_DAYS = 30


def _optical_tx_fallback_since_iso(days=OPTICAL_TX_FALLBACK_LOOKBACK_DAYS):
    lookback_days = max(int(days or OPTICAL_TX_FALLBACK_LOOKBACK_DAYS), 1)
    return (datetime.utcnow() - timedelta(days=lookback_days)).replace(microsecond=0).isoformat() + "Z"


def get_latest_non_null_optical_tx_for_devices(device_ids, since_iso=None):
    normalized_ids = [str(item).strip() for item in (device_ids or []) if str(item).strip()]
    if not normalized_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            params = []
            where = []
            if since_iso:
                where.append("timestamp >= ?")
                params.append(since_iso)
            where.extend(["tx IS NOT NULL", "device_id = ANY(?)"])
            params.append(list(normalized_ids))
            rows = conn.execute(
                f"""
                SELECT DISTINCT ON (device_id)
                    device_id, tx, timestamp
                FROM optical_results
                WHERE {' AND '.join(where)}
                ORDER BY device_id, timestamp DESC
                """,
                tuple(params),
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in normalized_ids)
            params = []
            where = []
            if since_iso:
                where.append("timestamp >= ?")
                params.append(since_iso)
            where.extend(["tx IS NOT NULL", f"device_id IN ({placeholders})"])
            params.extend(normalized_ids)
            rows = conn.execute(
                f"""
                SELECT o.device_id, o.tx, o.timestamp
                FROM optical_results o
                JOIN (
                    SELECT device_id, MAX(timestamp) AS max_ts
                    FROM optical_results
                    WHERE {' AND '.join(where)}
                    GROUP BY device_id
                ) latest
                ON o.device_id = latest.device_id AND o.timestamp = latest.max_ts
                """,
                params,
            ).fetchall()
        return {row["device_id"]: dict(row) for row in rows if row.get("device_id")}
    finally:
        conn.close()


def _apply_optical_tx_fallback(rows, fallback_since_iso=None):
    materialized = [dict(row) for row in (rows or []) if row]
    if not materialized:
        return materialized
    device_ids = []
    for row in materialized:
        device_id = (row.get("device_id") or "").strip()
        if device_id:
            device_ids.append(device_id)
    fallback_map = get_latest_non_null_optical_tx_for_devices(
        device_ids,
        since_iso=fallback_since_iso or _optical_tx_fallback_since_iso(),
    )
    out = []
    for row in materialized:
        device_id = (row.get("device_id") or "").strip()
        fallback_used = False
        if device_id and row.get("tx") is None:
            fallback = fallback_map.get(device_id) or {}
            fallback_tx = fallback.get("tx")
            if fallback_tx is not None:
                row["tx"] = fallback_tx
                row["tx_fallback_at"] = fallback.get("timestamp")
                fallback_used = True
        row["tx_fallback_used"] = fallback_used
        out.append(row)
    return out


def get_optical_samples_for_devices_since(device_ids, since_iso):
    if not device_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT device_id, COUNT(*) AS samples
                FROM optical_results
                WHERE timestamp >= ? AND device_id = ANY(?)
                GROUP BY device_id
                """,
                (since_iso, list(device_ids)),
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in device_ids)
            rows = conn.execute(
                f"""
                SELECT device_id, COUNT(*) AS samples
                FROM optical_results
                WHERE timestamp >= ? AND device_id IN ({placeholders})
                GROUP BY device_id
                """,
                [since_iso] + list(device_ids),
            ).fetchall()
        return {row["device_id"]: int(row["samples"] or 0) for row in rows}
    finally:
        conn.close()


def get_optical_rx_series_for_devices_since(device_ids, since_iso):
    if not device_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT device_id, rx
                FROM optical_results
                WHERE timestamp >= ? AND device_id = ANY(?)
                ORDER BY device_id ASC, timestamp ASC
                """,
                (since_iso, list(device_ids)),
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in device_ids)
            rows = conn.execute(
                f"""
                SELECT device_id, rx
                FROM optical_results
                WHERE timestamp >= ? AND device_id IN ({placeholders})
                ORDER BY device_id ASC, timestamp ASC
                """,
                [since_iso] + list(device_ids),
            ).fetchall()
        out = {}
        for row in rows:
            if not isinstance(row, dict):
                row = dict(row)
            dev = row.get("device_id")
            if not dev:
                continue
            rx = row.get("rx")
            if rx is None:
                continue
            out.setdefault(dev, []).append(rx)
        return out
    finally:
        conn.close()


def insert_wan_history_row(
    wan_id,
    status,
    timestamp=None,
    target=None,
    core_id=None,
    label=None,
    up_pct=None,
    retention_days=400,
):
    stamp = timestamp or utc_now_iso()
    cutoff = (datetime.utcnow() - timedelta(days=max(int(retention_days or 1), 1))).replace(microsecond=0).isoformat() + "Z"
    try:
        prune_interval_seconds = int(os.environ.get("THREEJ_WAN_HISTORY_PRUNE_INTERVAL_SECONDS", "300") or 300)
    except Exception:
        prune_interval_seconds = 300
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO wan_status_history (timestamp, wan_id, status, up_pct, target, core_id, label)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (stamp, wan_id, status, up_pct, target, core_id, label),
            )
            if _should_run_retention_prune("wan_status_history", prune_interval_seconds):
                conn.execute(
                    """
                    DELETE FROM wan_status_history
                    WHERE timestamp < ?
                    """,
                    (cutoff,),
                )
    finally:
        conn.close()


def insert_wan_target_ping_result(
    wan_id,
    target_id,
    target_host,
    ok,
    rtt_ms=None,
    timestamp=None,
    core_id=None,
    label=None,
    src_address=None,
    retention_days=400,
):
    stamp = timestamp or utc_now_iso()
    cutoff = (datetime.utcnow() - timedelta(days=max(int(retention_days or 1), 1))).replace(microsecond=0).isoformat() + "Z"
    try:
        prune_interval_seconds = int(os.environ.get("THREEJ_WAN_TARGET_PRUNE_INTERVAL_SECONDS", "300") or 300)
    except Exception:
        prune_interval_seconds = 300
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO wan_target_ping_results (
                    timestamp, wan_id, core_id, label, target_id, target_host, src_address, ok, rtt_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stamp,
                    wan_id,
                    core_id,
                    label,
                    target_id,
                    target_host,
                    src_address,
                    int(bool(ok)),
                    rtt_ms,
                ),
            )
            if _should_run_retention_prune("wan_target_ping_results", prune_interval_seconds):
                conn.execute(
                    """
                    DELETE FROM wan_target_ping_results
                    WHERE timestamp < ?
                    """,
                    (cutoff,),
                )
    finally:
        conn.close()


def delete_wan_target_ping_results_for_targets(target_ids):
    ids = [str(i).strip() for i in (target_ids or []) if str(i).strip()]
    if not ids:
        return
    conn = get_conn()
    try:
        with conn:
            if len(ids) == 1:
                conn.execute("DELETE FROM wan_target_ping_results WHERE target_id = ?", (ids[0],))
            else:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM wan_target_ping_results WHERE target_id IN ({placeholders})", ids)
    finally:
        conn.close()


def fetch_wan_target_ping_series_map(wan_ids, target_id, start_iso, end_iso, bucket_seconds=None):
    if not wan_ids or not target_id:
        return {}
    try:
        bucket_seconds = max(int(bucket_seconds or 0), 0)
    except Exception:
        bucket_seconds = 0
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in wan_ids)
        if bucket_seconds > 1:
            if _use_postgres():
                rows = conn.execute(
                    f"""
                    SELECT
                        wan_id,
                        FLOOR(EXTRACT(EPOCH FROM (timestamp::timestamptz)) / ?) * ? AS bucket_epoch,
                        MAX(CASE WHEN ok = 1 THEN rtt_ms END) AS rtt_ms,
                        MAX(ok) AS ok
                    FROM wan_target_ping_results
                    WHERE target_id = ?
                      AND timestamp BETWEEN ? AND ?
                      AND wan_id IN ({placeholders})
                    GROUP BY wan_id, bucket_epoch
                    ORDER BY bucket_epoch ASC
                    """,
                    [bucket_seconds, bucket_seconds, target_id, start_iso, end_iso] + list(wan_ids),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"""
                    SELECT
                        wan_id,
                        (CAST(strftime('%s', timestamp) AS INTEGER) / ?) * ? AS bucket_epoch,
                        MAX(CASE WHEN ok = 1 THEN rtt_ms END) AS rtt_ms,
                        MAX(ok) AS ok
                    FROM wan_target_ping_results
                    WHERE target_id = ?
                      AND timestamp BETWEEN ? AND ?
                      AND wan_id IN ({placeholders})
                    GROUP BY wan_id, bucket_epoch
                    ORDER BY bucket_epoch ASC
                    """,
                    [bucket_seconds, bucket_seconds, target_id, start_iso, end_iso] + list(wan_ids),
                ).fetchall()
        else:
            rows = conn.execute(
                f"""
                SELECT wan_id, timestamp, ok, rtt_ms
                FROM wan_target_ping_results
                WHERE target_id = ?
                  AND timestamp BETWEEN ? AND ?
                  AND wan_id IN ({placeholders})
                ORDER BY timestamp ASC
                """,
                [target_id, start_iso, end_iso] + list(wan_ids),
            ).fetchall()
        series = {}
        for row in rows:
            if not isinstance(row, dict):
                row = dict(row)
            wan_id = row.get("wan_id")
            if not wan_id:
                continue
            stamp = row.get("timestamp")
            if bucket_seconds > 1:
                epoch = row.get("bucket_epoch")
                if epoch is None:
                    continue
                try:
                    stamp = datetime.fromtimestamp(float(epoch), tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                except Exception:
                    continue
            if not stamp:
                continue
            series.setdefault(wan_id, []).append(
                {
                    "timestamp": stamp,
                    "ok": int(row.get("ok") or 0),
                    "rtt_ms": row.get("rtt_ms"),
                }
            )
        return series
    finally:
        conn.close()


def fetch_wan_history_map(wan_ids, start_iso, end_iso):
    if not wan_ids:
        return {}
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in wan_ids)
        params = [start_iso, end_iso] + list(wan_ids)
        rows = conn.execute(
            f"""
            SELECT wan_id, timestamp, status
            FROM wan_status_history
            WHERE timestamp BETWEEN ? AND ?
              AND wan_id IN ({placeholders})
            ORDER BY timestamp ASC
            """,
            params,
        ).fetchall()
        history = {}
        for row in rows:
            history.setdefault(row["wan_id"], []).append(
                {"ts": row["timestamp"], "status": row["status"]}
            )
        return history
    finally:
        conn.close()


def get_wan_status_counts(wan_ids, start_iso, end_iso):
    if not wan_ids:
        return {}
    placeholders = ",".join("?" for _ in wan_ids)
    params = [start_iso, end_iso] + list(wan_ids)
    conn = get_conn()
    try:
        rows = conn.execute(
            f"""
            SELECT
              wan_id,
              SUM(CASE WHEN LOWER(status) = 'up' THEN 1 ELSE 0 END) AS up,
              SUM(CASE WHEN LOWER(status) = 'down' THEN 1 ELSE 0 END) AS down,
              COUNT(*) AS total
            FROM wan_status_history
            WHERE timestamp BETWEEN ? AND ?
              AND wan_id IN ({placeholders})
            GROUP BY wan_id
            """,
            params,
        ).fetchall()
        counts = {}
        for row in rows:
            if not isinstance(row, dict):
                row = dict(row)
            counts[row["wan_id"]] = {
                "up": int(row["up"] or 0),
                "down": int(row["down"] or 0),
                "total": int(row["total"] or 0),
            }
        return counts
    finally:
        conn.close()


def clear_wan_history():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM wan_status_history")
            try:
                conn.execute("DELETE FROM wan_target_ping_results")
            except Exception:
                pass
    finally:
        conn.close()


def clear_surveillance_history():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM surveillance_sessions")
    finally:
        conn.close()


def insert_rto_result(ip, name, ok, timestamp=None):
    stamp = timestamp or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO rto_results (timestamp, ip, name, ok)
                VALUES (?, ?, ?, ?)
                """,
                (stamp, ip, name, 1 if ok else 0),
            )
    finally:
        conn.close()


def insert_optical_result(device_id, pppoe, ip, rx, tx, priority, timestamp=None):
    stamp = timestamp or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO optical_results (timestamp, device_id, pppoe, ip, rx, tx, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stamp,
                    device_id,
                    pppoe,
                    ip,
                    rx,
                    tx,
                    1 if priority else 0,
                ),
            )
    finally:
        conn.close()


def delete_optical_results_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM optical_results WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def clear_optical_results():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM optical_results")
    finally:
        conn.close()


def insert_pppoe_usage_sample(
    timestamp,
    router_id,
    router_name,
    pppoe,
    address=None,
    session_id=None,
    uptime=None,
    bytes_in=None,
    bytes_out=None,
    host_count=None,
    rx_bps=None,
    tx_bps=None,
):
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO pppoe_usage_samples
                    (timestamp, router_id, router_name, pppoe, address, session_id, uptime, bytes_in, bytes_out, host_count, rx_bps, tx_bps)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    router_id,
                    router_name,
                    pppoe,
                    address,
                    session_id,
                    uptime,
                    bytes_in,
                    bytes_out,
                    host_count,
                    rx_bps,
                    tx_bps,
                ),
            )
    finally:
        conn.close()


def delete_pppoe_usage_samples_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM pppoe_usage_samples WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def clear_pppoe_usage_samples():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM pppoe_usage_samples")
    finally:
        conn.close()


def get_pppoe_usage_window_stats_since(since_iso):
    """
    Returns a dict keyed by "<router_id>|<pppoe_lower>" with:
      - samples
      - max_total_bps (max(rx_bps + tx_bps) in window)
      - first_ts, last_ts
    """
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                router_id,
                pppoe,
                COUNT(*) AS samples,
                MAX(COALESCE(rx_bps, 0) + COALESCE(tx_bps, 0)) AS max_total_bps,
                MIN(timestamp) AS first_ts,
                MAX(timestamp) AS last_ts
            FROM pppoe_usage_samples
            WHERE timestamp >= ?
            GROUP BY router_id, pppoe
            """,
            (since_iso,),
        ).fetchall()
        out = {}
        for row in rows:
            router_id = (row["router_id"] or "").strip()
            pppoe = (row["pppoe"] or "").strip()
            if not pppoe:
                continue
            key = f"{router_id}|{pppoe.lower()}"
            out[key] = {
                "router_id": router_id,
                "pppoe": pppoe,
                "samples": int(row["samples"] or 0),
                "max_total_bps": float(row["max_total_bps"] or 0.0),
                "first_ts": row["first_ts"],
                "last_ts": row["last_ts"],
            }
        return out
    finally:
        conn.close()


def get_pppoe_usage_series_since(router_id, pppoe, since_iso):
    router_id = (router_id or "").strip()
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return []
    conn = get_conn()
    try:
        if router_id:
            rows = conn.execute(
                """
                SELECT timestamp, rx_bps, tx_bps, bytes_in, bytes_out, host_count
                FROM pppoe_usage_samples
                WHERE router_id = ? AND pppoe = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (router_id, pppoe, since_iso),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT timestamp, rx_bps, tx_bps, bytes_in, bytes_out, host_count
                FROM pppoe_usage_samples
                WHERE pppoe = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (pppoe, since_iso),
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_optical_results_since(since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, device_id, pppoe, ip, rx, tx, priority
            FROM optical_results
            WHERE timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (since_iso,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_optical_results_for_device_since(device_id, since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, rx, tx
            FROM optical_results
            WHERE device_id = ? AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (device_id, since_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_latest_optical_identity(device_id):
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT timestamp, device_id, pppoe, ip, rx, tx, priority
            FROM optical_results
            WHERE device_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_latest_optical_device_for_ip(ip):
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT device_id
            FROM optical_results
            WHERE ip = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()
        return row["device_id"] if row else None
    finally:
        conn.close()


def get_latest_optical_by_pppoe(pppoe_list):
    pppoe_list = [str(item).strip() for item in (pppoe_list or []) if str(item).strip()]
    if not pppoe_list:
        return {}
    rows = []
    conn = get_conn()
    try:
        if _use_postgres():
            placeholders = ",".join("?" for _ in pppoe_list)
            rows = conn.execute(
                f"""
                SELECT DISTINCT ON (pppoe)
                    timestamp, device_id, pppoe, ip, rx, tx, priority
                FROM optical_results
                WHERE pppoe IN ({placeholders})
                ORDER BY pppoe, timestamp DESC
                """,
                list(pppoe_list),
            ).fetchall()
            rows = [dict(row) for row in rows]
        else:
            placeholders = ",".join("?" for _ in pppoe_list)
            rows = conn.execute(
                f"""
                SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
                FROM optical_results o
                JOIN (
                    SELECT pppoe, MAX(timestamp) AS max_ts
                    FROM optical_results
                    WHERE pppoe IN ({placeholders})
                    GROUP BY pppoe
                ) latest
                ON o.pppoe = latest.pppoe AND o.timestamp = latest.max_ts
                """,
                list(pppoe_list),
            ).fetchall()
            rows = [dict(row) for row in rows]
        rows = _apply_optical_tx_fallback(rows)
        return {row["pppoe"]: row for row in rows if row.get("pppoe")}
    finally:
        conn.close()


def search_optical_customers(query, since_iso, limit=20):
    raw = (query or "").strip()
    if not raw:
        return []
    pattern = f"%{raw}%"
    limit = max(int(limit or 20), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
            FROM optical_results o
            JOIN (
                SELECT device_id, MAX(timestamp) AS max_ts
                FROM optical_results
                WHERE timestamp >= ?
                GROUP BY device_id
            ) latest
            ON o.device_id = latest.device_id AND o.timestamp = latest.max_ts
            WHERE o.timestamp >= ?
              AND (
                o.pppoe LIKE ?
                OR o.ip LIKE ?
                OR o.device_id LIKE ?
              )
            ORDER BY o.timestamp DESC
            LIMIT ?
            """,
            (since_iso, since_iso, pattern, pattern, pattern, limit),
        ).fetchall()
        return _apply_optical_tx_fallback([dict(row) for row in rows])
    finally:
        conn.close()


def get_recent_optical_readings(device_id, since_iso, limit=50):
    limit = max(int(limit or 50), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, rx, tx, priority
            FROM optical_results
            WHERE device_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (device_id, since_iso, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_optical_worst_candidates(since_iso, limit=200):
    limit = max(int(limit or 200), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
            FROM optical_results o
            JOIN (
                SELECT device_id, MAX(timestamp) AS max_ts
                FROM optical_results
                WHERE timestamp >= ?
                GROUP BY device_id
            ) latest
            ON o.device_id = latest.device_id AND o.timestamp = latest.max_ts
            WHERE o.timestamp >= ?
            ORDER BY (o.rx IS NULL) DESC,
                     (o.tx IS NULL) DESC,
                     o.rx ASC,
                     o.timestamp DESC
            LIMIT ?
            """,
            (since_iso, since_iso, limit),
        ).fetchall()
        return _apply_optical_tx_fallback([dict(row) for row in rows])
    finally:
        conn.close()


def clear_accounts_ping_data():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM accounts_ping_results")
            conn.execute("DELETE FROM accounts_ping_rollups")
    finally:
        conn.close()
