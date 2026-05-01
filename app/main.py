from pathlib import Path

import copy

import asyncio
import json
import os
import base64
import hashlib
import hmac
import re
import shlex
import shutil
import smtplib
import secrets
import ssl
import tempfile
import time
import subprocess
import threading
import urllib.parse
import urllib.request
import ipaddress
from datetime import datetime, timezone, timedelta, time as dt_time
from zoneinfo import ZoneInfo
from email.message import EmailMessage

import imghdr

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.background import BackgroundTask

from .db import (
    AUTH_DEFAULT_ROLE_PERMS,
    count_auth_users,
    clear_accounts_ping_data,
    clear_offline_history,
    clear_optical_results,
    clear_pppoe_usage_samples,
    clear_usage_modem_reboot_history,
    clear_surveillance_audit_logs,
    clear_surveillance_history,
    clear_isp_status_data,
    clear_mikrotik_logs,
    clear_wan_history,
    count_offline_history_accounts_since,
    count_usage_modem_reboot_history,
    create_auth_permission,
    create_auth_role,
    create_auth_session,
    create_auth_user,
    delete_auth_audit_logs_older_than,
    delete_auth_user,
    delete_wan_target_ping_results_for_targets,
    delete_auth_role,
    end_surveillance_session,
    ensure_surveillance_session,
    fetch_wan_history_map,
    fetch_isp_status_latest_map,
    fetch_isp_status_series_map,
    fetch_wan_target_ping_series_map,
    get_active_surveillance_session,
    get_auth_role_by_id,
    get_auth_role_by_name,
    get_auth_session,
    get_auth_user_by_email,
    get_auth_user_by_id,
    get_auth_user_by_username,
    get_auth_user_permission_codes,
    get_accounts_ping_latest_ip_since,
    get_accounts_ping_rollups_range,
    get_accounts_ping_rollups_since,
    get_accounts_ping_series,
    get_accounts_ping_series_range,
    get_accounts_ping_checker_stats_map,
    get_accounts_ping_window_stats,
    get_accounts_ping_window_stats_by_ip,
    get_job_status,
    get_latest_accounts_ping_map,
    get_latest_optical_by_pppoe,
    get_latest_optical_device_for_ip,
    get_latest_optical_identity,
    get_offline_history_accounts_page_since,
    list_offline_history_account_stats_map,
    get_offline_history_for_account,
    get_offline_history_for_pppoe,
    get_latest_pppoe_usage_snapshot,
    get_recent_surveillance_sessions_for_pppoe,
    get_surveillance_fixed_cycles_map,
    list_surveillance_audit_logs_for_pppoe,
    list_surveillance_cycle_sessions,
    get_surveillance_session_by_id,
    get_optical_latest_results_since,
    get_optical_results_for_device_since,
    get_optical_series_for_devices_since,
    get_optical_samples_for_devices_since,
    get_optical_worst_candidates,
    get_wan_status_counts,
    get_mikrotik_log_facets,
    get_mikrotik_log_stats,
    increment_surveillance_observed,
    get_offline_history_since,
    get_pppoe_usage_series_since,
    get_recent_optical_readings,
    init_db,
    insert_auth_audit_log,
    list_usage_modem_reboot_history,
    list_usage_modem_reboot_account_stats,
    list_usage_modem_reboot_history_for_account,
    list_mikrotik_logs,
    list_auth_audit_logs,
    list_auth_permissions,
    list_auth_roles,
    list_auth_users,
    list_active_surveillance_sessions,
    list_surveillance_history,
    revoke_auth_session,
    revoke_auth_sessions_for_user,
    search_optical_customers,
    set_auth_role_permissions,
    set_auth_user_password,
    touch_surveillance_session,
    touch_auth_session,
    touch_auth_user_login,
    update_auth_user,
    update_auth_role,
    insert_wan_target_ping_result,
    delete_mikrotik_logs_older_than,
    update_mikrotik_logs_router_for_sources,
    utc_now_iso,
)
from .accounts_ping_sources import (
    ACCOUNTS_PING_SOURCE_MIKROTIK,
    ACCOUNTS_PING_SOURCE_SSH_CSV,
    build_accounts_ping_account_id,
    build_accounts_ping_account_ids_by_pppoe,
    build_accounts_ping_source_devices,
    normalize_accounts_ping_device,
    normalize_accounts_ping_source_mode,
)
from .accounts_missing_support import (
    auto_delete_accounts_missing_entries,
    build_accounts_missing_secret_snapshot,
    normalize_accounts_missing_settings,
    purge_pppoe_account_data,
    reconcile_accounts_missing_state,
    selected_accounts_missing_routers,
)
from .mikrotik_logs_setup import (
    auto_configure_mikrotik_log_router,
    auto_configure_mikrotik_logs,
    build_mikrotik_log_setup_commands,
    get_mikrotik_log_setup_routers,
)
from .forms import parse_bool, parse_float, parse_int, parse_int_list, parse_lines
from .jobs import JobsManager
from .mikrotik import RouterOSClient
from .feature_usage import add_feature_cpu, sample_feature_cpu_percent, register_feature
from .ai_investigator import AIInvestigatorError, generate_investigation_report
from .offline_rules import enabled_offline_tracking_rules, normalize_offline_tracking_rules, offline_rules_summary_text
from .notifiers import optical as optical_notifier
from .notifiers import wan_ping as wan_ping_notifier
from .notifiers.telegram import TelegramError, send_telegram
from .settings_defaults import (
    ACCOUNTS_MISSING_DEFAULTS,
    ACCOUNTS_PING_DEFAULTS,
    ISP_PING_DEFAULTS,
    OFFLINE_DEFAULTS,
    OPTICAL_DEFAULTS,
    SURVEILLANCE_DEFAULTS,
    USAGE_DEFAULTS,
    WAN_PING_DEFAULTS,
    ISP_STATUS_DEFAULTS,
    MIKROTIK_LOGS_DEFAULTS,
    WAN_MESSAGE_DEFAULTS,
    WAN_SUMMARY_DEFAULTS,
)
from .settings_store import export_settings, get_settings, get_state, import_settings, save_settings, save_state
from .usage_logic import build_usage_summary_data as build_usage_summary_data_shared, normalize_usage_modem_reboot_settings

BASE_DIR = Path(__file__).resolve().parent
PH_TZ = ZoneInfo("Asia/Manila")
DATA_DIR = Path("/data")
SYSTEM_UPDATE_STATUS_PATH = DATA_DIR / "system_update_status.json"
SYSTEM_UPDATE_LOG_PATH = DATA_DIR / "system_update.log"
SYSTEM_UPDATE_CHECK_LIMIT = 50
SYSTEM_UPDATE_LOG_TAIL_BYTES = 16384
SYSTEM_UPDATE_STALE_SECONDS = 1800
SYSTEM_UPDATE_INSTALLED_CACHE_SECONDS = 120
SYSTEM_UPDATE_INSTALLED_VERSION_CACHE = {"repo_path": "", "expires_at": 0.0, "value": None}

SYSTEM_DEFAULTS = {
    "branding": {
        "app_name": "ThreeJ Notifier",
        "company_logo": {
            "path": "",
            "content_type": "",
            "updated_at": "",
        },
        "browser_logo": {
            "path": "",
            "content_type": "",
            "updated_at": "",
        },
    },
    "ai": {
        "enabled": False,
        "provider": "chatgpt",
        "chatgpt": {
            "api_key": "",
            "model": "gpt-4o-mini",
            "timeout_seconds": 30,
            "max_tokens": 900,
        },
        "gemini": {
            "api_key": "",
            "model": "gemini-2.5-flash-preview-09-2025",
            "timeout_seconds": 30,
            "max_tokens": 900,
        },
        "report": {
            "lookback_hours": 24,
            "max_samples": 60,
        },
    },
    "auth": {
        "enabled": True,
        "session_idle_hours": 8,
        "audit_retention_days": 180,
        "smtp": {
            "host": "",
            "port": 587,
            "username": "",
            "password": "",
            "from_email": "",
            "from_name": "ThreeJ Notifier",
            "use_tls": True,
            "use_ssl": False,
        },
    },
}

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
NO_STORE_HEADERS = {"Cache-Control": "no-store, max-age=0"}

jobs_manager = JobsManager()
_cpu_sample = {"total": None, "idle": None, "at": 0.0, "pct": 0.0}
_dashboard_kpis_cache_lock = threading.Lock()
_dashboard_kpis_cache = {"at": 0.0, "data": None}
_DASHBOARD_KPI_CACHE_SECONDS = 120
_DASHBOARD_ATTENTION_HISTORY_KEY = "dashboard_attention_history"
_DASHBOARD_ATTENTION_HISTORY_DAYS = 7
_DASHBOARD_ATTENTION_SAMPLE_SECONDS = 300
_surveillance_checker_cache_lock = threading.Lock()
_surveillance_checker_cache = {"at": 0.0, "key": None, "data": {}, "refreshing": False}
_surveillance_checker_compute_lock = threading.Lock()
_SURVEILLANCE_CHECKER_CACHE_SECONDS = 300
_surveillance_optical_cache_lock = threading.Lock()
_surveillance_optical_cache = {"at": 0.0, "key": None, "data": {}}
_SURVEILLANCE_OPTICAL_CACHE_SECONDS = 120
_optical_status_cache_lock = threading.Lock()
_optical_status_cache = {}
_OPTICAL_STATUS_CACHE_SECONDS = 30
_OPTICAL_STATUS_CACHE_MAX_ENTRIES = 16
_surveillance_new_seen_lock = threading.Lock()
_SURVEILLANCE_NEW_SEEN_STATE_KEY = "surveillance_new_seen_by_user_v1"
_SURVEILLANCE_NEW_VIEW_SECONDS = 10
_accounts_missing_new_seen_lock = threading.Lock()
_ACCOUNTS_MISSING_NEW_SEEN_STATE_KEY = "accounts_missing_new_seen_by_user_v1"
_ACCOUNTS_MISSING_NEW_VIEW_SECONDS = 10
_offline_new_seen_lock = threading.Lock()
_OFFLINE_NEW_SEEN_STATE_KEY = "offline_new_seen_by_user_v1"
_OFFLINE_NEW_VIEW_SECONDS = 10
_usage_new_seen_lock = threading.Lock()
_USAGE_NEW_SEEN_STATE_KEY = "usage_new_seen_by_user_v1"
_USAGE_NEW_VIEW_SECONDS = 10
_surv_ai_lock = threading.Lock()
_surv_ai_running = set()
_SURV_AI_MAX_PARALLEL = 1
_SURV_AI_STAGES = ("under", "level2", "observe")
_SURV_AI_STAGE_LABELS = {
    "under": "Active Monitoring",
    "level2": "Needs Manual Fix",
    "observe": "Post-Fix Observation",
}
for _feature_name in (
    "WAN Ping",
    "Accounts Ping",
    "Under Surveillance",
    "Usage",
    "Offline",
    "Optical Monitoring",
    "Telegram",
    "Dashboard/API",
):
    register_feature(_feature_name)

AI_MODEL_PRICING = {
    "chatgpt": [
        {
            "id": "gpt-4o-mini",
            "label": "gpt-4o-mini",
            "input_per_1m": 0.15,
            "output_per_1m": 0.60,
            "free_tier": False,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Balanced cost for frequent investigations.",
        },
        {
            "id": "gpt-4o",
            "label": "gpt-4o",
            "input_per_1m": 2.50,
            "output_per_1m": 10.00,
            "free_tier": False,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Higher quality, higher cost.",
        },
        {
            "id": "gpt-4.1",
            "label": "gpt-4.1",
            "input_per_1m": 2.00,
            "output_per_1m": 8.00,
            "free_tier": False,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Strong reasoning for complex diagnostics.",
        },
        {
            "id": "gpt-4.1-mini",
            "label": "gpt-4.1-mini",
            "input_per_1m": 0.40,
            "output_per_1m": 1.60,
            "free_tier": False,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Good quality with lower spend.",
        },
        {
            "id": "gpt-4.1-nano",
            "label": "gpt-4.1-nano",
            "input_per_1m": 0.10,
            "output_per_1m": 0.40,
            "free_tier": False,
            "recommended_max_tokens": 700,
            "max_tokens_hint": "Lowest cost, concise outputs.",
        },
        {
            "id": "o3",
            "label": "o3",
            "input_per_1m": 2.00,
            "output_per_1m": 8.00,
            "free_tier": False,
            "recommended_max_tokens": 1000,
            "max_tokens_hint": "Reasoning model; cost can rise with deeper analysis.",
        },
        {
            "id": "o4-mini",
            "label": "o4-mini",
            "input_per_1m": 1.10,
            "output_per_1m": 4.40,
            "free_tier": False,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Reasoning-focused and mid-cost.",
        },
    ],
    "gemini": [
        {
            "id": "gemini-2.5-flash-preview-09-2025",
            "label": "gemini-2.5-flash-preview-09-2025",
            "input_per_1m": 0.30,
            "output_per_1m": 2.50,
            "free_tier": True,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Fast and cost-effective for high-volume reports.",
        },
        {
            "id": "gemini-2.5-flash-lite-preview-09-2025",
            "label": "gemini-2.5-flash-lite-preview-09-2025",
            "input_per_1m": 0.10,
            "output_per_1m": 0.40,
            "free_tier": True,
            "recommended_max_tokens": 700,
            "max_tokens_hint": "Lowest-cost Gemini option.",
        },
        {
            "id": "gemini-2.5-pro",
            "label": "gemini-2.5-pro",
            "input_per_1m": 1.25,
            "output_per_1m": 10.00,
            "free_tier": True,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Best for deeper technical analysis.",
        },
        {
            "id": "gemini-3-flash-preview",
            "label": "gemini-3-flash-preview",
            "input_per_1m": 0.50,
            "output_per_1m": 3.00,
            "free_tier": True,
            "recommended_max_tokens": 1000,
            "max_tokens_hint": "Fast latest-generation preview model.",
        },
        {
            "id": "gemini-3-pro-preview",
            "label": "gemini-3-pro-preview",
            "input_per_1m": 2.00,
            "output_per_1m": 12.00,
            "free_tier": False,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Highest capability, highest cost.",
        },
        {
            "id": "gemini-2.0-flash-lite",
            "label": "gemini-2.0-flash-lite",
            "input_per_1m": 0.075,
            "output_per_1m": 0.30,
            "free_tier": True,
            "recommended_max_tokens": 700,
            "max_tokens_hint": "Legacy low-cost fallback.",
        },
    ],
}

AUTH_COOKIE_NAME = "threej_auth_session"
AUTH_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
AUTH_PASSWORD_MIN_LENGTH = 8
_AUTH_TOUCH_INTERVAL_SECONDS = 60
_auth_audit_prune_lock = threading.Lock()
_auth_audit_prune_last = 0.0

AUTH_PERMISSION_ALIASES = {
    "VIEW_Dashboard": "dashboard.view",
    "VIEW_ProfileReview": "profile_review.view",
    "VIEW_UnderSurveillance": "surveillance.view",
    "EDIT_UnderSurveillance": "surveillance.edit",
    "ADD_AccessMonitoring_UnderSurveillance": "surveillance.edit",
    "MARKFALSE_AccessMonitoring_UnderSurveillance": "surveillance.edit",
    "MOVE_AccessMonitoring_ToNeedsManualFix": "surveillance.edit",
    "FIX_NeedsManualFix_Account": "surveillance.edit",
    "RECOVER_PostFixObservation_Account": "surveillance.edit",
    "VIEW_Optical": "optical.view",
    "EDIT_Optical": "optical.edit",
    "VIEW_AccountsPing": "accounts_ping.view",
    "EDIT_AccountsPing": "accounts_ping.edit",
    "VIEW_Usage": "usage.view",
    "EDIT_Usage": "usage.edit",
    "VIEW_Offline": "offline.view",
    "EDIT_Offline": "offline.edit",
    "VIEW_WanPing": "wan.view",
    "EDIT_WanPing": "wan.edit",
    "VIEW_IspStatus": "isp_status.view",
    "EDIT_IspStatus": "isp_status.edit",
    "VIEW_SystemSettings": "system.view",
    "EDIT_SystemSettings": "system.edit",
    "RUN_TestTools": "tools.test",
    "MANAGE_BackupImportExport": "settings.import_export",
    "RUN_DangerActions": "settings.danger",
    "MANAGE_AccessControl": "auth.manage",
}
AUTH_PERMISSION_ALIASES_REVERSE = {legacy: modern for modern, legacy in AUTH_PERMISSION_ALIASES.items()}
AUTH_PERMISSION_ALIASES_LOWER = {str(k or "").strip().lower(): str(v or "").strip() for k, v in AUTH_PERMISSION_ALIASES.items()}
AUTH_PERMISSION_ALIASES_REVERSE_LOWER = {
    str(k or "").strip().lower(): str(v or "").strip() for k, v in AUTH_PERMISSION_ALIASES_REVERSE.items()
}
AUTH_PERMISSION_FEATURE_ORDER = [
    "dashboard",
    "under_surveillance",
    "profile_review",
    "optical",
    "accounts_ping",
    "accounts_missing",
    "usage",
    "offline",
    "wan_ping",
    "isp_status",
    "system_settings",
    "logs",
    "other",
]
AUTH_PERMISSION_FEATURE_LABELS = {
    "dashboard": "Dashboard",
    "under_surveillance": "Under Surveillance",
    "profile_review": "Profile Review",
    "optical": "Optical Monitoring",
    "accounts_ping": "Accounts Ping",
    "accounts_missing": "Missing Secrets",
    "usage": "Usage",
    "offline": "Offline",
    "wan_ping": "WAN Ping",
    "isp_status": "ISP Port Status",
    "system_settings": "System Settings",
    "logs": "Logs",
    "mikrotik_logs": "MikroTik Logs",
    "other": "Other",
}
AUTH_PERMISSION_DEPENDENCIES = {
    "dashboard.kpi.wan.view": ["dashboard.view"],
    "dashboard.kpi.accounts_ping.view": ["dashboard.view"],
    "dashboard.kpi.under_surveillance.view": ["dashboard.view"],
    "dashboard.kpi.usage.view": ["dashboard.view"],
    "dashboard.kpi.offline.view": ["dashboard.view"],
    "dashboard.kpi.optical.view": ["dashboard.view"],
    "dashboard.kpi.isp_status.view": ["dashboard.view"],
    "dashboard.kpi.mikrotik_routers.view": ["dashboard.view"],
    "dashboard.needs_attention.view": ["dashboard.view"],
    "dashboard.resources.view": ["dashboard.view"],
    "dashboard.logs.view": ["dashboard.view"],
    "EDIT_UnderSurveillance": ["VIEW_UnderSurveillance"],
    "ADD_AccessMonitoring_UnderSurveillance": ["VIEW_UnderSurveillance", "EDIT_UnderSurveillance"],
    "MARKFALSE_AccessMonitoring_UnderSurveillance": ["VIEW_UnderSurveillance", "EDIT_UnderSurveillance"],
    "MOVE_AccessMonitoring_ToNeedsManualFix": ["VIEW_UnderSurveillance", "EDIT_UnderSurveillance"],
    "FIX_NeedsManualFix_Account": ["VIEW_UnderSurveillance", "EDIT_UnderSurveillance"],
    "RECOVER_PostFixObservation_Account": ["VIEW_UnderSurveillance", "EDIT_UnderSurveillance"],
    "EDIT_Optical": ["VIEW_Optical"],
    "EDIT_AccountsPing": ["VIEW_AccountsPing"],
    "EDIT_Usage": ["VIEW_Usage"],
    "EDIT_Offline": ["VIEW_Offline"],
    "EDIT_WanPing": ["VIEW_WanPing"],
    "EDIT_IspStatus": ["VIEW_IspStatus"],
    "EDIT_SystemSettings": ["VIEW_SystemSettings"],
    "settings.danger": ["system.view", "system.tab.danger.view"],
    "system.general.branding.edit": ["system.general.branding.view"],
    "system.general.telegram.edit": ["system.general.telegram.view"],
    "system.routers.mikrotik.edit": ["system.routers.mikrotik.view"],
    "system.routers.cores.edit": ["system.routers.cores.view"],
    "system.routers.isp.edit": ["system.routers.isp.view"],
    "system.update.check.run": ["system.tab.update.view"],
    "system.update.run": ["system.tab.update.view", "system.update.check.run"],
    "surveillance.settings.danger.run": ["surveillance.view", "surveillance.edit", "system.view", "system.tab.danger.view"],
    "optical.settings.danger.run": ["optical.view", "optical.edit", "system.view", "system.tab.danger.view"],
    "accounts_ping.settings.danger.run": ["accounts_ping.view", "accounts_ping.edit", "system.view", "system.tab.danger.view"],
    "accounts_missing.edit": ["accounts_missing.view"],
    "accounts_missing.tab.status.view": ["accounts_missing.view"],
    "accounts_missing.tab.settings.view": ["accounts_missing.view"],
    "accounts_missing.table.details.view": ["accounts_missing.view"],
    "accounts_missing.action.delete.run": ["accounts_missing.view", "accounts_missing.edit"],
    "accounts_missing.action.bulk.edit": ["accounts_missing.view", "accounts_missing.edit"],
    "accounts_missing.action.test_source.run": ["accounts_missing.view", "accounts_missing.edit"],
    "accounts_missing.settings.general.edit": ["accounts_missing.view", "accounts_missing.edit"],
    "accounts_missing.settings.source.edit": ["accounts_missing.view", "accounts_missing.edit"],
    "accounts_missing.settings.auto_delete.edit": ["accounts_missing.view", "accounts_missing.edit"],
    "usage.settings.danger.run": ["usage.view", "usage.edit", "system.view", "system.tab.danger.view"],
    "usage.status.reboot_history.view": ["usage.view"],
    "usage.settings.modem_reboot.edit": ["usage.view", "usage.edit"],
    "offline.settings.danger.run": ["offline.view", "offline.edit", "system.view", "system.tab.danger.view"],
    "wan.settings.danger.run": ["wan.view", "wan.edit", "system.view", "system.tab.danger.view"],
    "isp_status.settings.danger.run": ["isp_status.view", "isp_status.edit", "system.view", "system.tab.danger.view"],
    "isp_status.settings.general.edit": ["isp_status.view", "isp_status.edit"],
    "isp_status.settings.capacity.edit": ["isp_status.view", "isp_status.edit"],
    "isp_status.settings.telegram.edit": ["isp_status.view", "isp_status.edit"],
    "isp_status.chart.series.view": ["isp_status.view"],
    "system.danger.uninstall.run": ["system.view", "system.tab.danger.view"],
    "optical.action.test_source.run": ["optical.view", "optical.edit"],
    "accounts_ping.action.test_source.run": ["accounts_ping.view", "accounts_ping.edit"],
    "usage.action.test_source.run": ["usage.view", "usage.edit"],
    "offline.action.radius_test.run": ["offline.view", "offline.edit"],
    "wan.action.test_router.run": ["wan.view", "wan.edit"],
    "system.backup.import_export.run": [],
    "system.routers.test.run": [],
    "system.access.auth.edit": ["system.access.auth.view"],
    "system.access.roles.edit": ["system.access.roles.view"],
    "system.access.users.edit": ["system.access.users.view"],
    "logs.timeline.view": ["dashboard.view"],
    "logs.system.view": ["logs.timeline.view"],
    "logs.mikrotik.view": ["logs.timeline.view"],
    "logs.mikrotik.edit": ["logs.mikrotik.view"],
    "logs.mikrotik.danger.run": ["logs.mikrotik.view", "logs.mikrotik.edit", "system.view", "system.tab.danger.view"],
    "logs.search.view": ["logs.timeline.view"],
    "logs.filter.view": ["logs.timeline.view"],
    "logs.category.surveillance.view": ["logs.timeline.view"],
    "logs.category.access.view": ["logs.timeline.view"],
    "logs.category.user_action.view": ["logs.timeline.view"],
    "logs.category.settings.view": ["logs.timeline.view"],
    "logs.category.system.view": ["logs.timeline.view"],
    "RUN_TestTools": ["VIEW_SystemSettings"],
    "MANAGE_BackupImportExport": ["VIEW_SystemSettings"],
    "RUN_DangerActions": ["VIEW_SystemSettings", "EDIT_SystemSettings"],
    "MANAGE_AccessControl": ["VIEW_SystemSettings"],
    "surveillance.edit": ["surveillance.view"],
    "optical.edit": ["optical.view"],
    "accounts_ping.edit": ["accounts_ping.view"],
    "usage.edit": ["usage.view"],
    "offline.edit": ["offline.view"],
    "wan.edit": ["wan.view"],
    "system.edit": [],
    "tools.test": [],
    "settings.import_export": [],
    "settings.danger": [],
    "auth.manage": [],
}
AUTH_PERMISSION_DEPENDENCIES_LOWER = {
    str(k or "").strip().lower(): [
        str(dep or "").strip() for dep in (v or []) if str(dep or "").strip()
    ]
    for k, v in AUTH_PERMISSION_DEPENDENCIES.items()
}
AUTH_PERMISSION_DEPRECATED_CODES = {
    "logs.view",
    "system.access.audit.view",
    "system.access.audit.retention.edit",
}
AUTH_PERMISSION_DEPRECATED_CODES_LOWER = {
    str(code or "").strip().lower()
    for code in AUTH_PERMISSION_DEPRECATED_CODES
    if str(code or "").strip()
}
AUTH_ROLE_EDITOR_HIDDEN_CODES = {
    "dashboard.view",
    "logs.view",
    "system.view",
    "system.edit",
    "auth.manage",
    "tools.test",
    "settings.import_export",
    "settings.danger",
    "system.targets.view",
    "system.targets.edit",
    "system.tab.general.view",
    "system.tab.routers.view",
    "system.tab.access.view",
    "system.tab.update.view",
    "system.tab.danger.view",
    "system.access.audit.view",
    "system.access.audit.retention.edit",
    *AUTH_PERMISSION_ALIASES.keys(),
}
AUTH_ROLE_EDITOR_HIDDEN_CODES_LOWER = {
    str(code or "").strip().lower()
    for code in AUTH_ROLE_EDITOR_HIDDEN_CODES
    if str(code or "").strip()
}
AUTH_UI_PERMISSION_REPLACEMENTS = {
    "system.edit": [
        "system.general.branding.edit",
        "system.general.telegram.edit",
        "system.routers.cores.edit",
        "system.routers.mikrotik.edit",
        "system.routers.isp.edit",
    ],
    "auth.manage": [
        "system.access.auth.edit",
        "system.access.permissions.view",
        "system.access.roles.edit",
        "system.access.users.edit",
    ],
    "tools.test": [
        "optical.action.test_source.run",
        "accounts_ping.action.test_source.run",
        "usage.action.test_source.run",
        "offline.action.radius_test.run",
        "wan.action.test_router.run",
        "system.routers.test.run",
    ],
    "settings.import_export": ["system.backup.import_export.run"],
    "settings.danger": [
        "surveillance.settings.danger.run",
        "optical.settings.danger.run",
        "accounts_ping.settings.danger.run",
        "usage.settings.danger.run",
        "offline.settings.danger.run",
        "wan.settings.danger.run",
        "isp_status.settings.danger.run",
        "logs.mikrotik.danger.run",
        "system.danger.uninstall.run",
        "VIEW_SystemSettings",
        "system.tab.danger.view",
    ],
    "system.targets.view": [],
    "system.targets.edit": [],
    "system.tab.general.view": [],
    "system.tab.routers.view": [],
    "system.tab.access.view": [],
    "system.tab.update.view": [],
    "system.tab.danger.view": [],
}
AUTH_UI_PERMISSION_REPLACEMENTS_LOWER = {
    str(code or "").strip().lower(): [
        str(item or "").strip()
        for item in (replacements or [])
        if str(item or "").strip()
    ]
    for code, replacements in AUTH_UI_PERMISSION_REPLACEMENTS.items()
    if str(code or "").strip()
}
AUTH_PERMISSION_COMPAT_GRANTS = {
    "tools.test": [
        "optical.action.test_source.run",
        "accounts_ping.action.test_source.run",
        "usage.action.test_source.run",
        "offline.action.radius_test.run",
        "wan.action.test_router.run",
        "system.routers.test.run",
    ],
    "settings.import_export": ["system.backup.import_export.run"],
    "settings.danger": [
        "surveillance.settings.danger.run",
        "optical.settings.danger.run",
        "accounts_ping.settings.danger.run",
        "usage.settings.danger.run",
        "offline.settings.danger.run",
        "wan.settings.danger.run",
        "isp_status.settings.danger.run",
        "logs.mikrotik.danger.run",
        "system.danger.uninstall.run",
        "VIEW_SystemSettings",
        "system.tab.danger.view",
    ],
    "system.general.branding.view": ["system.edit"],
    "system.general.branding.edit": ["system.edit"],
    "system.general.telegram.view": ["system.edit"],
    "system.general.telegram.edit": ["system.edit"],
    "system.routers.mikrotik.view": ["system.edit"],
    "system.routers.mikrotik.edit": ["system.edit"],
    "system.routers.cores.view": ["system.edit"],
    "system.routers.cores.edit": ["system.edit"],
    "system.routers.isp.view": ["system.edit"],
    "system.routers.isp.edit": ["system.edit"],
    "system.tab.update.view": ["system.edit"],
    "system.update.check.run": ["system.edit"],
    "system.update.run": ["system.edit"],
    "surveillance.settings.danger.run": ["settings.danger"],
    "optical.settings.danger.run": ["settings.danger"],
    "accounts_ping.settings.danger.run": ["settings.danger"],
    "usage.settings.danger.run": ["settings.danger"],
    "usage.status.reboot_history.view": ["usage.view"],
    "usage.settings.modem_reboot.edit": ["usage.edit"],
    "offline.settings.danger.run": ["settings.danger"],
    "wan.settings.danger.run": ["settings.danger"],
    "isp_status.settings.danger.run": ["settings.danger"],
    "logs.mikrotik.danger.run": ["settings.danger"],
    "system.danger.uninstall.run": ["settings.danger"],
    "optical.action.test_source.run": ["tools.test"],
    "accounts_ping.action.test_source.run": ["tools.test"],
    "usage.action.test_source.run": ["tools.test"],
    "offline.action.radius_test.run": ["tools.test"],
    "wan.action.test_router.run": ["tools.test"],
    "system.routers.test.run": ["tools.test"],
    "system.backup.import_export.run": ["settings.import_export"],
    "system.access.auth.view": ["auth.manage"],
    "system.access.auth.edit": ["auth.manage"],
    "system.access.permissions.view": ["auth.manage"],
    "system.access.roles.view": ["auth.manage"],
    "system.access.roles.edit": ["auth.manage"],
    "system.access.users.view": ["auth.manage"],
    "system.access.users.edit": ["auth.manage"],
}
AUTH_PERMISSION_COMPAT_GRANTS_LOWER = {
    str(code or "").strip().lower(): [
        str(item or "").strip()
        for item in (grants or [])
        if str(item or "").strip()
    ]
    for code, grants in AUTH_PERMISSION_COMPAT_GRANTS.items()
    if str(code or "").strip()
}
AUTH_IMPLICIT_PAGE_VIEW_FEATURES = {
    "system.view": "system_settings",
    "view_systemsettings": "system_settings",
}
AUTH_AUTODEP_ROOT_VIEW_FEATURES = {
    "dashboard",
    "profile_review",
    "surveillance",
    "optical",
    "accounts_ping",
    "accounts_missing",
    "usage",
    "offline",
    "wan",
    "isp_status",
    "system",
    "logs",
}
AUTH_AUTODEP_ROOT_EDIT_FEATURES = {
    "surveillance",
    "optical",
    "accounts_ping",
    "accounts_missing",
    "usage",
    "offline",
    "wan",
    "isp_status",
    "system",
}
AUTH_AUTODEP_ACTIONS = {
    "edit",
    "add",
    "create",
    "update",
    "delete",
    "remove",
    "format",
    "run",
    "manage",
    "test",
    "move",
    "fix",
    "recover",
    "mark",
    "toggle",
    "save",
    "upload",
    "download",
    "sync",
}


def _auth_permission_feature_key(code: str) -> str:
    normalized = (code or "").strip()
    lowered = normalized.lower()
    if not lowered:
        return "other"

    if lowered.startswith("dashboard.") or lowered.startswith("view_dashboard"):
        return "dashboard"
    if lowered.startswith("logs."):
        return "logs"
    if lowered.startswith("profile_review.") or lowered.startswith("view_profilereview"):
        return "profile_review"
    if (
        lowered.startswith("surveillance.")
        or "undersurveillance" in lowered
        or "accessmonitoring" in lowered
        or "needsmanualfix" in lowered
        or "postfixobservation" in lowered
    ):
        return "under_surveillance"
    if lowered.startswith("optical.") or "optical" in lowered:
        return "optical"
    if lowered.startswith("accounts_ping.") or "accountsping" in lowered or "accounts_ping" in lowered:
        return "accounts_ping"
    if lowered.startswith("accounts_missing.") or "accountsmissing" in lowered or "accounts_missing" in lowered:
        return "accounts_missing"
    if lowered.startswith("usage.") or lowered.startswith("view_usage") or lowered.startswith("edit_usage"):
        return "usage"
    if lowered.startswith("offline.") or lowered.startswith("view_offline") or lowered.startswith("edit_offline"):
        return "offline"
    if lowered.startswith("wan.") or "wanping" in lowered or lowered.startswith("view_wan") or lowered.startswith("edit_wan"):
        return "wan_ping"
    if lowered.startswith("isp_status.") or "ispstatus" in lowered or lowered.startswith("view_isp") or lowered.startswith("edit_isp"):
        return "isp_status"
    if (
        lowered.startswith("system.")
        or "systemsettings" in lowered
        or lowered == "auth.manage"
        or lowered.startswith("auth.")
        or lowered == "tools.test"
        or lowered == "settings.import_export"
        or lowered == "settings.danger"
        or "accesscontrol" in lowered
        or "backupimportexport" in lowered
        or "dangeractions" in lowered
        or "testtools" in lowered
    ):
        return "system_settings"

    return "other"


def _auth_permission_feature_label(feature_key: str) -> str:
    key = (feature_key or "").strip().lower()
    return AUTH_PERMISSION_FEATURE_LABELS.get(key, "Other")


def _auth_is_destructive_permission(code: str, label: str = "", description: str = "") -> bool:
    haystack = " ".join(
        [
            str(code or "").strip().lower(),
            str(label or "").strip().lower(),
            str(description or "").strip().lower(),
        ]
    )
    if not haystack:
        return False
    keywords = (
        "format",
        "delete",
        "remove",
        "danger",
        "uninstall",
        "reset",
        "wipe",
        "truncate",
    )
    return any(keyword in haystack for keyword in keywords)


def _auth_infer_modern_dependencies(code: str):
    normalized = (code or "").strip()
    if not normalized or "." not in normalized:
        return []

    parts = [part.strip() for part in normalized.split(".") if str(part or "").strip()]
    if len(parts) < 2:
        return []

    root = str(parts[0] or "").strip().lower()
    if root not in AUTH_AUTODEP_ROOT_VIEW_FEATURES:
        return []

    root_view = f"{parts[0]}.view"
    action = str(parts[-1] or "").strip().lower()
    out = []
    seen = set()

    def _add(dep_code: str):
        value = (dep_code or "").strip()
        key = value.lower()
        if not value or key in seen:
            return
        seen.add(key)
        out.append(value)

    if root == "system" and len(parts) > 2:
        return out

    if action == "view":
        if len(parts) > 2:
            _add(root_view)
        return out

    _add(root_view)
    if root in AUTH_AUTODEP_ROOT_EDIT_FEATURES and root != "system":
        _add(f"{parts[0]}.edit")

    return out


def _auth_permission_dependencies_for(code: str):
    normalized = (code or "").strip()
    lowered = normalized.lower()
    if not normalized:
        return []

    candidates = [normalized]
    alias = AUTH_PERMISSION_ALIASES.get(normalized) or AUTH_PERMISSION_ALIASES_LOWER.get(lowered)
    if alias and str(alias or "").strip():
        candidates.append(str(alias or "").strip())

    out = []
    seen = set()
    for candidate in candidates:
        value = (candidate or "").strip()
        if not value:
            continue
        direct = AUTH_PERMISSION_DEPENDENCIES.get(value)
        if direct is None:
            direct = AUTH_PERMISSION_DEPENDENCIES_LOWER.get(value.lower(), [])
        deps = []
        deps.extend(direct or [])
        deps.extend(_auth_infer_modern_dependencies(value))
        for dep in deps:
            dep_code = (dep or "").strip()
            dep_key = dep_code.lower()
            if not dep_code or dep_key in seen:
                continue
            seen.add(dep_key)
            out.append(dep_code)
    return out


def _auth_expand_permission_dependencies(permission_codes):
    selected = []
    seen = set()
    for code in permission_codes or []:
        value = (code or "").strip()
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        selected.append(value)

    auto_added = []
    idx = 0
    while idx < len(selected):
        current = selected[idx]
        idx += 1
        for dep in _auth_permission_dependencies_for(current):
            dep_code = (dep or "").strip()
            dep_key = dep_code.lower()
            if not dep_code or dep_key in seen:
                continue
            seen.add(dep_key)
            selected.append(dep_code)
            auto_added.append(dep_code)

    selected_sorted = sorted(selected, key=lambda item: str(item).lower())
    auto_sorted = sorted({item for item in auto_added if item}, key=lambda item: str(item).lower())
    return selected_sorted, auto_sorted


def _auth_is_ui_hidden_permission(code: str) -> bool:
    lowered = str(code or "").strip().lower()
    if not lowered:
        return False
    return lowered in AUTH_PERMISSION_DEPRECATED_CODES_LOWER or lowered in AUTH_ROLE_EDITOR_HIDDEN_CODES_LOWER


def _auth_visible_permission_codes(permission_codes):
    queue = [str(code or "").strip() for code in (permission_codes or []) if str(code or "").strip()]
    normalized = []
    seen_queue = set()
    while queue:
        current = (queue.pop(0) or "").strip()
        current_key = current.lower()
        if not current or current_key in seen_queue:
            continue
        seen_queue.add(current_key)

        alias = AUTH_PERMISSION_ALIASES.get(current) or AUTH_PERMISSION_ALIASES_LOWER.get(current_key)
        if alias and str(alias or "").strip().lower() != current_key:
            queue.append(str(alias or "").strip())
            continue

        replacements = AUTH_UI_PERMISSION_REPLACEMENTS.get(current)
        if replacements is None:
            replacements = AUTH_UI_PERMISSION_REPLACEMENTS_LOWER.get(current_key)
        if replacements is not None:
            queue.extend(replacements or [])
            continue

        normalized.append(current)

    expanded, _ = _auth_expand_permission_dependencies(normalized)
    visible = []
    seen_visible = set()
    for raw_code in expanded:
        code = (raw_code or "").strip()
        key = code.lower()
        if not code or key in seen_visible or _auth_is_ui_hidden_permission(code):
            continue
        seen_visible.add(key)
        visible.append(code)
    return visible


def _auth_annotate_permissions_with_dependencies(permission_rows):
    rows = [dict(item or {}) for item in (permission_rows or [])]
    by_code_lower = {}
    for item in rows:
        code = str(item.get("code") or "").strip()
        if code:
            by_code_lower[code.lower()] = item

    for item in rows:
        code = str(item.get("code") or "").strip()
        deps = _auth_permission_dependencies_for(code)
        item["is_destructive"] = _auth_is_destructive_permission(
            code,
            str(item.get("label") or ""),
            str(item.get("description") or ""),
        )
        dep_codes = []
        dep_labels = []
        seen_dep = set()
        for dep in deps:
            dep_code = (dep or "").strip()
            dep_key = dep_code.lower()
            if not dep_code or dep_key in seen_dep:
                continue
            match = by_code_lower.get(dep_key)
            resolved_code = str((match or {}).get("code") or dep_code).strip()
            resolved_key = resolved_code.lower()
            if not resolved_code or resolved_key in seen_dep:
                continue
            seen_dep.add(resolved_key)
            dep_codes.append(resolved_code)
            dep_label = str((match or {}).get("description") or (match or {}).get("label") or resolved_code).strip()
            dep_labels.append(dep_label)
        item["depends_on"] = dep_codes
        item["depends_on_labels"] = dep_labels
    return rows


def _build_auth_permission_groups(permission_rows):
    grouped = {}
    for row in permission_rows or []:
        item = dict(row or {})
        code = (item.get("code") or "").strip()
        key = _auth_permission_feature_key(code)
        if key not in grouped:
            grouped[key] = {
                "key": key,
                "label": _auth_permission_feature_label(key),
                "permissions": [],
            }
        grouped[key]["permissions"].append(item)
    for group in grouped.values():
        group["permissions"] = sorted(
            group.get("permissions") or [],
            key=lambda entry: str(entry.get("code") or "").lower(),
        )
    out = []
    for key in AUTH_PERMISSION_FEATURE_ORDER:
        group = grouped.get(key)
        if group and (group.get("permissions") or []):
            out.append(group)
    for key, group in sorted(grouped.items(), key=lambda item: item[0]):
        if key in AUTH_PERMISSION_FEATURE_ORDER:
            continue
        if group and (group.get("permissions") or []):
            out.append(group)
    return out


def _build_role_permission_groups(permission_codes):
    grouped = {}
    for raw_code in permission_codes or []:
        code = (raw_code or "").strip()
        if not code:
            continue
        key = _auth_permission_feature_key(code)
        if key not in grouped:
            grouped[key] = {
                "key": key,
                "label": _auth_permission_feature_label(key),
                "codes": [],
            }
        grouped[key]["codes"].append(code)
    for group in grouped.values():
        group["codes"] = sorted(group.get("codes") or [], key=lambda entry: str(entry).lower())
    out = []
    for key in AUTH_PERMISSION_FEATURE_ORDER:
        group = grouped.get(key)
        if group and (group.get("codes") or []):
            out.append(group)
    for key, group in sorted(grouped.items(), key=lambda item: item[0]):
        if key in AUTH_PERMISSION_FEATURE_ORDER:
            continue
        if group and (group.get("codes") or []):
            out.append(group)
    return out


AUTH_PERMISSION_SECTION_LABELS = {
    "access": "Access",
    "action": "Actions",
    "backup": "Backup",
    "chart": "Charts",
    "danger": "Danger",
    "details": "Details",
    "filter": "Filters",
    "general": "General",
    "history": "History",
    "kpi": "KPIs",
    "logs": "Logs",
    "needs_attention": "Needs Attention",
    "resources": "Resources",
    "routers": "Routers",
    "search": "Search",
    "settings": "Settings",
    "split_view": "Split View",
    "status": "Status",
    "system": "System",
    "tab": "Tabs",
    "table": "Tables",
}
AUTH_PERMISSION_ITEM_LABELS = {
    "accounts_ping": "Accounts Ping",
    "accounts_missing": "Missing Secrets",
    "add_manual": "Add Manual",
    "ai": "AI",
    "auth": "Auth",
    "auto_add": "Auto Add",
    "auto_delete": "Auto Delete",
    "baseline": "Baseline",
    "branding": "Branding",
    "checkers": "Checkers",
    "cores": "Cores",
    "datasource": "Data Source",
    "genieacs": "GenieACS",
    "history": "History",
    "import_export": "Import / Export",
    "inspection": "7D Activity",
    "isps": "ISPs",
    "isp": "ISP",
    "kpi": "KPI",
    "live_ping": "Live Ping",
    "manual_fix": "Needs Manual Fix",
    "mark_false": "Mark False",
    "mark_recovered": "Mark Recovered",
    "mikrotik": "MikroTik",
    "move_to_manual_fix": "Move To Manual Fix",
    "netwatch": "Netwatch",
    "offline": "Offline",
    "optical": "Optical",
    "permissions": "Permissions",
    "polling": "Polling",
    "post_fix": "Post-Fix Observation",
    "pppoe": "PPPoE",
    "radius": "Radius",
    "retention": "Retention",
    "roles": "Roles",
    "routers": "Routers",
    "run_now": "Run Now",
    "series": "Series",
    "stable": "Stable",
    "surveillance": "Surveillance",
    "sync": "Sync",
    "system": "System",
    "telegram": "Telegram",
    "test": "Test Connections",
    "test_source": "Test Data Source",
    "thresholds": "Thresholds",
    "timeline": "Timeline",
    "under_surveillance": "Under Surveillance",
    "uninstall": "Uninstall",
    "usage": "Usage",
    "usage_panel": "Usage Panel",
    "users": "Users",
    "wan": "WAN",
    "window": "Window",
}
AUTH_PERMISSION_ACTION_ORDER = {
    "view": 0,
    "edit": 1,
    "run": 2,
    "add": 3,
    "create": 3,
    "update": 4,
    "save": 5,
    "delete": 6,
    "remove": 7,
}


def _auth_permission_part_label(raw_value: str) -> str:
    value = str(raw_value or "").strip().lower()
    if not value:
        return "General"
    if value in AUTH_PERMISSION_ITEM_LABELS:
        return AUTH_PERMISSION_ITEM_LABELS[value]
    if value in AUTH_PERMISSION_SECTION_LABELS:
        return AUTH_PERMISSION_SECTION_LABELS[value]
    return " ".join(piece.capitalize() for piece in value.replace("-", "_").split("_") if piece)


def _auth_permission_section_meta(code: str):
    parts = [part.strip() for part in str(code or "").strip().split(".") if str(part or "").strip()]
    if len(parts) <= 1:
        return ("general", "General")

    root = parts[0].lower()
    second = parts[1].lower()

    if root in {"optical", "accounts_ping", "usage"} and second == "action" and len(parts) >= 3 and parts[2].lower() == "test_source":
        return ("settings.datasource", "Settings · Data Source")
    if root == "offline" and second == "action" and len(parts) >= 3 and parts[2].lower() == "radius_test":
        return ("settings.radius", "Settings · Radius")
    if root == "wan" and second == "action" and len(parts) >= 3 and parts[2].lower() == "test_router":
        return ("settings.routers", "Settings · Routers")

    if root == "system":
        if second == "general" and len(parts) >= 3 and parts[2].lower() == "telegram":
            return ("telegram", "Telegram Commands")
        if second == "general" and len(parts) >= 3 and parts[2].lower() == "branding":
            return ("general.branding", "General · Branding")
        if second in {"general", "routers", "access", "backup", "danger"}:
            if len(parts) >= 3:
                third = parts[2].lower()
                key = f"{second}.{third}"
                label = f"{_auth_permission_part_label(second)} · {_auth_permission_part_label(third)}"
                return key, label
            return second, _auth_permission_part_label(second)
        if second in {"targets"}:
            return second, _auth_permission_part_label(second)

    if second in {"tab", "status", "settings", "action", "chart", "split_view", "table", "kpi"}:
        if len(parts) >= 3:
            third = parts[2].lower()
            key = f"{second}.{third}"
            label = f"{_auth_permission_part_label(second)} · {_auth_permission_part_label(third)}"
            return key, label
        return second, _auth_permission_part_label(second)

    return second, _auth_permission_part_label(second)


def _auth_permission_leaf_sort_key(item):
    code = str((item or {}).get("code") or "").strip().lower()
    parts = [part.strip().lower() for part in code.split(".") if part.strip()]
    action = parts[-1] if parts else ""
    action_rank = AUTH_PERMISSION_ACTION_ORDER.get(action, 99)
    return (
        action_rank,
        str((item or {}).get("description") or (item or {}).get("label") or code).lower(),
        code,
    )


def _build_role_editor_permission_groups(permission_groups):
    out = []
    for group in permission_groups or []:
        permissions = []
        for item in (group.get("permissions") or []):
            code = str((item or {}).get("code") or "").strip()
            if not code:
                continue
            if _auth_is_ui_hidden_permission(code):
                continue
            permissions.append(dict(item or {}))
        if not permissions:
            continue
        section_map = {}
        for item in permissions:
            section_key, section_label = _auth_permission_section_meta(item.get("code"))
            if section_key not in section_map:
                section_map[section_key] = {
                    "key": section_key,
                    "label": section_label,
                    "permissions": [],
                }
            section_map[section_key]["permissions"].append(item)
        sections = sorted(section_map.values(), key=lambda item: str(item.get("label") or "").lower())
        for section in sections:
            section["permissions"] = sorted(section.get("permissions") or [], key=_auth_permission_leaf_sort_key)
        out.append(
            {
                "key": group.get("key"),
                "label": group.get("label"),
                "permissions": sorted(permissions, key=_auth_permission_leaf_sort_key),
                "sections": sections,
            }
        )
    return out


def _auth_encode_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _auth_decode_bytes(text: str) -> bytes:
    text = (text or "").strip()
    if not text:
        return b""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _auth_hash_password(password: str, salt_text: str = ""):
    raw_password = str(password or "")
    if not raw_password:
        raise ValueError("Password is required.")
    salt = _auth_decode_bytes(salt_text) if salt_text else secrets.token_bytes(16)
    if not salt:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_password.encode("utf-8"), salt, 260000, dklen=32)
    return _auth_encode_bytes(digest), _auth_encode_bytes(salt)


def _auth_verify_password(password: str, stored_hash: str, salt_text: str) -> bool:
    expected = (stored_hash or "").strip()
    salt_text = (salt_text or "").strip()
    if not expected or not salt_text:
        return False
    try:
        candidate_hash, _ = _auth_hash_password(password or "", salt_text)
    except Exception:
        return False
    return hmac.compare_digest(candidate_hash, expected)


def _auth_hash_session_token(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def _auth_generate_temporary_password(length: int = 14) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#_-"
    return "".join(secrets.choice(alphabet) for _ in range(max(int(length or 14), 10)))


def _auth_now_utc():
    return datetime.utcnow().replace(microsecond=0)


def _auth_now_iso():
    return _auth_now_utc().isoformat() + "Z"


def _auth_parse_iso(value: str):
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


def _auth_client_ip(request: Request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.client.host if request.client else "") or ""


def _auth_wants_json(request: Request) -> bool:
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("x-requested-with") or "").lower() == "xmlhttprequest":
        return True
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        return True
    return False


def _auth_is_public_path(path: str) -> bool:
    path = (path or "").strip()
    if not path:
        return True
    if path.startswith("/static/"):
        return True
    if path in ("/favicon.ico", "/company-logo", "/browser-logo", "/login", "/forgot-password", "/setup-owner", "/setup-admin"):
        return True
    return False


LOG_CATEGORY_PERMISSION_MAP = {
    "Surveillance": "logs.category.surveillance.view",
    "Access": "logs.category.access.view",
    "User Action": "logs.category.user_action.view",
    "Settings": "logs.category.settings.view",
    "System": "logs.category.system.view",
}


def _auth_allowed_log_categories(permission_codes) -> list[str]:
    perm_codes = permission_codes or []
    allowed = [
        category
        for category, perm_code in LOG_CATEGORY_PERMISSION_MAP.items()
        if _auth_check_permission(perm_codes, perm_code)
    ]
    if allowed:
        return allowed
    if _auth_check_permission(perm_codes, "logs.timeline.view"):
        return list(LOG_CATEGORY_PERMISSION_MAP.keys())
    return []


def _auth_can_view_logs_page(permission_codes) -> bool:
    return bool(_auth_allowed_log_categories(permission_codes) or _auth_check_permission(permission_codes or [], "logs.mikrotik.view"))


def _audit_rows_for_categories(
    limit: int = 20,
    allowed_categories=None,
    surveillance_only: bool = False,
):
    try:
        limit_value = int(limit or 20)
    except Exception:
        limit_value = 20
    limit_value = max(1, min(limit_value, 200))

    all_categories = {str(item or "").strip() for item in LOG_CATEGORY_PERMISSION_MAP.keys() if str(item or "").strip()}
    allowed_set = {str(item or "").strip() for item in (allowed_categories or []) if str(item or "").strip()}

    if not allowed_set:
        return []
    if allowed_set >= all_categories:
        return _audit_log_rows(limit=limit_value, surveillance_only=surveillance_only)

    scan_limit = max(200, limit_value * 20)
    max_scan_limit = 5000
    filtered = []
    while True:
        rows = _audit_log_rows(limit=scan_limit, surveillance_only=surveillance_only)
        filtered = [row for row in rows if str(row.get("category") or "").strip() in allowed_set]
        if len(filtered) >= limit_value:
            break
        if scan_limit >= max_scan_limit:
            break
        if len(rows) < scan_limit:
            break
        scan_limit = min(scan_limit * 2, max_scan_limit)

    return filtered[:limit_value]


def _auth_permission_for_route(path: str, method: str):
    path = (path or "").strip().lower()
    method = (method or "GET").strip().upper()
    if path == "/dashboard/latest-logs":
        return "dashboard.logs.view"
    if path == "/":
        return "VIEW_Dashboard"
    if path.startswith("/logs"):
        return "logs.timeline.view"
    if path.startswith("/dashboard/"):
        return "VIEW_Dashboard"
    if path.startswith("/system/resources"):
        return "dashboard.resources.view"
    if path.startswith("/profile-review"):
        return "VIEW_ProfileReview"

    if path.startswith("/surveillance"):
        if method == "GET":
            return "VIEW_UnderSurveillance"
        if path.endswith("/mark_new_seen"):
            return "VIEW_UnderSurveillance"
        if path.endswith("/format"):
            return "surveillance.settings.danger.run"
        if path.endswith("/add"):
            return "ADD_AccessMonitoring_UnderSurveillance"
        if path.endswith("/mark_false"):
            return "MARKFALSE_AccessMonitoring_UnderSurveillance"
        if path.endswith("/move_level2"):
            return "MOVE_AccessMonitoring_ToNeedsManualFix"
        if path.endswith("/fixed") or path.endswith("/fixed_many"):
            return "FIX_NeedsManualFix_Account"
        if path.endswith("/observe_recovered"):
            return "RECOVER_PostFixObservation_Account"
        return "EDIT_UnderSurveillance"

    if path.startswith("/settings/optical") or path.startswith("/optical"):
        if method == "GET":
            return "VIEW_Optical"
        if path.endswith("/format"):
            return "optical.settings.danger.run"
        if "/test" in path or path.endswith("/run"):
            return "optical.action.test_source.run"
        return "EDIT_Optical"

    if path.startswith("/settings/accounts-ping") or path.startswith("/accounts-ping"):
        if method == "GET":
            return "VIEW_AccountsPing"
        if path.endswith("/format"):
            return "accounts_ping.settings.danger.run"
        if "/test" in path:
            return "accounts_ping.action.test_source.run"
        return "EDIT_AccountsPing"

    if path.startswith("/settings/accounts-missing") or path.startswith("/accounts-missing"):
        if path.startswith("/accounts-missing/detail") and method == "GET":
            return "accounts_missing.table.details.view"
        if method == "GET":
            return "accounts_missing.view"
        if path.endswith("/mark_new_seen"):
            return "accounts_missing.view"
        if "/test" in path:
            return "accounts_missing.action.test_source.run"
        if path.endswith("/delete-many"):
            return "accounts_missing.action.bulk.edit"
        if path.endswith("/delete"):
            return "accounts_missing.action.delete.run"
        return "accounts_missing.edit"

    if path.startswith("/settings/usage") or path.startswith("/usage"):
        if method == "GET":
            return "VIEW_Usage"
        if path.endswith("/mark_new_seen"):
            return "VIEW_Usage"
        if path.endswith("/format"):
            return "usage.settings.danger.run"
        if "/test" in path:
            return "usage.action.test_source.run"
        return "EDIT_Usage"

    if path.startswith("/settings/offline") or path.startswith("/offline"):
        if method == "GET":
            return "VIEW_Offline"
        if path.endswith("/mark_new_seen"):
            return "VIEW_Offline"
        if path.endswith("/format"):
            return "offline.settings.danger.run"
        if "/test" in path:
            return "offline.action.radius_test.run"
        return "EDIT_Offline"

    if path.startswith("/settings/wan") or path.startswith("/wan"):
        if method == "GET":
            return "VIEW_WanPing"
        if path.endswith("/format") or path.endswith("/database"):
            return "wan.settings.danger.run"
        if "/test" in path:
            return "wan.action.test_router.run"
        return "EDIT_WanPing"

    if path.startswith("/settings/isp-status") or path.startswith("/isp-status"):
        if method == "GET":
            return "VIEW_IspStatus"
        if path.endswith("/format"):
            return "isp_status.settings.danger.run"
        return "EDIT_IspStatus"

    if path in ("/settings/export", "/settings/db/export"):
        return "system.backup.import_export.run"
    if path in ("/settings/import", "/settings/db/import"):
        return "system.backup.import_export.run"
    if path == "/settings/system/update/status":
        return "system.tab.update.view"
    if path == "/settings/system/update/check":
        return "system.update.check.run"
    if path == "/settings/system/update/start":
        return "system.update.run"

    if path == "/settings/system/auth/settings" or path == "/settings/system/auth/test-email":
        return "system.access.auth.edit"
    if path == "/settings/system/auth/permission/add":
        return "system.access.permissions.view"
    if path.startswith("/settings/system/auth/role/"):
        return "system.access.roles.edit"
    if path.startswith("/settings/system/auth/user/"):
        return "system.access.users.edit"
    if path.startswith("/settings/system/auth"):
        return "system.access.auth.view"

    if path.startswith("/settings/system/logo") or path.startswith("/settings/system/browser-logo") or path.startswith("/settings/system/branding"):
        return "system.general.branding.edit"

    if path.startswith("/settings/system/telegram"):
        return "system.general.telegram.edit"

    if path == "/settings/system/mikrotik/test" or path.startswith("/settings/system/routers/pppoe/test/"):
        return "system.routers.test.run"
    if path == "/settings/system/mikrotik" or path.startswith("/settings/system/mikrotik/"):
        return "system.routers.cores.edit"
    if path == "/settings/system/routers/pppoe" or path.startswith("/settings/system/routers/pppoe/"):
        return "system.routers.mikrotik.edit"
    if path == "/settings/system/routers/isps" or path == "/settings/system/routers/isp-port-tags":
        return "system.routers.isp.edit"

    if path.startswith("/settings/system"):
        if method == "GET":
            return "VIEW_SystemSettings"
        if path.endswith("/danger/run"):
            return "settings.danger"
        if path.endswith("/uninstall"):
            return "system.danger.uninstall.run"
        if "/test" in path:
            return "RUN_TestTools"
        return "EDIT_SystemSettings"

    if path.startswith("/settings"):
        if method == "GET":
            return "VIEW_SystemSettings"
        return "EDIT_SystemSettings"
    return None


def _auth_check_permission(permission_codes, code: str) -> bool:
    if not code:
        return True
    required = (code or "").strip()
    if not required:
        return True
    perms = {str(item or "").strip().lower() for item in (permission_codes or []) if str(item or "").strip()}
    if not perms:
        return False

    queue = [(required, True)]
    candidates = set()
    while queue:
        current, allow_compat = queue.pop(0)
        current = (current or "").strip()
        current_lower = current.lower()
        if not current or current_lower in candidates:
            continue
        candidates.add(current_lower)

        alias = AUTH_PERMISSION_ALIASES.get(current) or AUTH_PERMISSION_ALIASES_LOWER.get(current_lower)
        if alias and str(alias or "").strip():
            queue.append((str(alias or "").strip(), allow_compat))

        legacy = AUTH_PERMISSION_ALIASES_REVERSE.get(current) or AUTH_PERMISSION_ALIASES_REVERSE_LOWER.get(current_lower)
        if legacy and str(legacy or "").strip():
            queue.append((str(legacy or "").strip(), allow_compat))

        if allow_compat:
            compat = AUTH_PERMISSION_COMPAT_GRANTS.get(current)
            if compat is None:
                compat = AUTH_PERMISSION_COMPAT_GRANTS_LOWER.get(current_lower, [])
            queue.extend((item, False) for item in (compat or []))

    if any(item in perms for item in candidates):
        return True

    implied_feature = None
    for candidate in candidates:
        implied_feature = AUTH_IMPLICIT_PAGE_VIEW_FEATURES.get(candidate)
        if implied_feature:
            break
    if implied_feature:
        return any(_auth_permission_feature_key(item) == implied_feature for item in perms)

    return False


def _auth_request_has_permission(request: Request, code: str) -> bool:
    if not bool(getattr(request.state, "auth_enabled", True)):
        return True
    permission_codes = getattr(request.state, "auth_permission_codes", []) or []
    return _auth_check_permission(permission_codes, code)


def _auth_unauthorized_response(request: Request):
    if request.method != "GET" or _auth_wants_json(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    next_path = request.url.path or "/"
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    return RedirectResponse(url=f"/login?next={urllib.parse.quote(next_path, safe='/?:=&')}", status_code=303)


def _auth_forbidden_response(request: Request, required_code: str):
    if request.method != "GET" or _auth_wants_json(request):
        return JSONResponse(
            {"ok": False, "error": "Permission denied.", "required_permission": required_code},
            status_code=403,
        )
    return HTMLResponse(
        content=(
            "<html><head><title>Permission denied</title></head>"
            "<body style='font-family: sans-serif; padding: 24px;'>"
            f"<h2>Permission denied</h2><p>You do not have permission: <code>{required_code}</code></p>"
            "<p><a href='/'>Go to dashboard</a></p></body></html>"
        ),
        status_code=403,
    )


def _system_app_name(system_settings) -> str:
    branding = (system_settings.get("branding") or {}) if isinstance(system_settings, dict) else {}
    app_name = (branding.get("app_name") or "").strip()
    if not app_name:
        app_name = "ThreeJ Notifier"
    if len(app_name) > 80:
        app_name = app_name[:80].strip()
    return app_name or "ThreeJ Notifier"


def _auth_send_email(system_settings, to_email: str, subject: str, body_text: str):
    auth_cfg = (system_settings.get("auth") or {}) if isinstance(system_settings, dict) else {}
    smtp_cfg = (auth_cfg.get("smtp") or {}) if isinstance(auth_cfg.get("smtp"), dict) else {}
    host = (smtp_cfg.get("host") or "").strip()
    port = int(smtp_cfg.get("port") or 0)
    username = (smtp_cfg.get("username") or "").strip()
    password = (smtp_cfg.get("password") or "").strip()
    from_email = (smtp_cfg.get("from_email") or "").strip()
    app_name = _system_app_name(system_settings)
    from_name_raw = (smtp_cfg.get("from_name") or "").strip()
    if not from_name_raw or from_name_raw == "ThreeJ Notifier":
        from_name = app_name
    else:
        from_name = from_name_raw
    use_tls = bool(smtp_cfg.get("use_tls", True))
    use_ssl = bool(smtp_cfg.get("use_ssl", False))

    if not host or port <= 0:
        raise ValueError("SMTP host and port are required.")
    if not from_email:
        raise ValueError("SMTP from email is required.")
    to_email = (to_email or "").strip()
    if not to_email:
        raise ValueError("Recipient email is required.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg.set_content(body_text or "")

    context = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(host=host, port=port, timeout=30, context=context) as server:
            if username:
                server.login(username, password)
            server.send_message(msg)
        return

    with smtplib.SMTP(host=host, port=port, timeout=30) as server:
        server.ehlo()
        if use_tls:
            server.starttls(context=context)
            server.ehlo()
        if username:
            server.login(username, password)
        server.send_message(msg)


def _auth_log_event(request: Request, action: str, resource: str = "", details: str = ""):
    user = getattr(request.state, "current_user", None)
    user_id = 0
    username = ""
    if isinstance(user, dict):
        try:
            user_id = int(user.get("id") or 0)
        except Exception:
            user_id = 0
        username = (user.get("username") or "").strip()
    try:
        insert_auth_audit_log(
            timestamp=_auth_now_iso(),
            user_id=user_id,
            username=username,
            action=(action or "").strip(),
            resource=(resource or "").strip(),
            details=(details or "").strip()[:500],
            ip_address=_auth_client_ip(request),
        )
    except Exception:
        pass


def _auth_actor_name(request: Request, default: str = "system") -> str:
    user = getattr(request.state, "current_user", None)
    if isinstance(user, dict):
        name = (
            (user.get("username") or "").strip()
            or (user.get("full_name") or "").strip()
            or (user.get("email") or "").strip()
        )
        if name:
            return name
    return (default or "system").strip() or "system"


def _audit_details_map(details: str):
    out = {}
    for chunk in str(details or "").split(";"):
        part = chunk.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key and key not in out:
            out[key] = value
    return out


def _audit_action_category(action: str, resource: str = ""):
    action_l = (action or "").strip().lower()
    resource_l = (resource or "").strip().lower()
    if action_l.startswith("surveillance.") or resource_l.startswith("/surveillance"):
        return "Surveillance"
    if action_l.startswith("auth.") or resource_l.startswith("/settings/system/auth"):
        return "Access"
    if action_l.startswith("http."):
        return "User Action"
    if resource_l.startswith("/settings/"):
        return "Settings"
    return "System"


def _audit_human_message(username: str, action: str, resource: str, details: str):
    user = (username or "").strip() or "system"
    action_l = (action or "").strip().lower()
    resource = (resource or "").strip()
    details = (details or "").strip()
    details_map = _audit_details_map(details)

    if action_l == "auth.login":
        return f"User {user} successfully logged in."
    if action_l == "auth.logout":
        return f"User {user} logged out."
    if action_l == "auth.user_added":
        return f"User {user} created account {(resource or 'new user')}."
    if action_l == "auth.user_updated":
        return f"User {user} updated user settings for {(resource or 'a user')}."
    if action_l == "auth.user_deleted":
        return f"User {user} deleted account {(resource or 'a user')}."
    if action_l == "auth.user_reset_password":
        return f"User {user} requested password reset email for {(resource or 'a user')}."
    if action_l == "auth.role_added":
        return f"User {user} created role {(resource or 'new role')}."
    if action_l == "auth.role_updated":
        return f"User {user} updated role permissions for {(resource or 'a role')}."
    if action_l == "auth.role_deleted":
        return f"User {user} deleted role {(resource or 'a role')}."

    if action_l == "surveillance.add_manual":
        return f"User {user} added {(resource or 'an account')} to Active Monitoring."
    if action_l == "surveillance.add_auto":
        source = (details_map.get("source") or "").replace("_", " ").strip() or "accounts ping"
        reason = details_map.get("reason") or ""
        if reason:
            return f"System auto-added {(resource or 'an account')} to Active Monitoring from {source}. Reason: {reason}"
        return f"System auto-added {(resource or 'an account')} to Active Monitoring from {source}."
    if action_l == "surveillance.move_to_manual_fix":
        reason = details_map.get("reason") or ""
        if reason:
            return f"User {user} moved {(resource or 'an account')} to Needs Manual Fix. Reason: {reason}"
        return f"User {user} moved {(resource or 'an account')} to Needs Manual Fix."
    if action_l == "surveillance.mark_fixed":
        reason = details_map.get("reason") or ""
        if reason:
            return f"User {user} marked {(resource or 'an account')} as fixed. Note: {reason}"
        return f"User {user} marked {(resource or 'an account')} as fixed."
    if action_l == "surveillance.mark_fixed_bulk":
        count = details_map.get("count") or ""
        reason = details_map.get("reason") or ""
        if count and reason:
            return f"User {user} marked {count} accounts as fixed. Note: {reason}"
        if count:
            return f"User {user} marked {count} accounts as fixed."
        return f"User {user} marked multiple accounts as fixed."
    if action_l == "surveillance.mark_fully_recovered":
        count = details_map.get("count") or ""
        remarks = details_map.get("remarks") or ""
        if count and remarks:
            return f"User {user} marked {count} accounts as fully recovered. Remarks: {remarks}"
        if count:
            return f"User {user} marked {count} accounts as fully recovered."
        return f"User {user} marked accounts as fully recovered."
    if action_l == "surveillance.mark_false":
        count = details_map.get("count") or ""
        if count:
            return f"User {user} marked {count} accounts as false alarm."
        return f"User {user} marked {(resource or 'an account')} as false alarm."
    if action_l == "surveillance.mark_false_bulk":
        count = details_map.get("count") or ""
        remarks = details_map.get("remarks") or ""
        if count and remarks:
            return f"User {user} marked {count} accounts as false alarm using Select Multiple. Shared remarks: {remarks}"
        if count:
            return f"User {user} marked {count} accounts as false alarm using Select Multiple."
        return f"User {user} marked multiple accounts as false alarm using Select Multiple."
    if action_l == "surveillance.undo_add":
        return f"User {user} removed {(resource or 'an account')} during undo window."
    if action_l == "surveillance.remove":
        return f"User {user} removed {(resource or 'an account')} from surveillance."
    if action_l == "surveillance.remove_bulk":
        count = details_map.get("count") or ""
        if count:
            return f"User {user} removed {count} accounts from surveillance."
        return f"User {user} removed multiple accounts from surveillance."
    if action_l == "surveillance.settings_saved":
        return f"User {user} updated Under Surveillance settings."
    if action_l == "surveillance.formatted":
        return f"User {user} formatted Under Surveillance data."
    if action_l == "optical.formatted":
        return f"User {user} formatted Optical history."
    if action_l == "accounts_ping.formatted":
        return f"User {user} formatted Accounts Ping data."
    if action_l == "usage.formatted":
        return f"User {user} formatted Usage data."
    if action_l == "offline.formatted":
        return f"User {user} formatted Offline data."
    if action_l == "wan.formatted":
        return f"User {user} formatted WAN Ping data."
    if action_l == "system.danger.formatted_all":
        return f"User {user} formatted all monitoring feature data."
    if action_l == "system.uninstall_started":
        return f"User {user} started a full system uninstall."
    if action_l == "surveillance.ai_generate":
        stage = details_map.get("stage") or ""
        if stage:
            return f"User {user} requested AI report generation for {(resource or 'an account')} ({stage})."
        return f"User {user} requested AI report generation for {(resource or 'an account')}."

    if action_l.startswith("http."):
        method = action_l.split(".", 1)[1].upper()
        if resource.startswith("/surveillance/add"):
            return f"User {user} submitted an add-to-surveillance request."
        if resource.startswith("/surveillance/move_level2"):
            return f"User {user} submitted move to Needs Manual Fix."
        if resource.startswith("/surveillance/fixed"):
            return f"User {user} submitted account fixed action."
        if resource.startswith("/surveillance/observe_recovered"):
            return f"User {user} submitted mark as fully recovered."
        if resource.startswith("/settings/"):
            return f"User {user} saved changes in settings."
        if resource:
            return f"User {user} performed {method} on {resource}."
        return f"User {user} performed {method} action."

    if resource:
        return f"User {user} performed {action or 'action'} on {resource}."
    return f"User {user} performed {action or 'an action'}."


def _audit_log_rows(limit: int = 120, surveillance_only: bool = False):
    try:
        rows = list_auth_audit_logs(limit=max(int(limit or 120), 1))
    except Exception:
        rows = []
    out = []
    for row in rows:
        action = (row.get("action") or "").strip()
        resource = (row.get("resource") or "").strip()
        details = (row.get("details") or "").strip()
        username = (row.get("username") or "").strip() or "system"
        category = _audit_action_category(action, resource)
        if action.startswith("http."):
            continue
        if surveillance_only:
            if not action.startswith("surveillance."):
                continue
        out.append(
            {
                "id": int(row.get("id") or 0),
                "timestamp": (row.get("timestamp") or "").strip(),
                "timestamp_ph": format_ts_ph(row.get("timestamp")),
                "username": username,
                "action": action or "n/a",
                "category": category,
                "resource": resource,
                "details": details,
                "message": _audit_human_message(username, action, resource, details),
                "ip_address": (row.get("ip_address") or "").strip(),
            }
        )
    return out


def _auth_prune_audit_logs_if_due(system_settings):
    auth_cfg = (system_settings.get("auth") or {}) if isinstance(system_settings, dict) else {}
    try:
        retention_days = int(auth_cfg.get("audit_retention_days") or 180)
    except Exception:
        retention_days = 180
    retention_days = max(1, min(retention_days, 3650))
    now = time.monotonic()
    global _auth_audit_prune_last
    with _auth_audit_prune_lock:
        if now - _auth_audit_prune_last < 3600:
            return
        _auth_audit_prune_last = now
    cutoff = (_auth_now_utc() - timedelta(days=retention_days)).isoformat() + "Z"
    try:
        delete_auth_audit_logs_older_than(cutoff)
    except Exception:
        pass


def _auth_build_user_context(session_row, permission_codes):
    permission_codes = sorted(
        {
            (code or "").strip()
            for code in (permission_codes or [])
            if (code or "").strip()
            and (code or "").strip().lower() not in AUTH_PERMISSION_DEPRECATED_CODES_LOWER
        }
    )
    return {
        "id": int(session_row.get("user_id") or 0),
        "session_id": int(session_row.get("session_id") or 0),
        "username": (session_row.get("username") or "").strip(),
        "email": (session_row.get("email") or "").strip(),
        "full_name": (session_row.get("full_name") or "").strip(),
        "role_id": int(session_row.get("role_id") or 0),
        "role_name": (session_row.get("role_name") or "").strip(),
        "must_change_password": bool(session_row.get("must_change_password")),
        "is_active": bool(session_row.get("is_active")),
        "last_seen_at": (session_row.get("last_seen_at") or "").strip(),
        "permission_codes": permission_codes,
    }


def _auth_login_redirect_target(next_value: str):
    next_value = (next_value or "").strip()
    if not next_value:
        return "/"
    if next_value.startswith("http://") or next_value.startswith("https://"):
        return "/"
    if not next_value.startswith("/"):
        return "/"
    return next_value


@app.middleware("http")
async def auth_guard_middleware(request: Request, call_next):
    path = (request.url.path or "/").strip() or "/"
    request.state.current_user = None
    request.state.auth_enabled = True
    request.state.auth_permission_codes = []

    if request.method.upper() == "OPTIONS":
        return await call_next(request)

    try:
        system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    except Exception:
        system_settings = normalize_system_settings({})
    auth_cfg = (system_settings.get("auth") or {}) if isinstance(system_settings, dict) else {}
    auth_enabled = bool(auth_cfg.get("enabled", True))
    request.state.auth_enabled = auth_enabled
    _auth_prune_audit_logs_if_due(system_settings)

    if not auth_enabled:
        return await call_next(request)

    if _auth_is_public_path(path):
        if path in ("/setup-admin", "/setup-owner") and count_auth_users() > 0:
            return RedirectResponse(url="/login", status_code=303)
        return await call_next(request)

    cookie_token = (request.cookies.get(AUTH_COOKIE_NAME) or "").strip()
    clear_cookie = False
    user_ctx = None
    if cookie_token:
        token_hash = _auth_hash_session_token(cookie_token)
        session_row = get_auth_session(token_hash)
        if session_row and bool(session_row.get("is_active")):
            now_dt = _auth_now_utc().replace(tzinfo=timezone.utc)
            last_seen_dt = _auth_parse_iso(session_row.get("last_seen_at"))
            expires_dt = _auth_parse_iso(session_row.get("expires_at"))
            try:
                idle_hours = int(auth_cfg.get("session_idle_hours") or 8)
            except Exception:
                idle_hours = 8
            idle_hours = max(1, min(idle_hours, 72))
            expired = False
            if expires_dt and now_dt >= expires_dt:
                expired = True
            if last_seen_dt and (now_dt - last_seen_dt) > timedelta(hours=idle_hours):
                expired = True
            if expired:
                revoke_auth_session(token_hash)
                clear_cookie = True
            else:
                permission_codes = get_auth_user_permission_codes(session_row.get("user_id"))
                user_ctx = _auth_build_user_context(session_row, permission_codes)
                request.state.current_user = user_ctx
                request.state.auth_permission_codes = list(user_ctx.get("permission_codes") or [])
                if not last_seen_dt or (now_dt - last_seen_dt).total_seconds() >= _AUTH_TOUCH_INTERVAL_SECONDS:
                    try:
                        touch_auth_session(
                            user_ctx.get("session_id"),
                            at_iso=_auth_now_iso(),
                            ip_address=_auth_client_ip(request),
                            user_agent=(request.headers.get("user-agent") or "")[:255],
                        )
                    except Exception:
                        pass
        else:
            clear_cookie = bool(cookie_token)

    if not user_ctx:
        response = _auth_unauthorized_response(request)
        if clear_cookie:
            response.delete_cookie(AUTH_COOKIE_NAME, path="/")
        return response

    force_change_paths = {"/account/change-password", "/logout"}
    if user_ctx.get("must_change_password") and path not in force_change_paths:
        if request.method != "GET" or _auth_wants_json(request):
            response = JSONResponse({"ok": False, "error": "Password change required."}, status_code=403)
        else:
            response = RedirectResponse(url="/account/change-password", status_code=303)
        if clear_cookie:
            response.delete_cookie(AUTH_COOKIE_NAME, path="/")
        return response

    required_permission = _auth_permission_for_route(path, request.method)
    if required_permission and not _auth_check_permission(user_ctx.get("permission_codes"), required_permission):
        response = _auth_forbidden_response(request, required_permission)
        if clear_cookie:
            response.delete_cookie(AUTH_COOKIE_NAME, path="/")
        return response

    response = await call_next(request)
    if clear_cookie:
        response.delete_cookie(AUTH_COOKIE_NAME, path="/")
    return response


def _runtime_feature_from_path(path: str):
    value = (path or "").strip().lower()
    if not value:
        return ""
    if value.startswith("/static/") or value == "/favicon.ico":
        return ""
    if value.startswith("/surveillance"):
        return "Under Surveillance"
    if value.startswith("/accounts-ping") or value.startswith("/settings/accounts-ping"):
        return "Accounts Ping"
    if value.startswith("/accounts-missing") or value.startswith("/settings/accounts-missing"):
        return "Missing Secrets"
    if value.startswith("/settings/wan") or value.startswith("/wan"):
        return "WAN Ping"
    if value.startswith("/settings/isp-status") or value.startswith("/isp-status"):
        return "ISP Port Status"
    if value.startswith("/settings/optical") or value.startswith("/optical"):
        return "Optical Monitoring"
    if value.startswith("/usage") or value.startswith("/settings/usage"):
        return "Usage"
    if value.startswith("/offline") or value.startswith("/settings/offline"):
        return "Offline"
    return "Dashboard/API"


@app.middleware("http")
async def runtime_feature_cpu_middleware(request: Request, call_next):
    feature = _runtime_feature_from_path(request.url.path)
    start = time.thread_time() if feature else 0.0
    try:
        return await call_next(request)
    finally:
        if feature:
            add_feature_cpu(feature, max(time.thread_time() - start, 0.0))


@app.on_event("startup")
async def startup_event():
    init_db()
    try:
        _auth_ensure_owner_user_assignment()
    except Exception:
        pass
    try:
        _auth_sync_builtin_role_permissions()
    except Exception:
        pass
    try:
        _auth_sync_centralized_danger_role_permissions()
    except Exception:
        pass
    jobs_manager.start()

    def _startup_prewarm():
        try:
            _prewarm_surveillance_checker_cache()
        except Exception:
            pass
        try:
            job_status = {item["job_name"]: dict(item) for item in get_job_status()}
            _get_dashboard_kpis_cached(job_status, force=True)
        except Exception:
            pass
        try:
            _prewarm_optical_status_cache()
        except Exception:
            pass

    threading.Thread(target=_startup_prewarm, daemon=True).start()


@app.on_event("shutdown")
async def shutdown_event():
    jobs_manager.stop()


def make_context(request, extra=None):
    ctx = {"request": request}
    current_user = getattr(request.state, "current_user", None)
    if isinstance(current_user, dict):
        perms = sorted({(p or "").strip() for p in (current_user.get("permission_codes") or []) if (p or "").strip()})
        current_user = {**current_user, "permission_codes": perms}
    else:
        current_user = None
        perms = []
    perm_set = set(perms)
    ctx["current_user"] = current_user
    ctx["auth_enabled"] = bool(getattr(request.state, "auth_enabled", True))
    ctx["auth_permission_codes"] = perms
    ctx["has_perm"] = lambda code: _auth_check_permission(perm_set, (code or "").strip())
    ctx["can_view_logs_page"] = _auth_can_view_logs_page(perm_set)
    ctx["can_view_system_logs_page"] = bool(
        _auth_allowed_log_categories(perm_set)
        or _auth_check_permission(perm_set, "logs.system.view")
        or _auth_check_permission(perm_set, "logs.timeline.view")
    )
    try:
        system_settings = get_settings("system", SYSTEM_DEFAULTS)
        branding = system_settings.get("branding") or {}

        company_logo = branding.get("company_logo") or {}
        company_logo_path = (company_logo.get("path") or "").strip()
        if company_logo_path and os.path.isfile(company_logo_path):
            version = urllib.parse.quote((company_logo.get("updated_at") or "").strip() or str(int(os.path.getmtime(company_logo_path))))
            ctx["company_logo_url"] = f"/company-logo?v={version}"
        else:
            ctx["company_logo_url"] = ""

        browser_logo = branding.get("browser_logo") or {}
        browser_logo_path = (browser_logo.get("path") or "").strip()
        if browser_logo_path and os.path.isfile(browser_logo_path):
            version = urllib.parse.quote((browser_logo.get("updated_at") or "").strip() or str(int(os.path.getmtime(browser_logo_path))))
            ctx["browser_logo_url"] = f"/browser-logo?v={version}"
            ctx["browser_logo_type"] = (browser_logo.get("content_type") or "").strip() or "image/png"
        else:
            ctx["browser_logo_url"] = ""
            ctx["browser_logo_type"] = ""
    except Exception:
        ctx["company_logo_url"] = ""
        ctx["browser_logo_url"] = ""
        ctx["browser_logo_type"] = ""
    try:
        surv = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
        entries = surv.get("entries") if isinstance(surv.get("entries"), list) else []
        index = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            key = (entry.get("pppoe") or "").strip()
            if not key:
                continue
            index[key] = _resolve_surveillance_ai_stage(entry)
        ctx["surveillance_index"] = index
        ctx["surveillance_count"] = len(index)
    except Exception:
        ctx["surveillance_index"] = {}
        ctx["surveillance_count"] = 0
    if extra:
        ctx.update(extra)
    return ctx


def _offline_nav_entry_id(row):
    if not isinstance(row, dict):
        return ""
    pppoe = (row.get("pppoe") or "").strip().lower()
    if not pppoe:
        return ""
    router_id = (row.get("router_id") or "").strip().lower()
    mode = (row.get("mode") or "offline").strip().lower()
    return f"{router_id or mode}|{pppoe}"


def _offline_account_matches(row, pppoe, router_id="", mode=""):
    if not isinstance(row, dict):
        return False
    pppoe_key = (pppoe or "").strip().lower()
    if not pppoe_key or (row.get("pppoe") or "").strip().lower() != pppoe_key:
        return False
    router_key = (router_id or "").strip().lower()
    row_router_key = (row.get("router_id") or "").strip().lower()
    if router_key:
        return row_router_key == router_key
    if row_router_key:
        return False
    mode_key = (mode or "offline").strip().lower() or "offline"
    row_mode_key = (row.get("mode") or "offline").strip().lower() or "offline"
    return row_mode_key == mode_key


def _collect_offline_current_keyed_map(offline_state):
    state = offline_state if isinstance(offline_state, dict) else {}
    tracker = state.get("tracker") if isinstance(state.get("tracker"), dict) else {}
    current_rows = state.get("rows") if isinstance(state.get("rows"), list) else []
    merged = {}

    def _merge_candidate(candidate):
        if not isinstance(candidate, dict):
            return
        entry_id = _offline_nav_entry_id(candidate)
        if not entry_id:
            return
        row = {
            "pppoe": (candidate.get("pppoe") or "").strip(),
            "router_id": (candidate.get("router_id") or "").strip(),
            "router_name": (candidate.get("router_name") or candidate.get("router_id") or "").strip(),
            "mode": (candidate.get("mode") or state.get("mode") or "").strip() or "secrets",
            "service_profile": (candidate.get("profile") or "").strip(),
            "disabled": bool(candidate.get("disabled")) if candidate.get("disabled") is not None else None,
            "last_logged_out": (candidate.get("last_logged_out") or "").strip(),
            "radius_status": (candidate.get("radius_status") or "").strip(),
            "offline_since_iso": (candidate.get("offline_since") or "").strip(),
            "last_offline_at_iso": (candidate.get("last_offline_at") or "").strip(),
            "listed": bool(candidate.get("listed")),
            "status": "offline" if bool(candidate.get("listed")) else "tracking",
        }
        existing = merged.get(entry_id)
        if not existing:
            merged[entry_id] = row
            return
        existing_score = (
            1 if existing.get("listed") else 0,
            existing.get("offline_since_iso") or "",
            existing.get("last_offline_at_iso") or "",
        )
        row_score = (
            1 if row.get("listed") else 0,
            row.get("offline_since_iso") or "",
            row.get("last_offline_at_iso") or "",
        )
        if row_score > existing_score:
            merged[entry_id] = row
            return
        for field in (
            "router_id",
            "router_name",
            "mode",
            "service_profile",
            "last_logged_out",
            "radius_status",
            "offline_since_iso",
            "last_offline_at_iso",
        ):
            if row.get(field) and not existing.get(field):
                existing[field] = row.get(field)
        if existing.get("disabled") is None and row.get("disabled") is not None:
            existing["disabled"] = row.get("disabled")
        if row.get("listed"):
            existing["listed"] = True
            existing["status"] = "offline"

    for item in tracker.values():
        if not isinstance(item, dict):
            continue
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        _merge_candidate(
            {
                **meta,
                "mode": item.get("mode") or state.get("mode") or "",
                "offline_since": item.get("first_offline_at"),
                "last_offline_at": item.get("last_offline_at"),
                "listed": bool(item.get("listed")),
            }
        )

    for row in current_rows:
        if not isinstance(row, dict):
            continue
        _merge_candidate({**row, "listed": True})

    return merged


def _usage_nav_entry_id(row):
    if not isinstance(row, dict):
        return ""
    pppoe = (row.get("pppoe") or "").strip().lower()
    if not pppoe:
        return ""
    router_id = (row.get("router_id") or "").strip().lower()
    return f"{router_id or 'usage'}|{pppoe}"


def _surveillance_nav_entry_id(entry):
    if not isinstance(entry, dict):
        return ""
    pppoe = (entry.get("pppoe") or "").strip().lower()
    if not pppoe:
        return ""
    added_at = (entry.get("added_at") or entry.get("first_added_at") or "").strip()
    if not added_at:
        return pppoe
    return f"{pppoe}|{added_at}"


def _accounts_missing_nav_entry_id(entry):
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("pppoe") or "").strip().lower()


def _accounts_missing_current_entry_ids(state):
    current_ids = []
    seen = set()
    raw_entries = state.get("missing_entries") if isinstance(state, dict) else []
    for entry in raw_entries if isinstance(raw_entries, list) else []:
        entry_id = _accounts_missing_nav_entry_id(entry)
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        current_ids.append(entry_id)
    return current_ids


def _offline_current_entry_ids(rule_views):
    current_ids = []
    seen = set()
    rows_by_rule = rule_views.get("rows_by_rule") if isinstance(rule_views, dict) else {}
    for rows in rows_by_rule.values() if isinstance(rows_by_rule, dict) else []:
        if not isinstance(rows, list):
            continue
        for row in rows:
            entry_id = _offline_nav_entry_id(row)
            if not entry_id or entry_id in seen:
                continue
            seen.add(entry_id)
            current_ids.append(entry_id)
    return current_ids


def _surveillance_new_viewer_key(request: Request) -> str:
    if not bool(getattr(request.state, "auth_enabled", True)):
        return "anon"
    current_user = getattr(request.state, "current_user", None)
    if not isinstance(current_user, dict):
        return ""
    try:
        user_id = int(current_user.get("id") or 0)
    except Exception:
        user_id = 0
    if user_id <= 0:
        return ""
    return f"user:{user_id}"


def _normalize_surveillance_new_seen_state(raw_state):
    out = {"users": {}}
    raw_users = raw_state.get("users") if isinstance(raw_state, dict) else {}
    if not isinstance(raw_users, dict):
        return out
    for raw_viewer_key, raw_user_state in raw_users.items():
        viewer_key = str(raw_viewer_key or "").strip()
        if not viewer_key:
            continue
        user_state = raw_user_state if isinstance(raw_user_state, dict) else {}
        entries = {}
        raw_entries = user_state.get("entries")
        if isinstance(raw_entries, dict):
            for raw_entry_id, raw_seen_at in raw_entries.items():
                entry_id = str(raw_entry_id or "").strip()
                if not entry_id:
                    continue
                entries[entry_id] = str(raw_seen_at or "").strip()
        out["users"][viewer_key] = {
            "seeded_at": str(user_state.get("seeded_at") or "").strip(),
            "entries": entries,
        }
    return out


def _load_surveillance_new_seen_state():
    return _normalize_surveillance_new_seen_state(get_state(_SURVEILLANCE_NEW_SEEN_STATE_KEY, {}))


def _save_surveillance_new_seen_state(state):
    save_state(_SURVEILLANCE_NEW_SEEN_STATE_KEY, _normalize_surveillance_new_seen_state(state))


def _surveillance_new_ids_for_request(request: Request, current_entry_ids, seed_if_needed: bool = True):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    current_ids = []
    seen = set()
    for raw_entry_id in current_entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        current_ids.append(entry_id)

    changed = False
    with _surveillance_new_seen_lock:
        state = _load_surveillance_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": "", "entries": {}}
            users[viewer_key] = user_state
            changed = True

        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
            changed = True

        current_set = set(current_ids)
        pruned_entries = {
            entry_id: str(seen_at or "").strip()
            for entry_id, seen_at in entries.items()
            if str(entry_id or "").strip() in current_set
        }
        if pruned_entries != entries:
            user_state["entries"] = pruned_entries
            entries = pruned_entries
            changed = True
        else:
            entries = pruned_entries

        seeded_at = str(user_state.get("seeded_at") or "").strip()
        if seed_if_needed and not seeded_at:
            seeded_at = utc_now_iso()
            user_state["seeded_at"] = seeded_at
            user_state["entries"] = {entry_id: seeded_at for entry_id in current_ids}
            entries = user_state["entries"]
            changed = True

        new_ids = [entry_id for entry_id in current_ids if entry_id not in entries]
        if changed:
            _save_surveillance_new_seen_state(state)
    return new_ids


def _load_accounts_missing_new_seen_state():
    return _normalize_surveillance_new_seen_state(get_state(_ACCOUNTS_MISSING_NEW_SEEN_STATE_KEY, {}))


def _save_accounts_missing_new_seen_state(state):
    save_state(_ACCOUNTS_MISSING_NEW_SEEN_STATE_KEY, _normalize_surveillance_new_seen_state(state))


def _accounts_missing_new_ids_for_request(request: Request, current_entry_ids, seed_if_needed: bool = True):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    current_ids = []
    seen = set()
    for raw_entry_id in current_entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        current_ids.append(entry_id)

    changed = False
    with _accounts_missing_new_seen_lock:
        state = _load_accounts_missing_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": "", "entries": {}}
            users[viewer_key] = user_state
            changed = True

        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
            changed = True

        current_set = set(current_ids)
        pruned_entries = {
            entry_id: str(seen_at or "").strip()
            for entry_id, seen_at in entries.items()
            if str(entry_id or "").strip() in current_set
        }
        if pruned_entries != entries:
            user_state["entries"] = pruned_entries
            entries = pruned_entries
            changed = True
        else:
            entries = pruned_entries

        seeded_at = str(user_state.get("seeded_at") or "").strip()
        if seed_if_needed and not seeded_at:
            seeded_at = utc_now_iso()
            user_state["seeded_at"] = seeded_at
            user_state["entries"] = {entry_id: seeded_at for entry_id in current_ids}
            entries = user_state["entries"]
            changed = True

        new_ids = [entry_id for entry_id in current_ids if entry_id not in entries]
        if changed:
            _save_accounts_missing_new_seen_state(state)
    return new_ids


def _mark_surveillance_new_entries_seen(request: Request, entry_ids):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    normalized_ids = []
    seen = set()
    for raw_entry_id in entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        normalized_ids.append(entry_id)
    if not normalized_ids:
        return []

    seen_at = utc_now_iso()
    with _surveillance_new_seen_lock:
        state = _load_surveillance_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": seen_at, "entries": {}}
            users[viewer_key] = user_state
        if not str(user_state.get("seeded_at") or "").strip():
            user_state["seeded_at"] = seen_at
        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
        for entry_id in normalized_ids:
            entries[entry_id] = seen_at
        _save_surveillance_new_seen_state(state)
    return normalized_ids


def _mark_accounts_missing_new_entries_seen(request: Request, entry_ids):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    normalized_ids = []
    seen = set()
    for raw_entry_id in entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        normalized_ids.append(entry_id)
    if not normalized_ids:
        return []

    seen_at = utc_now_iso()
    with _accounts_missing_new_seen_lock:
        state = _load_accounts_missing_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": seen_at, "entries": {}}
            users[viewer_key] = user_state
        if not str(user_state.get("seeded_at") or "").strip():
            user_state["seeded_at"] = seen_at
        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
        for entry_id in normalized_ids:
            entries[entry_id] = seen_at
        _save_accounts_missing_new_seen_state(state)
    return normalized_ids


def _load_offline_new_seen_state():
    return _normalize_surveillance_new_seen_state(get_state(_OFFLINE_NEW_SEEN_STATE_KEY, {}))


def _save_offline_new_seen_state(state):
    save_state(_OFFLINE_NEW_SEEN_STATE_KEY, _normalize_surveillance_new_seen_state(state))


def _offline_new_ids_for_request(request: Request, current_entry_ids, seed_if_needed: bool = True):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    current_ids = []
    seen = set()
    for raw_entry_id in current_entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        current_ids.append(entry_id)

    changed = False
    with _offline_new_seen_lock:
        state = _load_offline_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": "", "entries": {}}
            users[viewer_key] = user_state
            changed = True

        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
            changed = True

        current_set = set(current_ids)
        pruned_entries = {
            entry_id: str(seen_at or "").strip()
            for entry_id, seen_at in entries.items()
            if str(entry_id or "").strip() in current_set
        }
        if pruned_entries != entries:
            user_state["entries"] = pruned_entries
            entries = pruned_entries
            changed = True
        else:
            entries = pruned_entries

        seeded_at = str(user_state.get("seeded_at") or "").strip()
        if seed_if_needed and not seeded_at:
            seeded_at = utc_now_iso()
            user_state["seeded_at"] = seeded_at
            user_state["entries"] = {entry_id: seeded_at for entry_id in current_ids}
            entries = user_state["entries"]
            changed = True

        new_ids = [entry_id for entry_id in current_ids if entry_id not in entries]
        if changed:
            _save_offline_new_seen_state(state)
    return new_ids


def _mark_offline_new_entries_seen(request: Request, entry_ids):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    normalized_ids = []
    seen = set()
    for raw_entry_id in entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        normalized_ids.append(entry_id)
    if not normalized_ids:
        return []

    seen_at = utc_now_iso()
    with _offline_new_seen_lock:
        state = _load_offline_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": seen_at, "entries": {}}
            users[viewer_key] = user_state
        if not str(user_state.get("seeded_at") or "").strip():
            user_state["seeded_at"] = seen_at
        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
        for entry_id in normalized_ids:
            entries[entry_id] = seen_at
        _save_offline_new_seen_state(state)
    return normalized_ids


def _load_usage_new_seen_state():
    return _normalize_surveillance_new_seen_state(get_state(_USAGE_NEW_SEEN_STATE_KEY, {}))


def _save_usage_new_seen_state(state):
    save_state(_USAGE_NEW_SEEN_STATE_KEY, _normalize_surveillance_new_seen_state(state))


def _usage_new_ids_for_request(request: Request, current_entry_ids, seed_if_needed: bool = True):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    current_ids = []
    seen = set()
    for raw_entry_id in current_entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        current_ids.append(entry_id)

    changed = False
    with _usage_new_seen_lock:
        state = _load_usage_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": "", "entries": {}}
            users[viewer_key] = user_state
            changed = True

        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
            changed = True

        current_set = set(current_ids)
        pruned_entries = {
            entry_id: str(seen_at or "").strip()
            for entry_id, seen_at in entries.items()
            if str(entry_id or "").strip() in current_set
        }
        if pruned_entries != entries:
            user_state["entries"] = pruned_entries
            entries = pruned_entries
            changed = True
        else:
            entries = pruned_entries

        seeded_at = str(user_state.get("seeded_at") or "").strip()
        if seed_if_needed and not seeded_at:
            seeded_at = utc_now_iso()
            user_state["seeded_at"] = seeded_at
            user_state["entries"] = {entry_id: seeded_at for entry_id in current_ids}
            entries = user_state["entries"]
            changed = True

        new_ids = [entry_id for entry_id in current_ids if entry_id not in entries]
        if changed:
            _save_usage_new_seen_state(state)
    return new_ids


def _mark_usage_new_entries_seen(request: Request, entry_ids):
    viewer_key = _surveillance_new_viewer_key(request)
    if not viewer_key:
        return []

    normalized_ids = []
    seen = set()
    for raw_entry_id in entry_ids or []:
        entry_id = str(raw_entry_id or "").strip()
        if not entry_id or entry_id in seen:
            continue
        seen.add(entry_id)
        normalized_ids.append(entry_id)
    if not normalized_ids:
        return []

    seen_at = utc_now_iso()
    with _usage_new_seen_lock:
        state = _load_usage_new_seen_state()
        users = state.setdefault("users", {})
        user_state = users.get(viewer_key)
        if not isinstance(user_state, dict):
            user_state = {"seeded_at": seen_at, "entries": {}}
            users[viewer_key] = user_state
        if not str(user_state.get("seeded_at") or "").strip():
            user_state["seeded_at"] = seen_at
        entries = user_state.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            user_state["entries"] = entries
        for entry_id in normalized_ids:
            entries[entry_id] = seen_at
        _save_usage_new_seen_state(state)
    return normalized_ids


def _sort_surveillance_rows_recent(rows, *fields):
    rows = list(rows or [])
    rows.sort(key=lambda row: (row.get("pppoe") or "").lower())

    def _primary(row):
        for field in fields:
            value = str((row or {}).get(field) or "").strip()
            if value:
                return value
        return ""

    rows.sort(key=_primary, reverse=True)
    return rows


def _json_no_store(payload, status_code=200):
    return JSONResponse(payload, status_code=status_code, headers=NO_STORE_HEADERS)


@app.get("/auth/ping", response_class=JSONResponse)
async def auth_ping(request: Request):
    current_user = getattr(request.state, "current_user", None)
    return _json_no_store(
        {
            "ok": True,
            "now": utc_now_iso(),
            "user": (current_user or {}).get("username", ""),
        }
    )


@app.get("/navigation/summary", response_class=JSONResponse)
async def navigation_summary(request: Request):
    payload = {
        "updated_at": utc_now_iso(),
        "offline": {"current_ids": [], "current_count": 0, "new_ids": [], "new_count": 0},
        "usage": {"current_ids": [], "current_count": 0, "new_ids": [], "new_count": 0},
        "accounts_missing": {"current_ids": [], "current_count": 0, "new_ids": [], "new_count": 0},
        "surveillance": {"under_ids": [], "under_count": 0, "new_ids": [], "new_count": 0},
        "isp_status": {"hundred_mbps_ids": [], "hundred_mbps_count": 0},
    }

    if not bool(getattr(request.state, "auth_enabled", True)) or _auth_request_has_permission(request, "offline.view"):
        try:
            offline_settings = normalize_offline_settings(get_settings("offline", OFFLINE_DEFAULTS))
            offline_state = get_state("offline_state", {})
            offline_rule_views = _build_offline_rule_views(offline_state, offline_settings)
            current_ids = _offline_current_entry_ids(offline_rule_views)
            new_ids = _offline_new_ids_for_request(request, current_ids, seed_if_needed=True)
            payload["offline"] = {
                "current_ids": current_ids,
                "current_count": len(current_ids),
                "new_ids": new_ids,
                "new_count": len(new_ids),
            }
        except Exception:
            pass

    if not bool(getattr(request.state, "auth_enabled", True)) or _auth_request_has_permission(request, "usage.view"):
        try:
            usage_settings = get_settings("usage", USAGE_DEFAULTS)
            usage_state = get_state("usage_state", {})
            usage_summary_data = _build_usage_summary_data(usage_settings, usage_state)
            current_ids = [
                str(row.get("entry_id") or "").strip()
                for row in (usage_summary_data.get("issues") or [])
                if str(row.get("entry_id") or "").strip()
            ]
            new_ids = _usage_new_ids_for_request(request, current_ids, seed_if_needed=True)
            payload["usage"] = {
                "current_ids": current_ids,
                "current_count": len(current_ids),
                "new_ids": new_ids,
                "new_count": len(new_ids),
            }
        except Exception:
            pass

    if not bool(getattr(request.state, "auth_enabled", True)) or _auth_request_has_permission(request, "surveillance.view"):
        try:
            surveillance_settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
            entry_map = _surveillance_entry_map(surveillance_settings)
            under_ids = []
            for entry in entry_map.values():
                if not isinstance(entry, dict):
                    continue
                if (entry.get("status") or "under").strip().lower() != "under":
                    continue
                if str(entry.get("last_fixed_at") or "").strip():
                    continue
                entry_id = _surveillance_nav_entry_id(entry)
                if entry_id:
                    under_ids.append(entry_id)
            new_ids = _surveillance_new_ids_for_request(request, under_ids, seed_if_needed=True)
            payload["surveillance"] = {
                "under_ids": under_ids,
                "under_count": len(under_ids),
                "new_ids": new_ids,
                "new_count": len(new_ids),
            }
        except Exception:
            pass

    if not bool(getattr(request.state, "auth_enabled", True)) or _auth_request_has_permission(request, "accounts_missing.view"):
        try:
            accounts_missing_state = get_state("accounts_missing_state", {})
            current_ids = _accounts_missing_current_entry_ids(accounts_missing_state)
            new_ids = _accounts_missing_new_ids_for_request(request, current_ids, seed_if_needed=True)
            payload["accounts_missing"] = {
                "current_ids": current_ids,
                "current_count": len(current_ids),
                "new_ids": new_ids,
                "new_count": len(new_ids),
            }
        except Exception:
            pass

    if not bool(getattr(request.state, "auth_enabled", True)) or _auth_request_has_permission(request, "isp_status.view"):
        try:
            state = get_state("isp_status_state", {})
            latest = state.get("latest") if isinstance(state.get("latest"), dict) else {}
            hundred_mbps_ids = [
                str(wan_id or "").strip()
                for wan_id, row in latest.items()
                if str(wan_id or "").strip()
                and isinstance(row, dict)
                and (row.get("capacity_status") or "").strip().lower() == "100m"
            ]
            payload["isp_status"] = {
                "hundred_mbps_ids": hundred_mbps_ids,
                "hundred_mbps_count": len(hundred_mbps_ids),
            }
        except Exception:
            pass

    return _json_no_store(payload)


def _render_login_page(request: Request, message: str = "", next_url: str = "/", username: str = "", mode: str = "login"):
    return templates.TemplateResponse(
        "login.html",
        make_context(
            request,
            {
                "message": (message or "").strip(),
                "next_url": _auth_login_redirect_target(next_url),
                "username": (username or "").strip(),
                "mode": (mode or "login").strip().lower(),
                "auth_user_count": count_auth_users(),
            },
        ),
    )


def _get_owner_role_id():
    owner_role = get_auth_role_by_name("owner")
    if not owner_role:
        owner_role = get_auth_role_by_name("admin")
    if not owner_role:
        raise ValueError("Owner role is not available.")
    return int(owner_role.get("id") or 0)


def _auth_ensure_owner_user_assignment():
    if count_auth_users() <= 0:
        return
    owner_role = get_auth_role_by_name("owner")
    if not owner_role:
        return
    try:
        owner_role_id = int(owner_role.get("id") or 0)
    except Exception:
        owner_role_id = 0
    if owner_role_id <= 0:
        return
    users = list_auth_users() or []
    for user in users:
        if str(user.get("role_name") or "").strip().lower() == "owner":
            return
    valid_users = [user for user in users if int(user.get("id") or 0) > 0]
    if not valid_users:
        return
    first_user = min(valid_users, key=lambda item: int(item.get("id") or 0))
    try:
        update_auth_user(
            user_id=int(first_user.get("id") or 0),
            email=(first_user.get("email") or "").strip(),
            full_name=(first_user.get("full_name") or "").strip(),
            role_id=owner_role_id,
            is_active=bool(first_user.get("is_active")),
        )
    except Exception:
        return


@app.get("/setup-owner", response_class=HTMLResponse)
@app.get("/setup-admin", response_class=HTMLResponse)
async def setup_owner_page(request: Request):
    if count_auth_users() > 0:
        return RedirectResponse(url="/login", status_code=303)
    return _render_login_page(request, mode="setup")


@app.post("/setup-owner", response_class=HTMLResponse)
@app.post("/setup-admin", response_class=HTMLResponse)
async def setup_owner_submit(request: Request):
    if count_auth_users() > 0:
        return RedirectResponse(url="/login", status_code=303)
    form = await request.form()
    username = (form.get("username") or "").strip()
    full_name = (form.get("full_name") or "").strip()
    email = (form.get("email") or "").strip().lower()
    password = (form.get("password") or "").strip()
    confirm = (form.get("confirm_password") or "").strip()

    if not username:
        return _render_login_page(request, "Username is required.", mode="setup", username=username)
    if len(password) < AUTH_PASSWORD_MIN_LENGTH:
        return _render_login_page(
            request,
            f"Password must be at least {AUTH_PASSWORD_MIN_LENGTH} characters.",
            mode="setup",
            username=username,
        )
    if password != confirm:
        return _render_login_page(request, "Password confirmation does not match.", mode="setup", username=username)
    try:
        owner_role_id = _get_owner_role_id()
        password_hash, password_salt = _auth_hash_password(password)
        create_auth_user(
            username=username,
            email=email,
            full_name=full_name,
            role_id=owner_role_id,
            password_hash=password_hash,
            password_salt=password_salt,
            must_change_password=False,
            is_active=True,
        )
    except Exception as exc:
        return _render_login_page(request, f"Failed to create owner user: {exc}", mode="setup", username=username)
    return _render_login_page(request, "Owner account created. You can now sign in.", mode="login", username=username)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    if count_auth_users() <= 0:
        return RedirectResponse(url="/setup-owner", status_code=303)
    current_user = getattr(request.state, "current_user", None)
    if isinstance(current_user, dict) and current_user.get("id"):
        return RedirectResponse(url=_auth_login_redirect_target(next), status_code=303)
    return _render_login_page(request, next_url=next, mode="login")


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request):
    if count_auth_users() <= 0:
        return RedirectResponse(url="/setup-owner", status_code=303)
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "").strip()
    next_url = _auth_login_redirect_target((form.get("next") or "/").strip() or "/")

    if not username or not password:
        return _render_login_page(request, "Username and password are required.", next_url=next_url, username=username)

    user = None
    if "@" in username:
        user = get_auth_user_by_email(username)
    if not user:
        user = get_auth_user_by_username(username)
    if not user:
        return _render_login_page(request, "Invalid username or password.", next_url=next_url, username=username)
    if not bool(user.get("is_active")):
        return _render_login_page(request, "Account is disabled. Contact administrator.", next_url=next_url, username=username)
    if not _auth_verify_password(password, user.get("password_hash"), user.get("password_salt")):
        return _render_login_page(request, "Invalid username or password.", next_url=next_url, username=username)

    token = secrets.token_urlsafe(48)
    token_hash = _auth_hash_session_token(token)
    now_iso = _auth_now_iso()
    expires_iso = (_auth_now_utc() + timedelta(days=30)).isoformat() + "Z"
    try:
        create_auth_session(
            token_hash=token_hash,
            user_id=user.get("id"),
            created_at=now_iso,
            expires_at=expires_iso,
            ip_address=_auth_client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
        touch_auth_user_login(user.get("id"), at_iso=now_iso)
        insert_auth_audit_log(
            timestamp=now_iso,
            user_id=int(user.get("id") or 0),
            username=(user.get("username") or "").strip(),
            action="auth.login",
            resource="/login",
            details="login successful",
            ip_address=_auth_client_ip(request),
        )
    except Exception:
        return _render_login_page(request, "Login failed due to a server error.", next_url=next_url, username=username)

    if bool(user.get("must_change_password")):
        target = "/account/change-password"
    else:
        target = next_url or "/"
    response = RedirectResponse(url=target, status_code=303)
    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        max_age=AUTH_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return response


@app.api_route("/logout", methods=["GET", "POST"], response_class=HTMLResponse)
async def logout_submit(request: Request):
    token = (request.cookies.get(AUTH_COOKIE_NAME) or "").strip()
    if token:
        token_hash = _auth_hash_session_token(token)
        session_row = get_auth_session(token_hash)
        try:
            revoke_auth_session(token_hash)
        except Exception:
            pass
        if session_row:
            try:
                insert_auth_audit_log(
                    timestamp=_auth_now_iso(),
                    user_id=int(session_row.get("user_id") or 0),
                    username=(session_row.get("username") or "").strip(),
                    action="auth.logout",
                    resource="/logout",
                    details="logout",
                    ip_address=_auth_client_ip(request),
                )
            except Exception:
                pass
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")
    return response


@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return _render_login_page(request, mode="forgot")


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password_submit(request: Request):
    form = await request.form()
    identity = (form.get("identity") or "").strip()
    if not identity:
        return _render_login_page(request, "Enter username or email.", mode="forgot")

    user = None
    if "@" in identity:
        user = get_auth_user_by_email(identity)
    if not user:
        user = get_auth_user_by_username(identity)

    if not user or not bool(user.get("is_active")):
        return _render_login_page(
            request,
            "If the account exists, a reset email was sent.",
            mode="forgot",
        )

    email = (user.get("email") or "").strip()
    if not email:
        return _render_login_page(
            request,
            "This account has no email address configured. Contact administrator.",
            mode="forgot",
        )

    temp_password = _auth_generate_temporary_password()
    temp_hash, temp_salt = _auth_hash_password(temp_password)
    try:
        set_auth_user_password(user.get("id"), temp_hash, temp_salt, must_change_password=True)
        revoke_auth_sessions_for_user(user.get("id"))
        system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
        app_name = _system_app_name(system_settings)
        _auth_send_email(
            system_settings,
            to_email=email,
            subject=f"{app_name} password reset",
            body_text=(
                f"Your {app_name} password was reset.\n\n"
                f"Username: {(user.get('username') or '').strip()}\n"
                f"Temporary password: {temp_password}\n\n"
                "Sign in and change your password immediately."
            ),
        )
        insert_auth_audit_log(
            timestamp=_auth_now_iso(),
            user_id=int(user.get("id") or 0),
            username=(user.get("username") or "").strip(),
            action="auth.password_reset_email_sent",
            resource="/forgot-password",
            details="temporary password issued",
            ip_address=_auth_client_ip(request),
        )
    except Exception as exc:
        return _render_login_page(
            request,
            f"Password reset failed: {exc}",
            mode="forgot",
        )

    return _render_login_page(
        request,
        "Reset email sent. Check your inbox for the temporary password.",
        mode="login",
        username=(user.get("username") or "").strip(),
    )


@app.get("/account/change-password", response_class=HTMLResponse)
async def account_change_password_page(request: Request):
    current_user = getattr(request.state, "current_user", None)
    if not isinstance(current_user, dict) or not current_user.get("id"):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "change_password.html",
        make_context(
            request,
            {
                "message": "",
            },
        ),
    )


@app.get("/account/profile", response_class=HTMLResponse)
async def account_profile_page(request: Request):
    current_user = getattr(request.state, "current_user", None)
    if not isinstance(current_user, dict) or not current_user.get("id"):
        return RedirectResponse(url="/login", status_code=303)
    user = get_auth_user_by_id(current_user.get("id")) or {}
    profile_user = {
        "username": (user.get("username") or current_user.get("username") or "").strip(),
        "full_name": (user.get("full_name") or current_user.get("full_name") or "").strip(),
        "email": (user.get("email") or current_user.get("email") or "").strip(),
        "role_name": (user.get("role_name") or current_user.get("role_name") or "").strip(),
        "last_login_at": (user.get("last_login_at") or "").strip(),
        "created_at": (user.get("created_at") or "").strip(),
    }
    return templates.TemplateResponse(
        "account_profile.html",
        make_context(
            request,
            {
                "profile_user": profile_user,
            },
        ),
    )


@app.post("/account/change-password", response_class=HTMLResponse)
async def account_change_password_submit(request: Request):
    current_user = getattr(request.state, "current_user", None)
    if not isinstance(current_user, dict) or not current_user.get("id"):
        return RedirectResponse(url="/login", status_code=303)
    form = await request.form()
    current_password = (form.get("current_password") or "").strip()
    new_password = (form.get("new_password") or "").strip()
    confirm_password = (form.get("confirm_password") or "").strip()

    user = get_auth_user_by_id(current_user.get("id"))
    if not user:
        response = RedirectResponse(url="/login", status_code=303)
        response.delete_cookie(AUTH_COOKIE_NAME, path="/")
        return response
    if not _auth_verify_password(current_password, user.get("password_hash"), user.get("password_salt")):
        return templates.TemplateResponse(
            "change_password.html",
            make_context(request, {"message": "Current password is incorrect."}),
        )
    if len(new_password) < AUTH_PASSWORD_MIN_LENGTH:
        return templates.TemplateResponse(
            "change_password.html",
            make_context(request, {"message": f"New password must be at least {AUTH_PASSWORD_MIN_LENGTH} characters."}),
        )
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "change_password.html",
            make_context(request, {"message": "Password confirmation does not match."}),
        )

    password_hash, password_salt = _auth_hash_password(new_password)
    now_iso = _auth_now_iso()
    try:
        set_auth_user_password(user.get("id"), password_hash, password_salt, must_change_password=False)
        revoke_auth_sessions_for_user(user.get("id"))
        token = secrets.token_urlsafe(48)
        create_auth_session(
            token_hash=_auth_hash_session_token(token),
            user_id=user.get("id"),
            created_at=now_iso,
            expires_at=(_auth_now_utc() + timedelta(days=30)).isoformat() + "Z",
            ip_address=_auth_client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
        insert_auth_audit_log(
            timestamp=now_iso,
            user_id=int(user.get("id") or 0),
            username=(user.get("username") or "").strip(),
            action="auth.password_changed",
            resource="/account/change-password",
            details="password updated by user",
            ip_address=_auth_client_ip(request),
        )
    except Exception as exc:
        return templates.TemplateResponse(
            "change_password.html",
            make_context(request, {"message": f"Password update failed: {exc}"}),
        )

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        max_age=AUTH_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return response


@app.get("/company-logo")
async def company_logo():
    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    company_logo = (system_settings.get("branding") or {}).get("company_logo") or {}
    logo_path = (company_logo.get("path") or "").strip()
    if not logo_path or not os.path.isfile(logo_path):
        return Response(status_code=404)
    media_type = (company_logo.get("content_type") or "").strip() or "application/octet-stream"
    return FileResponse(logo_path, media_type=media_type)


@app.get("/browser-logo")
async def browser_logo():
    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    browser_logo_cfg = (system_settings.get("branding") or {}).get("browser_logo") or {}
    logo_path = (browser_logo_cfg.get("path") or "").strip()
    if not logo_path or not os.path.isfile(logo_path):
        return Response(status_code=404)
    media_type = (browser_logo_cfg.get("content_type") or "").strip() or "application/octet-stream"
    return FileResponse(logo_path, media_type=media_type)


def run_host_command(script, timeout_seconds=60):
    def run_cmd(cmd, timeout_seconds=30):
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return None

    docker_path = None
    for candidate in ("/usr/bin/docker", "/usr/local/bin/docker"):
        if os.path.exists(candidate):
            docker_path = candidate
            break
    if docker_path is None:
        docker_path = shutil.which("docker")
    if docker_path:
        command = (
            f"{docker_path} run --rm --privileged --pid=host --network host "
            "-v /:/host "
            "ubuntu bash -c "
            f"\"chroot /host bash -c {shlex.quote(script)}\""
        )
        result = run_cmd(["/bin/sh", "-c", command], timeout_seconds=timeout_seconds)
        if result is None:
            return False, "Host command timed out."
        if result.returncode != 0:
            stderr = (result.stderr or result.stdout or "").strip()
            return False, f"Host command failed: {stderr}"
        return True, (result.stdout or "").strip()

    sock = "/var/run/docker.sock"
    if not os.path.exists(sock):
        return False, "Host command skipped (docker socket not available)."
    if not shutil.which("curl"):
        return False, "Host command skipped (curl not available in container)."

    pull_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        "http://localhost/images/create?fromImage=ubuntu&tag=latest",
    ]
    pulled = run_cmd(pull_cmd, timeout_seconds=timeout_seconds)
    if pulled is None:
        return False, "Host command timed out."
    if pulled.returncode != 0:
        return False, f"Host command failed: {pulled.stderr.strip() or pulled.stdout.strip()}"

    payload = {
        "Image": "ubuntu",
        "Cmd": [
            "bash",
            "-c",
            f"chroot /host bash -c {shlex.quote(script)} 2>&1",
        ],
        "Tty": True,
        "HostConfig": {
            "Privileged": True,
            "Binds": ["/:/host"],
            "AutoRemove": False,
            "PidMode": "host",
            "NetworkMode": "host",
        },
    }
    create_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-H",
        "Content-Type: application/json",
        "-X",
        "POST",
        "-d",
        json.dumps(payload),
        "http://localhost/containers/create",
    ]
    created = run_cmd(create_cmd, timeout_seconds=timeout_seconds)
    if created is None or created.returncode != 0:
        return False, f"Host command failed: {created.stderr.strip() if created else 'timeout'}"
    try:
        container_id = json.loads(created.stdout).get("Id")
    except json.JSONDecodeError:
        container_id = None
    if not container_id:
        return False, f"Host command failed: {created.stdout.strip()}"

    start_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/start",
    ]
    started = run_cmd(start_cmd, timeout_seconds=timeout_seconds)
    if started is None or started.returncode != 0:
        return False, f"Host command failed: {started.stderr.strip() if started else 'timeout'}"

    wait_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/wait",
    ]
    waited = run_cmd(wait_cmd, timeout_seconds=timeout_seconds)
    status = 1
    if waited and waited.returncode == 0:
        try:
            status = json.loads(waited.stdout).get("StatusCode", 1)
        except json.JSONDecodeError:
            status = 1
    logs_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        f"http://localhost/containers/{container_id}/logs?stdout=1&stderr=1",
    ]
    logged = run_cmd(logs_cmd, timeout_seconds=timeout_seconds)
    logs_output = ""
    if logged and logged.returncode == 0:
        logs_output = (logged.stdout or "").strip()

    delete_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "DELETE",
        f"http://localhost/containers/{container_id}?force=1",
    ]
    run_cmd(delete_cmd)

    if status != 0:
        detail = logs_output or f"container exit {status}"
        return False, f"Host command failed: {detail}"
    return True, logs_output


def _system_update_host_repo() -> str:
    return (os.environ.get("THREEJ_HOST_REPO") or "/opt/threejnotif").strip() or "/opt/threejnotif"


def _system_update_normalize_remote_url(remote_url: str) -> str:
    url = str(remote_url or "").strip()
    if not url:
        return ""
    lowered = url.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return url
    if url.startswith("git@") and ":" in url:
        host_part, path_part = url[4:].split(":", 1)
        host_part = host_part.strip()
        path_part = path_part.strip().lstrip("/")
        if host_part and path_part:
            return f"https://{host_part}/{path_part}"
    if lowered.startswith("ssh://"):
        parsed = urllib.parse.urlparse(url)
        host_part = (parsed.hostname or "").strip()
        path_part = (parsed.path or "").strip().lstrip("/")
        if host_part and path_part:
            return f"https://{host_part}/{path_part}"
    return url


def _system_update_preferred_source(remote_url: str = "") -> str:
    override = str(os.environ.get("THREEJ_REPO_URL") or "").strip()
    if override:
        return override
    normalized = _system_update_normalize_remote_url(remote_url)
    return normalized or str(remote_url or "").strip() or "https://github.com/Jess-is-it/threejmon.git"


def _system_update_branch_name() -> str:
    return (str(os.environ.get("THREEJ_BRANCH") or "").strip() or "master")


def _system_update_git_commit_info(repo_path: str = "", ref: str = "HEAD") -> dict:
    repo_path = (str(repo_path or "").strip() or _system_update_host_repo())
    ref = (str(ref or "").strip() or "HEAD")
    info = {"full": "", "short": "", "date": ""}
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", ref],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return info
        full_sha = str(result.stdout or "").strip()
        if not full_sha or full_sha.lower() == "head":
            return info
        info["full"] = full_sha
        info["short"] = full_sha[:7]
    except Exception:
        return info
    try:
        date_result = subprocess.run(
            ["git", "-C", repo_path, "show", "-s", "--format=%cI", info["full"]],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if date_result.returncode == 0:
            info["date"] = str(date_result.stdout or "").strip()[:10]
    except Exception:
        pass
    return info


def _system_update_host_git_commit_info(repo_path: str = "") -> dict:
    repo_path = (str(repo_path or "").strip() or _system_update_host_repo())
    now = time.time()
    cached = SYSTEM_UPDATE_INSTALLED_VERSION_CACHE
    cached_value = cached.get("value")
    if (
        cached.get("repo_path") == repo_path
        and float(cached.get("expires_at") or 0.0) > now
        and isinstance(cached_value, dict)
    ):
        return dict(cached_value)

    info = {"full": "", "short": "", "date": ""}
    script = "\n".join(
        [
            "set -e",
            f"repo={shlex.quote(repo_path)}",
            'full=$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)',
            'date=$(git -C "$repo" show -s --format=%cI "$full" 2>/dev/null || true)',
            'printf "%s\\n%s\\n" "$full" "$date"',
        ]
    )
    ok, output = run_host_command(script, timeout_seconds=15)
    if ok:
        lines = str(output or "").splitlines()
        full_sha = str(lines[0] if lines else "").strip()
        if full_sha and full_sha.lower() != "head":
            info["full"] = full_sha
            info["short"] = full_sha[:7]
            info["date"] = str(lines[1] if len(lines) > 1 else "").strip()[:10]

    ttl = SYSTEM_UPDATE_INSTALLED_CACHE_SECONDS if info.get("full") else 30
    SYSTEM_UPDATE_INSTALLED_VERSION_CACHE.update(
        {"repo_path": repo_path, "expires_at": now + ttl, "value": dict(info)}
    )
    return info


def _system_update_version_file_info(repo_path: str = "") -> dict:
    repo_path = (str(repo_path or "").strip() or _system_update_host_repo())
    info = {"full": "", "short": "", "date": ""}
    candidates = []
    if repo_path:
        candidates.append(Path(repo_path) / ".threej_version")
    candidates.append(BASE_DIR.parent / ".threej_version")
    for version_path in candidates:
        try:
            if not version_path.is_file():
                continue
            parts = version_path.read_text(encoding="utf-8", errors="replace").strip().split()
            version = str(parts[0] if parts else "").strip()
            if not version or version.lower() == "unknown":
                continue
            info["full"] = version
            info["short"] = version[:7]
            info["date"] = str(parts[1] if len(parts) > 1 else "").strip()[:10]
            return info
        except Exception:
            continue
    return info


def _system_update_installed_version() -> dict:
    version = str(os.environ.get("THREEJ_VERSION") or "").strip()
    version_date = str(os.environ.get("THREEJ_VERSION_DATE") or "").strip()
    git_info = {"full": "", "short": "", "date": ""}
    version_info = _system_update_version_file_info()
    status = _read_system_update_status()

    if not version or version.lower() == "unknown":
        git_info = _system_update_git_commit_info()
        if not git_info.get("full") and not version_info.get("full"):
            git_info = _system_update_host_git_commit_info()
        version = (
            git_info.get("full")
            or version_info.get("full")
            or str(status.get("new_commit") or "").strip()
            or str(status.get("old_commit") or "").strip()
        )
    if not version_date or version_date.lower() == "unknown":
        version_date = (
            git_info.get("date")
            or version_info.get("date")
            or (status.get("updated_at") or "")[:10]
        )

    if not version or version.lower() == "unknown":
        return {"full": "", "short": "", "date": ""}
    return {
        "full": version,
        "short": version[:7],
        "date": version_date if version_date.lower() != "unknown" else "",
    }


def _system_update_github_repo(source_url: str) -> tuple[str, str]:
    normalized = _system_update_normalize_remote_url(source_url)
    if not normalized:
        return "", ""
    parsed = urllib.parse.urlparse(normalized)
    host = (parsed.netloc or "").strip().lower()
    path = (parsed.path or "").strip().lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [item for item in path.split("/") if item]
    if host != "github.com" or len(parts) < 2:
        return "", ""
    return parts[0], parts[1]


def _system_update_fetch_github_commits(source_url: str, branch: str, limit: int):
    owner, repo = _system_update_github_repo(source_url)
    if not owner or not repo:
        raise RuntimeError("Only GitHub repositories are supported for remote commit listing.")
    api_url = (
        f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/commits"
        f"?sha={urllib.parse.quote(branch)}&per_page={max(min(int(limit or 50), 100), 1)}"
    )
    request = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ThreeJNotifier-SystemUpdate",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"GitHub API returned HTTP {exc.code}.") from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch remote commits: {exc}") from exc
    if not isinstance(payload, list):
        raise RuntimeError("GitHub API returned an unexpected response.")
    commits = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        full_sha = str(item.get("sha") or "").strip()
        commit_obj = item.get("commit") if isinstance(item.get("commit"), dict) else {}
        author_obj = commit_obj.get("author") if isinstance(commit_obj.get("author"), dict) else {}
        message = str(commit_obj.get("message") or "").strip()
        subject = message.splitlines()[0].strip() if message else "No commit subject."
        commits.append(
            {
                "full": full_sha,
                "short": full_sha[:7] if full_sha else "",
                "date": str(author_obj.get("date") or "").strip()[:10],
                "author": str(author_obj.get("name") or "").strip(),
                "subject": subject,
            }
        )
    return commits


def _default_system_update_status():
    return {
        "status": "idle",
        "phase": "idle",
        "message": "",
        "step_index": 0,
        "step_total": 5,
        "percent": 0,
        "started_at": "",
        "updated_at": "",
        "branch": "",
        "old_commit": "",
        "new_commit": "",
        "remote_url": "",
        "trigger": "",
        "runner_id": "",
        "error": "",
    }


def _parse_system_update_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _normalize_system_update_status(payload):
    raw = payload if isinstance(payload, dict) else {}
    out = dict(_default_system_update_status())
    status = str(raw.get("status") or out["status"]).strip().lower()
    if status not in {"idle", "queued", "running", "done", "failed"}:
        status = "idle"
    out["status"] = status
    phase = str(raw.get("phase") or out["phase"]).strip().lower() or status
    out["phase"] = phase
    for key in ("message", "started_at", "updated_at", "branch", "old_commit", "new_commit", "remote_url", "trigger", "runner_id", "error"):
        out[key] = str(raw.get(key) or "").strip()
    try:
        out["step_total"] = max(int(raw.get("step_total") or out["step_total"]), 1)
    except Exception:
        out["step_total"] = _default_system_update_status()["step_total"]
    try:
        out["step_index"] = max(min(int(raw.get("step_index") or 0), out["step_total"]), 0)
    except Exception:
        out["step_index"] = 0
    try:
        percent = int(raw.get("percent") or 0)
    except Exception:
        percent = 0
    if percent <= 0 and out["step_total"] > 0:
        percent = int((out["step_index"] / out["step_total"]) * 100)
    out["percent"] = max(0, min(percent, 100))
    status_ts = _parse_system_update_timestamp(out["updated_at"] or out["started_at"])
    if out["status"] in {"queued", "running"} and status_ts:
        age_seconds = max((datetime.now(timezone.utc) - status_ts).total_seconds(), 0.0)
        if age_seconds > SYSTEM_UPDATE_STALE_SECONDS:
            out["status"] = "failed"
            out["phase"] = "failed"
            out["message"] = "Previous update state became stale. Check for updates again."
            if not out["error"]:
                out["error"] = "Updater status became stale."
    out["is_running"] = out["status"] in {"queued", "running"}
    return out


def _read_system_update_status():
    try:
        if SYSTEM_UPDATE_STATUS_PATH.is_file():
            return _normalize_system_update_status(json.loads(SYSTEM_UPDATE_STATUS_PATH.read_text(encoding="utf-8")))
    except Exception:
        pass
    return _normalize_system_update_status({})


def _write_system_update_status(payload):
    status = _normalize_system_update_status(payload)
    try:
        SYSTEM_UPDATE_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = SYSTEM_UPDATE_STATUS_PATH.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(status, ensure_ascii=True, indent=2), encoding="utf-8")
        tmp_path.replace(SYSTEM_UPDATE_STATUS_PATH)
    except Exception:
        pass
    return status


def _read_system_update_log_tail(max_bytes: int = SYSTEM_UPDATE_LOG_TAIL_BYTES) -> str:
    try:
        if not SYSTEM_UPDATE_LOG_PATH.is_file():
            return ""
        size = SYSTEM_UPDATE_LOG_PATH.stat().st_size
        with open(SYSTEM_UPDATE_LOG_PATH, "rb") as handle:
            if size > max_bytes:
                handle.seek(-max_bytes, os.SEEK_END)
            return handle.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _system_update_status_payload(include_log: bool = True):
    status = _read_system_update_status()
    if include_log:
        status["log_tail"] = _read_system_update_log_tail()
    return status


def _system_update_parse_check_output(output: str):
    info = {
        "repo_path": _system_update_host_repo(),
        "branch": "",
        "remote_url": "",
        "origin_url": "",
        "source_url": "",
        "current": {"full": "", "short": "", "date": ""},
        "latest": {"full": "", "short": "", "date": ""},
        "ahead": 0,
        "behind": 0,
        "has_update": False,
        "is_dirty": False,
        "dirty_files": [],
        "commits": [],
    }
    text = str(output or "")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\x1f")
        if not parts:
            continue
        tag = parts[0]
        if tag == "META" and len(parts) >= 3:
            key = parts[1]
            value = parts[2]
            if key == "branch":
                info["branch"] = value
            elif key == "remote_url":
                info["remote_url"] = value
            elif key == "origin_url":
                info["origin_url"] = value
            elif key == "source_url":
                info["source_url"] = value
            elif key == "local_full":
                info["current"]["full"] = value
            elif key == "local_short":
                info["current"]["short"] = value
            elif key == "local_date":
                info["current"]["date"] = value
            elif key == "remote_full":
                info["latest"]["full"] = value
            elif key == "remote_short":
                info["latest"]["short"] = value
            elif key == "remote_date":
                info["latest"]["date"] = value
            elif key == "ahead":
                try:
                    info["ahead"] = max(int(value or 0), 0)
                except Exception:
                    info["ahead"] = 0
            elif key == "behind":
                try:
                    info["behind"] = max(int(value or 0), 0)
                except Exception:
                    info["behind"] = 0
            elif key == "dirty":
                info["is_dirty"] = str(value or "").strip() == "1"
        elif tag == "DIRTY" and len(parts) >= 2:
            entry = parts[1].strip()
            if entry:
                info["dirty_files"].append(entry)
        elif tag == "COMMIT" and len(parts) >= 6:
            info["commits"].append(
                {
                    "full": parts[1].strip(),
                    "short": parts[2].strip(),
                    "date": parts[3].strip(),
                    "author": parts[4].strip(),
                    "subject": parts[5].strip(),
                }
            )
    current_full = info["current"]["full"]
    info["has_update"] = bool(info["latest"]["full"]) and bool(current_full) and current_full != info["latest"]["full"]
    current_index = -1
    for idx, item in enumerate(info["commits"]):
        if item.get("full") == current_full:
            current_index = idx
            break
    for idx, item in enumerate(info["commits"]):
        item["is_current"] = item.get("full") == current_full
        item["is_latest"] = idx == 0
        if item["is_current"]:
            item["state"] = "installed"
        elif current_index >= 0:
            item["state"] = "newer" if idx < current_index else "older"
        elif idx == 0:
            item["state"] = "latest"
        else:
            item["state"] = "available"
    return info


def _system_update_check_remote():
    branch = _system_update_branch_name()
    source_url = _system_update_preferred_source("")
    current = _system_update_installed_version()
    try:
        commits = _system_update_fetch_github_commits(source_url, branch, SYSTEM_UPDATE_CHECK_LIMIT)
    except Exception as exc:
        return False, str(exc or "").strip() or "Unable to check updates."
    latest = commits[0] if commits else {"full": "", "short": "", "date": ""}
    current_full = str(current.get("full") or "").strip()
    current_short = str(current.get("short") or "").strip()
    has_known_current = bool(current_full or current_short)
    has_update = bool(latest.get("full")) and has_known_current and not (
        (current_full and current_full == latest.get("full"))
        or (current_short and current_short == str(latest.get("short") or "").strip())
    )
    current_index = -1
    if current_full or current_short:
        for idx, item in enumerate(commits):
            full = str(item.get("full") or "").strip()
            short = str(item.get("short") or "").strip()
            if (current_full and full == current_full) or (current_short and short == current_short):
                current_index = idx
                break
    for idx, item in enumerate(commits):
        full = str(item.get("full") or "").strip()
        short = str(item.get("short") or "").strip()
        is_current = bool((current_full and full == current_full) or (current_short and short == current_short))
        item["is_current"] = is_current
        item["is_latest"] = idx == 0
        if is_current:
            item["state"] = "installed"
        elif current_index >= 0:
            item["state"] = "newer" if idx < current_index else "older"
        elif idx == 0:
            item["state"] = "latest"
        else:
            item["state"] = "available"
    info = {
        "repo_path": _system_update_host_repo(),
        "branch": branch,
        "remote_url": source_url,
        "origin_url": source_url,
        "source_url": source_url,
        "current": current,
        "latest": latest,
        "ahead": 0,
        "behind": 0,
        "has_update": has_update,
        "is_dirty": False,
        "dirty_files": [],
        "commits": commits,
    }
    return True, info


def _system_update_docker_path() -> str:
    for candidate in ("/usr/bin/docker", "/usr/local/bin/docker"):
        if os.path.exists(candidate):
            return candidate
    return shutil.which("docker") or ""


def _start_system_update_runner(check_info: dict, target_commit: str = "", allow_dirty: bool = False):
    docker_path = _system_update_docker_path()
    host_repo = _system_update_host_repo()
    host_status_file = f"{host_repo.rstrip('/')}/data/system_update_status.json"
    host_log_file = f"{host_repo.rstrip('/')}/data/system_update.log"
    branch = str((check_info or {}).get("branch") or "").strip() or "master"
    source_url = _system_update_preferred_source(
        str((check_info or {}).get("source_url") or (check_info or {}).get("remote_url") or "")
    )
    target_commit = str(target_commit or "").strip() or (((check_info or {}).get("latest") or {}).get("full") or "")
    target_short = target_commit[:7] if target_commit else ""
    queued = _write_system_update_status(
        {
            "status": "queued",
            "phase": "queued",
            "message": f"Update to {target_short or 'selected commit'} queued.",
            "step_index": 0,
            "step_total": 5,
            "percent": 0,
            "started_at": utc_now_iso(),
            "updated_at": utc_now_iso(),
            "branch": branch,
            "old_commit": ((check_info or {}).get("current") or {}).get("full") or "",
            "new_commit": target_commit,
            "remote_url": source_url or (check_info or {}).get("remote_url") or "",
            "trigger": "system-ui",
            "runner_id": "",
            "error": "",
        }
    )
    try:
        SYSTEM_UPDATE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        SYSTEM_UPDATE_LOG_PATH.write_text("", encoding="utf-8")
    except Exception:
        pass
    host_script = (
        f"mkdir -p {shlex.quote(os.path.dirname(host_status_file))} && "
        f": > {shlex.quote(host_log_file)} && "
        f"cd {shlex.quote(host_repo)} && "
        f"env THREEJ_STATUS_FILE={shlex.quote(host_status_file)} "
        f"THREEJ_UPDATE_TRIGGER=system-ui "
        f"THREEJ_BRANCH={shlex.quote(branch)} "
        f"THREEJ_REPO_URL={shlex.quote(source_url)} "
        f"THREEJ_TARGET_COMMIT={shlex.quote(target_commit)} "
        f"THREEJ_ALLOW_DIRTY={'1' if allow_dirty else '0'} "
        f"{shlex.quote(host_repo.rstrip('/') + '/update.sh')} >> {shlex.quote(host_log_file)} 2>&1"
    )
    runner_id = ""
    if docker_path:
        outer_command = (
            f"{shlex.quote(docker_path)} run -d --rm --privileged --pid=host --network host "
            f"-v /:/host ubuntu bash -lc "
            f"{shlex.quote(f'chroot /host /bin/bash -lc {shlex.quote(host_script)}')}"
        )
        result = subprocess.run(
            ["/bin/sh", "-c", outer_command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "Failed to start updater container.").strip())
        runner_id = (result.stdout or "").strip()
    else:
        sock = "/var/run/docker.sock"
        if not os.path.exists(sock):
            raise RuntimeError("docker is not available inside the application container.")
        if not shutil.which("curl"):
            raise RuntimeError("curl is required to start the updater container.")

        def _curl_cmd(args: list[str], timeout_seconds: int = 30):
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )

        pull_cmd = [
            "curl",
            "-sS",
            "--unix-socket",
            sock,
            "-X",
            "POST",
            "http://localhost/images/create?fromImage=ubuntu&tag=latest",
        ]
        pulled = _curl_cmd(pull_cmd, timeout_seconds=120)
        if pulled.returncode != 0:
            raise RuntimeError((pulled.stderr or pulled.stdout or "Unable to pull ubuntu image.").strip())

        payload = {
            "Image": "ubuntu",
            "Cmd": [
                "bash",
                "-lc",
                f"chroot /host /bin/bash -lc {shlex.quote(host_script)}",
            ],
            "HostConfig": {
                "Privileged": True,
                "Binds": ["/:/host"],
                "AutoRemove": True,
                "PidMode": "host",
                "NetworkMode": "host",
            },
        }
        create_cmd = [
            "curl",
            "-sS",
            "--unix-socket",
            sock,
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            "-d",
            json.dumps(payload),
            "http://localhost/containers/create",
        ]
        created = _curl_cmd(create_cmd, timeout_seconds=120)
        if created.returncode != 0:
            raise RuntimeError((created.stderr or created.stdout or "Unable to create updater container.").strip())
        try:
            runner_id = str((json.loads(created.stdout or "{}") or {}).get("Id") or "").strip()
        except Exception as exc:
            raise RuntimeError(f"Unable to parse updater container id: {exc}") from exc
        if not runner_id:
            raise RuntimeError((created.stdout or "Unable to create updater container.").strip())
        start_cmd = [
            "curl",
            "-sS",
            "--unix-socket",
            sock,
            "-X",
            "POST",
            f"http://localhost/containers/{runner_id}/start",
        ]
        started = _curl_cmd(start_cmd, timeout_seconds=120)
        if started.returncode != 0:
            delete_cmd = [
                "curl",
                "-sS",
                "--unix-socket",
                sock,
                "-X",
                "DELETE",
                f"http://localhost/containers/{runner_id}?force=1",
            ]
            try:
                _curl_cmd(delete_cmd)
            except Exception:
                pass
            raise RuntimeError((started.stderr or started.stdout or "Unable to start updater container.").strip())
    if runner_id:
        queued["runner_id"] = runner_id
        queued["updated_at"] = utc_now_iso()
        _write_system_update_status(queued)
    return queued


def normalize_pulsewatch_settings(settings):
    pulse = settings.setdefault("pulsewatch", {})
    pulse.setdefault("retention_days", 30)
    pulse.setdefault("rollup_retention_days", 365)
    dashboard = pulse.setdefault("dashboard", {})
    dashboard.setdefault("default_target", "all")
    dashboard.setdefault("refresh_seconds", 2)
    dashboard.setdefault("loss_history_minutes", 120)
    dashboard.setdefault("pie_default_days", 7)
    stability = pulse.setdefault("stability", {})
    stability.setdefault("stable_max_ms", 80)
    stability.setdefault("unstable_max_ms", 150)
    stability.setdefault("down_source", "wan")
    mikrotik = pulse.setdefault("mikrotik", {})
    cores = mikrotik.get("cores")
    if cores is None:
        cores = []
        core2 = mikrotik.get("core2")
        core3 = mikrotik.get("core3")
        if core2 is not None:
            cores.append(
                {
                    "id": "core2",
                    "label": "Core2",
                    "host": core2.get("host", ""),
                    "port": core2.get("port", 8728),
                    "username": core2.get("username", ""),
                    "password": core2.get("password", ""),
                }
            )
        if core3 is not None:
            cores.append(
                {
                    "id": "core3",
                    "label": "Core3",
                    "host": core3.get("host", ""),
                    "port": core3.get("port", 8728),
                    "username": core3.get("username", ""),
                    "password": core3.get("password", ""),
                }
            )
        mikrotik["cores"] = cores

    for idx, core in enumerate(cores, start=1):
        core.setdefault("id", f"core{idx}")
        core.setdefault("label", core["id"].upper())
        core.setdefault("host", "")
        core.setdefault("port", 8728)
        core.setdefault("username", "")
        core.setdefault("password", "")
        core.pop("interface", None)
        core.pop("prefix", None)
        core.pop("gateway", None)

    for isp in pulse.get("isps", []):
        sources = isp.get("sources")
        if not isinstance(sources, dict):
            sources = {}
        if not sources:
            core2_ip = isp.get("core2_source_ip")
            core3_ip = isp.get("core3_source_ip")
            if core2_ip:
                sources["core2"] = core2_ip
            if core3_ip:
                sources["core3"] = core3_ip
        isp["sources"] = sources
        if "ping_core_id" not in isp:
            ping_core = isp.get("ping_router")
            isp["ping_core_id"] = ping_core if ping_core in ("core2", "core3") else "auto"
    pulse.setdefault("list_presets", [])
    return settings


def normalize_wan_ping_settings(settings):
    settings.setdefault("enabled", False)
    telegram = settings.setdefault("telegram", {})
    telegram.setdefault("bot_token", "")
    telegram.setdefault("chat_id", "")
    general = settings.setdefault("general", {})
    general.setdefault("interval_seconds", 30)
    general.setdefault("target_latency_interval_seconds", general.get("interval_seconds", 30))
    general.setdefault("target_rotation_enabled", False)
    general.setdefault("target_parallel_workers", 0)
    general.setdefault("targets_per_wan_per_run", 1)
    general.setdefault("target_ping_timeout_ms", 1000)
    general.setdefault("target_ping_count", 1)
    general.setdefault("history_retention_days", 400)
    general.setdefault("targets_configured", False)

    try:
        general["interval_seconds"] = max(int(general.get("interval_seconds") or 30), 1)
    except Exception:
        general["interval_seconds"] = 30
    try:
        general["target_latency_interval_seconds"] = max(
            int(general.get("target_latency_interval_seconds") or general.get("interval_seconds") or 30),
            1,
        )
    except Exception:
        general["target_latency_interval_seconds"] = general.get("interval_seconds", 30)
    rotation_raw = general.get("target_rotation_enabled", False)
    if isinstance(rotation_raw, str):
        general["target_rotation_enabled"] = rotation_raw.strip().lower() in ("1", "true", "yes", "on")
    else:
        general["target_rotation_enabled"] = bool(rotation_raw)
    parallel_workers_raw = general.get("target_parallel_workers", 0)
    if parallel_workers_raw in (None, ""):
        parallel_workers_raw = 0
    try:
        general["target_parallel_workers"] = max(min(int(parallel_workers_raw), 64), 0)
    except Exception:
        general["target_parallel_workers"] = 0
    targets_per_wan_raw = general.get("targets_per_wan_per_run", 1)
    if targets_per_wan_raw in (None, ""):
        targets_per_wan_raw = 1
    try:
        general["targets_per_wan_per_run"] = max(int(targets_per_wan_raw), 0)
    except Exception:
        general["targets_per_wan_per_run"] = 1
    try:
        general["target_ping_timeout_ms"] = max(min(int(general.get("target_ping_timeout_ms") or 1000), 60000), 100)
    except Exception:
        general["target_ping_timeout_ms"] = 1000
    try:
        general["target_ping_count"] = max(min(int(general.get("target_ping_count") or 1), 20), 1)
    except Exception:
        general["target_ping_count"] = 1

    targets = general.get("targets")
    default_targets = copy.deepcopy(WAN_PING_DEFAULTS.get("general", {}).get("targets", []))
    if not isinstance(targets, list):
        general["targets"] = copy.deepcopy(default_targets)
    else:
        cleaned = []
        for idx, item in enumerate(targets):
            if not isinstance(item, dict):
                continue
            host = (item.get("host") or "").strip()
            label = (item.get("label") or "").strip()
            if not host:
                continue
            cleaned.append(
                {
                    "id": (item.get("id") or "").strip() or f"target-{idx+1}",
                    "label": label or host,
                    "host": host,
                    "enabled": bool(item.get("enabled", True)),
                }
            )
        if not bool(general.get("targets_configured")):
            if not cleaned:
                cleaned = copy.deepcopy(default_targets)
            else:
                existing_hosts = {((t.get("host") or "").strip().lower()) for t in cleaned if (t.get("host") or "").strip()}
                existing_ids = {((t.get("id") or "").strip()) for t in cleaned if (t.get("id") or "").strip()}
                for item in default_targets:
                    if not isinstance(item, dict):
                        continue
                    host = (item.get("host") or "").strip()
                    if not host:
                        continue
                    host_key = host.lower()
                    item_id = (item.get("id") or "").strip()
                    if host_key in existing_hosts:
                        continue
                    if item_id and item_id in existing_ids:
                        continue
                    cleaned.append(
                        {
                            "id": item_id or f"default-{len(cleaned)+1}",
                            "label": (item.get("label") or "").strip() or host,
                            "host": host,
                            "enabled": bool(item.get("enabled", True)),
                        }
                    )
        general["targets"] = cleaned
    wans = settings.get("wans")
    if not isinstance(wans, list):
        wans = []
    cleaned_wans = []
    for item in wans:
        if not isinstance(item, dict):
            continue
        core_id = (item.get("core_id") or "").strip()
        list_name = (item.get("list_name") or "").strip()
        if not core_id or not list_name:
            continue
        mode = (item.get("mode") or "routed").strip().lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"
        local_ip = (item.get("local_ip") or "").strip()
        netwatch_host = (item.get("netwatch_host") or "").strip()
        if mode == "bridged" and not netwatch_host:
            netwatch_host = local_ip
        enabled = bool(item.get("enabled", True))
        if not local_ip:
            enabled = False
        elif mode == "routed" and not netwatch_host and not enabled:
            enabled = True
        cleaned_wans.append(
            {
                "id": (item.get("id") or wan_row_id(core_id, list_name)).strip(),
                "core_id": core_id,
                "list_name": list_name,
                "identifier": (item.get("identifier") or "").strip(),
                "color": _sanitize_hex_color((item.get("color") or "").strip()),
                "enabled": enabled,
                "mode": mode,
                "local_ip": local_ip,
                "gateway_ip": (item.get("gateway_ip") or "").strip(),
                "netwatch_host": netwatch_host,
                "pppoe_router_id": (item.get("pppoe_router_id") or "").strip(),
                "traffic_interface": (item.get("traffic_interface") or "").strip(),
            }
        )
    settings["wans"] = cleaned_wans
    settings.setdefault("pppoe_routers", [])
    settings.setdefault("messages", {})
    summary = settings.setdefault("summary", {})
    summary.setdefault("enabled", WAN_SUMMARY_DEFAULTS["enabled"])
    summary.setdefault("daily_time", WAN_SUMMARY_DEFAULTS["daily_time"])
    summary.setdefault("all_up_msg", WAN_SUMMARY_DEFAULTS["all_up_msg"])
    summary.setdefault("partial_msg", WAN_SUMMARY_DEFAULTS["partial_msg"])
    summary.setdefault("line_template", WAN_SUMMARY_DEFAULTS["line_template"])
    return settings


def normalize_isp_status_settings(settings):
    settings = copy.deepcopy(settings) if isinstance(settings, dict) else {}
    defaults = copy.deepcopy(ISP_STATUS_DEFAULTS)
    settings.setdefault("enabled", defaults.get("enabled", False))
    settings["enabled"] = bool(settings.get("enabled"))
    general = settings.setdefault("general", {})
    default_general = defaults.get("general", {})
    try:
        general["poll_interval_seconds"] = max(
            int(general.get("poll_interval_seconds") or default_general.get("poll_interval_seconds", 30)),
            5,
        )
    except Exception:
        general["poll_interval_seconds"] = int(default_general.get("poll_interval_seconds", 30))
    try:
        general["history_retention_days"] = max(
            int(general.get("history_retention_days") or default_general.get("history_retention_days", 400)),
            1,
        )
    except Exception:
        general["history_retention_days"] = int(default_general.get("history_retention_days", 400))
    try:
        general["chart_window_hours"] = max(
            int(general.get("chart_window_hours") or default_general.get("chart_window_hours", 24)),
            1,
        )
    except Exception:
        general["chart_window_hours"] = int(default_general.get("chart_window_hours", 24))
    capacity = settings.setdefault("capacity", {})
    default_capacity = defaults.get("capacity", {})
    try:
        capacity["hundred_mbps_min"] = max(
            float(capacity.get("hundred_mbps_min") or default_capacity.get("hundred_mbps_min", 90)),
            1.0,
        )
    except Exception:
        capacity["hundred_mbps_min"] = float(default_capacity.get("hundred_mbps_min", 90))
    try:
        capacity["hundred_mbps_max"] = max(
            float(capacity.get("hundred_mbps_max") or default_capacity.get("hundred_mbps_max", 105)),
            capacity["hundred_mbps_min"],
        )
    except Exception:
        capacity["hundred_mbps_max"] = float(default_capacity.get("hundred_mbps_max", 105))
    try:
        capacity["window_minutes"] = max(
            int(capacity.get("window_minutes") or default_capacity.get("window_minutes", 10)),
            1,
        )
    except Exception:
        capacity["window_minutes"] = int(default_capacity.get("window_minutes", 10))
    capacity["average_detection_enabled"] = bool(
        capacity.get(
            "average_detection_enabled",
            default_capacity.get("average_detection_enabled", True),
        )
    )
    try:
        capacity["average_window_hours"] = max(
            int(capacity.get("average_window_hours") or default_capacity.get("average_window_hours", 4)),
            1,
        )
    except Exception:
        capacity["average_window_hours"] = int(default_capacity.get("average_window_hours", 4))
    telegram = settings.setdefault("telegram", {})
    default_telegram = defaults.get("telegram", {})
    telegram["daily_enabled"] = bool(telegram.get("daily_enabled", default_telegram.get("daily_enabled", False)))
    telegram["daily_time"] = (telegram.get("daily_time") or default_telegram.get("daily_time", "07:00")).strip() or "07:00"
    telegram["immediate_100m_enabled"] = bool(
        telegram.get("immediate_100m_enabled", default_telegram.get("immediate_100m_enabled", True))
    )
    try:
        telegram["recovery_confirm_minutes"] = max(
            int(telegram.get("recovery_confirm_minutes") or default_telegram.get("recovery_confirm_minutes", 2)),
            1,
        )
    except Exception:
        telegram["recovery_confirm_minutes"] = int(default_telegram.get("recovery_confirm_minutes", 2))
    return settings


def normalize_mikrotik_logs_settings(settings):
    cfg = copy.deepcopy(MIKROTIK_LOGS_DEFAULTS)
    if isinstance(settings, dict):
        cfg["enabled"] = bool(settings.get("enabled", cfg["enabled"]))
        for section in ("receiver", "storage", "filters", "auto_setup"):
            if isinstance(settings.get(section), dict):
                cfg[section].update(settings.get(section) or {})

    receiver = cfg.setdefault("receiver", {})
    receiver["host"] = (receiver.get("host") or "0.0.0.0").strip() or "0.0.0.0"
    try:
        port = int(receiver.get("port") or 5514)
    except Exception:
        port = 5514
    receiver["port"] = max(1, min(port, 65535))

    storage = cfg.setdefault("storage", {})
    try:
        retention_days = int(storage.get("retention_days") or 30)
    except Exception:
        retention_days = 30
    try:
        batch_size = int(storage.get("batch_size") or 100)
    except Exception:
        batch_size = 100
    try:
        flush_interval = int(storage.get("flush_interval_seconds") or 2)
    except Exception:
        flush_interval = 2
    storage["retention_days"] = max(1, min(retention_days, 3650))
    storage["batch_size"] = max(1, min(batch_size, 1000))
    storage["flush_interval_seconds"] = max(1, min(flush_interval, 30))

    filters = cfg.setdefault("filters", {})
    filters["allow_unknown_sources"] = bool(filters.get("allow_unknown_sources", True))
    min_severity = (filters.get("min_severity") or "debug").strip().lower()
    if min_severity not in {"debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"}:
        min_severity = "debug"
    filters["min_severity"] = min_severity
    if isinstance(filters.get("drop_topics"), list):
        filters["drop_topics"] = [str(item or "").strip().lower() for item in filters["drop_topics"] if str(item or "").strip()]
    else:
        filters["drop_topics"] = []

    auto_setup = cfg.setdefault("auto_setup", {})
    auto_setup["enabled"] = bool(auto_setup.get("enabled", False))
    auto_setup["server_host"] = (auto_setup.get("server_host") or "").strip()
    try:
        auto_setup["check_interval_hours"] = max(1, min(int(auto_setup.get("check_interval_hours") or 24), 720))
    except Exception:
        auto_setup["check_interval_hours"] = 24
    try:
        auto_setup["timeout_seconds"] = max(1, min(int(auto_setup.get("timeout_seconds") or 8), 60))
    except Exception:
        auto_setup["timeout_seconds"] = 8
    return cfg


def _apply_mikrotik_log_source_aliases_to_history(results):
    updated = 0
    for item in results or []:
        if not isinstance(item, dict) or item.get("status") != "configured":
            continue
        aliases = item.get("source_aliases") if isinstance(item.get("source_aliases"), list) else []
        if not aliases:
            continue
        try:
            updated += update_mikrotik_logs_router_for_sources(
                aliases,
                item.get("router_id") or item.get("router_name") or "",
                item.get("router_name") or item.get("router_id") or "",
                item.get("router_kind") or "mikrotik",
            )
        except Exception:
            continue
    return updated


def normalize_offline_settings(settings):
    settings = settings if isinstance(settings, dict) else {}
    settings.setdefault("enabled", False)
    mode = (settings.get("mode") or OFFLINE_DEFAULTS.get("mode") or "secrets").strip().lower()
    if mode not in ("secrets", "radius"):
        mode = "secrets"
    settings["mode"] = mode

    general = settings.setdefault("general", {})
    general.setdefault("poll_interval_seconds", OFFLINE_DEFAULTS["general"]["poll_interval_seconds"])
    general.setdefault("min_offline_value", OFFLINE_DEFAULTS["general"]["min_offline_value"])
    general.setdefault("min_offline_unit", OFFLINE_DEFAULTS["general"]["min_offline_unit"])
    general.setdefault("history_retention_days", OFFLINE_DEFAULTS["general"]["history_retention_days"])
    tracking_rules = normalize_offline_tracking_rules(
        general.get("tracking_rules"),
        fallback_value=general.get("min_offline_value", OFFLINE_DEFAULTS["general"]["min_offline_value"]),
        fallback_unit=general.get("min_offline_unit", OFFLINE_DEFAULTS["general"]["min_offline_unit"]),
    )
    enabled_tracking_rules = [dict(rule) for rule in tracking_rules if bool(rule.get("enabled"))] or [dict(tracking_rules[0])]
    general["tracking_rules"] = tracking_rules
    general["enabled_tracking_rules"] = enabled_tracking_rules
    general["min_offline_value"] = int(enabled_tracking_rules[0].get("value", OFFLINE_DEFAULTS["general"]["min_offline_value"]) or 0)
    general["min_offline_unit"] = (enabled_tracking_rules[0].get("unit") or OFFLINE_DEFAULTS["general"]["min_offline_unit"]).strip().lower()
    general["tracking_rules_summary"] = offline_rules_summary_text(
        tracking_rules,
        fallback_value=general["min_offline_value"],
        fallback_unit=general["min_offline_unit"],
    )

    radius = settings.setdefault("radius", {})
    radius.setdefault("enabled", OFFLINE_DEFAULTS["radius"]["enabled"])
    ssh = radius.setdefault("ssh", {})
    for key, value in (OFFLINE_DEFAULTS.get("radius", {}).get("ssh") or {}).items():
        ssh.setdefault(key, value)
    radius.setdefault("list_command", OFFLINE_DEFAULTS["radius"]["list_command"])

    mikrotik = settings.setdefault("mikrotik", {})
    router_enabled = mikrotik.get("router_enabled")
    mikrotik["router_enabled"] = router_enabled if isinstance(router_enabled, dict) else {}
    return settings


def _parse_offline_tracking_rules_form(form, current_rules):
    existing_rules = normalize_offline_tracking_rules(current_rules)
    existing_by_id = {
        str(rule.get("id") or "").strip().lower(): dict(rule)
        for rule in existing_rules
        if str(rule.get("id") or "").strip()
    }
    count = parse_int(form, "tracking_rule_count", len(existing_rules))
    count = max(int(count or 0), 0)
    parsed_rules = []

    for idx in range(count):
        rule_id = str(form.get(f"tracking_rule_{idx}_id") or "").strip()
        remove_rule = parse_bool(form, f"tracking_rule_{idx}_remove")
        if remove_rule:
            continue
        existing = existing_by_id.get(rule_id.lower()) if rule_id else None
        value_raw = form.get(f"tracking_rule_{idx}_value")
        unit_raw = form.get(f"tracking_rule_{idx}_unit")
        position_raw = form.get(f"tracking_rule_{idx}_position")
        if not rule_id and value_raw in (None, "") and unit_raw in (None, "") and position_raw in (None, ""):
            continue

        parsed_rules.append(
            {
                "id": rule_id or f"offline-rule-{idx + 1}",
                "value": parse_int(
                    form,
                    f"tracking_rule_{idx}_value",
                    int((existing or {}).get("value", existing_rules[0].get("value", 1)) or 1),
                ),
                "unit": (form.get(f"tracking_rule_{idx}_unit") or (existing or {}).get("unit") or "day").strip().lower(),
                "enabled": parse_bool(form, f"tracking_rule_{idx}_enabled"),
                "position": parse_int(
                    form,
                    f"tracking_rule_{idx}_position",
                    int((existing or {}).get("position", idx + 1) or idx + 1),
                ),
            }
        )

    if not parsed_rules and ("min_offline_value" in form or "min_offline_unit" in form):
        parsed_rules = [
            {
                "id": "offline-rule-1",
                "value": parse_int(form, "min_offline_value", int(existing_rules[0].get("value", 1) or 1)),
                "unit": (form.get("min_offline_unit") or existing_rules[0].get("unit") or "day").strip().lower(),
                "enabled": True,
                "position": 1,
            }
        ]

    fallback_rule = existing_rules[0] if existing_rules else {"value": 1, "unit": "day"}
    return normalize_offline_tracking_rules(
        parsed_rules,
        fallback_value=fallback_rule.get("value", 1),
        fallback_unit=fallback_rule.get("unit", "day"),
    )


def _build_offline_rule_views(offline_state, offline_settings):
    state = offline_state if isinstance(offline_state, dict) else {}
    settings = normalize_offline_settings(offline_settings)
    general_cfg = settings.get("general") if isinstance(settings.get("general"), dict) else {}
    rules = enabled_offline_tracking_rules(
        general_cfg.get("tracking_rules"),
        fallback_value=general_cfg.get("min_offline_value", 1),
        fallback_unit=general_cfg.get("min_offline_unit", "day"),
    )
    tracker = state.get("tracker") if isinstance(state.get("tracker"), dict) else {}
    current_rows = state.get("rows") if isinstance(state.get("rows"), list) else []
    now_dt = datetime.utcnow()
    merged = {}

    def _candidate_key(candidate):
        router_id = (candidate.get("router_id") or "").strip().lower()
        pppoe = (candidate.get("pppoe") or "").strip().lower()
        if not pppoe:
            return ""
        if router_id:
            return f"{router_id}|{pppoe}"
        mode = (candidate.get("mode") or state.get("mode") or "offline").strip().lower()
        return f"{mode}|{pppoe}"

    def _merge_candidate(candidate):
        if not isinstance(candidate, dict):
            return
        pppoe = (candidate.get("pppoe") or "").strip()
        if not pppoe:
            return
        key = _candidate_key(candidate)
        if not key:
            return
        offline_since_iso = (candidate.get("offline_since") or "").strip()
        offline_since_dt = _parse_iso_z(offline_since_iso)
        offline_seconds = int(max(0, (now_dt - offline_since_dt).total_seconds())) if offline_since_dt else 0
        offline_minutes = int(offline_seconds / 60)
        row = {
            "pppoe": pppoe,
            "router_id": (candidate.get("router_id") or "").strip(),
            "router_name": (candidate.get("router_name") or candidate.get("router_id") or "").strip(),
            "mode": (candidate.get("mode") or state.get("mode") or "").strip() or "secrets",
            "profile": (candidate.get("profile") or "").strip(),
            "disabled": bool(candidate.get("disabled")) if candidate.get("disabled") is not None else None,
            "last_logged_out": (candidate.get("last_logged_out") or "").strip(),
            "radius_status": (candidate.get("radius_status") or "").strip(),
            "offline_since_ts": offline_since_iso,
            "offline_since": format_ts_ph(offline_since_iso) if offline_since_iso else "",
            "offline_duration_seconds": offline_seconds,
            "offline_duration": _format_duration_short(offline_seconds),
        }
        existing = merged.get(key)
        if not existing:
            merged[key] = row
            return
        existing_score = (
            existing.get("offline_since_ts") or "",
            existing.get("router_name") or "",
            existing.get("radius_status") or "",
        )
        row_score = (
            row.get("offline_since_ts") or "",
            row.get("router_name") or "",
            row.get("radius_status") or "",
        )
        if row_score > existing_score:
            merged[key] = row
            return
        for field in ("router_id", "router_name", "mode", "profile", "last_logged_out", "radius_status", "offline_since_ts", "offline_since"):
            if row.get(field) and not existing.get(field):
                existing[field] = row.get(field)
        if existing.get("disabled") is None and row.get("disabled") is not None:
            existing["disabled"] = row.get("disabled")

    for item in tracker.values():
        if not isinstance(item, dict):
            continue
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        _merge_candidate(
            {
                **meta,
                "mode": item.get("mode") or state.get("mode") or "",
                "offline_since": item.get("first_offline_at"),
            }
        )

    for row in current_rows:
        if not isinstance(row, dict):
            continue
        _merge_candidate(row)

    all_rows = sorted(
        merged.values(),
        key=lambda item: (
            item.get("offline_since_ts") or "",
            str(item.get("pppoe") or "").lower(),
        ),
    )

    rule_defs = []
    for idx, rule in enumerate(rules, start=1):
        threshold_minutes = int(rule.get("minutes", 0) or 0)
        rule_defs.append(
            {
                "id": rule.get("id"),
                "label": rule.get("label"),
                "tab_label": rule.get("tab_label"),
                "value": int(rule.get("value", 0) or 0),
                "unit": rule.get("unit"),
                "minutes": threshold_minutes,
                "position": int(rule.get("position", idx) or idx),
            }
        )

    rows_by_rule = {str(rule.get("id") or ""): [] for rule in rule_defs if str(rule.get("id") or "").strip()}
    for row in all_rows:
        if not isinstance(row, dict):
            continue
        duration_seconds = int(row.get("offline_duration_seconds", 0) or 0)
        best_rule = None
        best_minutes = -1
        for rule in rule_defs:
            rule_id = str(rule.get("id") or "").strip()
            threshold_minutes = int(rule.get("minutes", 0) or 0)
            if not rule_id:
                continue
            if duration_seconds < threshold_minutes * 60:
                continue
            if threshold_minutes >= best_minutes:
                best_rule = rule
                best_minutes = threshold_minutes
        if best_rule:
            rows_by_rule[str(best_rule.get("id") or "")].append(dict(row))

    payload_rules = []
    for rule in rule_defs:
        rule_id = str(rule.get("id") or "").strip()
        if not rule_id:
            continue
        rule_rows = rows_by_rule.get(rule_id, [])
        payload_rules.append(
            {
                "id": rule_id,
                "label": rule.get("label"),
                "tab_label": rule.get("tab_label"),
                "value": int(rule.get("value", 0) or 0),
                "unit": rule.get("unit"),
                "minutes": int(rule.get("minutes", 0) or 0),
                "position": int(rule.get("position", 0) or 0),
                "count": len(rule_rows),
            }
        )

    default_rule_id = payload_rules[0]["id"] if payload_rules else ""
    return {
        "rules": payload_rules,
        "rows_by_rule": rows_by_rule,
        "default_rule_id": default_rule_id,
        "default_rows": rows_by_rule.get(default_rule_id, []),
    }


WAN_STATUS_WINDOW_OPTIONS = [
    ("1H", 1),
    ("6H", 6),
    ("12H", 12),
    ("1D", 24),
    ("7D", 168),
    ("15D", 360),
    ("30D", 720),
]


def _normalize_wan_window(value):
    if value is None:
        return 24
    raw = str(value).strip().lower()
    if not raw:
        return 24
    for label, hours in WAN_STATUS_WINDOW_OPTIONS:
        if raw == label.lower():
            return hours
    try:
        hours = int(raw)
        if hours in {opt[1] for opt in WAN_STATUS_WINDOW_OPTIONS}:
            return hours
    except ValueError:
        pass
    return 24


def _wan_target_bucket_seconds(hours, max_points_per_series=1800):
    try:
        window_hours = max(int(hours or 24), 1)
    except Exception:
        window_hours = 24
    try:
        max_points = max(int(max_points_per_series or 1800), 300)
    except Exception:
        max_points = 1800
    total_seconds = window_hours * 3600
    return max((total_seconds + max_points - 1) // max_points, 1)


def _isp_status_bucket_seconds(hours):
    try:
        hours = int(hours or 24)
    except Exception:
        hours = 24
    if hours <= 24:
        return 300
    if hours <= 168:
        return 1800
    return 7200


def _bps_to_mbps(value):
    try:
        return round(float(value or 0.0) / 1_000_000.0, 2)
    except Exception:
        return 0.0


def _capacity_status_label(status):
    value = (status or "").strip().lower()
    if value == "1g":
        return "1G"
    if value == "100m":
        return "100M"
    if value == "not_configured":
        return "Interface Missing"
    if value == "error":
        return "Error"
    return "Observing"


def _capacity_status_badge(status):
    value = (status or "").strip().lower()
    if value == "1g":
        return "bg-green-lt text-green"
    if value == "100m":
        return "bg-yellow-lt text-yellow"
    if value in ("error", "not_configured"):
        return "bg-red-lt text-red"
    return "bg-blue-lt text-blue"


def _build_isp_status_rows(pulse_settings, wan_settings, state=None):
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_ids = [row.get("wan_id") for row in wan_rows if row.get("wan_id")]
    db_latest = fetch_isp_status_latest_map(wan_ids)
    state = state if isinstance(state, dict) else get_state("isp_status_state", {})
    state_latest = state.get("latest") if isinstance(state.get("latest"), dict) else {}
    rows = []
    for row in wan_rows:
        wan_id = row.get("wan_id")
        latest = state_latest.get(wan_id) if isinstance(state_latest.get(wan_id), dict) else {}
        if not latest:
            latest = db_latest.get(wan_id) if isinstance(db_latest.get(wan_id), dict) else {}
        capacity_status = (latest.get("capacity_status") or "").strip().lower()
        traffic_interface = (row.get("traffic_interface") or latest.get("interface_name") or "").strip()
        capacity_reason = (latest.get("capacity_reason") or latest.get("last_error") or "").strip()
        if not traffic_interface:
            capacity_status = "not_configured"
            capacity_reason = capacity_reason or "Traffic Interface is not set in System Settings -> Routers -> ISP Port Tagging."
        rx_bps = latest.get("rx_bps")
        tx_bps = latest.get("tx_bps")
        total_bps = latest.get("total_bps")
        if total_bps is None and (rx_bps is not None or tx_bps is not None):
            try:
                total_bps = float(rx_bps or 0.0) + float(tx_bps or 0.0)
            except Exception:
                total_bps = None
        rows.append(
            {
                **row,
                "rx_mbps": _bps_to_mbps(rx_bps),
                "tx_mbps": _bps_to_mbps(tx_bps),
                "total_mbps": _bps_to_mbps(total_bps),
                "peak_mbps": round(float(latest.get("peak_mbps") or 0.0), 2),
                "capacity_status": capacity_status or "observing",
                "capacity_label": _capacity_status_label(capacity_status),
                "capacity_badge": _capacity_status_badge(capacity_status),
                "capacity_reason": capacity_reason,
                "last_sample_at": (latest.get("last_sample_at") or latest.get("timestamp") or "").strip(),
                "last_sample_at_ph": format_ts_ph(latest.get("last_sample_at") or latest.get("timestamp")),
                "traffic_interface": traffic_interface,
            }
        )
    return rows


TABLE_PAGE_SIZE_OPTIONS = [50, 100, 200, 500, 1000]


def _parse_table_limit(value, default=50):
    raw = str(value or "").strip().lower()
    if raw in ("all", "0"):
        return 0
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return default
    if parsed in TABLE_PAGE_SIZE_OPTIONS:
        return parsed
    return default


def _parse_table_page(value, default=1):
    try:
        parsed = int(str(value or "").strip() or default)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _paginate_items(items, page, limit):
    total = len(items)
    if not limit or int(limit) <= 0:
        return items, {
            "page": 1,
            "pages": 1,
            "limit": 0,
            "total": total,
            "start": 1 if total else 0,
            "end": total,
            "has_prev": False,
            "has_next": False,
        }
    limit = int(limit)
    pages = max((total + limit - 1) // limit, 1)
    page = max(int(page or 1), 1)
    if page > pages:
        page = pages
    start_idx = (page - 1) * limit
    end_idx = min(start_idx + limit, total)
    return items[start_idx:end_idx], {
        "page": page,
        "pages": pages,
        "limit": limit,
        "total": total,
        "start": start_idx + 1 if total else 0,
        "end": end_idx,
        "has_prev": page > 1,
        "has_next": page < pages,
    }


def build_wan_status_summary(wan_rows, wan_state, history_map, window_hours=24):
    history_map = history_map or {}
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=max(int(window_hours or 24), 1))
    window_label = next((label for label, hours in WAN_STATUS_WINDOW_OPTIONS if hours == window_hours), "1D")
    rows = []
    total = 0
    down_total = 0
    for row in wan_rows:
        if not row.get("local_ip"):
            continue
        if (row.get("mode") or "routed").lower() == "bridged" and not row.get("pppoe_router_id"):
            continue
        wan_id = row.get("wan_id")
        total += 1
        state_row = wan_state.get("wans", {}).get(wan_id, {})
        history = history_map.get(wan_id, [])
        values = []
        for item in history:
            ts_raw = item.get("ts")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                else:
                    ts = ts.astimezone(timezone.utc)
            except Exception:
                continue
            if ts < window_start:
                continue
            status = (item.get("status") or "").lower()
            values.append(100 if status == "up" else 0)
        if not values:
            state_hist = state_row.get("history", [])
            for item in state_hist:
                ts_raw = item.get("ts")
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    else:
                        ts = ts.astimezone(timezone.utc)
                except Exception:
                    continue
                if ts < window_start:
                    continue
                status = (item.get("status") or "").lower()
                values.append(100 if status == "up" else 0)
        uptime_pct = sum(values) / len(values) if values else None
        spark_points = _sparkline_points_fixed(values or [0], 0, 100, width=120, height=28)
        last_status = (history[-1].get("status") if history else state_row.get("status")) or "n/a"
        if str(last_status).lower() == "down":
            down_total += 1
        rows.append(
            {
                "label": f"{row.get('core_label')} - {(row.get('identifier') or row.get('list_name') or '')}".strip(),
                "status": last_status,
                "target": state_row.get("target") or "",
                "last_check": format_ts_ph(state_row.get("last_check")),
                "last_rtt_ms": state_row.get("last_rtt_ms"),
                "last_error": state_row.get("last_error") or "",
                "uptime_pct": uptime_pct,
                "spark_points": spark_points,
            }
        )
    up_total = max(total - down_total, 0)
    return {
        "total": total,
        "up_total": up_total,
        "down_total": down_total,
        "rows": rows,
        "window_hours": window_hours,
        "window_label": window_label,
    }


def wan_row_id(core_id, list_name):
    raw = f"{core_id}|{list_name}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def is_wan_list_name(list_name):
    return "TO-ISP" in (list_name or "").upper()


_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _sanitize_hex_color(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if _HEX_COLOR_RE.match(raw):
        return raw.lower()
    return ""


def _routeros_sentence_to_dict(sentence):
    data = {}
    for word in sentence[1:]:
        if not word:
            continue
        token = word[1:] if word.startswith("=") else word
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        data[key] = value
    return data


def _routeros_rows(client, words):
    replies = client.talk(words)
    rows = []
    for sentence in replies:
        if not sentence or sentence[0] != "!re":
            continue
        rows.append(_routeros_sentence_to_dict(sentence))
    return rows


def _routeros_trap_message(replies):
    for sentence in replies:
        if not sentence or sentence[0] != "!trap":
            continue
        data = _routeros_sentence_to_dict(sentence)
        message = (data.get("message") or "").strip()
        return message or "RouterOS trap"
    return ""


def _routeros_flag_true(value):
    return str(value or "").strip().lower() in {"true", "yes", "on", "1"}


def _extract_route_interface(route):
    for key in ("immediate-gw", "gateway"):
        raw = (route.get(key) or "").strip()
        if not raw:
            continue
        if "%" in raw:
            iface = raw.split("%", 1)[1].strip()
            if iface:
                return iface
        if raw and re.match(r"^[A-Za-z].*", raw) and "." not in raw:
            return raw
    status = (route.get("gateway-status") or "").strip()
    match = re.search(r"\bvia\s+([^\s,]+)", status)
    if match:
        return (match.group(1) or "").strip()
    return (route.get("out-interface") or "").strip()


def _extract_route_gateway_ip(route):
    for key in ("immediate-gw", "gateway"):
        raw = (route.get(key) or "").strip()
        if not raw:
            continue
        ip_part = raw.split("%", 1)[0].strip()
        try:
            ip_obj = ipaddress.ip_address(ip_part)
            if ip_obj.version == 4:
                return str(ip_obj)
        except Exception:
            continue
    status = (route.get("gateway-status") or "").strip()
    for token in _IPV4_RE.findall(status):
        try:
            ip_obj = ipaddress.ip_address(token)
            if ip_obj.version == 4:
                return str(ip_obj)
        except Exception:
            continue
    return ""


def _pick_interface_local_ip(address_rows, interface_name="", gateway_ip=""):
    iface_name = (interface_name or "").strip()
    gateway_obj = None
    if gateway_ip:
        try:
            parsed = ipaddress.ip_address(str(gateway_ip).strip())
            if parsed.version == 4:
                gateway_obj = parsed
        except Exception:
            gateway_obj = None
    candidates = []
    for row in address_rows:
        if _routeros_flag_true(row.get("disabled")):
            continue
        row_iface = (row.get("interface") or "").strip()
        if iface_name and row_iface != iface_name:
            continue
        raw = (row.get("address") or "").strip()
        if not raw:
            continue
        try:
            iface = ipaddress.ip_interface(raw)
        except Exception:
            continue
        if iface.version != 4:
            continue
        if gateway_obj is not None:
            try:
                if gateway_obj in iface.network:
                    return str(iface.ip)
            except Exception:
                pass
        dynamic_rank = 0 if _routeros_flag_true(row.get("dynamic")) else 1
        candidates.append((dynamic_rank, str(iface.ip)))
    if not candidates:
        return ""
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][1]


def _remove_mangle_rules_by_comment(client, comment):
    if not comment:
        return
    try:
        rows = _routeros_rows(client, ["/ip/firewall/mangle/print", f"?comment={comment}"])
    except Exception:
        return
    for row in rows:
        rule_id = (row.get(".id") or "").strip()
        if not rule_id:
            continue
        try:
            client.talk(["/ip/firewall/mangle/remove", f"=.id={rule_id}"])
        except Exception:
            continue


def _is_public_ipv4(value):
    raw = (value or "").strip()
    if not raw:
        return False
    try:
        ip_obj = ipaddress.ip_address(raw)
    except Exception:
        return False
    if ip_obj.version != 4:
        return False
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified)


def _detect_public_ip_for_source(client, src_address, routing_mark="", sample_index=0):
    src = (src_address or "").strip()
    if not src:
        return ""
    mark = (routing_mark or "").strip()
    providers = [
        "http://1.1.1.1/cdn-cgi/trace",
        "http://ifconfig.me/ip",
    ]
    safe_src = re.sub(r"[^0-9A-Za-z_.-]", "_", src)
    probe_comment = ""
    probe_rule_added = False
    if mark:
        probe_comment = f"threej_wanip_probe_{safe_src}_{int(time.time() * 1000)}_{sample_index}"
        try:
            replies = client.talk(
                [
                    "/ip/firewall/mangle/add",
                    "=chain=output",
                    "=action=mark-routing",
                    f"=new-routing-mark={mark}",
                    "=passthrough=no",
                    f"=src-address={src}",
                    f"=comment={probe_comment}",
                ]
            )
            trap_message = _routeros_trap_message(replies)
            if not trap_message:
                probe_rule_added = True
        except Exception:
            probe_rule_added = False
    try:
        for idx, url in enumerate(providers):
            stamp = int(time.time() * 1000)
            delimiter = "&" if "?" in url else "?"
            probe_url = f"{url}{delimiter}threej_probe={stamp}_{sample_index}_{idx}"
            file_name = f"threej_wanip_{safe_src}_{stamp}_{idx}.txt"
            try:
                replies = client.talk(
                    [
                        "/tool/fetch",
                        f"=url={probe_url}",
                        f"=dst-path={file_name}",
                        f"=src-address={src}",
                        "=keep-result=yes",
                    ]
                )
                trap_message = _routeros_trap_message(replies)
                if trap_message:
                    continue
                file_rows = _routeros_rows(client, ["/file/print", "=detail=yes", f"?name={file_name}"])
                if not file_rows:
                    continue
                contents = (file_rows[0].get("contents") or "").strip()
                if not contents:
                    continue
                for token in _IPV4_RE.findall(contents):
                    try:
                        ip_obj = ipaddress.ip_address(token)
                        if ip_obj.version == 4:
                            return str(ip_obj)
                    except Exception:
                        continue
            except Exception:
                continue
            finally:
                try:
                    client.talk(["/file/remove", f"=numbers={file_name}"])
                except Exception:
                    pass
    finally:
        if probe_rule_added:
            _remove_mangle_rules_by_comment(client, probe_comment)
    return ""


def _collect_public_ip_samples(client, local_ip, routing_mark, attempts=1, start_index=0):
    src = (local_ip or "").strip()
    if not src:
        return []
    samples = []
    for idx in range(max(int(attempts or 1), 1)):
        probe = _detect_public_ip_for_source(
            client,
            src,
            routing_mark=routing_mark,
            sample_index=max(int(start_index or 0), 0) + idx,
        )
        if probe:
            samples.append(probe)
        if idx < max(int(attempts or 1), 1) - 1:
            time.sleep(0.2)
    return samples


def detect_routed_wan_autofill(pulsewatch_settings, wan_rows, probe_public=True):
    wanted_by_core = {}
    existing_by_key = {}
    for row in (wan_rows or []):
        if not isinstance(row, dict):
            continue
        mode = (row.get("mode") or "routed").strip().lower()
        if mode != "routed":
            continue
        core_id = (row.get("core_id") or "").strip()
        list_name = (row.get("list_name") or "").strip()
        if not core_id or not list_name:
            continue
        existing_by_key[(core_id, list_name)] = {
            "local_ip": (row.get("local_ip") or "").strip(),
            "netwatch_host": (row.get("netwatch_host") or "").strip(),
        }
        if not is_wan_list_name(list_name):
            continue
        wanted_by_core.setdefault(core_id, set()).add(list_name)

    if not wanted_by_core:
        return {}, []

    cores = pulsewatch_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_map = {
        (item.get("id") or "").strip(): item
        for item in (cores or [])
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }
    detected = {}
    warnings = []

    for core_id, wanted_lists in wanted_by_core.items():
        core = core_map.get(core_id)
        if not core:
            for list_name in wanted_lists:
                detected[(core_id, list_name)] = {"local_ip": "", "netwatch_host": "", "interface": "", "routing_mark": ""}
            warnings.append(f"{core_id}: core not found")
            continue
        host = (core.get("host") or "").strip()
        if not host:
            for list_name in wanted_lists:
                detected[(core_id, list_name)] = {"local_ip": "", "netwatch_host": "", "interface": "", "routing_mark": ""}
            warnings.append(f"{core_id}: core host not configured")
            continue

        client = RouterOSClient(
            host,
            int(core.get("port", 8728)),
            core.get("username", ""),
            core.get("password", ""),
        )
        try:
            client.connect()
            mangle_rows = client.list_mangle_rules()
            address_rows = _routeros_rows(client, ["/ip/address/print"])
            route_rows = _routeros_rows(client, ["/ip/route/print"])

            marks_by_list = {}
            iface_hint_by_list = {}
            for rule in mangle_rows:
                if not isinstance(rule, dict):
                    continue
                if _routeros_flag_true(rule.get("disabled")):
                    continue
                list_name = (rule.get("src-address-list") or "").strip()
                if not list_name or list_name not in wanted_lists:
                    continue
                mark = (
                    (rule.get("new-routing-mark") or "").strip()
                    or (rule.get("new-routing-table") or "").strip()
                    or (rule.get("routing-mark") or "").strip()
                )
                if mark:
                    marks_by_list.setdefault(list_name, []).append(mark)
                iface_hint = (rule.get("out-interface") or "").strip()
                if iface_hint and list_name not in iface_hint_by_list:
                    iface_hint_by_list[list_name] = iface_hint

            default_routes = []
            for route in route_rows:
                if not isinstance(route, dict):
                    continue
                if _routeros_flag_true(route.get("disabled")):
                    continue
                if (route.get("dst-address") or "").strip() != "0.0.0.0/0":
                    continue
                default_routes.append(route)

            def _pick_route(list_name):
                marks = [item for item in marks_by_list.get(list_name, []) if item]
                candidates = []
                if marks:
                    mark_set = set(marks)
                    for route in default_routes:
                        routing_key = ((route.get("routing-table") or "").strip() or (route.get("routing-mark") or "").strip())
                        if routing_key and routing_key in mark_set:
                            candidates.append(route)
                if not candidates:
                    suffix_match = re.search(r"(\d+)$", list_name)
                    if suffix_match:
                        suffix = suffix_match.group(1)
                        tag = f"ISP{suffix}"
                        via_tag = f"via-{tag}"
                        for route in default_routes:
                            comment = (route.get("comment") or "").strip().upper()
                            routing_key = ((route.get("routing-table") or "").strip() or (route.get("routing-mark") or "").strip())
                            if tag in comment or routing_key == via_tag:
                                candidates.append(route)
                if not candidates and iface_hint_by_list.get(list_name):
                    iface_hint = iface_hint_by_list.get(list_name) or ""
                    for route in default_routes:
                        route_iface = _extract_route_interface(route)
                        if route_iface and route_iface == iface_hint:
                            candidates.append(route)
                if not candidates:
                    candidates = list(default_routes)
                if not candidates:
                    return None

                def _route_score(route):
                    active = 0 if _routeros_flag_true(route.get("active")) else 1
                    try:
                        distance = int(str(route.get("distance") or "999").strip())
                    except Exception:
                        distance = 999
                    return (active, distance)

                candidates.sort(key=_route_score)
                return candidates[0]

            used_wan_ips = set()
            for list_name in sorted(wanted_lists):
                route = _pick_route(list_name) or {}
                routing_mark = (
                    (route.get("routing-table") or "").strip()
                    or (route.get("routing-mark") or "").strip()
                    or (marks_by_list.get(list_name, [""])[0] if marks_by_list.get(list_name) else "")
                )
                iface_name = _extract_route_interface(route) or (iface_hint_by_list.get(list_name) or "")
                gateway_ip = _extract_route_gateway_ip(route)
                local_ip = _pick_interface_local_ip(address_rows, iface_name, gateway_ip)
                if not local_ip and gateway_ip:
                    local_ip = _pick_interface_local_ip(address_rows, "", gateway_ip)

                netwatch_host = ""
                existing = existing_by_key.get((core_id, list_name), {}) or {}
                existing_local_ip = (existing.get("local_ip") or "").strip()
                existing_netwatch = (existing.get("netwatch_host") or "").strip()
                if local_ip and existing_local_ip == local_ip and _is_public_ipv4(existing_netwatch):
                    netwatch_host = existing_netwatch
                elif local_ip and probe_public:
                    samples = _collect_public_ip_samples(client, local_ip, routing_mark, attempts=1)
                    if (
                        routing_mark
                        and samples
                        and samples[0] in used_wan_ips
                    ):
                        extra = _collect_public_ip_samples(client, local_ip, routing_mark, attempts=2, start_index=1)
                        if extra:
                            samples.extend(extra)
                    if not samples:
                        samples = _collect_public_ip_samples(client, local_ip, "", attempts=1)
                    if samples:
                        counts = {}
                        order = []
                        for item in samples:
                            if item not in counts:
                                counts[item] = 0
                                order.append(item)
                            counts[item] += 1
                        order_index = {item: idx for idx, item in enumerate(order)}
                        ranked = sorted(order, key=lambda item: (-counts[item], order_index[item]))
                        for candidate in ranked:
                            if candidate not in used_wan_ips:
                                netwatch_host = candidate
                                break
                        if not netwatch_host:
                            netwatch_host = ranked[0]
                        if netwatch_host:
                            used_wan_ips.add(netwatch_host)
                        if len(counts) > 1:
                            warnings.append(
                                f"{core_id} {list_name}: WAN IP probe returned multiple values ({', '.join(order[:3])})"
                            )
                elif _is_public_ipv4(existing_netwatch):
                    netwatch_host = existing_netwatch

                detected[(core_id, list_name)] = {
                    "local_ip": local_ip,
                    "netwatch_host": netwatch_host,
                    "interface": iface_name,
                    "routing_mark": routing_mark,
                }
                if not local_ip:
                    warnings.append(f"{core_id} {list_name}: unable to auto-detect local IP")
                if local_ip and not netwatch_host:
                    warnings.append(f"{core_id} {list_name}: unable to auto-detect WAN/public IP")
        except Exception as exc:
            for list_name in wanted_lists:
                detected[(core_id, list_name)] = {"local_ip": "", "netwatch_host": "", "interface": "", "routing_mark": ""}
            warnings.append(f"{core_id}: auto-detect failed ({exc})")
        finally:
            client.close()

    return detected, warnings


def build_wan_rows(pulsewatch_settings, wan_settings):
    cores = pulsewatch_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    list_map = fetch_mikrotik_lists(cores)
    preset_map = {}
    for preset in pulsewatch_settings.get("pulsewatch", {}).get("list_presets", []):
        core_id = preset.get("core_id")
        list_name = preset.get("list")
        identifier = (preset.get("identifier") or "").strip()
        color = _sanitize_hex_color(preset.get("color") or "")
        if core_id and list_name:
            preset_map[(core_id, list_name)] = {
                "identifier": identifier,
                "address": (preset.get("address") or "").strip(),
                "color": color,
            }
    saved_wans = {
        (item.get("core_id"), item.get("list_name")): item
        for item in wan_settings.get("wans", [])
        if item.get("core_id") and item.get("list_name")
    }
    rows = []
    for core in cores:
        core_id = core.get("id")
        if not core_id:
            continue
        lists = [name for name in list_map.get(core_id, []) if is_wan_list_name(name)]
        if not lists:
            lists = sorted(
                {
                    list_name
                    for (saved_core_id, list_name) in saved_wans.keys()
                    if saved_core_id == core_id
                }
            )
        for list_name in sorted(lists):
            saved = saved_wans.get((core_id, list_name), {}) or {}
            mode = (saved.get("mode") or "routed").strip().lower()
            if mode not in ("routed", "bridged"):
                mode = "routed"
            preset_data = preset_map.get((core_id, list_name), {}) or {}
            identifier = (saved.get("identifier") or "").strip() or (preset_data.get("identifier") or "").strip()
            color = _sanitize_hex_color((saved.get("color") or "").strip()) or _sanitize_hex_color(preset_data.get("color") or "")
            rows.append(
                {
                    "wan_id": wan_row_id(core_id, list_name),
                    "core_id": core_id,
                    "core_label": core.get("label") or core_id,
                    "list_name": list_name,
                    "identifier": identifier,
                    "identifier_missing": not identifier,
                    "color": color,
                    "mode": mode,
                    "local_ip": saved.get("local_ip", ""),
                    "netwatch_host": saved.get("netwatch_host", ""),
                    "gateway_ip": saved.get("gateway_ip", ""),
                    "preset_address": preset_data.get("address", ""),
                    "pppoe_router_id": saved.get("pppoe_router_id", ""),
                    "traffic_interface": (saved.get("traffic_interface") or "").strip(),
                    "enabled": bool(saved.get("enabled", True)),
                }
            )
    return rows


def fetch_mikrotik_lists(cores):
    list_map = {}
    for core in cores:
        core_id = core.get("id") or "core"
        host = core.get("host")
        if not host:
            list_map[core_id] = []
            continue
        client = RouterOSClient(
            host,
            int(core.get("port", 8728)),
            core.get("username", ""),
            core.get("password", ""),
        )
        try:
            client.connect()
            mangle_entries = client.list_mangle_rules()
            names = sorted(
                {
                    entry.get("src-address-list")
                    for entry in mangle_entries
                    if entry.get("src-address-list")
                }
            )
            if not names:
                entries = client.list_address_list()
                names = sorted({entry.get("list") for entry in entries if entry.get("list")})
            list_map[core_id] = names
        except Exception:
            list_map[core_id] = []
        finally:
            client.close()
    return list_map


def fetch_mikrotik_interfaces(cores):
    interface_map = {}
    warnings = []
    for core in cores:
        core_id = (core.get("id") or "core").strip() or "core"
        label = (core.get("label") or core_id).strip() or core_id
        host = (core.get("host") or "").strip()
        if not host:
            interface_map[core_id] = []
            warnings.append(f"{label}: no MikroTik host configured for interface detection")
            continue
        client = RouterOSClient(
            host,
            int(core.get("port", 8728)),
            core.get("username", ""),
            core.get("password", ""),
        )
        try:
            client.connect()
            rows = []
            seen_names = set()
            for entry in client.list_interfaces():
                if not isinstance(entry, dict):
                    continue
                name = (entry.get("name") or "").strip()
                if not name or name.lower() in seen_names:
                    continue
                seen_names.add(name.lower())
                disabled = str(entry.get("disabled", "")).strip().lower() in ("true", "yes", "1")
                running = str(entry.get("running", "")).strip().lower() in ("true", "yes", "1")
                rows.append(
                    {
                        "name": name,
                        "comment": (entry.get("comment") or "").strip(),
                        "type": (entry.get("type") or "").strip(),
                        "default_name": (entry.get("default-name") or "").strip(),
                        "disabled": disabled,
                        "running": running,
                    }
                )
            rows.sort(key=lambda item: (bool(item.get("disabled")), (item.get("name") or "").lower()))
            interface_map[core_id] = rows
        except Exception as exc:
            interface_map[core_id] = []
            warnings.append(f"{label}: failed to load interfaces ({exc})")
        finally:
            client.close()
    return interface_map, warnings


def _process_proc_root():
    host_root = "/host_proc"
    try:
        if os.path.isfile(f"{host_root}/stat") and os.path.isdir(f"{host_root}/1"):
            return host_root
    except Exception:
        pass
    return "/proc"


def _read_cpu_times(proc_root: str = "/proc"):
    try:
        with open(f"{proc_root}/stat", "r", encoding="utf-8") as handle:
            line = handle.readline()
        parts = line.split()
        if len(parts) < 5 or parts[0] != "cpu":
            return None
        values = [int(value) for value in parts[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        return total, idle
    except Exception:
        return None


def _cpu_percent():
    now = time.monotonic()
    last_at = float(_cpu_sample.get("at") or 0.0)
    if last_at > 0 and (now - last_at) < 1.0:
        return float(_cpu_sample.get("pct") or 0.0)
    proc_root = _process_proc_root()
    current = _read_cpu_times(proc_root=proc_root)
    if not current:
        return float(_cpu_sample.get("pct") or 0.0)
    prev_total = _cpu_sample.get("total")
    prev_idle = _cpu_sample.get("idle")
    try:
        prev_total = int(prev_total) if prev_total is not None else None
        prev_idle = int(prev_idle) if prev_idle is not None else None
    except Exception:
        prev_total = None
        prev_idle = None
    total_now = int(current[0])
    idle_now = int(current[1])
    if prev_total is None or prev_idle is None:
        _cpu_sample["total"] = total_now
        _cpu_sample["idle"] = idle_now
        _cpu_sample["at"] = now
        return float(_cpu_sample.get("pct") or 0.0)
    total_delta = total_now - prev_total
    idle_delta = idle_now - prev_idle
    pct = float(_cpu_sample.get("pct") or 0.0)
    if total_delta > 0:
        pct = max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta))
    _cpu_sample["total"] = total_now
    _cpu_sample["idle"] = idle_now
    _cpu_sample["pct"] = pct
    _cpu_sample["at"] = now
    return pct


def _memory_percent():
    try:
        mem_total = 0
        mem_available = 0
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1])
        if mem_total <= 0:
            return 0.0
        used = mem_total - mem_available
        return max(0.0, min(100.0, 100.0 * used / mem_total))
    except Exception:
        return 0.0


def _memory_used_including_cache_percent():
    """Proxmox-like 'used' view: MemTotal - MemFree (includes page cache/buffers)."""
    try:
        mem_total = 0
        mem_free = 0
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemFree:"):
                    mem_free = int(line.split()[1])
        if mem_total <= 0:
            return 0.0
        used = mem_total - mem_free
        return max(0.0, min(100.0, 100.0 * used / mem_total))
    except Exception:
        return 0.0


def _memory_details_kb():
    try:
        values = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                key, rest = line.split(":", 1)
                parts = rest.strip().split()
                if not parts:
                    continue
                try:
                    values[key] = int(parts[0])
                except Exception:
                    continue
        return {
            "mem_total_kb": int(values.get("MemTotal") or 0),
            "mem_free_kb": int(values.get("MemFree") or 0),
            "mem_available_kb": int(values.get("MemAvailable") or 0),
            "buffers_kb": int(values.get("Buffers") or 0),
            "cached_kb": int(values.get("Cached") or 0),
            "swap_total_kb": int(values.get("SwapTotal") or 0),
            "swap_free_kb": int(values.get("SwapFree") or 0),
        }
    except Exception:
        return {
            "mem_total_kb": 0,
            "mem_free_kb": 0,
            "mem_available_kb": 0,
            "buffers_kb": 0,
            "cached_kb": 0,
            "swap_total_kb": 0,
            "swap_free_kb": 0,
        }


def _disk_percent():
    try:
        usage = shutil.disk_usage("/")
        if usage.total <= 0:
            return 0.0
        return max(0.0, min(100.0, 100.0 * usage.used / usage.total))
    except Exception:
        return 0.0


def _uptime_seconds():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as handle:
            value = handle.read().split()[0]
        return int(float(value))
    except Exception:
        return 0


def _classify_process_feature(proc_name: str, proc_args: str):
    hay = f"{proc_name or ''} {proc_args or ''}".strip().lower()
    if proc_name == "ping" or hay.startswith("ping ") or " ping " in hay:
        return "WAN Ping Probes"
    if "uvicorn" in hay or "app.main:app" in hay or "threejnotif" in hay:
        return "ThreeJ API / Jobs"
    if "postgres" in hay:
        return "PostgreSQL"
    if "docker" in hay or "containerd" in hay:
        return "Docker Engine"
    if "sshd" in hay:
        return "SSH Sessions"
    if "python" in hay:
        return "Python Worker"
    if "nginx" in hay:
        return "Web Proxy"
    return (proc_name or "System Process").strip()


def _read_proc_snapshot(proc_root: str = "/proc"):
    snapshot = {}
    try:
        names = os.listdir(proc_root)
    except Exception:
        return snapshot
    try:
        page_size_kb = max(int(os.sysconf("SC_PAGE_SIZE")) // 1024, 1)
    except Exception:
        page_size_kb = 4
    for entry in names:
        if not entry.isdigit():
            continue
        pid = int(entry)
        base = f"{proc_root}/{entry}"
        try:
            with open(f"{base}/stat", "r", encoding="utf-8") as handle:
                stat_line = handle.read().strip()
            left = stat_line.find("(")
            right = stat_line.rfind(")")
            if left < 0 or right <= left:
                continue
            proc_name = stat_line[left + 1 : right].strip() or "n/a"
            parts = stat_line[right + 2 :].split()
            if len(parts) < 15:
                continue
            utime = int(parts[11])
            stime = int(parts[12])
            rss_kb = 0
            try:
                with open(f"{base}/statm", "r", encoding="utf-8") as handle:
                    statm = handle.read().strip().split()
                if len(statm) >= 2:
                    rss_kb = max(int(statm[1]), 0) * page_size_kb
            except Exception:
                rss_kb = 0
            snapshot[pid] = {
                "pid": pid,
                "name": proc_name,
                "args": proc_name,
                "cpu_ticks": max(utime + stime, 0),
                "rss_kb": max(rss_kb, 0),
            }
        except Exception:
            continue
    return snapshot


def _top_process_usage_from_proc(limit: int = 12, proc_root: str = "/proc"):
    return _sample_process_usage(limit=limit, sample_seconds=0.25, proc_root=proc_root).get("rows", [])


def _read_mem_total_kb(proc_root: str = "/proc"):
    try:
        with open(f"{proc_root}/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return int(_memory_details_kb().get("mem_total_kb") or 0)


def _sample_process_usage(limit: int = 12, sample_seconds: float = 0.25, proc_root: str = "/proc"):
    try:
        first = _read_proc_snapshot(proc_root=proc_root)
        if not first:
            return {"rows": [], "total_cpu_pct": 0.0, "process_count": 0}
        hz = 100
        try:
            hz = max(int(os.sysconf("SC_CLK_TCK")), 1)
        except Exception:
            hz = 100
        cpu_count = max(int(os.cpu_count() or 1), 1)
        wait_seconds = max(0.05, min(float(sample_seconds or 0.25), 1.0))
        start_ts = time.monotonic()
        time.sleep(wait_seconds)
        second = _read_proc_snapshot(proc_root=proc_root)
        elapsed = max(time.monotonic() - start_ts, 0.05)
        if not second:
            return {"rows": [], "total_cpu_pct": 0.0, "process_count": 0}
        mem_total_kb = _read_mem_total_kb(proc_root=proc_root)
        rows = []
        total_cpu_pct = 0.0
        for pid, cur in second.items():
            prev = first.get(pid)
            if prev:
                proc_delta = max(int(cur.get("cpu_ticks") or 0) - int(prev.get("cpu_ticks") or 0), 0)
                cpu_pct = (100.0 * float(proc_delta) / float(hz * cpu_count * elapsed)) if hz > 0 else 0.0
            else:
                cpu_pct = 0.0
            rss_kb = max(int(cur.get("rss_kb") or 0), 0)
            ram_pct = (100.0 * rss_kb / mem_total_kb) if mem_total_kb > 0 else 0.0
            cpu_pct = max(cpu_pct, 0.0)
            total_cpu_pct += cpu_pct
            rows.append(
                {
                    "pid": int(cur.get("pid") or pid),
                    "name": (cur.get("name") or "n/a").strip(),
                    "feature": _classify_process_feature(cur.get("name") or "", cur.get("args") or ""),
                    "cpu_pct": round(cpu_pct, 1),
                    "ram_pct": round(max(ram_pct, 0.0), 1),
                    "rss_mb": round(rss_kb / 1024.0, 1),
                }
            )
        rows.sort(key=lambda item: (item.get("cpu_pct") or 0.0, item.get("ram_pct") or 0.0), reverse=True)
        limit_value = None
        try:
            if limit is not None:
                limit_value = int(limit)
        except Exception:
            limit_value = None
        if limit_value is None or limit_value <= 0:
            top = list(rows)
        else:
            top = rows[:limit_value]
        if any((item.get("cpu_pct") or 0.0) > 0 for item in top):
            return {
                "rows": top,
                "total_cpu_pct": round(max(0.0, min(100.0, total_cpu_pct)), 1),
                "process_count": len(rows),
            }
        rows.sort(key=lambda item: (item.get("ram_pct") or 0.0, item.get("rss_mb") or 0.0), reverse=True)
        if limit_value is None or limit_value <= 0:
            top = list(rows)
        else:
            top = rows[:limit_value]
        return {
            "rows": top,
            "total_cpu_pct": round(max(0.0, min(100.0, total_cpu_pct)), 1),
            "process_count": len(rows),
        }
    except Exception:
        return {"rows": [], "total_cpu_pct": 0.0, "process_count": 0}


def _is_threej_feature(feature: str):
    item = (feature or "").strip()
    if not item:
        return False
    if item.startswith("ThreeJ "):
        return True
    return item in {
        "WAN Ping Probes",
        "Accounts Ping Probes",
        "Usage Probes",
        "Optical Monitor",
        "Offline Monitor",
        "WAN Ping",
        "Accounts Ping",
        "Under Surveillance",
        "Usage",
        "Offline",
        "Optical Monitoring",
        "Telegram",
        "Dashboard/API",
    }


def _aggregate_threej_vs_system(process_rows, limit_threej: int = 8):
    threej = {}
    system_bucket = {"cpu_pct": 0.0, "ram_pct": 0.0, "process_count": 0}
    for row in process_rows or []:
        feature = (row.get("feature") or "Unknown").strip() or "Unknown"
        cpu = float(row.get("cpu_pct") or 0.0)
        ram = float(row.get("ram_pct") or 0.0)
        if _is_threej_feature(feature):
            bucket = threej.setdefault(feature, {"cpu_pct": 0.0, "ram_pct": 0.0, "process_count": 0})
            bucket["cpu_pct"] += cpu
            bucket["ram_pct"] += ram
            bucket["process_count"] += 1
        else:
            system_bucket["cpu_pct"] += cpu
            system_bucket["ram_pct"] += ram
            system_bucket["process_count"] += 1
    rows = sorted(
        (
            {
                "name": name,
                "cpu_pct": round(values["cpu_pct"], 1),
                "ram_pct": round(values["ram_pct"], 1),
                "process_count": int(values["process_count"] or 0),
                "kind": "threej",
            }
            for name, values in threej.items()
        ),
        key=lambda item: (item.get("cpu_pct") or 0.0, item.get("ram_pct") or 0.0),
        reverse=True,
    )
    limit_value = max(int(limit_threej or 0), 1)
    rows = rows[:limit_value]
    rows.append(
        {
            "name": "System",
            "cpu_pct": round(system_bucket["cpu_pct"], 1),
            "ram_pct": round(system_bucket["ram_pct"], 1),
            "process_count": int(system_bucket["process_count"] or 0),
            "kind": "system",
        }
    )
    return rows


def _build_runtime_threej_summary(feature_cpu_rows, process_rows, host_cpu_pct: float):
    mandatory = {"Accounts Ping", "Under Surveillance"}
    rows = []
    threej_cpu_total = 0.0
    for item in feature_cpu_rows or []:
        name = (item.get("name") or "").strip()
        if not name:
            continue
        cpu = float(item.get("cpu_pct") or 0.0)
        if cpu <= 0 and name not in mandatory:
            continue
        rows.append(
            {
                "name": name,
                "cpu_pct": round(max(cpu, 0.0), 1),
                "ram_pct": None,
                "process_count": None,
                "kind": "threej",
                "source": "ThreeJ runtime",
            }
        )
        threej_cpu_total += max(cpu, 0.0)
    system_ram = 0.0
    system_count = 0
    for row in process_rows or []:
        feature = (row.get("feature") or "").strip()
        if _is_threej_feature(feature):
            continue
        system_ram += float(row.get("ram_pct") or 0.0)
        system_count += 1
    system_cpu = max(float(host_cpu_pct or 0.0) - threej_cpu_total, 0.0)
    rows.sort(key=lambda item: (item.get("cpu_pct") or 0.0, item.get("name") or ""), reverse=True)
    rows.append(
        {
            "name": "System",
            "cpu_pct": round(system_cpu, 1),
            "ram_pct": round(system_ram, 1),
            "process_count": int(system_count),
            "kind": "system",
            "source": "Host OS / other processes",
        }
    )
    return rows


def _top_process_usage(limit: int = 12):
    try:
        cmd = ["ps", "-eo", "pid=,comm=,pcpu=,pmem=,rss=,args=", "--sort=-pcpu"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0, check=False)
        lines = (out.stdout or "").splitlines()
        items = []
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            pid_raw, comm_raw, cpu_raw, mem_raw, rss_raw = parts[:5]
            args_raw = parts[5] if len(parts) > 5 else comm_raw
            try:
                pid = int(pid_raw)
                cpu_pct = max(float(cpu_raw), 0.0)
                ram_pct = max(float(mem_raw), 0.0)
                rss_kb = max(int(float(rss_raw)), 0)
            except Exception:
                continue
            feature = _classify_process_feature(comm_raw, args_raw)
            items.append(
                {
                    "pid": pid,
                    "name": (comm_raw or "").strip() or "n/a",
                    "feature": feature,
                    "cpu_pct": round(cpu_pct, 1),
                    "ram_pct": round(ram_pct, 1),
                    "rss_mb": round(rss_kb / 1024.0, 1),
                }
            )
            if len(items) >= max(int(limit or 0), 1):
                break
        if items:
            return items
        return _top_process_usage_from_proc(limit=limit)
    except Exception:
        return _top_process_usage_from_proc(limit=limit)


def _aggregate_feature_usage(process_rows, limit: int = 8):
    summary = {}
    for row in process_rows or []:
        feature = (row.get("feature") or "Unknown").strip() or "Unknown"
        bucket = summary.setdefault(feature, {"cpu_pct": 0.0, "ram_pct": 0.0, "process_count": 0})
        bucket["cpu_pct"] += float(row.get("cpu_pct") or 0.0)
        bucket["ram_pct"] += float(row.get("ram_pct") or 0.0)
        bucket["process_count"] += 1
    ranked = sorted(
        (
            {
                "feature": feature,
                "cpu_pct": round(vals["cpu_pct"], 1),
                "ram_pct": round(vals["ram_pct"], 1),
                "process_count": int(vals["process_count"] or 0),
            }
            for feature, vals in summary.items()
        ),
        key=lambda item: (item.get("cpu_pct") or 0.0, item.get("ram_pct") or 0.0),
        reverse=True,
    )
    return ranked[: max(int(limit or 0), 1)]


def _sparkline_points_fixed(values, min_val, max_val, width=120, height=30):
    if not values:
        return ""
    max_points = max(int(width) + 1, 2)
    if len(values) > max_points:
        last_idx = len(values) - 1
        values = [values[int(i * last_idx / (max_points - 1))] for i in range(max_points)]
    span = max(max_val - min_val, 1)
    step = width / max(len(values) - 1, 1)
    points = []
    for idx, value in enumerate(values):
        value = max(min_val, min(max_val, value))
        x = idx * step
        y = height - ((value - min_val) / span) * height
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def _optical_state_snapshot():
    state = get_state("optical_state", {})
    return state if isinstance(state, dict) else {}


def _optical_current_device_ids(state=None):
    state = state if isinstance(state, dict) else _optical_state_snapshot()
    return {
        (item or "").strip()
        for item in (state.get("current_device_ids") or [])
        if (item or "").strip()
    }


def _optical_current_pppoe_keys(state=None):
    state = state if isinstance(state, dict) else _optical_state_snapshot()
    keys = {
        (item or "").strip().lower()
        for item in (state.get("current_pppoe_keys") or [])
        if (item or "").strip()
    }
    if keys:
        return keys
    for item in (state.get("current_devices") or []):
        if not isinstance(item, dict):
            continue
        pppoe = (item.get("pppoe") or "").strip().lower()
        if pppoe:
            keys.add(pppoe)
    return keys


def _optical_known_account_map(state=None):
    state = state if isinstance(state, dict) else _optical_state_snapshot()
    known_accounts = state.get("known_accounts") if isinstance(state.get("known_accounts"), list) else []
    mapping = {}
    for item in known_accounts:
        if not isinstance(item, dict):
            continue
        pppoe = (item.get("pppoe") or "").strip()
        if not pppoe:
            continue
        mapping.setdefault(pppoe.lower(), []).append(item)
    return mapping


def _optical_current_device_entry(device_id="", pppoe="", state=None):
    state = state if isinstance(state, dict) else _optical_state_snapshot()
    device_key = (device_id or "").strip()
    pppoe_key = (pppoe or "").strip().lower()
    devices = state.get("current_devices") if isinstance(state.get("current_devices"), list) else []
    for item in devices:
        if not isinstance(item, dict):
            continue
        if device_key and (item.get("device_id") or "").strip() == device_key:
            return item
        if pppoe_key and (item.get("pppoe") or "").strip().lower() == pppoe_key:
            return item
    return {}


def _optical_known_account_entry(pppoe="", state=None):
    pppoe_key = (pppoe or "").strip().lower()
    if not pppoe_key:
        return {}
    mapping = _optical_known_account_map(state)
    rows = mapping.get(pppoe_key) or []
    return rows[0] if rows else {}


def _optical_chart_gap_threshold_seconds(default_seconds=3600):
    try:
        settings = get_settings("optical", OPTICAL_DEFAULTS)
        minutes = int((settings.get("general") or {}).get("check_interval_minutes", 60) or 60)
    except Exception:
        minutes = max(int(default_seconds / 60), 1)
    interval_seconds = max(minutes, 1) * 60
    return max(int(interval_seconds * 1.5), interval_seconds + 60)


def _optical_with_gaps(rows, *, gap_threshold_seconds=None):
    items = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        ts = (row.get("timestamp") or row.get("ts") or "").strip()
        dt = _parse_iso_z(ts)
        if not ts or not isinstance(dt, datetime):
            continue
        items.append(
            {
                "timestamp": ts,
                "dt": dt,
                "rx": row.get("rx"),
                "tx": row.get("tx"),
            }
        )
    if not items:
        return []
    items.sort(key=lambda item: item["dt"])
    threshold = max(int(gap_threshold_seconds or _optical_chart_gap_threshold_seconds()), 60)
    gap_anchor_seconds = max(int(threshold / 2), 60)
    series = []
    prev = None
    for item in items:
        if prev is not None:
            delta_seconds = (item["dt"] - prev["dt"]).total_seconds()
            if delta_seconds > threshold:
                gap_dt = prev["dt"] + timedelta(seconds=min(gap_anchor_seconds, max(delta_seconds - 1, 1)))
                gap_ts = gap_dt.replace(microsecond=0).isoformat() + "Z"
                series.append({"ts": gap_ts, "rx": None, "tx": None, "gap": True})
        series.append(
            {
                "ts": item["timestamp"],
                "rx": item.get("rx"),
                "tx": item.get("tx"),
                "gap": False,
            }
        )
        prev = item
    return series


def _sparkline_segments_from_series(series, min_val, max_val, width=120, height=30):
    if not series:
        return []
    parsed = []
    for item in series:
        if not isinstance(item, dict):
            continue
        ts = (item.get("ts") or item.get("timestamp") or "").strip()
        dt = _parse_iso_z(ts)
        if not ts or not isinstance(dt, datetime):
            continue
        try:
            x_value = dt.timestamp()
        except Exception:
            continue
        rx = item.get("rx")
        parsed.append({"x": x_value, "rx": rx})
    if not parsed:
        return []
    min_x = parsed[0]["x"]
    max_x = parsed[-1]["x"]
    span_x = max(max_x - min_x, 1.0)
    span_y = max(max_val - min_val, 1.0)
    segments = []
    current = []
    for item in parsed:
        value = item.get("rx")
        if value is None:
            if len(current) >= 2:
                segments.append(" ".join(current))
            current = []
            continue
        value = max(min_val, min(max_val, float(value)))
        x = ((item["x"] - min_x) / span_x) * float(width)
        y = float(height) - ((value - min_val) / span_y) * float(height)
        current.append(f"{x:.1f},{y:.1f}")
    if len(current) >= 2:
        segments.append(" ".join(current))
    return segments


def format_ts_ph(value):
    if not value:
        return "n/a"
    try:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1]
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_ph = dt.astimezone(PH_TZ)
        return dt_ph.strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        return str(value)


def format_bytes(value):
    try:
        value = int(value)
    except Exception:
        return "n/a"
    if value < 0:
        value = 0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(value)
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def format_bps(value):
    try:
        value = float(value)
    except Exception:
        return "n/a"
    if value < 0:
        value = 0.0
    units = ["bps", "kbps", "Mbps", "Gbps"]
    size = value
    idx = 0
    while size >= 1000 and idx < len(units) - 1:
        size /= 1000.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    if size >= 100:
        return f"{size:.0f} {units[idx]}"
    if size >= 10:
        return f"{size:.1f} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def _parse_hhmm(value, default=(0, 0)):
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        return default
    try:
        return int(parts[0]), int(parts[1])
    except Exception:
        return default


def is_time_window_ph(now_ph, start_hhmm, end_hhmm):
    sh, sm = _parse_hhmm(start_hhmm, default=(17, 30))
    eh, em = _parse_hhmm(end_hhmm, default=(21, 0))
    start_t = dt_time(hour=max(min(sh, 23), 0), minute=max(min(sm, 59), 0))
    end_t = dt_time(hour=max(min(eh, 23), 0), minute=max(min(em, 59), 0))
    current_t = now_ph.time()
    if start_t <= end_t:
        return start_t <= current_t <= end_t
    # crosses midnight
    return current_t >= start_t or current_t <= end_t


def build_wan_latency_series(rows, state, hours=24, window_start=None, window_end=None, history_map=None):
    palette = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
        "#e377c2",
        "#7f7f7f",
        "#bcbd22",
        "#17becf",
        "#e41a1c",
        "#377eb8",
        "#4daf4a",
        "#984ea3",
        "#ff7f00",
        "#a65628",
        "#f781bf",
        "#999999",
    ]
    def _parse_ts(value):
        if not value:
            return None
        raw = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    wan_state = (state or {}).get("wans", {})
    series = []
    all_times = []
    row_points = {}
    for idx, row in enumerate(rows):
        wan_id = row.get("wan_id")
        if not wan_id:
            continue
        mode = (row.get("mode") or "routed").lower()
        if not row.get("local_ip"):
            continue
        if mode == "bridged":
            if not row.get("pppoe_router_id"):
                continue
        state_row = wan_state.get(wan_id, {})
        if history_map and wan_id in history_map:
            history = history_map.get(wan_id, [])
        else:
            history = state_row.get("history", [])
        target = state_row.get("target") or ""
        label = row.get("identifier") or row.get("list_name") or wan_id
        points = []
        for item in history:
            ts_raw = item.get("ts")
            ts = _parse_ts(ts_raw)
            if ts is None:
                continue
            points.append(
                {
                    "ts": ts,
                    "status": item.get("status"),
                }
            )
            all_times.append(ts)
        row_points[wan_id] = points
        series.append(
            {
                "id": wan_id,
                "name": f"{row.get('core_label')} {label}".strip(),
                "target": target,
                "core_id": row.get("core_id"),
                "core_label": row.get("core_label"),
                "color": palette[idx % len(palette)],
                "points": [],
            }
        )

    if not all_times:
        return []

    min_all = min(all_times)
    max_all = max(all_times)
    if window_start or window_end:
        if window_start is None:
            window_start = min_all
        if window_end is None:
            window_end = max_all
    else:
        window_end = max_all
        window_start = window_end - timedelta(hours=max(int(hours or 24), 1))
    if window_start > window_end:
        window_start, window_end = window_end, window_start

    def _iso(dt):
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    for item in series:
        wan_id = item["id"]
        points = row_points.get(wan_id, [])
        if not points:
            continue
        points.sort(key=lambda entry: entry["ts"])
        state = None
        first_in_window = None
        for point in points:
            if point["ts"] <= window_start:
                state = point.get("status") or state
            elif first_in_window is None:
                first_in_window = point
                break
        if state is None:
            if first_in_window is not None:
                state = first_in_window.get("status") or "down"
            else:
                state = points[-1].get("status") or "down"
        uptime = 0.0
        downtime = 0.0
        cursor = window_start
        render_points = []
        initial_value = 0 if state == "down" else 100
        render_points.append(
            {"ts": _iso(window_start), "value": initial_value, "downtime_seconds": downtime}
        )
        for point in points:
            ts = point["ts"]
            if ts < window_start:
                continue
            if ts > window_end:
                break
            delta = (ts - cursor).total_seconds()
            if delta > 0:
                if state == "up":
                    uptime += delta
                else:
                    downtime += delta
            cursor = ts
            state = point.get("status") or state
            total = uptime + downtime
            pct = (uptime / total * 100) if total > 0 else (100 if state == "up" else 0)
            y_value = 0 if state == "down" else pct
            render_points.append(
                {"ts": _iso(ts), "value": y_value, "downtime_seconds": downtime}
            )
        if cursor < window_end:
            delta = (window_end - cursor).total_seconds()
            if delta > 0:
                if state == "up":
                    uptime += delta
                else:
                    downtime += delta
            total = uptime + downtime
            pct = (uptime / total * 100) if total > 0 else (100 if state == "up" else 0)
            y_value = 0 if state == "down" else pct
            render_points.append(
                {"ts": _iso(window_end), "value": y_value, "downtime_seconds": downtime}
            )
        item["points"] = render_points
    return series


def _dashboard_job_health(enabled, status):
    if not enabled:
        return ("Disabled", "secondary")
    status = status or {}
    if status.get("last_error"):
        return ("Error", "danger")
    if status.get("last_success_at"):
        return ("OK", "success")
    if status.get("last_run_at"):
        return ("Running", "warning")
    return ("Idle", "secondary")


def _dashboard_surveillance_health(surveillance):
    surveillance = surveillance or {}
    if not bool(surveillance.get("enabled")):
        return ("Disabled", "secondary")
    total = int(surveillance.get("total") or 0)
    level2 = int(surveillance.get("level2") or 0)
    if total <= 0:
        return ("Ready", "success")
    if level2 > 0:
        return ("Active", "danger")
    return ("Active", "warning")


def _dashboard_attention_key(label: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", str(label or "").strip().lower()).strip("_")
    return key or "attention"


def _dashboard_attention_snapshot_payload(attention: dict, ts_iso: str = "") -> dict:
    ts_iso = (ts_iso or utc_now_iso()).strip()
    values = {}
    items_meta = {}
    total_count = 0.0
    for item in (attention or {}).get("items") or []:
        if not isinstance(item, dict):
            continue
        label = (item.get("label") or "").strip()
        key = (item.get("key") or _dashboard_attention_key(label)).strip()
        if not key:
            continue
        try:
            value = float(item.get("value") or 0)
        except Exception:
            value = 0.0
        count_in_total = bool(item.get("count_in_total", True))
        if count_in_total:
            total_count += value
        values[key] = value
        items_meta[key] = {
            "key": key,
            "label": label or key.replace("_", " ").title(),
            "value_label": (item.get("value_label") or str(int(value))).strip(),
            "note": (item.get("note") or "").strip(),
            "active": bool(item.get("active")),
            "count_in_total": count_in_total,
        }
    return {
        "ts": ts_iso,
        "total": float((attention or {}).get("total_count") if (attention or {}).get("total_count") is not None else total_count),
        "values": values,
        "items": items_meta,
    }


def _record_dashboard_attention_snapshot(attention: dict):
    if not isinstance(attention, dict):
        return
    now_iso = utc_now_iso()
    next_snapshot = _dashboard_attention_snapshot_payload(attention, now_iso)
    state = get_state(_DASHBOARD_ATTENTION_HISTORY_KEY, {})
    if not isinstance(state, dict):
        state = {}
    samples = state.get("samples") if isinstance(state.get("samples"), list) else []
    last = samples[-1] if samples and isinstance(samples[-1], dict) else {}
    last_dt = _parse_iso_z(last.get("ts")) if last else None
    now_dt = _parse_iso_z(now_iso) or datetime.utcnow()
    should_append = True
    if isinstance(last_dt, datetime):
        elapsed = (now_dt - last_dt).total_seconds()
        same_total = float(last.get("total") or 0) == float(next_snapshot.get("total") or 0)
        same_values = (last.get("values") or {}) == (next_snapshot.get("values") or {})
        should_append = elapsed >= _DASHBOARD_ATTENTION_SAMPLE_SECONDS or not (same_total and same_values)
    if not should_append:
        return
    cutoff = now_dt - timedelta(days=_DASHBOARD_ATTENTION_HISTORY_DAYS)
    kept = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        sample_dt = _parse_iso_z(sample.get("ts"))
        if isinstance(sample_dt, datetime) and sample_dt >= cutoff:
            kept.append(sample)
    kept.append(next_snapshot)
    save_state(
        _DASHBOARD_ATTENTION_HISTORY_KEY,
        {
            "updated_at": now_iso,
            "samples": kept[-2500:],
        },
    )


def _dashboard_attention_trends_payload(current_attention: dict | None = None) -> dict:
    state = get_state(_DASHBOARD_ATTENTION_HISTORY_KEY, {})
    samples = state.get("samples") if isinstance(state, dict) and isinstance(state.get("samples"), list) else []
    if current_attention:
        current_snapshot = _dashboard_attention_snapshot_payload(current_attention)
        if not samples or (samples[-1].get("ts") if isinstance(samples[-1], dict) else "") != current_snapshot.get("ts"):
            samples = [*samples, current_snapshot]
    keys = []
    meta = {}
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        sample_items = sample.get("items") if isinstance(sample.get("items"), dict) else {}
        for key, item in sample_items.items():
            if key not in keys:
                keys.append(key)
            if isinstance(item, dict):
                meta[key] = item
        values = sample.get("values") if isinstance(sample.get("values"), dict) else {}
        for key in values.keys():
            if key not in keys:
                keys.append(key)
    total_series = []
    item_series = {key: [] for key in keys}
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        ts = (sample.get("ts") or "").strip()
        if not ts:
            continue
        try:
            total_value = float(sample.get("total") or 0)
        except Exception:
            total_value = 0.0
        total_series.append({"x": ts, "y": total_value})
        values = sample.get("values") if isinstance(sample.get("values"), dict) else {}
        for key in keys:
            try:
                item_value = float(values.get(key) or 0)
            except Exception:
                item_value = 0.0
            item_series.setdefault(key, []).append({"x": ts, "y": item_value})
    latest_items = []
    if current_attention:
        for item in (current_attention.get("items") or []):
            if isinstance(item, dict):
                latest_items.append(item)
    return {
        "updated_at": utc_now_iso(),
        "window_days": _DASHBOARD_ATTENTION_HISTORY_DAYS,
        "sample_count": len(samples),
        "total": total_series,
        "items": [
            {
                "key": key,
                "label": (meta.get(key) or {}).get("label") or key.replace("_", " ").title(),
                "note": (meta.get(key) or {}).get("note") or "",
                "series": item_series.get(key) or [],
            }
            for key in keys
        ],
        "latest_items": latest_items,
    }


def _dashboard_isp_status_summary():
    try:
        settings = normalize_isp_status_settings(get_settings("isp_status", ISP_STATUS_DEFAULTS))
        wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
        state = get_state("isp_status_state", {})
        latest = state.get("latest") if isinstance(state.get("latest"), dict) else {}
        counts = {"1g": 0, "100m": 0, "observing": 0, "not_configured": 0, "error": 0}
        enabled_wans = [
            wan
            for wan in (wan_settings.get("wans") or [])
            if isinstance(wan, dict) and bool(wan.get("enabled", True))
        ]
        configured = 0
        for wan in enabled_wans:
            wan_id = (wan.get("id") or f"{wan.get('core_id')}:{wan.get('list_name')}").strip()
            row = latest.get(wan_id) if isinstance(latest.get(wan_id), dict) else {}
            status = (row.get("capacity_status") or "observing").strip().lower()
            if not (wan.get("traffic_interface") or row.get("interface_name") or "").strip():
                status = "not_configured"
            else:
                configured += 1
            if status not in counts:
                status = "observing"
            counts[status] += 1
        review_total = counts["observing"] + counts["not_configured"] + counts["error"]
        if counts["100m"] > 0:
            state_label = "100M"
            tone = "red"
        elif counts["error"] > 0 or counts["not_configured"] > 0:
            state_label = "Review"
            tone = "orange"
        elif counts["observing"] > 0:
            state_label = "Observing"
            tone = "blue"
        elif enabled_wans:
            state_label = "OK"
            tone = "green"
        else:
            state_label = "Off"
            tone = "secondary"
        return {
            "enabled": bool(settings.get("enabled")),
            "total": len(enabled_wans),
            "configured": configured,
            "counts": counts,
            "review_total": review_total,
            "state_label": state_label,
            "tone": tone,
            "last_check_at_ph": format_ts_ph(state.get("last_check_at")),
        }
    except Exception:
        return {
            "enabled": False,
            "total": 0,
            "configured": 0,
            "counts": {"1g": 0, "100m": 0, "observing": 0, "not_configured": 0, "error": 0},
            "review_total": 0,
            "state_label": "Error",
            "tone": "red",
            "last_check_at_ph": "n/a",
        }


def _dashboard_mikrotik_router_summary():
    try:
        pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
        wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
        routers = {}

        def _router_key(kind, router_id):
            return f"{kind}:{str(router_id or '').strip()}"

        def _add_router(kind, router_id, label, host):
            router_id = str(router_id or "").strip()
            if not router_id:
                return
            key = _router_key(kind, router_id)
            routers[key] = {
                "kind": kind,
                "id": router_id,
                "label": (label or router_id).strip(),
                "host": (host or "").strip(),
                "status": "unknown",
                "source": "",
                "last_seen": "",
                "error": "",
            }
            if not routers[key]["host"]:
                routers[key].update({"status": "down", "source": "Settings", "error": "Router host is not configured."})

        for core in (((pulse_settings.get("pulsewatch") or {}).get("mikrotik") or {}).get("cores") or []):
            if isinstance(core, dict):
                _add_router("core", core.get("id"), core.get("label") or core.get("id"), core.get("host"))
        for router in wan_settings.get("pppoe_routers") or []:
            if isinstance(router, dict):
                _add_router("pppoe", router.get("id"), router.get("name") or router.get("id"), router.get("host"))

        health_state = get_state("mikrotik_router_health_state", {})
        health_rows = health_state.get("rows") if isinstance(health_state, dict) and isinstance(health_state.get("rows"), list) else []
        if health_rows:
            for row in health_rows:
                if not isinstance(row, dict):
                    continue
                key = row.get("key") or _router_key(row.get("kind"), row.get("id"))
                if key not in routers:
                    continue
                status = (row.get("status") or "").strip().lower()
                if status not in {"up", "down"}:
                    status = "unknown"
                routers[key].update(
                    {
                        "status": status,
                        "source": "API Health",
                        "last_seen": row.get("last_check_at") or health_state.get("last_check_at") or "",
                        "error": (row.get("error") or "").strip(),
                        "response_ms": row.get("response_ms"),
                    }
                )
            rows = sorted(routers.values(), key=lambda item: (item.get("kind") or "", item.get("label") or ""))
            up = sum(1 for item in rows if item.get("status") == "up")
            down = sum(1 for item in rows if item.get("status") == "down")
            unknown = sum(1 for item in rows if item.get("status") == "unknown")
            if down > 0:
                state_label = "Down"
                tone = "red"
            elif unknown > 0:
                state_label = "Unknown"
                tone = "yellow"
            elif rows:
                state_label = "OK"
                tone = "green"
            else:
                state_label = "None"
                tone = "secondary"
            return {
                "total": len(rows),
                "up": up,
                "down": down,
                "unknown": unknown,
                "state_label": state_label,
                "tone": tone,
                "rows": rows,
                "last_check_at_ph": format_ts_ph(health_state.get("last_check_at")),
            }

        def _parse_dt(value):
            raw = str(value or "").strip()
            if not raw:
                return datetime.min.replace(tzinfo=timezone.utc)
            try:
                if raw.endswith("Z"):
                    raw = raw[:-1] + "+00:00"
                dt = datetime.fromisoformat(raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                return datetime.min.replace(tzinfo=timezone.utc)

        def _apply_status(kind, router_id, connected=None, error="", source="", ts=""):
            key = _router_key(kind, router_id)
            if key not in routers:
                return
            current_dt = _parse_dt(routers[key].get("last_seen"))
            next_dt = _parse_dt(ts)
            if routers[key].get("last_seen") and next_dt < current_dt:
                return
            if connected is True:
                status = "up"
            elif connected is False or (error or "").strip():
                status = "down"
            else:
                status = "unknown"
            routers[key].update(
                {
                    "status": status,
                    "source": source or routers[key].get("source") or "",
                    "last_seen": ts or routers[key].get("last_seen") or "",
                    "error": (error or "").strip(),
                }
            )

        for state_key, source_name, ts_key in (
            ("usage_state", "Usage", "last_check_at"),
            ("offline_state", "Offline", "last_check_at"),
            ("accounts_ping_state", "Accounts Ping", "devices_refreshed_at"),
        ):
            state = get_state(state_key, {})
            if not isinstance(state, dict):
                continue
            rows_key = "routers" if state_key in {"usage_state", "offline_state"} else "router_status"
            rows = state.get(rows_key) if isinstance(state.get(rows_key), list) else []
            state_ts = state.get(ts_key) or ""
            for row in rows:
                if not isinstance(row, dict):
                    continue
                router_id = (row.get("router_id") or "").strip()
                if not router_id:
                    continue
                connected = row.get("connected")
                if connected is not True and connected is not False:
                    connected = None
                _apply_status(
                    "pppoe",
                    router_id,
                    connected=connected,
                    error=row.get("error") or "",
                    source=source_name,
                    ts=row.get("last_check_at") or state_ts,
                )

        isp_state = get_state("isp_status_state", {})
        latest = isp_state.get("latest") if isinstance(isp_state.get("latest"), dict) else {}
        core_observations = {}
        for row in latest.values():
            if not isinstance(row, dict):
                continue
            core_id = (row.get("core_id") or "").strip()
            if not core_id:
                continue
            item = core_observations.setdefault(core_id, {"ok": 0, "error": 0, "ts": "", "error_text": ""})
            row_status = (row.get("status") or "").strip().lower()
            capacity_status = (row.get("capacity_status") or "").strip().lower()
            if row_status == "ok":
                item["ok"] += 1
            elif row_status == "error" or capacity_status == "error":
                item["error"] += 1
                item["error_text"] = item["error_text"] or (row.get("last_error") or row.get("capacity_reason") or "")
            row_ts = row.get("last_sample_at") or row.get("timestamp") or isp_state.get("last_check_at") or ""
            if _parse_dt(row_ts) >= _parse_dt(item.get("ts")):
                item["ts"] = row_ts
        for core_id, item in core_observations.items():
            if item.get("ok"):
                _apply_status("core", core_id, connected=True, source="ISP Port Status", ts=item.get("ts") or isp_state.get("last_check_at") or "")
            elif item.get("error"):
                _apply_status(
                    "core",
                    core_id,
                    connected=False,
                    error=item.get("error_text") or "Core check failed.",
                    source="ISP Port Status",
                    ts=item.get("ts") or isp_state.get("last_check_at") or "",
                )

        rows = sorted(routers.values(), key=lambda item: (item.get("kind") or "", item.get("label") or ""))
        up = sum(1 for item in rows if item.get("status") == "up")
        down = sum(1 for item in rows if item.get("status") == "down")
        unknown = sum(1 for item in rows if item.get("status") == "unknown")
        if down > 0:
            state_label = "Down"
            tone = "red"
        elif unknown > 0:
            state_label = "Unknown"
            tone = "yellow"
        elif rows:
            state_label = "OK"
            tone = "green"
        else:
            state_label = "None"
            tone = "secondary"
        return {
            "total": len(rows),
            "up": up,
            "down": down,
            "unknown": unknown,
            "state_label": state_label,
            "tone": tone,
            "rows": rows,
        }
    except Exception:
        return {
            "total": 0,
            "up": 0,
            "down": 0,
            "unknown": 0,
            "state_label": "Error",
            "tone": "red",
            "rows": [],
        }


def _build_dashboard_kpis(job_status):
    now = datetime.utcnow()
    out = {
        "features": [],
        "surveillance": {},
        "wan": {},
        "usage": {},
        "accounts_ping": {},
        "optical": {},
        "offline": {},
        "isp_status": {},
        "mikrotik_routers": {},
        "attention": {},
    }

    try:
        surv_cfg = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entries = surv_cfg.get("entries") if isinstance(surv_cfg.get("entries"), list) else []
        under = level2 = observe = auto = manual = 0
        ai_pending = ai_error = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            status = (entry.get("status") or "under").strip().lower()
            if status == "level2":
                level2 += 1
            elif status == "observe":
                observe += 1
            else:
                under += 1
            if (entry.get("added_mode") or "manual").strip().lower() == "auto":
                auto += 1
            else:
                manual += 1
            reports = entry.get("ai_reports") if isinstance(entry.get("ai_reports"), dict) else {}
            for stage in ("under", "level2", "observe"):
                item = reports.get(stage) if isinstance(reports.get(stage), dict) else {}
                st = (item.get("status") or "").strip().lower()
                if st in ("queued", "running"):
                    ai_pending += 1
                elif st == "error":
                    ai_error += 1
        history_total = 0
        try:
            history_total = int((list_surveillance_history(page=1, limit=1) or {}).get("total") or 0)
        except Exception:
            history_total = 0
        out["surveillance"] = {
            "total": under + level2 + observe,
            "under": under,
            "level2": level2,
            "observe": observe,
            "auto": auto,
            "manual": manual,
            "history_total": history_total,
            "ai_pending": ai_pending,
            "ai_error": ai_error,
            "enabled": bool(surv_cfg.get("enabled", True)),
        }
    except Exception:
        out["surveillance"] = {
            "total": 0,
            "under": 0,
            "level2": 0,
            "observe": 0,
            "auto": 0,
            "manual": 0,
            "history_total": 0,
            "ai_pending": 0,
            "ai_error": 0,
            "enabled": False,
        }

    try:
        wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
        wan_state = get_state("wan_ping_state", {})
        wans_cfg = wan_cfg.get("wans") if isinstance(wan_cfg.get("wans"), list) else []
        wan_rows = wan_state.get("wans") if isinstance(wan_state.get("wans"), dict) else {}
        up = down = unknown = 0
        latency_ready = 0
        for info in wan_rows.values():
            if not isinstance(info, dict):
                continue
            status = (info.get("status") or "").strip().lower()
            if status == "up":
                up += 1
            elif status == "down":
                down += 1
            else:
                unknown += 1
            if info.get("last_target_check"):
                latency_ready += 1
        targets = [
            item
            for item in ((wan_cfg.get("general") or {}).get("targets") or [])
            if isinstance(item, dict) and bool(item.get("enabled", True))
        ]
        out["wan"] = {
            "configured": len(wans_cfg),
            "up": up,
            "down": down,
            "unknown": unknown,
            "targets_enabled": len(targets),
            "routers": len(wan_cfg.get("pppoe_routers") or []),
            "latency_ready": latency_ready,
            "interval_seconds": int(((wan_cfg.get("general") or {}).get("interval_seconds") or 30)),
            "target_interval_seconds": int(((wan_cfg.get("general") or {}).get("target_latency_interval_seconds") or 30)),
            "enabled": bool(wan_cfg.get("enabled")),
            "last_poll_at_ph": format_ts_ph(wan_state.get("last_status_poll_at")),
        }
    except Exception:
        out["wan"] = {
            "configured": 0,
            "up": 0,
            "down": 0,
            "unknown": 0,
            "targets_enabled": 0,
            "routers": 0,
            "latency_ready": 0,
            "interval_seconds": 30,
            "target_interval_seconds": 30,
            "enabled": False,
            "last_poll_at_ph": "n/a",
        }

    try:
        usage_cfg = get_settings("usage", USAGE_DEFAULTS)
        usage_state = get_state("usage_state", {})
        active_rows = usage_state.get("active_rows") if isinstance(usage_state.get("active_rows"), list) else []
        active_accounts = {
            (row.get("pppoe") or "").strip().lower()
            for row in active_rows
            if isinstance(row, dict) and (row.get("pppoe") or "").strip()
        }
        routers = usage_state.get("routers") if isinstance(usage_state.get("routers"), list) else []
        connected_routers = sum(1 for row in routers if isinstance(row, dict) and bool(row.get("connected")))
        router_errors = sum(1 for row in routers if isinstance(row, dict) and (row.get("error") or "").strip())
        anytime_issues = usage_state.get("anytime_issues") if isinstance(usage_state.get("anytime_issues"), dict) else {}
        out["usage"] = {
            "active_sessions": len(active_rows),
            "active_accounts": len(active_accounts),
            "offline_accounts": len(usage_state.get("offline_rows") or []),
            "router_count": len(routers),
            "router_connected": connected_routers,
            "router_errors": router_errors,
            "anytime_issues": len(anytime_issues),
            "sample_interval_seconds": int(((usage_cfg.get("storage") or {}).get("sample_interval_seconds") or 60)),
            "enabled": bool(usage_cfg.get("enabled")),
            "last_check_at_ph": format_ts_ph(usage_state.get("last_check_at")),
        }
    except Exception:
        out["usage"] = {
            "active_sessions": 0,
            "active_accounts": 0,
            "offline_accounts": 0,
            "router_count": 0,
            "router_connected": 0,
            "router_errors": 0,
            "anytime_issues": 0,
            "sample_interval_seconds": 60,
            "enabled": False,
            "last_check_at_ph": "n/a",
        }

    try:
        acc_cfg = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
        acc_state = get_state("accounts_ping_state", {})
        accounts = acc_state.get("accounts") if isinstance(acc_state.get("accounts"), dict) else {}
        devices = _accounts_ping_state_devices(acc_state)
        device_account_ids = {
            (device.get("account_id") or "").strip()
            for device in devices
            if isinstance(device, dict) and (device.get("account_id") or "").strip()
        }

        tracked_ids = device_account_ids or set(accounts.keys())
        down = issue = up = burst = 0
        for aid in tracked_ids:
            item = accounts.get(aid) if isinstance(accounts.get(aid), dict) else {}
            if not isinstance(item, dict):
                continue
            status = (item.get("last_status") or "").strip().lower()
            if status == "down":
                down += 1
            elif status == "issue":
                issue += 1
            elif status == "up":
                up += 1
            if item.get("burst_until"):
                burst += 1
        issue_total = int(down + issue)
        stable_total = int(up)
        total_accounts = int(len(tracked_ids))
        known_total = int(down + issue + up)
        pending_total = max(total_accounts - known_total, 0)
        out["accounts_ping"] = {
            "accounts": total_accounts,
            "devices": int(len(devices)),
            "up": stable_total,
            "down": down,
            "issue": issue_total,
            "pending": pending_total,
            "burst": burst,
            "interval_seconds": int(((acc_cfg.get("general") or {}).get("base_interval_seconds") or 30)),
            "max_parallel": int(((acc_cfg.get("general") or {}).get("max_parallel") or 16)),
            "enabled": bool(acc_cfg.get("enabled")),
            "last_refresh_at_ph": format_ts_ph(acc_state.get("devices_refreshed_at")),
        }
    except Exception:
        out["accounts_ping"] = {
            "accounts": 0,
            "devices": 0,
            "up": 0,
            "down": 0,
            "issue": 0,
            "burst": 0,
            "interval_seconds": 30,
            "max_parallel": 16,
            "enabled": False,
            "last_refresh_at_ph": "n/a",
        }

    try:
        opt_cfg = get_settings("optical", OPTICAL_DEFAULTS)
        classification = opt_cfg.get("classification") if isinstance(opt_cfg.get("classification"), dict) else {}
        issue_rx = float(classification.get("issue_rx_dbm", -27.0) or -27.0)
        issue_tx = float(classification.get("issue_tx_dbm", -2.0) or -2.0)
        tx_real_min = float(classification.get("tx_realistic_min_dbm", -10.0) or -10.0)
        tx_real_max = float(classification.get("tx_realistic_max_dbm", 10.0) or 10.0)
        since_iso = (now - timedelta(hours=48)).replace(microsecond=0).isoformat() + "Z"
        latest = get_optical_latest_results_since(since_iso, apply_tx_fallback=False)
        current_device_ids = _optical_current_device_ids()
        if current_device_ids:
            latest = [
                row
                for row in latest
                if isinstance(row, dict) and (row.get("device_id") or "").strip() in current_device_ids
            ]
        issue_rx_count = 0
        issue_tx_count = 0
        priority_count = 0
        pppoe_set = set()
        for row in latest:
            if not isinstance(row, dict):
                continue
            pppoe = (row.get("pppoe") or "").strip().lower()
            if pppoe:
                pppoe_set.add(pppoe)
            rx = row.get("rx")
            tx = row.get("tx")
            if row.get("priority"):
                priority_count += 1
            try:
                if rx is not None and float(rx) <= issue_rx:
                    issue_rx_count += 1
            except Exception:
                pass
            try:
                if tx is not None:
                    tx_value = float(tx)
                    if tx_real_min <= tx_value <= tx_real_max and tx_value <= issue_tx:
                        issue_tx_count += 1
            except Exception:
                pass
        out["optical"] = {
            "latest_devices": len(latest),
            "latest_accounts": len(pppoe_set),
            "issue_rx": issue_rx_count,
            "issue_tx": issue_tx_count,
            "priority": priority_count,
            "enabled": bool(opt_cfg.get("enabled")),
            "threshold_rx": issue_rx,
            "threshold_tx": issue_tx,
        }
    except Exception:
        out["optical"] = {
            "latest_devices": 0,
            "latest_accounts": 0,
            "issue_rx": 0,
            "issue_tx": 0,
            "priority": 0,
            "enabled": False,
            "threshold_rx": -27.0,
            "threshold_tx": -2.0,
        }

    try:
        off_cfg = get_settings("offline", OFFLINE_DEFAULTS)
        off_state = get_state("offline_state", {})
        history_since = (now - timedelta(days=1)).replace(microsecond=0).isoformat() + "Z"
        off_hist = get_offline_history_since(history_since, limit=2000)
        out["offline"] = {
            "current": len(off_state.get("rows") or []),
            "history_24h": len(off_hist),
            "routers": len(off_state.get("routers") or []),
            "router_errors": len(off_state.get("router_errors") or []),
            "mode": (off_state.get("mode") or off_cfg.get("mode") or "secrets"),
            "threshold_minutes": int(off_state.get("min_offline_minutes") or 0),
            "enabled": bool(off_cfg.get("enabled")),
            "last_check_at_ph": format_ts_ph(off_state.get("last_check_at")),
        }
    except Exception:
        out["offline"] = {
            "current": 0,
            "history_24h": 0,
            "routers": 0,
            "router_errors": 0,
            "mode": "secrets",
            "threshold_minutes": 0,
            "enabled": False,
            "last_check_at_ph": "n/a",
        }

    out["isp_status"] = _dashboard_isp_status_summary()
    out["mikrotik_routers"] = _dashboard_mikrotik_router_summary()

    try:
        accounts_issue_total = int(out["accounts_ping"].get("issue") or 0)
        optical_issue_total = int(out["optical"].get("issue_rx") or 0) + int(out["optical"].get("issue_tx") or 0)
        active_monitoring_total = int(out["surveillance"].get("under") or 0)
        needs_manual_fix_total = int(out["surveillance"].get("level2") or 0)
        usage_issue_total = int(out["usage"].get("anytime_issues") or 0)
        wan_down_total = int(out["wan"].get("down") or 0)
        offline_total = int(out["offline"].get("current") or 0)
        cpu_pct = round(float(_cpu_percent()), 1)
        ram_pct = round(float(_memory_percent()), 1)
        attention_items = [
            {
                "key": "accounts_ping_issues",
                "label": "Accounts Ping Issues",
                "value": accounts_issue_total,
                "value_label": f"{accounts_issue_total} accounts",
                "active": accounts_issue_total > 0,
                "note": "Accounts currently classified as issue/down.",
                "count_in_total": True,
            },
            {
                "key": "optical_monitoring_issues",
                "label": "Optical Monitoring Issues",
                "value": optical_issue_total,
                "value_label": f"{optical_issue_total} findings",
                "active": optical_issue_total > 0,
                "note": "RX/TX threshold violations from latest optical data.",
                "count_in_total": True,
            },
            {
                "key": "surveillance_active_monitoring",
                "label": "Under Surveillance · Active Monitoring",
                "value": active_monitoring_total,
                "value_label": f"{active_monitoring_total} accounts",
                "active": active_monitoring_total > 0,
                "note": "Accounts still under active watch.",
                "count_in_total": True,
            },
            {
                "key": "surveillance_needs_manual_fix",
                "label": "Under Surveillance · Needs Manual Fix",
                "value": needs_manual_fix_total,
                "value_label": f"{needs_manual_fix_total} accounts",
                "active": needs_manual_fix_total > 0,
                "note": "Accounts requiring manual intervention.",
                "count_in_total": True,
            },
            {
                "key": "usage_issues",
                "label": "Usage Issues",
                "value": usage_issue_total,
                "value_label": f"{usage_issue_total} accounts",
                "active": usage_issue_total > 0,
                "note": "Accounts currently detected in Usage Issues.",
                "count_in_total": True,
            },
            {
                "key": "wan_ping_down_isps",
                "label": "WAN Ping · Down ISPs",
                "value": wan_down_total,
                "value_label": f"{wan_down_total} down",
                "active": wan_down_total > 0,
                "note": "Any ISP marked down by WAN Ping/Netwatch.",
                "count_in_total": True,
            },
            {
                "key": "offline_accounts",
                "label": "Offline Accounts",
                "value": offline_total,
                "value_label": f"{offline_total} offline",
                "active": offline_total > 0,
                "note": "Accounts currently in Offline state.",
                "count_in_total": True,
            },
            {
                "key": "cpu_usage",
                "label": "CPU Usage",
                "value": cpu_pct,
                "value_label": f"{cpu_pct:.1f}%",
                "active": cpu_pct >= 85.0,
                "note": "Triggers attention at 85% and above.",
                "count_in_total": False,
            },
            {
                "key": "ram_usage",
                "label": "RAM Usage",
                "value": ram_pct,
                "value_label": f"{ram_pct:.1f}%",
                "active": ram_pct >= 85.0,
                "note": "Triggers attention at 85% and above.",
                "count_in_total": False,
            },
        ]
        active_total = sum(1 for item in attention_items if bool(item.get("active")))
        total_count = int(sum(float(item.get("value") or 0) for item in attention_items if bool(item.get("count_in_total", True))))
        out["attention"] = {
            "title": "Operations Attention Board",
            "active_total": active_total,
            "total_count": total_count,
            "items": attention_items,
            "healthy": active_total == 0,
        }
    except Exception:
        out["attention"] = {
            "title": "Operations Attention Board",
            "active_total": 0,
            "total_count": 0,
            "items": [],
            "healthy": True,
        }
    try:
        _record_dashboard_attention_snapshot(out.get("attention") or {})
    except Exception:
        pass

    isp_counts = out["isp_status"].get("counts") if isinstance(out.get("isp_status"), dict) else {}
    isp_counts = isp_counts if isinstance(isp_counts, dict) else {}
    router_summary = out.get("mikrotik_routers") if isinstance(out.get("mikrotik_routers"), dict) else {}
    feature_defs = [
        ("WAN Ping", "wan_ping", out["wan"].get("enabled"), f"{out['wan'].get('configured', 0)} ISPs · {out['wan'].get('targets_enabled', 0)} targets"),
        (
            "ISP Port Status",
            "isp_status",
            out["isp_status"].get("enabled"),
            f"{out['isp_status'].get('total', 0)} ISPs · {isp_counts.get('1g', 0)} 1G / {isp_counts.get('100m', 0)} 100M",
        ),
        (
            "MikroTik Routers",
            "",
            bool(router_summary.get("total")),
            f"{router_summary.get('up', 0)} up · {router_summary.get('down', 0)} down · {router_summary.get('unknown', 0)} unknown",
        ),
        ("Accounts Ping", "accounts_ping", out["accounts_ping"].get("enabled"), f"{out['accounts_ping'].get('accounts', 0)} accounts"),
        ("Under Surveillance", "", out["surveillance"].get("enabled"), f"{out['surveillance'].get('total', 0)} active"),
        ("Usage", "usage", out["usage"].get("enabled"), f"{out['usage'].get('active_accounts', 0)} active accounts"),
        ("Offline", "offline", out["offline"].get("enabled"), f"{out['offline'].get('current', 0)} offline now"),
        ("Optical Monitoring", "optical", out["optical"].get("enabled"), f"{out['optical'].get('latest_devices', 0)} devices"),
    ]
    features = []
    for label, job_key, enabled, subtitle in feature_defs:
        status = job_status.get(job_key) if job_key else {}
        if label == "Under Surveillance":
            state_label, tone = _dashboard_surveillance_health(out["surveillance"])
            badge_label = state_label
        elif label == "ISP Port Status":
            state_label = out["isp_status"].get("state_label") or "Off"
            tone = out["isp_status"].get("tone") or "secondary"
            badge_label = f"{isp_counts.get('1g', 0)}/{isp_counts.get('100m', 0)}"
        elif label == "MikroTik Routers":
            state_label = router_summary.get("state_label") or "None"
            tone = router_summary.get("tone") or "secondary"
            badge_label = f"{router_summary.get('up', 0)}/{router_summary.get('total', 0)}"
        else:
            state_label, tone = _dashboard_job_health(bool(enabled), status)
            badge_label = state_label
        features.append(
            {
                "label": label,
                "state_label": state_label,
                "tone": tone,
                "badge_label": badge_label,
                "subtitle": subtitle,
                "last_run_at_ph": format_ts_ph((status or {}).get("last_run_at")) if job_key else "n/a",
                "last_success_at_ph": format_ts_ph((status or {}).get("last_success_at")) if job_key else "n/a",
            }
        )
    out["features"] = features
    return out


def _get_dashboard_kpis_cached(job_status, force=False):
    now_mono = time.monotonic()
    if not force:
        with _dashboard_kpis_cache_lock:
            cached = _dashboard_kpis_cache.get("data")
            cached_at = float(_dashboard_kpis_cache.get("at") or 0.0)
            if cached is not None and (now_mono - cached_at) < float(_DASHBOARD_KPI_CACHE_SECONDS):
                return copy.deepcopy(cached)
    fresh = _build_dashboard_kpis(job_status)
    with _dashboard_kpis_cache_lock:
        _dashboard_kpis_cache["data"] = copy.deepcopy(fresh)
        _dashboard_kpis_cache["at"] = now_mono
    return fresh


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    for status in job_status.values():
        status["last_run_at_ph"] = format_ts_ph(status.get("last_run_at"))
        status["last_success_at_ph"] = format_ts_ph(status.get("last_success_at"))
        status["last_error_at_ph"] = format_ts_ph(status.get("last_error_at"))
    dashboard_kpis = _get_dashboard_kpis_cached(job_status)
    dashboard_latest_logs = _audit_log_rows(limit=20, surveillance_only=False)
    if bool(getattr(request.state, "auth_enabled", True)):
        allowed_categories = _auth_allowed_log_categories(getattr(request.state, "auth_permission_codes", []) or [])
        dashboard_latest_logs = _audit_rows_for_categories(
            limit=20,
            allowed_categories=allowed_categories,
            surveillance_only=False,
        )
    return templates.TemplateResponse(
        "dashboard.html",
        make_context(
            request,
            {
                "job_status": job_status,
                "dashboard_kpis": dashboard_kpis,
                "dashboard_latest_logs": dashboard_latest_logs,
            },
        ),
    )


@app.get("/dashboard/latest-logs", response_class=JSONResponse)
async def dashboard_latest_logs(request: Request, limit: int = 20):
    try:
        limit_value = int(limit or 20)
    except Exception:
        limit_value = 20
    limit_value = max(1, min(limit_value, 100))
    rows = _audit_log_rows(limit=limit_value, surveillance_only=False)
    if bool(getattr(request.state, "auth_enabled", True)):
        allowed_categories = _auth_allowed_log_categories(getattr(request.state, "auth_permission_codes", []) or [])
        rows = _audit_rows_for_categories(
            limit=limit_value,
            allowed_categories=allowed_categories,
            surveillance_only=False,
        )
    return JSONResponse({"rows": rows, "captured_at": utc_now_iso()})


@app.get("/dashboard/attention-trends", response_class=JSONResponse)
async def dashboard_attention_trends(request: Request):
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    dashboard_kpis = _get_dashboard_kpis_cached(job_status)
    attention = dashboard_kpis.get("attention") if isinstance(dashboard_kpis, dict) else {}
    return _json_no_store({"ok": True, "trends": _dashboard_attention_trends_payload(attention if isinstance(attention, dict) else {})})


@app.get("/dashboard/kpis", response_class=JSONResponse)
async def dashboard_kpis_live(request: Request):
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    for status in job_status.values():
        status["last_run_at_ph"] = format_ts_ph(status.get("last_run_at"))
        status["last_success_at_ph"] = format_ts_ph(status.get("last_success_at"))
        status["last_error_at_ph"] = format_ts_ph(status.get("last_error_at"))
    dashboard_kpis = _get_dashboard_kpis_cached(job_status, force=True)
    return _json_no_store({"ok": True, "dashboard_kpis": dashboard_kpis, "updated_at": utc_now_iso()})


@app.get("/logs", response_class=HTMLResponse)
@app.get("/logs/system", response_class=HTMLResponse)
@app.get("/logs/mikrotik", response_class=HTMLResponse)
async def logs_page(request: Request):
    path = request.url.path.rstrip("/")
    if path.endswith("/mikrotik"):
        active_tab = "mikrotik"
    elif path.endswith("/system"):
        active_tab = "system"
    else:
        active_tab = (request.query_params.get("tab") or "system").strip().lower()
    query = (request.query_params.get("q") or "").strip()
    category = (request.query_params.get("category") or "all").strip()
    action_filter = (request.query_params.get("action") or "").strip()
    user_filter = (request.query_params.get("user") or "").strip()
    window = (request.query_params.get("window") or "all").strip().lower()
    page = _parse_table_page(request.query_params.get("page"), default=1)
    mt_query = (request.query_params.get("mt_q") or "").strip()
    mt_router = (request.query_params.get("mt_router") or "").strip()
    mt_severity = (request.query_params.get("mt_severity") or "").strip().lower()
    mt_topic = (request.query_params.get("mt_topic") or "").strip()
    mt_window = (request.query_params.get("mt_window") or "24h").strip().lower()
    mt_limit = _parse_table_limit(request.query_params.get("mt_limit"), default=100)
    mt_page = _parse_table_page(request.query_params.get("mt_page"), default=1)
    mt_tab = (request.query_params.get("mt_tab") or "logs").strip().lower()
    mt_settings_panel_tab = (request.query_params.get("setup_tab") or "router").strip().lower()
    mt_router_setup_tab = (request.query_params.get("router_setup_tab") or "manual").strip().lower()
    if mt_tab not in {"logs", "settings"}:
        mt_tab = "logs"
    if mt_settings_panel_tab not in {"router", "settings"}:
        mt_settings_panel_tab = "router"
    if mt_router_setup_tab not in {"manual", "auto"}:
        mt_router_setup_tab = "manual"

    all_categories = list(LOG_CATEGORY_PERMISSION_MAP.keys())
    can_view_system_logs = _auth_request_has_permission(request, "logs.system.view") or _auth_request_has_permission(request, "logs.timeline.view")
    can_view_mikrotik_logs = _auth_request_has_permission(request, "logs.mikrotik.view")
    can_edit_mikrotik_logs = _auth_request_has_permission(request, "logs.mikrotik.edit")
    if bool(getattr(request.state, "auth_enabled", True)):
        allowed_categories = _auth_allowed_log_categories(getattr(request.state, "auth_permission_codes", []) or [])
    else:
        allowed_categories = list(all_categories)
        can_view_system_logs = True
        can_view_mikrotik_logs = True
        can_edit_mikrotik_logs = True
    if not allowed_categories and not can_view_mikrotik_logs:
        return _auth_forbidden_response(request, "logs.timeline.view")
    if active_tab not in {"system", "mikrotik"}:
        active_tab = "system"
    if active_tab == "system" and not can_view_system_logs and can_view_mikrotik_logs:
        active_tab = "mikrotik"
    if active_tab == "mikrotik" and not can_view_mikrotik_logs and can_view_system_logs:
        active_tab = "system"

    allowed_category_set = {str(item or "").strip() for item in allowed_categories if str(item or "").strip()}
    valid_category_values = {"all", *allowed_category_set}
    if category not in valid_category_values:
        category = "all"
    if window not in {"all", "24h", "7d", "30d"}:
        window = "all"

    all_rows = _audit_log_rows(limit=20000, surveillance_only=False)
    visible_rows = [row for row in all_rows if str(row.get("category") or "").strip() in allowed_category_set]
    users = sorted(
        {
            (row.get("username") or "").strip()
            for row in visible_rows
            if (row.get("username") or "").strip()
        },
        key=lambda value: value.lower(),
    )
    actions = sorted(
        {
            (row.get("action") or "").strip()
            for row in visible_rows
            if (row.get("action") or "").strip()
        },
        key=lambda value: value.lower(),
    )

    now_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
    cutoff = None
    if window == "24h":
        cutoff = now_utc - timedelta(hours=24)
    elif window == "7d":
        cutoff = now_utc - timedelta(days=7)
    elif window == "30d":
        cutoff = now_utc - timedelta(days=30)

    filtered_rows = []
    query_l = query.lower()
    for row in visible_rows:
        if category != "all" and (row.get("category") or "") != category:
            continue
        if action_filter and (row.get("action") or "") != action_filter:
            continue
        if user_filter and (row.get("username") or "") != user_filter:
            continue
        if cutoff is not None:
            ts_raw = (row.get("timestamp") or "").strip()
            ts_dt = None
            try:
                raw = ts_raw[:-1] + "+00:00" if ts_raw.endswith("Z") else ts_raw
                ts_dt = datetime.fromisoformat(raw)
                if ts_dt.tzinfo is None:
                    ts_dt = ts_dt.replace(tzinfo=timezone.utc)
                else:
                    ts_dt = ts_dt.astimezone(timezone.utc)
            except Exception:
                ts_dt = None
            if ts_dt is None or ts_dt < cutoff:
                continue
        if query_l:
            blob = " ".join(
                [
                    str(row.get("username") or ""),
                    str(row.get("action") or ""),
                    str(row.get("category") or ""),
                    str(row.get("resource") or ""),
                    str(row.get("details") or ""),
                    str(row.get("message") or ""),
                    str(row.get("ip_address") or ""),
                ]
            ).lower()
            if query_l not in blob:
                continue
        filtered_rows.append(row)

    page_limit = 100
    total = len(filtered_rows)
    pages = max((total + page_limit - 1) // page_limit, 1)
    page = max(1, min(page, pages))
    start_idx = (page - 1) * page_limit
    end_idx = start_idx + page_limit
    rows_page = filtered_rows[start_idx:end_idx]

    base_params = {
        "q": query,
        "category": category if category != "all" else "",
        "action": action_filter,
        "user": user_filter,
        "window": window if window != "all" else "",
    }
    base_params = {key: value for key, value in base_params.items() if value}
    logs_base_query = urllib.parse.urlencode(base_params)

    if mt_window not in {"all", "24h", "7d", "30d"}:
        mt_window = "24h"
    valid_severities = {"", "debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"}
    if mt_severity not in valid_severities:
        mt_severity = ""
    mt_offset = (mt_page - 1) * mt_limit
    mt_total, mt_rows = (0, [])
    mt_facets = {"routers": [], "severities": [], "topics": []}
    mt_stats = {"total": 0, "today": 0, "warning": 0, "error": 0, "critical": 0, "sources": 0}
    mt_settings = normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
    mt_drop_topics = [
        str(item or "").strip()
        for item in (((mt_settings.get("filters") or {}).get("drop_topics")) or [])
        if str(item or "").strip() and str(item or "").count("\t") >= 2
    ]
    mt_state = get_state("mikrotik_logs_state", {})
    if not isinstance(mt_state, dict):
        mt_state = {}
    if can_view_mikrotik_logs:
        mt_total, mt_rows = list_mikrotik_logs(
            limit=mt_limit,
            offset=mt_offset,
            query=mt_query,
            router=mt_router,
            severity=mt_severity,
            topic=mt_topic,
            window=mt_window,
            drop_topics=mt_drop_topics,
        )
        mt_facets = get_mikrotik_log_facets(drop_topics=mt_drop_topics)
        mt_stats = get_mikrotik_log_stats(drop_topics=mt_drop_topics)
    mt_pages = max((mt_total + mt_limit - 1) // mt_limit, 1)
    if mt_page > mt_pages and can_view_mikrotik_logs:
        mt_page = mt_pages
        mt_offset = (mt_page - 1) * mt_limit
        mt_total, mt_rows = list_mikrotik_logs(
            limit=mt_limit,
            offset=mt_offset,
            query=mt_query,
            router=mt_router,
            severity=mt_severity,
            topic=mt_topic,
            window=mt_window,
            drop_topics=mt_drop_topics,
        )
    mt_page = max(1, min(mt_page, mt_pages))
    mt_router_tabs_map = {}
    for item in mt_facets.get("routers") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        mt_router_tabs_map[value] = {
            "value": value,
            "label": str(item.get("label") or value).strip(),
            "count": int(item.get("count") or 0),
        }
    try:
        pulse_settings_for_tabs = get_settings("isp_ping", ISP_PING_DEFAULTS)
        for core in ((((pulse_settings_for_tabs.get("pulsewatch") or {}).get("mikrotik") or {}).get("cores")) or []):
            if not isinstance(core, dict):
                continue
            value = (core.get("id") or core.get("host") or "").strip()
            if not value:
                continue
            mt_router_tabs_map.setdefault(
                value,
                {
                    "value": value,
                    "label": (core.get("label") or core.get("id") or core.get("host") or value).strip(),
                    "count": 0,
                },
            )
    except Exception:
        pass
    try:
        wan_settings_for_tabs = get_settings("wan_ping", WAN_PING_DEFAULTS)
        for router in (wan_settings_for_tabs.get("pppoe_routers") or []):
            if not isinstance(router, dict):
                continue
            value = (router.get("id") or router.get("host") or "").strip()
            if not value:
                continue
            mt_router_tabs_map.setdefault(
                value,
                {
                    "value": value,
                    "label": (router.get("name") or router.get("id") or router.get("host") or value).strip(),
                    "count": 0,
                },
            )
    except Exception:
        pass
    mt_drop_counts_by_router = {}
    for drop_rule in mt_drop_topics:
        router_value = drop_rule.split("\t", 1)[0].strip()
        if not router_value:
            continue
        router_key = router_value.lower()
        mt_drop_counts_by_router[router_key] = mt_drop_counts_by_router.get(router_key, 0) + 1
    for item in mt_router_tabs_map.values():
        item["drop_count"] = mt_drop_counts_by_router.get(str(item.get("value") or "").strip().lower(), 0)
    mt_router_tabs = sorted(mt_router_tabs_map.values(), key=lambda item: (item.get("label") or item.get("value") or "").lower())
    mt_active_router_label = ""
    if mt_router:
        active_router_info = mt_router_tabs_map.get(mt_router) or {}
        mt_active_router_label = (active_router_info.get("label") or mt_router).strip()
    mt_base_params = {
        "mt_tab": "logs",
        "mt_q": mt_query,
        "mt_router": mt_router,
        "mt_severity": mt_severity,
        "mt_topic": mt_topic,
        "mt_window": mt_window if mt_window != "24h" else "",
        "mt_limit": mt_limit if mt_limit != 100 else "",
    }
    mt_base_query = urllib.parse.urlencode({key: value for key, value in mt_base_params.items() if value})
    mt_router_tab_params = {
        "mt_tab": "logs",
        "mt_q": mt_query,
        "mt_severity": mt_severity,
        "mt_topic": mt_topic,
        "mt_window": mt_window if mt_window != "24h" else "",
        "mt_limit": mt_limit if mt_limit != 100 else "",
    }
    mt_router_tab_query = urllib.parse.urlencode({key: value for key, value in mt_router_tab_params.items() if value})
    configured_drop_topics = {item.lower() for item in mt_drop_topics}
    noisy_topic_keywords = ("debug", "packet", "firewall", "dhcp", "dns", "route", "wireless")
    mt_drop_topic_options = []
    seen_topic_values = set()
    for item in (mt_facets.get("topics") or []):
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        normalized = value.lower()
        if normalized in seen_topic_values:
            continue
        seen_topic_values.add(normalized)
        count = int(item.get("count") or 0)
        suggested = count >= 100 or any(keyword in normalized for keyword in noisy_topic_keywords)
        mt_drop_topic_options.append(
            {
                "value": value,
                "count": count,
                "selected": normalized in configured_drop_topics,
                "suggested": suggested,
            }
        )
    mt_drop_topic_options = sorted(
        mt_drop_topic_options,
        key=lambda item: (not bool(item.get("selected")), not bool(item.get("suggested")), -int(item.get("count") or 0), item.get("value", "").lower()),
    )
    mt_custom_drop_topics = [
        item
        for item in mt_drop_topics
        if str(item or "").strip().lower() not in seen_topic_values
    ]
    mt_router_drop_topics = [
        item
        for item in mt_drop_topics
        if mt_router and item.split("\t", 1)[0].strip().lower() == mt_router.lower()
    ]
    server_host = (request.url.hostname or "SERVER_IP").strip()
    auto_setup_cfg = mt_settings.get("auto_setup") if isinstance(mt_settings.get("auto_setup"), dict) else {}
    mt_setup_host = (auto_setup_cfg.get("server_host") or server_host or "SERVER_IP").strip()
    mt_port = int((mt_settings.get("receiver") or {}).get("port") or 5514)
    mt_commands = build_mikrotik_log_setup_commands(mt_setup_host, mt_port)
    mt_setup_routers = get_mikrotik_log_setup_routers()
    mt_setup_state = mt_state.get("setup") if isinstance(mt_state.get("setup"), dict) else {}
    mt_setup_results = mt_setup_state.get("results") if isinstance(mt_setup_state.get("results"), list) else []
    mt_setup_result_map = {
        f"{(item.get('router_kind') or '').strip()}::{(item.get('router_id') or '').strip()}": item
        for item in mt_setup_results
        if isinstance(item, dict)
    }
    mt_setup_routers = [
        {
            **router,
            "setup_status": mt_setup_result_map.get(
                f"{(router.get('kind') or '').strip()}::{(router.get('id') or '').strip()}",
                {},
            ),
        }
        for router in mt_setup_routers
    ]
    status_map = {item["job_name"]: dict(item) for item in get_job_status()}
    mt_job = status_map.get("mikrotik_logs", {})
    mt_job["last_run_at_ph"] = format_ts_ph(mt_job.get("last_run_at"))
    mt_job["last_success_at_ph"] = format_ts_ph(mt_job.get("last_success_at"))
    mt_job["last_error_at_ph"] = format_ts_ph(mt_job.get("last_error_at"))

    return templates.TemplateResponse(
        "logs.html",
        make_context(
            request,
            {
                "active_tab": active_tab,
                "can_view_system_logs": can_view_system_logs,
                "can_view_mikrotik_logs": can_view_mikrotik_logs,
                "can_edit_mikrotik_logs": can_edit_mikrotik_logs,
                "logs_rows": rows_page,
                "logs_total": total,
                "logs_page": page,
                "logs_pages": pages,
                "logs_query": query,
                "logs_category": category,
                "logs_action": action_filter,
                "logs_user": user_filter,
                "logs_window": window,
                "logs_category_options": allowed_categories,
                "logs_users": users,
                "logs_actions": actions,
                "logs_base_query": logs_base_query,
                "mikrotik_logs_rows": [
                    {
                        **dict(row),
                        "timestamp_ph": format_ts_ph(row.get("timestamp")),
                        "received_at_ph": format_ts_ph(row.get("received_at")),
                    }
                    for row in mt_rows
                ],
                "mikrotik_logs_total": mt_total,
                "mikrotik_logs_page": mt_page,
                "mikrotik_logs_pages": mt_pages,
                "mikrotik_logs_limit": mt_limit,
                "mikrotik_logs_query": mt_query,
                "mikrotik_logs_router": mt_router,
                "mikrotik_logs_severity": mt_severity,
                "mikrotik_logs_topic": mt_topic,
                "mikrotik_logs_window": mt_window,
                "mikrotik_logs_base_query": mt_base_query,
                "mikrotik_logs_router_tab_query": mt_router_tab_query,
                "mikrotik_logs_router_tabs": mt_router_tabs,
                "mikrotik_logs_active_tab": mt_tab,
                "mikrotik_logs_settings_panel_tab": mt_settings_panel_tab,
                "mikrotik_logs_router_setup_tab": mt_router_setup_tab,
                "mikrotik_logs_facets": mt_facets,
                "mikrotik_logs_stats": mt_stats,
                "mikrotik_logs_settings": mt_settings,
                "mikrotik_logs_drop_topic_options": mt_drop_topic_options,
                "mikrotik_logs_custom_drop_topics": mt_custom_drop_topics,
                "mikrotik_logs_drop_topics": mt_drop_topics,
                "mikrotik_logs_router_drop_topics": mt_router_drop_topics,
                "mikrotik_logs_active_router_label": mt_active_router_label,
                "mikrotik_logs_state": mt_state,
                "mikrotik_logs_setup_state": mt_setup_state,
                "mikrotik_logs_setup_routers": mt_setup_routers,
                "mikrotik_logs_setup_host": mt_setup_host,
                "mikrotik_logs_job": mt_job,
                "mikrotik_logs_commands": mt_commands,
            },
        ),
    )


@app.post("/logs/mikrotik/settings", response_class=HTMLResponse)
async def mikrotik_logs_settings_save(request: Request):
    if not _auth_request_has_permission(request, "logs.mikrotik.edit"):
        return _auth_forbidden_response(request, "logs.mikrotik.edit")
    form = await request.form()
    existing = normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
    selected_drop_topics = [
        str(item or "").strip()
        for item in (((existing.get("filters") or {}).get("drop_topics")) or [])
        if str(item or "").strip() and str(item or "").count("\t") >= 2
    ]
    if "drop_topics" in form or "drop_topics_custom" in form:
        selected_drop_topics = []
        try:
            selected_drop_topics.extend([str(item or "").strip() for item in form.getlist("drop_topics") if str(item or "").strip()])
        except Exception:
            selected_drop_topics.extend(parse_lines(form.get("drop_topics")))
        selected_drop_topics.extend(parse_lines(form.get("drop_topics_custom")))
    settings = {
        "enabled": parse_bool(form, "enabled"),
        "receiver": {
            "host": (form.get("receiver_host") or "0.0.0.0").strip() or "0.0.0.0",
            "port": parse_int(form, "receiver_port", 5514),
        },
        "storage": {
            "retention_days": parse_int(form, "retention_days", 30),
            "batch_size": parse_int(form, "batch_size", 100),
            "flush_interval_seconds": parse_int(form, "flush_interval_seconds", 2),
        },
        "filters": {
            "allow_unknown_sources": parse_bool(form, "allow_unknown_sources"),
            "min_severity": (form.get("min_severity") or "debug").strip().lower(),
            "drop_topics": sorted({item.lower(): item for item in selected_drop_topics if item}.values(), key=lambda value: value.lower()),
        },
        "auto_setup": {
            "enabled": parse_bool(form, "auto_setup_enabled"),
            "server_host": (form.get("auto_setup_server_host") or "").strip(),
            "check_interval_hours": parse_int(form, "auto_setup_check_interval_hours", 24),
            "timeout_seconds": parse_int(form, "auto_setup_timeout_seconds", 8),
        },
    }
    settings = normalize_mikrotik_logs_settings(settings)
    save_settings("mikrotik_logs", settings)
    _auth_log_event(
        request,
        "mikrotik_logs.settings_saved",
        resource="/logs/mikrotik",
        details=f"enabled={int(bool(settings.get('enabled')))};port={(settings.get('receiver') or {}).get('port')}",
    )
    return RedirectResponse(url="/logs/mikrotik?mt_tab=settings&setup_tab=settings&saved=1", status_code=303)


@app.post("/logs/mikrotik/drop-topics", response_class=HTMLResponse)
async def mikrotik_logs_drop_topics(request: Request):
    if not _auth_request_has_permission(request, "logs.mikrotik.edit"):
        return _auth_forbidden_response(request, "logs.mikrotik.edit")
    form = await request.form()
    settings = normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
    existing = [
        str(item or "").strip()
        for item in (((settings.get("filters") or {}).get("drop_topics")) or [])
        if str(item or "").strip() and str(item or "").count("\t") >= 2
    ]
    selected = []
    try:
        selected.extend([str(item or "").strip() for item in form.getlist("topics") if str(item or "").strip()])
    except Exception:
        selected.extend(parse_lines(form.get("topics")))
    selected.extend(parse_lines(form.get("topics_custom")))
    selected = [item for item in selected if item and item.count("\t") >= 2]
    merged = sorted({item.lower(): item for item in (existing + selected) if item}.values(), key=lambda value: value.lower())
    settings.setdefault("filters", {})["drop_topics"] = merged
    save_settings("mikrotik_logs", normalize_mikrotik_logs_settings(settings))
    added = [item for item in selected if item and item.lower() not in {value.lower() for value in existing}]
    _auth_log_event(
        request,
        "mikrotik_logs.drop_topics",
        resource=f"count={len(added)}",
        details=", ".join(added[:20]),
    )
    return RedirectResponse(url="/logs/mikrotik?mt_tab=logs&drop_topics=1", status_code=303)


@app.post("/logs/mikrotik/drop-topics/remove", response_class=HTMLResponse)
async def mikrotik_logs_drop_topics_remove(request: Request):
    if not _auth_request_has_permission(request, "logs.mikrotik.edit"):
        return _auth_forbidden_response(request, "logs.mikrotik.edit")
    form = await request.form()
    remove_topic = (form.get("topic") or "").strip().lower()
    settings = normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
    existing = [
        str(item or "").strip()
        for item in (((settings.get("filters") or {}).get("drop_topics")) or [])
        if str(item or "").strip() and str(item or "").count("\t") >= 2
    ]
    settings.setdefault("filters", {})["drop_topics"] = [item for item in existing if item.lower() != remove_topic]
    save_settings("mikrotik_logs", normalize_mikrotik_logs_settings(settings))
    _auth_log_event(request, "mikrotik_logs.drop_topic_removed", resource=remove_topic, details="")
    return RedirectResponse(url="/logs/mikrotik?mt_tab=logs&drop_topics=1", status_code=303)


@app.post("/logs/mikrotik/auto-setup", response_class=HTMLResponse)
async def mikrotik_logs_auto_setup(request: Request):
    if not _auth_request_has_permission(request, "logs.mikrotik.edit"):
        return _auth_forbidden_response(request, "logs.mikrotik.edit")
    settings = normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
    auto_setup = settings.get("auto_setup") if isinstance(settings.get("auto_setup"), dict) else {}
    remote_host = (auto_setup.get("server_host") or request.url.hostname or "").strip()
    results = auto_configure_mikrotik_logs(settings, remote_host=remote_host, update_state=True)
    updated_rows = _apply_mikrotik_log_source_aliases_to_history(results)
    ok_count = sum(1 for item in results if item.get("status") == "configured")
    fail_count = len(results) - ok_count
    _auth_log_event(
        request,
        "mikrotik_logs.auto_setup",
        resource="/logs/mikrotik",
        details=f"configured={ok_count};failed={fail_count};updated_logs={updated_rows};target={remote_host}",
    )
    return RedirectResponse(
        url=f"/logs/mikrotik?mt_tab=settings&setup_tab=router&router_setup_tab=auto&auto_setup=1&ok={ok_count}&failed={fail_count}",
        status_code=303,
    )


@app.post("/logs/mikrotik/auto-setup-router", response_class=HTMLResponse)
async def mikrotik_logs_auto_setup_router(request: Request):
    if not _auth_request_has_permission(request, "logs.mikrotik.edit"):
        return _auth_forbidden_response(request, "logs.mikrotik.edit")
    form = await request.form()
    router_id = (form.get("router_id") or "").strip()
    router_kind = (form.get("router_kind") or "").strip()
    settings = normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
    auto_setup = settings.get("auto_setup") if isinstance(settings.get("auto_setup"), dict) else {}
    remote_host = (auto_setup.get("server_host") or request.url.hostname or "").strip()
    result = auto_configure_mikrotik_log_router(
        settings,
        router_id,
        router_kind=router_kind,
        remote_host=remote_host,
        update_state=True,
    )
    updated_rows = _apply_mikrotik_log_source_aliases_to_history([result])
    status = result.get("status") or "error"
    _auth_log_event(
        request,
        "mikrotik_logs.auto_setup_router",
        resource=router_id,
        details=f"kind={router_kind};status={status};updated_logs={updated_rows};target={remote_host};message={(result.get('message') or '')[:160]}",
    )
    return RedirectResponse(
        url=f"/logs/mikrotik?mt_tab=settings&setup_tab=router&router_setup_tab=auto&router_setup={urllib.parse.quote(router_id)}&status={urllib.parse.quote(status)}",
        status_code=303,
    )


@app.get("/wan/latency-series")
async def wan_latency_series(
    core_id: str = "all",
    target: str = "all",
    hours: int = 24,
    start: str | None = None,
    end: str | None = None,
):
    def _parse_iso_utc(value):
        if not value:
            return None
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1]
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    start_dt = _parse_iso_utc(start)
    end_dt = _parse_iso_utc(end)
    if start_dt or end_dt:
        if start_dt and end_dt:
            window_start = start_dt
            window_end = end_dt
        elif start_dt:
            window_start = start_dt
            window_end = start_dt + timedelta(hours=max(int(hours), 1))
        else:
            window_end = end_dt
            window_start = end_dt - timedelta(hours=max(int(hours), 1))
    else:
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(hours=max(int(hours), 1))
    if window_start > window_end:
        window_start, window_end = window_end, window_start
    max_window = timedelta(days=370)
    if window_end - window_start > max_window:
        window_start = window_end - max_window

    start_iso = window_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    end_iso = window_end.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    history_start_iso = (window_start - timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_state = get_state("wan_ping_state", {})
    wan_ids = [row.get("wan_id") for row in wan_rows if row.get("wan_id")]
    history_map = fetch_wan_history_map(wan_ids, history_start_iso, end_iso)
    series = build_wan_latency_series(
        wan_rows,
        wan_state,
        hours=hours,
        window_start=window_start,
        window_end=window_end,
        history_map=history_map,
    )
    if core_id and core_id != "all":
        series = [item for item in series if item.get("core_id") == core_id]
    if target and target != "all":
        series = [item for item in series if item.get("target") == target]
    return JSONResponse({"series": series, "window": {"start": start_iso, "end": end_iso}})


@app.get("/wan/status")
async def wan_status():
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
    router_map = {
        (item.get("id") or "").strip(): item
        for item in routers
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }
    wan_state = get_state("wan_ping_state", {})
    payload = []
    for row in wan_rows:
        wan_id = row.get("wan_id")
        mode = (row.get("mode") or "routed").lower()
        if not row.get("local_ip"):
            continue
        if mode == "bridged":
            if not row.get("pppoe_router_id"):
                continue
        state = wan_state.get("wans", {}).get(wan_id, {})
        label = f"{row.get('core_label')} - {(row.get('identifier') or row.get('list_name') or '')}".strip()
        router_id = (row.get("pppoe_router_id") or "").strip()
        router_name = ((router_map.get(router_id) or {}).get("name") or "").strip() if router_id else ""
        payload.append(
            {
                "id": wan_id,
                "label": label,
                "core_id": row.get("core_id") or "",
                "core_label": row.get("core_label") or "",
                "mode": row.get("mode") or "",
                "local_ip": row.get("local_ip") or "",
                "pppoe_router_id": row.get("pppoe_router_id") or "",
                "pppoe_router_name": router_name,
                "status": state.get("status"),
                "target": state.get("target"),
                "last_check": state.get("last_check"),
                "last_target_check": state.get("last_target_check"),
                "target_src_address": state.get("target_src_address"),
                "last_rtt_ms": state.get("last_rtt_ms"),
                "last_error": state.get("last_error"),
            }
        )
    return JSONResponse({"rows": payload, "updated_at": utc_now_iso()})


@app.get("/wan/targets/series")
async def wan_targets_series(target_id: str, hours: int = 24, core_id: str = "all"):
    target_id = (target_id or "").strip()
    if not target_id:
        return JSONResponse({"series": [], "window": {"start": "", "end": ""}}, status_code=400)
    hours = _normalize_wan_window(hours)
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    start_dt = now_dt - timedelta(hours=max(int(hours or 24), 1))
    start_iso = start_dt.isoformat().replace("+00:00", "Z")
    end_iso = now_dt.isoformat().replace("+00:00", "Z")

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    targets = (wan_settings.get("general") or {}).get("targets") if isinstance(wan_settings.get("general"), dict) else []
    target = next((item for item in (targets or []) if isinstance(item, dict) and (item.get("id") or "").strip() == target_id), None)
    if not target:
        return JSONResponse({"series": [], "window": {"start": start_iso, "end": end_iso}, "error": "Target not found."}, status_code=404)

    core_id = (core_id or "all").strip()
    cores = pulse_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_map = {item.get("id"): item for item in cores if isinstance(item, dict) and item.get("id")}
    preset_map = {}
    for preset in pulse_settings.get("pulsewatch", {}).get("list_presets", []):
        if not isinstance(preset, dict):
            continue
        preset_core_id = (preset.get("core_id") or "").strip()
        preset_list_name = (preset.get("list") or "").strip()
        if not preset_core_id or not preset_list_name:
            continue
        preset_map[(preset_core_id, preset_list_name)] = {
            "identifier": (preset.get("identifier") or "").strip(),
            "color": _sanitize_hex_color((preset.get("color") or "").strip()),
        }
    wan_rows = []
    for item in (wan_settings.get("wans") or []):
        if not isinstance(item, dict):
            continue
        if not item.get("enabled", True):
            continue
        if not (item.get("local_ip") or "").strip():
            continue
        if core_id != "all" and (item.get("core_id") or "") != core_id:
            continue
        wan_id = (item.get("id") or "").strip() or wan_row_id(item.get("core_id"), item.get("list_name"))
        if not wan_id:
            continue
        list_name = (item.get("list_name") or "").strip()
        preset_data = preset_map.get(((item.get("core_id") or "").strip(), list_name), {})
        identifier = (item.get("identifier") or "").strip() or (preset_data.get("identifier") or "").strip()
        color = _sanitize_hex_color((item.get("color") or "").strip()) or _sanitize_hex_color((preset_data.get("color") or "").strip())
        display_name = identifier or list_name or wan_id
        core_ref = (core_map.get(item.get("core_id")) or {})
        core_label = (core_ref.get("label") or item.get("core_id") or "").strip()
        wan_rows.append(
            {
                "id": wan_id,
                "name": display_name,
                "core_id": item.get("core_id") or "",
                "core_label": core_label,
                "label": display_name,
                "color": color,
            }
        )

    name_counts = {}
    for row in wan_rows:
        key = (row.get("name") or "").strip().lower()
        if not key:
            continue
        name_counts[key] = name_counts.get(key, 0) + 1
    for row in wan_rows:
        key = (row.get("name") or "").strip().lower()
        if key and name_counts.get(key, 0) > 1:
            core_label = (row.get("core_label") or "").strip()
            if core_label:
                row["name"] = f"{core_label} · {row.get('name')}"

    wan_ids = [item.get("id") for item in wan_rows if item.get("id")]
    bucket_seconds = _wan_target_bucket_seconds(hours, max_points_per_series=1800)
    series_map = fetch_wan_target_ping_series_map(wan_ids, target_id, start_iso, end_iso, bucket_seconds=bucket_seconds)
    out_series = []
    for row in wan_rows:
        wan_id = row.get("id")
        points = []
        for item in series_map.get(wan_id, []) or []:
            ts = item.get("timestamp")
            if not ts:
                continue
            points.append({"ts": ts, "rtt_ms": item.get("rtt_ms"), "ok": item.get("ok")})
        out_series.append(
            {
                "id": wan_id,
                "name": row.get("name") or wan_id,
                "color": row.get("color") or "",
                "points": points,
            }
        )

    return JSONResponse(
        {
            "target": {"id": target_id, "label": (target.get("label") or "").strip() or (target.get("host") or ""), "host": (target.get("host") or "").strip()},
            "window": {"start": start_iso, "end": end_iso, "hours": hours, "bucket_seconds": bucket_seconds, "max_points_per_series": 1800},
            "series": out_series,
        }
    )


@app.get("/wan/targets/ping/stream")
async def wan_targets_ping_stream(
    request: Request,
    wan_ids: str = "",
    sel: str = "",
    target_id: str = "",
    interval_s: int = 1,
    count: int = 1,
):
    count = max(min(int(count or 1), 5), 1)
    interval_s = max(min(int(interval_s or 1), 60), 1)
    selected_wan_ids = {part.strip() for part in (wan_ids or "").split(",") if part.strip()}
    selection = {}
    for entry in (sel or "").split(","):
        raw = entry.strip()
        if not raw or ":" not in raw:
            continue
        sel_wan_id, sel_target_id = raw.split(":", 1)
        sel_wan_id = sel_wan_id.strip()
        sel_target_id = sel_target_id.strip()
        if sel_wan_id and sel_target_id:
            selection[sel_wan_id] = sel_target_id

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))

    general_cfg = wan_settings.get("general") if isinstance(wan_settings.get("general"), dict) else {}
    history_retention_days = max(int(general_cfg.get("history_retention_days") or 400), 1)
    enabled_targets = [
        {
            "id": (item.get("id") or "").strip(),
            "label": (item.get("label") or "").strip() or (item.get("host") or "").strip(),
            "host": (item.get("host") or "").strip(),
        }
        for item in (general_cfg.get("targets") or [])
        if isinstance(item, dict)
        and (item.get("id") or "").strip()
        and (item.get("host") or "").strip()
        and bool(item.get("enabled", True))
    ]
    target_map = {item.get("id"): item for item in enabled_targets if item.get("id")}
    target_filter_id = (target_id or "").strip()
    if target_filter_id and target_filter_id not in target_map:
        target_filter_id = ""
    if not enabled_targets:
        async def _empty():
            yield f"event: init\ndata: {json.dumps({'wans': [], 'targets': [], 'error': 'No enabled ping targets configured.'})}\n\n"
            yield "event: done\ndata: complete\n\n"
        return StreamingResponse(_empty(), media_type="text/event-stream")

    cores = pulse_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_map = {
        (item.get("id") or "").strip(): item
        for item in (cores or [])
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }
    routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
    router_map = {
        (item.get("id") or "").strip(): item
        for item in (routers or [])
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }

    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wans_meta = []
    groups = {}
    skipped = []
    resolved_selection = {}

    for row in wan_rows:
        wan_id = (row.get("wan_id") or "").strip()
        if not wan_id:
            continue
        if selected_wan_ids and wan_id not in selected_wan_ids:
            continue
        if not row.get("enabled", True):
            continue
        local_ip = (row.get("local_ip") or "").strip()
        if not local_ip:
            continue
        mode = (row.get("mode") or "routed").strip().lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"

        label_value = (row.get("identifier") or "").strip() or (row.get("list_name") or "").strip() or wan_id
        series_name = f"{(row.get('core_label') or '').strip()} {label_value}".strip() or wan_id
        source_ip = local_ip

        selected_target_id = (selection.get(wan_id) or "").strip()
        if selected_target_id and selected_target_id not in target_map:
            selected_target_id = ""
        if target_filter_id:
            selected_targets = [target_map[target_filter_id]]
        elif selected_target_id:
            selected_targets = [target_map[selected_target_id]]
        else:
            selected_targets = list(enabled_targets)
        if not selected_targets:
            skipped.append({"wan_id": wan_id, "reason": "No enabled ping targets available."})
            continue
        resolved_selection[wan_id] = selected_target_id

        router_name = ""
        router_cfg = None
        if mode == "bridged":
            router_id = (row.get("pppoe_router_id") or "").strip()
            if not router_id:
                skipped.append({"wan_id": wan_id, "reason": "PPPoE router not selected (bridged mode)."})
                continue
            router_cfg = router_map.get(router_id)
            if not router_cfg:
                skipped.append({"wan_id": wan_id, "reason": f"PPPoE router '{router_id}' not found."})
                continue
            if router_cfg.get("use_tls"):
                skipped.append({"wan_id": wan_id, "reason": f"PPPoE router '{router_id}' uses TLS (not supported)."})
                continue
            router_name = ((router_cfg.get("name") or router_id).strip() or router_id)
        else:
            core_id = (row.get("core_id") or "").strip()
            router_cfg = core_map.get(core_id)
            if not router_cfg:
                skipped.append({"wan_id": wan_id, "reason": f"Core router '{core_id}' not found."})
                continue
            router_name = ((router_cfg.get("label") or core_id).strip() or core_id)

        host = (router_cfg.get("host") or "").strip() if isinstance(router_cfg, dict) else ""
        if not host:
            skipped.append({"wan_id": wan_id, "reason": "Router host not configured."})
            continue

        port = int(router_cfg.get("port", 8728)) if isinstance(router_cfg, dict) else 8728
        username = router_cfg.get("username", "") if isinstance(router_cfg, dict) else ""
        password = router_cfg.get("password", "") if isinstance(router_cfg, dict) else ""

        group_key = (host, port, username, password)
        groups.setdefault(
            group_key,
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "wans": [],
            },
        )["wans"].append(
            {
                "id": wan_id,
                "name": series_name,
                "label": label_value,
                "core_id": (row.get("core_id") or "").strip(),
                "core_label": (row.get("core_label") or "").strip(),
                "mode": mode,
                "router_name": router_name,
                "src_address": source_ip,
                "targets": selected_targets,
            }
        )
        wans_meta.append(
            {
                "id": wan_id,
                "name": series_name,
                "router_name": router_name,
                "src_address": source_ip,
                "mode": mode,
                "color": (row.get("color") or "").strip(),
                "target_ids": [str(item.get("id") or "").strip() for item in selected_targets if (item.get("id") or "").strip()],
            }
        )

    if selected_wan_ids:
        want = selected_wan_ids
        have = {item.get("id") for item in wans_meta}
        missing = sorted(want - have)
        for wan_id in missing:
            skipped.append({"wan_id": wan_id, "reason": "WAN not found or not eligible for ping."})

    if not wans_meta:
        async def _empty_wans():
            payload = {"wans": [], "targets": enabled_targets, "skipped": skipped, "error": "No eligible ISPs found."}
            yield f"event: init\ndata: {json.dumps(payload)}\n\n"
            yield "event: done\ndata: complete\n\n"
        return StreamingResponse(_empty_wans(), media_type="text/event-stream")

    queue: asyncio.Queue = asyncio.Queue()
    stop_flag = threading.Event()
    loop = asyncio.get_running_loop()

    def _queue_put(item):
        try:
            loop.call_soon_threadsafe(queue.put_nowait, item)
            return
        except Exception:
            pass
        try:
            asyncio.run_coroutine_threadsafe(queue.put(item), loop)
        except Exception:
            pass

    def _worker(group, wans):
        client = RouterOSClient(
            group.get("host", ""),
            int(group.get("port", 8728)),
            group.get("username", ""),
            group.get("password", ""),
        )
        try:
            client.connect()
            # Fetch router interface IPs once so we can validate src-address strictly against
            # real local router interface IPs.
            iface_ips = []
            try:
                replies = client.talk(["/ip/address/print"])
                for sentence in replies:
                    if not sentence or sentence[0] != "!re":
                        continue
                    data = {}
                    for word in sentence[1:]:
                        if not word:
                            continue
                        if word.startswith("="):
                            word = word[1:]
                        if "=" in word:
                            key, value = word.split("=", 1)
                            data[key] = value
                    addr = (data.get("address") or "").strip()
                    if not addr:
                        continue
                    try:
                        iface_ips.append(ipaddress.ip_interface(addr))
                    except Exception:
                        continue
            except Exception:
                iface_ips = []

            def pick_src(hint):
                raw = (hint or "").strip()
                if not raw or not iface_ips:
                    return None
                try:
                    ip_obj = ipaddress.ip_address(raw)
                except Exception:
                    return None
                for iface in iface_ips:
                    try:
                        if iface.ip == ip_obj:
                            return str(iface.ip)
                    except Exception:
                        continue
                return None

            wan_list = [item for item in (wans or []) if isinstance(item, dict) and (item.get("id") or "").strip()]
            next_due = {item["id"]: time.monotonic() for item in wan_list}
            wan_lookup = {item["id"]: item for item in wan_list}

            while not stop_flag.is_set() and wan_list:
                due_wan_id = min(next_due, key=next_due.get)
                due_at = next_due.get(due_wan_id, 0.0)
                now = time.monotonic()
                sleep_s = due_at - now
                if sleep_s > 0:
                    time.sleep(min(sleep_s, 0.2))
                    continue

                wan = wan_lookup.get(due_wan_id) or {}
                wan_id = due_wan_id
                targets = wan.get("targets") if isinstance(wan.get("targets"), list) else []
                if not targets:
                    next_due[wan_id] = time.monotonic() + float(interval_s)
                    continue

                src_hint = (wan.get("src_address") or "").strip()
                src_address = pick_src(src_hint)
                has_src_hint = bool(src_hint)
                used_src = bool(src_address)
                for target in targets:
                    if stop_flag.is_set():
                        break
                    target_id = (target.get("id") or "").strip() if isinstance(target, dict) else ""
                    target_host = (target.get("host") or "").strip() if isinstance(target, dict) else ""
                    if not target_id or not target_host:
                        continue

                    now_iso = utc_now_iso()
                    ok = 0
                    rtt_ms = None
                    note = ""
                    if has_src_hint and not used_src:
                        note = f"Configured src-address {src_hint} is not a local router interface"
                    else:
                        try:
                            # Keep DNS resolution inside the router itself so results match manual
                            # `/tool/ping` from the same MikroTik.
                            times = client.ping_times(target_host, count=count, src_address=src_address, timeout="1000ms")
                            if times:
                                ok = 1
                                rtt_ms = float(times[-1])
                        except Exception as exc:
                            ok = 0
                            rtt_ms = None
                            note = str(exc)
                    try:
                        insert_wan_target_ping_result(
                            wan_id,
                            target_id,
                            target_host,
                            ok,
                        rtt_ms=rtt_ms,
                            timestamp=now_iso,
                            core_id=wan.get("core_id") or "",
                            label=wan.get("label") or "",
                            src_address=(src_address or "").strip(),
                            retention_days=history_retention_days,
                        )
                    except Exception:
                        pass
                    _queue_put(
                        (
                            "result",
                            {
                                "timestamp": now_iso,
                                "wan_id": wan_id,
                                "wan_name": wan.get("name") or wan_id,
                                "router_name": wan.get("router_name") or "",
                                "src_address": (src_address or "").strip(),
                                "configured_src_address": src_hint,
                                "target_id": target_id,
                                "target_label": target.get("label") or target_host,
                                "target_host": target_host,
                                "ok": ok,
                                "rtt_ms": rtt_ms,
                                "used_src_address": bool(used_src),
                                "note": note,
                            },
                        )
                    )
                if stop_flag.is_set():
                    break
                next_due[wan_id] = time.monotonic() + float(interval_s)
        except Exception as exc:
            _queue_put(("error", {"error": f"Router ping failed: {exc}"}))
        finally:
            try:
                client.close()
            except Exception:
                pass
            _queue_put(("done_group", None))

    tasks = []
    for group in groups.values():
        tasks.append(asyncio.create_task(asyncio.to_thread(_worker, group, group.get("wans") or [])))

    async def _stream():
        cancelled = False
        init_payload = {
            "wans": wans_meta,
            "targets": enabled_targets,
            "count": count,
            "interval_s": interval_s,
            "retention_days": history_retention_days,
            "skipped": skipped,
            "selection": resolved_selection,
            "target_filter_id": target_filter_id,
        }
        yield f"event: init\ndata: {json.dumps(init_payload)}\n\n"
        try:
            active = len(tasks)
            while active > 0:
                if await request.is_disconnected():
                    break
                try:
                    kind, payload = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                if kind == "done_group":
                    active -= 1
                    continue
                if kind == "result":
                    yield f"event: result\ndata: {json.dumps(payload)}\n\n"
                elif kind == "error":
                    yield f"event: error\ndata: {json.dumps(payload)}\n\n"
        except asyncio.CancelledError:
            cancelled = True
        finally:
            stop_flag.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
        if not cancelled:
            yield "event: done\ndata: complete\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


def _build_usage_summary_data(settings, state):
    return build_usage_summary_data_shared(settings, state)


def _usage_account_key(router_id, pppoe):
    return f"{(router_id or '').strip()}|{(pppoe or '').strip().lower()}"


def _usage_parse_iso_utc(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1]
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _usage_status_rank(status):
    ranks = {
        "issue": 4,
        "stable": 3,
        "no_session": 2,
        "history_only": 1,
    }
    return ranks.get((status or "").strip().lower(), 0)


def _usage_status_label(status):
    labels = {
        "issue": "Usage Issue",
        "stable": "Stable Usage",
        "no_session": "No Active Session",
        "history_only": "History Only",
    }
    return labels.get((status or "").strip().lower(), "Unknown")


def _build_usage_accounts_rows(summary, reboot_stats=None, reboot_settings=None):
    summary = summary if isinstance(summary, dict) else {}
    reboot_stats = reboot_stats if isinstance(reboot_stats, list) else []
    reboot_settings = normalize_usage_modem_reboot_settings({"modem_reboot": reboot_settings or {}})
    max_attempts = max(int(reboot_settings.get("max_attempts", 50) or 50), 1)
    checker_days = max(int(reboot_settings.get("unrebootable_check_interval_days", 14) or 14), 1)
    accounts = {}

    def _base_for(row, status):
        row = row if isinstance(row, dict) else {}
        pppoe = (row.get("pppoe") or "").strip()
        if not pppoe:
            return None, None
        router_id = (row.get("router_id") or "").strip()
        key = _usage_account_key(router_id, pppoe)
        item = accounts.get(key)
        if not item:
            item = {
                "entry_id": key,
                "pppoe": pppoe,
                "router_id": router_id,
                "router_name": (row.get("router_name") or router_id or "").strip(),
                "address": (row.get("address") or row.get("ip") or "").strip(),
                "device_id": (row.get("device_id") or "").strip(),
                "current_status": status,
                "current_status_label": _usage_status_label(status),
                "dl_bps": None,
                "ul_bps": None,
                "dl_total_bytes": None,
                "ul_total_bytes": None,
                "host_count": None,
                "hostnames": [],
                "last_seen": "",
                "last_seen_ts": "",
                "profile": (row.get("profile") or "").strip(),
                "last_logged_out": (row.get("last_logged_out") or "").strip(),
                "reboot_attempt_count": 0,
                "reboot_success_count": 0,
                "reboot_failed_count": 0,
                "reboot_no_tr069_count": 0,
                "reboot_verification_passed_count": 0,
                "reboot_verification_failed_count": 0,
                "reboot_failed_total_count": 0,
                "reboot_blocked": False,
                "reboot_blocked_label": "",
                "reboot_blocked_reason": "",
                "reboot_next_check_at": "",
                "reboot_next_check_at_ph": "",
                "reboot_max_attempts": max_attempts,
                "reboot_check_interval_days": checker_days,
                "last_reboot_at": "",
                "last_reboot_at_ph": "",
                "last_reboot_verified_at": "",
                "last_reboot_verified_at_ph": "",
                "last_reboot_status": "",
                "last_reboot_verification_status": "",
                "last_reboot_error": "",
                "last_reboot_detail": "",
            }
            accounts[key] = item
        if _usage_status_rank(status) > _usage_status_rank(item.get("current_status")):
            item["current_status"] = status
            item["current_status_label"] = _usage_status_label(status)
        for field in ("router_name", "address", "device_id", "profile", "last_logged_out"):
            value = (row.get(field) or "").strip() if isinstance(row.get(field), str) else row.get(field)
            if value and not item.get(field):
                item[field] = value
        return key, item

    def _merge_live(row, status):
        _key, item = _base_for(row, status)
        if not item:
            return
        if status in ("issue", "stable"):
            item["dl_bps"] = row.get("dl_bps")
            item["ul_bps"] = row.get("ul_bps")
            item["dl_total_bytes"] = row.get("dl_total_bytes")
            item["ul_total_bytes"] = row.get("ul_total_bytes")
            item["host_count"] = row.get("host_count")
            item["hostnames"] = row.get("hostnames") if isinstance(row.get("hostnames"), list) else []
            item["last_seen"] = row.get("last_seen") or ""
            item["last_seen_ts"] = row.get("last_seen_ts") or ""

    for row in summary.get("issues") or []:
        _merge_live(row, "issue")
    for row in summary.get("stable") or []:
        _merge_live(row, "stable")
    for row in summary.get("offline_rows") or []:
        _merge_live(row, "no_session")

    for stat in reboot_stats:
        _key, item = _base_for(stat, "history_only")
        if not item:
            continue
        item["reboot_attempt_count"] = int(stat.get("attempt_count") or 0)
        item["reboot_success_count"] = int(stat.get("success_count") or 0)
        item["reboot_failed_count"] = int(stat.get("failed_count") or 0)
        item["reboot_no_tr069_count"] = int(stat.get("no_tr069_count") or 0)
        item["reboot_verification_passed_count"] = int(stat.get("verification_passed_count") or 0)
        item["reboot_verification_failed_count"] = int(stat.get("verification_failed_count") or 0)
        item["reboot_failed_total_count"] = item["reboot_failed_count"] + item["reboot_verification_failed_count"]
        item["last_reboot_at"] = stat.get("latest_attempted_at") or ""
        item["last_reboot_at_ph"] = format_ts_ph(stat.get("latest_attempted_at"))
        item["last_reboot_verified_at"] = stat.get("latest_verified_at") or ""
        item["last_reboot_verified_at_ph"] = format_ts_ph(stat.get("latest_verified_at"))
        item["last_reboot_status"] = (stat.get("latest_status") or "").strip()
        item["last_reboot_verification_status"] = (stat.get("latest_verification_status") or "").strip()
        item["last_reboot_error"] = (stat.get("latest_error_message") or "").strip()
        item["last_reboot_detail"] = (stat.get("latest_detail") or "").strip()
        if item["reboot_failed_total_count"] >= max_attempts:
            item["reboot_blocked"] = True
            item["reboot_blocked_label"] = "Reboot Blocked"
            latest_dt = _usage_parse_iso_utc(item.get("last_reboot_at"))
            next_check_dt = latest_dt + timedelta(days=checker_days) if latest_dt else None
            item["reboot_next_check_at"] = next_check_dt.isoformat().replace("+00:00", "Z") if next_check_dt else ""
            item["reboot_next_check_at_ph"] = format_ts_ph(item["reboot_next_check_at"]) if item["reboot_next_check_at"] else ""
            item["reboot_blocked_reason"] = (
                f"{item['reboot_failed_total_count']} failed reboot checks reached the configured maximum "
                f"of {max_attempts}."
            )

    return sorted(
        accounts.values(),
        key=lambda item: (
            str(item.get("pppoe") or "").lower(),
            str(item.get("router_name") or item.get("router_id") or "").lower(),
        ),
    )


@app.get("/usage/summary")
async def usage_summary(request: Request):
    settings = get_settings("usage", USAGE_DEFAULTS)
    state = get_state("usage_state", {})
    summary = _build_usage_summary_data(settings, state)
    reboot_settings = normalize_usage_modem_reboot_settings(settings)
    issue_ids = [
        str(row.get("entry_id") or "").strip()
        for row in (summary.get("issues") or [])
        if str(row.get("entry_id") or "").strip()
    ]
    new_ids = _usage_new_ids_for_request(request, issue_ids, seed_if_needed=True)
    new_id_set = set(new_ids)
    for row in summary.get("issues") or []:
        row["is_new"] = bool(str(row.get("entry_id") or "").strip() in new_id_set)

    issues = summary.get("issues") or []
    stable = summary.get("stable") or []
    offline_rows = summary.get("offline_rows") or []
    can_view_reboot_history = (
        not bool(getattr(request.state, "auth_enabled", True))
        or _auth_request_has_permission(request, "usage.status.reboot_history.view")
    )
    reboot_history_rows = []
    reboot_history_count = 0
    reboot_account_stats = list_usage_modem_reboot_account_stats() if can_view_reboot_history else []
    if reboot_settings.get("enabled") and can_view_reboot_history:
        reboot_history_count = count_usage_modem_reboot_history()
        for row in list_usage_modem_reboot_history(limit=250):
            item = dict(row or {})
            item["attempted_at_ph"] = format_ts_ph(item.get("attempted_at"))
            item["verified_at_ph"] = format_ts_ph(item.get("verified_at"))
            reboot_history_rows.append(item)
    account_rows = _build_usage_accounts_rows(summary, reboot_account_stats, reboot_settings)
    return JSONResponse(
        {
            "updated_at": utc_now_iso(),
            "last_check": format_ts_ph(state.get("last_check_at")),
            "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
            "genieacs_error": (state.get("genieacs_error") or "").strip(),
            "peak": summary.get("peak") or {},
            "anytime": summary.get("anytime") or {},
            "modem_reboot": {
                "enabled": bool(reboot_settings.get("enabled")),
                "can_view_history": bool(can_view_reboot_history),
            },
            "new": {"ids": new_ids, "count": len(new_ids)},
            "counts": {
                "issues": len(issues),
                "stable": len(stable),
                "offline": len(offline_rows),
                "reboot_history": reboot_history_count,
                "accounts": len(account_rows),
            },
            "rows": {
                "issues": issues,
                "stable": stable,
                "offline": offline_rows,
                "reboot_history": reboot_history_rows,
                "accounts": account_rows,
            },
        }
    )


@app.post("/usage/mark_new_seen", response_class=JSONResponse)
async def usage_mark_new_seen(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    raw_entry_ids = payload.get("entry_ids") if isinstance(payload, dict) else []
    seen_ids = _mark_usage_new_entries_seen(request, raw_entry_ids)
    return _json_no_store({"ok": True, "seen_ids": seen_ids, "seen_at": utc_now_iso()})


@app.get("/usage/series", response_class=JSONResponse)
async def usage_series(pppoe: str, router_id: str = "", hours: int = 24):
    pppoe = (pppoe or "").strip()
    router_id = (router_id or "").strip()
    if not pppoe:
        return _json_no_store({"hours": 0, "points": 0, "series": []}, status_code=400)
    hours = max(int(hours or 24), 1)
    hours = min(hours, 24 * 30)
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    rows = get_pppoe_usage_series_since(router_id, pppoe, since_iso)
    max_points = 1500
    if len(rows) > max_points:
        step = max(1, int(len(rows) / max_points))
        sampled = rows[::step]
        if rows and (not sampled or sampled[-1].get("timestamp") != rows[-1].get("timestamp")):
            sampled.append(rows[-1])
        rows = sampled
    series = []
    last_devices = None
    for item in rows:
        ts = item.get("timestamp")
        if not ts:
            continue
        devices = item.get("host_count")
        if devices is not None:
            try:
                last_devices = int(devices)
            except Exception:
                last_devices = last_devices
        devices_filled = last_devices
        series.append(
            {
                "ts": ts,
                "dl_bps": item.get("tx_bps"),
                "ul_bps": item.get("rx_bps"),
                "dl_total_bytes": item.get("bytes_out"),
                "ul_total_bytes": item.get("bytes_in"),
                "devices": devices_filled,
            }
        )
    # If we only started storing devices recently, backfill earlier points in this window
    # using the first known device count in the series.
    if series:
        first_known = None
        for p in series:
            if p.get("devices") is not None:
                first_known = p.get("devices")
                break
        if first_known is not None:
            for p in series:
                if p.get("devices") is None:
                    p["devices"] = first_known
    return _json_no_store({"hours": hours, "points": len(series), "series": series})


@app.get("/usage/account-detail", response_class=JSONResponse)
async def usage_account_detail(pppoe: str, router_id: str = "", hours: int = 168):
    pppoe_value = (pppoe or "").strip()
    router_id_value = (router_id or "").strip()
    if not pppoe_value:
        return _json_no_store({"ok": False, "error": "Missing account."}, status_code=400)

    settings = get_settings("usage", USAGE_DEFAULTS)
    state = get_state("usage_state", {})
    summary = _build_usage_summary_data(settings, state)
    reboot_stats = list_usage_modem_reboot_account_stats()
    accounts = _build_usage_accounts_rows(summary, reboot_stats, normalize_usage_modem_reboot_settings(settings))
    account_key = _usage_account_key(router_id_value, pppoe_value)
    account = next(
        (row for row in accounts if _usage_account_key(row.get("router_id"), row.get("pppoe")) == account_key),
        None,
    )
    if not account and not router_id_value:
        account = next(
            (row for row in accounts if (row.get("pppoe") or "").strip().lower() == pppoe_value.lower()),
            None,
        )

    history_rows = list_usage_modem_reboot_history_for_account(pppoe_value, router_id=router_id_value, limit=250)
    if not account and not history_rows:
        return _json_no_store({"ok": False, "error": "Account not found."}, status_code=404)
    if not account:
        latest = history_rows[0] if history_rows else {}
        account = {
            "entry_id": _usage_account_key(router_id_value or latest.get("router_id"), pppoe_value),
            "pppoe": pppoe_value,
            "router_id": router_id_value or (latest.get("router_id") or ""),
            "router_name": latest.get("router_name") or latest.get("router_id") or router_id_value or "",
            "address": latest.get("address") or "",
            "device_id": latest.get("device_id") or "",
            "current_status": "history_only",
            "current_status_label": _usage_status_label("history_only"),
        }

    history_payload = []
    for row in history_rows:
        item = dict(row or {})
        item["attempted_at_ph"] = format_ts_ph(item.get("attempted_at"))
        item["verified_at_ph"] = format_ts_ph(item.get("verified_at"))
        history_payload.append(item)

    try:
        hours = max(min(int(hours or 168), 24 * 30), 1)
    except Exception:
        hours = 168
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    series_rows = get_pppoe_usage_series_since(account.get("router_id") or router_id_value, pppoe_value, since_iso)
    max_points = 1000
    if len(series_rows) > max_points:
        step = max(1, int(len(series_rows) / max_points))
        sampled = series_rows[::step]
        if series_rows and (not sampled or sampled[-1].get("timestamp") != series_rows[-1].get("timestamp")):
            sampled.append(series_rows[-1])
        series_rows = sampled
    series_payload = [
        {
            "ts": row.get("timestamp"),
            "dl_bps": row.get("tx_bps"),
            "ul_bps": row.get("rx_bps"),
            "dl_total_bytes": row.get("bytes_out"),
            "ul_total_bytes": row.get("bytes_in"),
            "devices": row.get("host_count"),
        }
        for row in series_rows
        if row.get("timestamp")
    ]

    return _json_no_store(
        {
            "ok": True,
            "account": account,
            "history": history_payload,
            "series": series_payload,
            "hours": hours,
        }
    )


@app.get("/offline/summary")
async def offline_summary(request: Request):
    settings = normalize_offline_settings(get_settings("offline", OFFLINE_DEFAULTS))
    state = get_state("offline_state", {})
    rule_views = _build_offline_rule_views(state, settings)
    source_accounts = state.get("source_accounts") if isinstance(state.get("source_accounts"), list) else []
    payload_rows = rule_views.get("default_rows") if isinstance(rule_views.get("default_rows"), list) else []
    rules = rule_views.get("rules") if isinstance(rule_views.get("rules"), list) else []
    rows_by_rule = rule_views.get("rows_by_rule") if isinstance(rule_views.get("rows_by_rule"), dict) else {}
    current_ids = _offline_current_entry_ids(rule_views)
    new_ids = _offline_new_ids_for_request(request, current_ids, seed_if_needed=True)
    new_id_set = set(new_ids)

    def _annotate_rows(rows):
        out = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            item = dict(row)
            entry_id = _offline_nav_entry_id(item)
            item["entry_id"] = entry_id
            item["is_new"] = bool(entry_id and entry_id in new_id_set)
            out.append(item)
        return out

    annotated_rows_by_rule = {
        str(rule_id): _annotate_rows(rule_rows)
        for rule_id, rule_rows in rows_by_rule.items()
        if str(rule_id).strip()
    }
    annotated_payload_rows = _annotate_rows(payload_rows)
    total_offline_count = len(current_ids)
    return JSONResponse(
        {
            "updated_at": utc_now_iso(),
            "last_check": format_ts_ph(state.get("last_check_at")),
            "mode": (state.get("mode") or "").strip() or "secrets",
            "new": {"ids": new_ids, "count": len(new_ids)},
            "counts": {
                "active": int(state.get("active_accounts") or 0),
                "offline": total_offline_count,
                "accounts": len(source_accounts),
            },
            "rows": annotated_payload_rows,
            "rules": rules,
            "rows_by_rule": annotated_rows_by_rule,
            "default_rule_id": (rule_views.get("default_rule_id") or "").strip(),
            "router_errors": state.get("router_errors") if isinstance(state.get("router_errors"), list) else [],
            "radius_error": (state.get("radius_error") or "").strip(),
            "min_offline_minutes": int(state.get("min_offline_minutes") or 0),
            "tracking_rules_summary": (settings.get("general") or {}).get("tracking_rules_summary", ""),
        }
    )


@app.post("/offline/mark_new_seen", response_class=JSONResponse)
async def offline_mark_new_seen(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    raw_entry_ids = payload.get("entry_ids") if isinstance(payload, dict) else []
    seen_ids = _mark_offline_new_entries_seen(request, raw_entry_ids)
    return _json_no_store({"ok": True, "seen_ids": seen_ids, "seen_at": utc_now_iso()})


@app.get("/offline/history", response_class=JSONResponse)
async def offline_history(request: Request, days: int = 30, limit: str | int = 100, page: int = 1):
    days = max(min(int(days or 30), 3650), 1)
    limit = _parse_table_limit(limit, default=100)
    if not limit:
        limit = TABLE_PAGE_SIZE_OPTIONS[-1]
    limit = max(min(int(limit or 100), TABLE_PAGE_SIZE_OPTIONS[-1]), 1)
    page = _parse_table_page(page, 1)
    search_query = str(request.query_params.get("q") or "").strip()
    router_filters = [str(item or "").strip() for item in request.query_params.getlist("router") if str(item or "").strip()]
    sort_key = str(request.query_params.get("sort") or "recent_offline_ended_at").strip() or "recent_offline_ended_at"
    sort_dir = str(request.query_params.get("dir") or "desc").strip().lower()
    since_iso = (datetime.utcnow() - timedelta(days=days)).replace(microsecond=0).isoformat() + "Z"
    total = count_offline_history_accounts_since(since_iso, search=search_query, router_names=router_filters)
    pages = max((total + limit - 1) // limit, 1)
    page = min(max(page, 1), pages)
    offset = (page - 1) * limit
    rows = get_offline_history_accounts_page_since(
        since_iso,
        limit=limit,
        offset=offset,
        sort_key=sort_key,
        sort_dir=sort_dir,
        search=search_query,
        router_names=router_filters,
    )
    payload = []
    for row in rows:
        payload.append(
            {
                "pppoe": (row.get("pppoe") or "").strip(),
                "router_id": (row.get("router_id") or "").strip(),
                "router_name": (row.get("router_name") or row.get("router_id") or "").strip(),
                "mode": (row.get("mode") or "").strip() or "offline",
                "offline_count": int(row.get("offline_count") or 0),
                "recent_offline_started_at": row.get("recent_offline_started_at"),
                "recent_offline_ended_at": row.get("recent_offline_ended_at"),
                "recent_offline_started": format_ts_ph(row.get("recent_offline_started_at")),
                "recent_offline_ended": format_ts_ph(row.get("recent_offline_ended_at")),
                "recent_duration_seconds": row.get("recent_duration_seconds"),
                "recent_duration": _format_duration_short(row.get("recent_duration_seconds")),
                "longest_duration_seconds": row.get("longest_duration_seconds"),
                "longest_duration": _format_duration_short(row.get("longest_duration_seconds")),
                "first_offline_started_at": row.get("first_offline_started_at"),
                "first_offline_started": format_ts_ph(row.get("first_offline_started_at")),
                "latest_radius_status": (row.get("latest_radius_status") or "").strip(),
                "latest_disabled": bool(row.get("latest_disabled")) if row.get("latest_disabled") is not None else None,
                "latest_profile": (row.get("latest_profile") or "").strip(),
                "latest_last_logged_out": (row.get("latest_last_logged_out") or "").strip(),
            }
        )
    return JSONResponse(
        {
            "days": days,
            "count": total,
            "rows": payload,
            "pagination": {
                "page": page,
                "pages": pages,
                "limit": limit,
                "total": total,
                "start": offset + 1 if total else 0,
                "end": min(offset + len(payload), total),
                "has_prev": page > 1,
                "has_next": page < pages,
            },
        }
    )


@app.get("/offline/accounts", response_class=JSONResponse)
async def offline_accounts(request: Request, limit: str | int = 100, page: int = 1):
    limit = _parse_table_limit(limit, default=100)
    if not limit:
        limit = TABLE_PAGE_SIZE_OPTIONS[-1]
    limit = max(min(int(limit or 100), TABLE_PAGE_SIZE_OPTIONS[-1]), 1)
    page = _parse_table_page(page, 1)
    search_query = str(request.query_params.get("q") or "").strip().lower()
    router_filters = [str(item or "").strip().lower() for item in request.query_params.getlist("router") if str(item or "").strip()]
    sort_key = str(request.query_params.get("sort") or "pppoe").strip() or "pppoe"
    sort_dir = str(request.query_params.get("dir") or "asc").strip().lower()
    reverse = sort_dir == "desc"

    state = get_state("offline_state", {})
    source_accounts = state.get("source_accounts") if isinstance(state.get("source_accounts"), list) else []
    current_map = _collect_offline_current_keyed_map(state)
    history_stats_map = list_offline_history_account_stats_map()
    threshold_minutes = int(
        state.get("min_offline_minutes")
        or int((normalize_offline_settings(get_settings("offline", OFFLINE_DEFAULTS)).get("general") or {}).get("min_offline_value", 1) or 1) * 60
    )

    rows = []
    for item in source_accounts:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        entry_id = _offline_nav_entry_id(row)
        if not entry_id:
            continue
        current = current_map.get(entry_id) if isinstance(current_map.get(entry_id), dict) else {}
        hist = history_stats_map.get(entry_id) if isinstance(history_stats_map.get(entry_id), dict) else {}
        current_status = ""
        current_status_label = ""
        offline_since_iso = ""
        if current:
            current_status = (current.get("status") or "").strip().lower()
            if current_status == "offline":
                current_status_label = "Offline"
            elif current_status == "tracking":
                current_status_label = "Tracking"
            offline_since_iso = (current.get("offline_since_iso") or "").strip()
        elif str(row.get("source_status") or "").strip().lower() == "active":
            current_status = "online"
            current_status_label = "Online"
        else:
            current_status = "inactive"
            current_status_label = "Inactive"

        row_out = {
            "pppoe": (row.get("pppoe") or "").strip(),
            "router_id": (row.get("router_id") or "").strip(),
            "router_name": (row.get("router_name") or row.get("router_id") or "").strip(),
            "mode": (row.get("mode") or state.get("mode") or "secrets").strip() or "secrets",
            "profile": (current.get("service_profile") or row.get("profile") or "").strip(),
            "disabled": current.get("disabled") if current else row.get("disabled"),
            "last_logged_out": (current.get("last_logged_out") or row.get("last_logged_out") or "").strip(),
            "radius_status": (current.get("radius_status") or row.get("radius_status") or "").strip(),
            "source_status": str(row.get("source_status") or "").strip().lower(),
            "current_status": current_status,
            "current_status_label": current_status_label,
            "offline_since_at": offline_since_iso,
            "offline_since": format_ts_ph(offline_since_iso) if offline_since_iso else "",
            "offline_for": _format_duration_short(max(int((datetime.utcnow() - _parse_iso_z(offline_since_iso)).total_seconds()), 0)) if offline_since_iso and _parse_iso_z(offline_since_iso) else "",
            "threshold_text": _format_duration_short(threshold_minutes * 60) or f"{threshold_minutes}m",
            "history_count": int(hist.get("offline_count") or 0),
            "has_history": bool(hist),
            "recent_offline_started_at": hist.get("recent_offline_started_at"),
            "recent_offline_started": format_ts_ph(hist.get("recent_offline_started_at")) if hist.get("recent_offline_started_at") else "",
            "recent_offline_ended_at": hist.get("recent_offline_ended_at"),
            "recent_offline_ended": format_ts_ph(hist.get("recent_offline_ended_at")) if hist.get("recent_offline_ended_at") else "",
            "recent_duration_seconds": int(hist.get("recent_duration_seconds") or 0),
            "recent_duration": _format_duration_short(hist.get("recent_duration_seconds")),
            "longest_duration_seconds": int(hist.get("longest_duration_seconds") or 0),
            "longest_duration": _format_duration_short(hist.get("longest_duration_seconds")),
            "online_since": (row.get("online_since") or "").strip(),
            "ip": (row.get("ip") or "").strip(),
        }
        rows.append(row_out)

    def _matches(row):
        if router_filters:
            router_value = str(row.get("router_name") or row.get("router_id") or "").strip().lower()
            router_id_value = str(row.get("router_id") or "").strip().lower()
            if router_value not in router_filters and router_id_value not in router_filters:
                return False
        if not search_query:
            return True
        hay = [
            row.get("pppoe"),
            row.get("router_name"),
            row.get("router_id"),
            row.get("profile"),
            row.get("last_logged_out"),
            row.get("radius_status"),
            row.get("current_status_label"),
            row.get("source_status"),
            row.get("recent_offline_started"),
            row.get("recent_offline_ended"),
            row.get("online_since"),
            row.get("ip"),
        ]
        return any(search_query in str(value or "").lower() for value in hay)

    rows = [row for row in rows if _matches(row)]

    def _sort_value(row):
        if sort_key == "router_name":
            return str(row.get("router_name") or row.get("router_id") or "").lower()
        if sort_key == "current_status":
            order = {"offline": 3, "tracking": 2, "inactive": 1, "online": 0}
            return order.get(str(row.get("current_status") or "").lower(), -1)
        if sort_key == "history_count":
            return int(row.get("history_count") or 0)
        if sort_key == "has_history":
            return 1 if row.get("has_history") else 0
        if sort_key == "recent_offline_ended_at":
            return str(row.get("recent_offline_ended_at") or "")
        if sort_key == "recent_offline_started_at":
            return str(row.get("recent_offline_started_at") or "")
        if sort_key == "longest_duration_seconds":
            return int(row.get("longest_duration_seconds") or 0)
        if sort_key == "offline_since_at":
            return str(row.get("offline_since_at") or "")
        return str(row.get("pppoe") or "").lower()

    rows = sorted(rows, key=lambda row: (_sort_value(row), str(row.get("pppoe") or "").lower()), reverse=reverse)
    total = len(rows)
    pages = max((total + limit - 1) // limit, 1)
    page = min(max(page, 1), pages)
    offset = (page - 1) * limit
    payload = rows[offset: offset + limit]
    return JSONResponse(
        {
            "count": total,
            "rows": payload,
            "pagination": {
                "page": page,
                "pages": pages,
                "limit": limit,
                "total": total,
                "start": offset + 1 if total else 0,
                "end": min(offset + len(payload), total),
                "has_prev": page > 1,
                "has_next": page < pages,
            },
        }
    )


@app.get("/offline/account-detail", response_class=JSONResponse)
async def offline_account_detail(pppoe: str, router_id: str = "", mode: str = ""):
    pppoe_value = (pppoe or "").strip()
    router_id_value = (router_id or "").strip()
    mode_value = (mode or "").strip().lower() or "offline"
    if not pppoe_value:
        return _json_no_store({"ok": False, "error": "Missing account."}, status_code=400)

    settings = normalize_offline_settings(get_settings("offline", OFFLINE_DEFAULTS))
    state = get_state("offline_state", {})
    rule_views = _build_offline_rule_views(state, settings)
    current_rows_by_rule = rule_views.get("rows_by_rule") if isinstance(rule_views.get("rows_by_rule"), dict) else {}
    rules = rule_views.get("rules") if isinstance(rule_views.get("rules"), list) else []

    current_row = None
    current_bucket_label = ""
    for rule in rules:
        rule_id = str((rule or {}).get("id") or "").strip()
        if not rule_id:
            continue
        rows = current_rows_by_rule.get(rule_id) if isinstance(current_rows_by_rule.get(rule_id), list) else []
        for row in rows:
            if _offline_account_matches(row, pppoe_value, router_id=router_id_value, mode=mode_value):
                current_row = dict(row)
                current_bucket_label = str((rule or {}).get("tab_label") or "").strip()
                break
        if current_row:
            break

    history_rows = get_offline_history_for_account(pppoe_value, router_id=router_id_value, mode=mode_value, limit=1000)
    if not current_row and not history_rows:
        return _json_no_store({"ok": False, "error": "Account not found."}, status_code=404)

    latest_history = history_rows[0] if history_rows else {}
    oldest_history = history_rows[-1] if history_rows else {}
    history_payload = []
    longest_duration_seconds = 0
    for row in history_rows:
        duration_seconds = int(row.get("duration_seconds") or 0)
        longest_duration_seconds = max(longest_duration_seconds, duration_seconds)
        history_payload.append(
            {
                "offline_started_at": row.get("offline_started_at"),
                "offline_ended_at": row.get("offline_ended_at"),
                "offline_started": format_ts_ph(row.get("offline_started_at")),
                "offline_ended": format_ts_ph(row.get("offline_ended_at")),
                "duration_seconds": duration_seconds,
                "duration": _format_duration_short(duration_seconds),
                "mode": (row.get("mode") or "").strip() or "offline",
                "radius_status": (row.get("radius_status") or "").strip(),
                "disabled": bool(row.get("disabled")) if row.get("disabled") is not None else None,
                "profile": (row.get("profile") or "").strip(),
                "last_logged_out": (row.get("last_logged_out") or "").strip(),
            }
        )

    router_name_value = (
        (current_row or {}).get("router_name")
        or (current_row or {}).get("router_id")
        or (latest_history or {}).get("router_name")
        or (latest_history or {}).get("router_id")
        or ""
    )
    profile_value = (
        (current_row or {}).get("profile")
        or (latest_history or {}).get("profile")
        or ""
    )
    radius_status_value = (
        (current_row or {}).get("radius_status")
        or (latest_history or {}).get("radius_status")
        or ""
    )
    last_logged_out_value = (
        (current_row or {}).get("last_logged_out")
        or (latest_history or {}).get("last_logged_out")
        or ""
    )
    current_offline_since_iso = (current_row or {}).get("offline_since_ts") if isinstance(current_row, dict) else ""
    current_offline_duration_seconds = int((current_row or {}).get("offline_duration_seconds") or 0) if current_row else 0
    recent_duration_seconds = int((latest_history or {}).get("duration_seconds") or 0) if latest_history else 0

    return _json_no_store(
        {
            "ok": True,
            "account": {
                "pppoe": pppoe_value,
                "router_id": router_id_value or (current_row or {}).get("router_id") or (latest_history or {}).get("router_id") or "",
                "router_name": router_name_value,
                "mode": (current_row or {}).get("mode") or (latest_history or {}).get("mode") or mode_value,
                "status": "offline" if current_row else "restored",
                "status_label": "Currently Offline" if current_row else "Restored",
                "current_bucket_label": current_bucket_label,
                "history_count": len(history_rows),
                "longest_duration_seconds": longest_duration_seconds,
                "longest_duration": _format_duration_short(longest_duration_seconds),
                "recent_duration_seconds": recent_duration_seconds,
                "recent_duration": _format_duration_short(recent_duration_seconds),
                "profile": profile_value,
                "radius_status": radius_status_value,
                "last_logged_out": last_logged_out_value,
                "current_offline_since_at": current_offline_since_iso,
                "current_offline_since": format_ts_ph(current_offline_since_iso) if current_offline_since_iso else "",
                "current_offline_duration_seconds": current_offline_duration_seconds,
                "current_offline_duration": _format_duration_short(current_offline_duration_seconds),
                "recent_offline_started_at": (latest_history or {}).get("offline_started_at"),
                "recent_offline_started": format_ts_ph((latest_history or {}).get("offline_started_at")) if latest_history else "",
                "recent_offline_ended_at": (latest_history or {}).get("offline_ended_at"),
                "recent_offline_ended": format_ts_ph((latest_history or {}).get("offline_ended_at")) if latest_history else "",
                "first_recorded_at": format_ts_ph((oldest_history or {}).get("offline_started_at")) if oldest_history else "",
            },
            "history": history_payload,
        }
    )


@app.get("/offline/radius/accounts", response_class=JSONResponse)
async def offline_radius_accounts(limit: int = 5000):
    limit = max(min(int(limit or 5000), 50000), 1)
    settings = get_settings("offline", OFFLINE_DEFAULTS)
    radius_cfg = settings.get("radius") if isinstance(settings.get("radius"), dict) else {}
    try:
        from .notifiers import offline as offline_notifier

        rows = offline_notifier.fetch_radius_account_details(radius_cfg, limit=limit)
        return JSONResponse({"ok": True, "count": len(rows), "rows": rows})
    except Exception as exc:
        # Do not include secrets in error output.
        return JSONResponse({"ok": False, "error": str(exc), "count": 0, "rows": []}, status_code=400)


@app.get("/wan/stability")
async def wan_stability(days: int = 1, hours: int | None = None, live: bool = False):
    days = max(int(days or 1), 1)
    hours = int(hours) if hours is not None else None

    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    if live:
        since_dt = now_dt
    elif hours:
        since_dt = now_dt - timedelta(hours=max(int(hours), 1))
    else:
        since_dt = now_dt - timedelta(days=days)
    start_iso = since_dt.isoformat().replace("+00:00", "Z")
    end_iso = now_dt.isoformat().replace("+00:00", "Z")

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_display_rows = []
    for row in wan_rows:
        if not row.get("enabled", True):
            continue
        mode = (row.get("mode") or "routed").lower()
        if not (row.get("local_ip") or "").strip():
            continue
        if mode == "bridged" and not (row.get("pppoe_router_id") or "").strip():
            continue
        wan_display_rows.append(row)

    wan_ids = [row.get("wan_id") for row in wan_display_rows if row.get("wan_id")]
    counts = {} if live else get_wan_status_counts(wan_ids, start_iso, end_iso)
    wan_state = get_state("wan_ping_state", {})
    payload = []
    for row in wan_display_rows:
        wan_id = row.get("wan_id")
        stats = counts.get(wan_id, {"up": 0, "down": 0, "total": 0})
        up_total = int(stats.get("up") or 0)
        down_total = int(stats.get("down") or 0)
        total = int(stats.get("total") or 0)

        current_status = (wan_state.get("wans", {}).get(wan_id, {}).get("status") or "").lower()
        if live:
            if current_status == "up":
                up_total, down_total, total = 1, 0, 1
            elif current_status == "down":
                up_total, down_total, total = 0, 1, 1
            else:
                up_total, down_total, total = 0, 0, 0
        elif total <= 0:
            if current_status == "up":
                up_total, down_total, total = 1, 0, 1
            elif current_status == "down":
                up_total, down_total, total = 0, 1, 1
            else:
                up_total, down_total, total = 0, 0, 0

        label_value = (row.get("identifier") or row.get("list_name") or "").strip()
        label_value = label_value or (row.get("core_label") or wan_id or "").strip()
        full_label = f"{row.get('core_label') or ''} {(row.get('identifier') or row.get('list_name') or '')}".strip()
        full_label = full_label or label_value
        payload.append(
            {
                "id": wan_id,
                "label": label_value,
                "full_label": full_label,
                "status": current_status or "n/a",
                "up": up_total,
                "down": down_total,
                "total": total,
            }
        )
    return JSONResponse({"live": bool(live), "days": days, "rows": payload})


def _is_postgres_database_url(db_url: str) -> bool:
    raw = (db_url or "").strip().lower()
    return raw.startswith("postgres://") or raw.startswith("postgresql://")


def _parse_postgres_database_url(db_url: str):
    raw = (db_url or "").strip()
    if not _is_postgres_database_url(raw):
        return None
    parsed = urllib.parse.urlparse(raw)
    dbname = urllib.parse.unquote((parsed.path or "").lstrip("/"))
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 5432)
    if not dbname or not username:
        return None
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {
        "dbname": dbname,
        "username": username,
        "password": password,
        "host": host,
        "port": port,
        "query": query,
    }


def _cleanup_temp_file(path: str):
    try:
        os.unlink(path)
    except OSError:
        pass


@app.get("/settings/export")
async def export_settings_route():
    payload = export_settings()
    data = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
    headers = {"Content-Disposition": "attachment; filename=threejnotif-settings.json"}
    return Response(content=data, media_type="application/json", headers=headers)


@app.post("/settings/import", response_class=HTMLResponse)
async def import_settings_route(request: Request):
    form = await request.form()
    uploaded = form.get("settings_file")
    message = ""
    if not uploaded:
        message = "No file uploaded."
    else:
        try:
            content = await uploaded.read()
            payload = json.loads(content.decode("utf-8"))
            import_settings(payload)
            message = "Settings imported successfully."
        except json.JSONDecodeError:
            message = "Invalid JSON file."
        except Exception as exc:
            message = f"Import failed: {exc}"
    if message.startswith("Settings imported"):
        settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
        save_settings("isp_ping", settings)
    return render_system_settings_response(request, message, active_tab="backup", routers_tab="cores")


@app.get("/settings/db/export")
async def export_db_route():
    db_url = (os.environ.get("THREEJ_DATABASE_URL") or "").strip()
    if _is_postgres_database_url(db_url):
        pg_details = _parse_postgres_database_url(db_url)
        if not pg_details:
            return Response(
                content=b"Database export failed: invalid Postgres connection settings.",
                media_type="text/plain",
                status_code=500,
            )
        pg_dump_path = shutil.which("pg_dump")
        if not pg_dump_path:
            return Response(
                content=b"Database export failed: pg_dump is not available in the application container.",
                media_type="text/plain",
                status_code=500,
            )
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        temp_handle = tempfile.NamedTemporaryFile(
            prefix=f"threejnotif-db-{timestamp}-",
            suffix=".dump",
            delete=False,
        )
        temp_path = temp_handle.name
        temp_handle.close()
        cmd = [
            pg_dump_path,
            "--format=custom",
            "--compress=6",
            "--no-owner",
            "--no-privileges",
            "--file",
            temp_path,
            "--host",
            pg_details["host"],
            "--port",
            str(pg_details["port"]),
            "--username",
            pg_details["username"],
            "--dbname",
            pg_details["dbname"],
        ]
        env = os.environ.copy()
        if pg_details.get("password"):
            env["PGPASSWORD"] = pg_details["password"]
        sslmode_values = pg_details.get("query", {}).get("sslmode") or []
        if sslmode_values and str(sslmode_values[0] or "").strip():
            env["PGSSLMODE"] = str(sslmode_values[0]).strip()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=1800,
            )
        except subprocess.TimeoutExpired:
            _cleanup_temp_file(temp_path)
            return Response(
                content=b"Database export failed: pg_dump timed out.",
                media_type="text/plain",
                status_code=504,
            )
        if result.returncode != 0 or not os.path.exists(temp_path):
            _cleanup_temp_file(temp_path)
            message = (result.stderr or result.stdout or "pg_dump failed").strip()
            return Response(
                content=f"Database export failed: {message}".encode("utf-8", errors="replace"),
                media_type="text/plain",
                status_code=500,
            )
        return FileResponse(
            temp_path,
            media_type="application/octet-stream",
            filename=f"threejnotif-db-{timestamp}.dump",
            background=BackgroundTask(_cleanup_temp_file, temp_path),
        )
    db_path = os.environ.get("THREEJ_DB_PATH", "/data/threejnotif.db")
    if not os.path.exists(db_path):
        return Response(content=b"Database not found.", media_type="text/plain", status_code=404)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    headers = {"Content-Disposition": f"attachment; filename=threejnotif-db-{timestamp}.db"}
    with open(db_path, "rb") as handle:
        content = handle.read()
    return Response(content=content, media_type="application/octet-stream", headers=headers)


@app.post("/settings/db/import", response_class=HTMLResponse)
async def import_db_route(request: Request):
    form = await request.form()
    uploaded = form.get("db_file")
    message = ""
    db_url = (os.environ.get("THREEJ_DATABASE_URL") or "").strip()
    if _is_postgres_database_url(db_url):
        message = "Database restore is not available in the UI when using Postgres. Use psql/pg_restore instead."
        return render_system_settings_response(request, message, active_tab="backup", routers_tab="cores")
    db_path = os.environ.get("THREEJ_DB_PATH", "/data/threejnotif.db")
    if not uploaded:
        message = "No database file uploaded."
    else:
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            if os.path.exists(db_path):
                shutil.copy(db_path, f"{db_path}.bak-{timestamp}")
            content = await uploaded.read()
            with open(db_path, "wb") as handle:
                handle.write(content)
            init_db()
            message = "Database restored successfully."
        except Exception as exc:
            message = f"Database restore failed: {exc}"
    return render_system_settings_response(request, message, active_tab="backup", routers_tab="cores")


@app.get("/settings/system/update/status", response_class=JSONResponse)
async def system_update_status_route():
    return _json_no_store({"ok": True, "status": _system_update_status_payload(include_log=True)})


@app.get("/settings/system/update/check", response_class=JSONResponse)
async def system_update_check_route():
    ok, payload = _system_update_check_remote()
    if not ok:
        return _json_no_store(
            {
                "ok": False,
                "error": str(payload or "").strip() or "Unable to check for updates.",
                "status": _system_update_status_payload(include_log=True),
            },
            status_code=500,
        )
    return _json_no_store({"ok": True, "check": payload, "status": _system_update_status_payload(include_log=True)})


@app.post("/settings/system/update/start", response_class=JSONResponse)
async def system_update_start_route(request: Request):
    form = await request.form()
    ok, password_error = _system_danger_verify_password(request, form.get("confirm_password") or "")
    if not ok:
        return _json_no_store({"ok": False, "error": password_error}, status_code=400)

    current_status = _system_update_status_payload(include_log=False)
    if current_status.get("is_running"):
        return _json_no_store(
            {"ok": False, "error": "An update is already running.", "status": current_status},
            status_code=409,
        )

    check_ok, check_payload = _system_update_check_remote()
    if not check_ok:
        return _json_no_store(
            {"ok": False, "error": str(check_payload or "").strip() or "Unable to check for updates."},
            status_code=500,
        )
    current_full = str(((check_payload or {}).get("current") or {}).get("full") or "").strip()
    latest_full = str(((check_payload or {}).get("latest") or {}).get("full") or "").strip()
    target_commit = str(form.get("target_commit") or latest_full).strip()
    commit_map = {
        str(item.get("full") or "").strip(): item
        for item in ((check_payload or {}).get("commits") or [])
        if str(item.get("full") or "").strip()
    }
    if not target_commit:
        return _json_no_store({"ok": False, "error": "No target commit was selected."}, status_code=400)
    if target_commit == current_full:
        return _json_no_store(
            {
                "ok": False,
                "error": "The selected commit is already installed.",
                "check": check_payload,
            },
            status_code=400,
        )
    if target_commit not in commit_map and target_commit != latest_full:
        return _json_no_store(
            {
                "ok": False,
                "error": "Select one of the commits listed in Latest Remote Changes.",
                "check": check_payload,
            },
            status_code=400,
        )

    try:
        queued_status = _start_system_update_runner(
            check_payload,
            target_commit=target_commit,
            allow_dirty=bool((check_payload or {}).get("is_dirty")),
        )
    except Exception as exc:
        return _json_no_store({"ok": False, "error": f"Failed to start update: {exc}"}, status_code=500)

    target_info = commit_map.get(target_commit) or {}
    _auth_log_event(
        request,
        action="system.update.started",
        resource="/settings/system/update/start",
        details=(
            f"branch={check_payload.get('branch') or 'master'};"
            f"from={(check_payload.get('current') or {}).get('short') or ''};"
            f"to={target_info.get('short') or target_commit[:7]};"
            f"dirty={1 if (check_payload or {}).get('is_dirty') else 0}"
        ),
    )
    return _json_no_store(
        {
            "ok": True,
            "message": "System update started.",
            "check": check_payload,
            "status": queued_status,
        }
    )


OPTICAL_WINDOW_OPTIONS = WAN_STATUS_WINDOW_OPTIONS


def _build_optical_status_uncached(
    settings,
    window_hours=24,
    limit=50,
    issues_page=1,
    stable_page=1,
    offline_page=1,
    acs_los_page=1,
    issues_sort="",
    issues_dir="",
    stable_sort="",
    stable_dir="",
    offline_sort="",
    offline_dir="",
    acs_los_sort="",
    acs_los_dir="",
    query="",
):
    def _preferred_status_tab(query_text, ordered_counts, default_key):
        if not str(query_text or "").strip():
            return default_key
        for key, count in ordered_counts:
            try:
                if int(count or 0) > 0:
                    return key
            except Exception:
                continue
        return default_key

    window_hours = max(int(window_hours or 24), 1)
    limit = _parse_table_limit(limit, default=50)
    issues_page = _parse_table_page(issues_page, default=1)
    stable_page = _parse_table_page(stable_page, default=1)
    offline_page = _parse_table_page(offline_page, default=1)
    acs_los_page = _parse_table_page(acs_los_page, default=1)
    optical_cfg = settings.get("optical", {})
    classification = settings.get("classification", {})
    window_label = next((label for label, hours in OPTICAL_WINDOW_OPTIONS if hours == window_hours), "1D")
    issue_rx = float(classification.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]))
    issue_tx = float(classification.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]))
    priority_rx = float(optical_cfg.get("priority_rx_threshold_dbm", OPTICAL_DEFAULTS["optical"]["priority_rx_threshold_dbm"]))
    stable_rx = float(classification.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]))
    stable_tx = float(classification.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]))
    rx_realistic_min = float(classification.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]))
    rx_realistic_max = float(classification.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]))
    tx_realistic_min = float(classification.get("tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]))
    tx_realistic_max = float(classification.get("tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]))
    chart_min = float(classification.get("chart_min_dbm", OPTICAL_DEFAULTS["classification"]["chart_min_dbm"]))
    chart_max = float(classification.get("chart_max_dbm", OPTICAL_DEFAULTS["classification"]["chart_max_dbm"]))
    genie_base = (optical_cfg.get("genieacs_base_url") or settings.get("genieacs", {}).get("base_url") or "").rstrip("/")

    def genie_device_url(base_url, device_id):
        if not base_url or not device_id:
            return ""
        try:
            parsed = urllib.parse.urlparse(base_url)
            scheme = parsed.scheme or "http"
            host = parsed.hostname or parsed.netloc or ""
            device_path = f"/devices/{urllib.parse.quote(str(device_id))}"
            netloc = f"{host}:3000" if host else ""
            return urllib.parse.urlunparse((scheme, netloc, "/", "", "", f"/{device_path.lstrip('/')}"))
        except Exception:
            return ""

    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).replace(microsecond=0).isoformat() + "Z"
    latest_rows = get_optical_latest_results_since(since_iso)
    optical_state = _optical_state_snapshot()
    current_devices = optical_state.get("current_devices") if isinstance(optical_state.get("current_devices"), list) else []
    current_device_ids = _optical_current_device_ids(optical_state)
    current_pppoe_keys = _optical_current_pppoe_keys(optical_state)
    known_account_map = _optical_known_account_map(optical_state)
    current_by_device_id = {}
    current_by_pppoe = {}
    current_by_ip = {}
    for item in current_devices:
        if not isinstance(item, dict):
            continue
        device_id = (item.get("device_id") or "").strip()
        pppoe = (item.get("pppoe") or "").strip().lower()
        ip = (item.get("ip") or "").strip()
        if device_id:
            current_by_device_id[device_id] = item
        if pppoe and pppoe not in current_by_pppoe:
            current_by_pppoe[pppoe] = item
        if ip and ip not in current_by_ip:
            current_by_ip[ip] = item

    def _row_to_candidate(row):
        if not isinstance(row, dict):
            return "", None
        dev_id = (row.get("device_id") or "").strip()
        pppoe = (row.get("pppoe") or "").strip()
        ip = (row.get("ip") or "").strip()
        pppoe_key = pppoe.lower()

        if known_account_map:
            if pppoe_key:
                if pppoe_key not in known_account_map:
                    return "", None
            elif ip:
                if ip not in current_by_ip:
                    return "", None
            else:
                return "", None

        current_entry = (
            current_by_device_id.get(dev_id)
            or (current_by_pppoe.get(pppoe_key) if pppoe_key else None)
            or (current_by_ip.get(ip) if ip else None)
        )
        known_entries = list(known_account_map.get(pppoe_key) or []) if pppoe_key else []
        account_key = pppoe_key or (ip or dev_id)
        if not account_key:
            return "", None
        candidate = dict(row)
        candidate["_current_entry"] = current_entry or {}
        candidate["_known_entries"] = known_entries
        candidate["_current_available"] = bool(current_entry)
        candidate["_is_current_device"] = bool(current_entry and (current_entry.get("device_id") or "").strip() == dev_id)
        return account_key, candidate

    def _candidate_score(candidate):
        return (
            1 if candidate.get("_current_available") else 0,
            1 if candidate.get("_is_current_device") else 0,
            candidate.get("timestamp") or "",
            1 if candidate.get("rx") is not None else 0,
        )

    collapsed_rows = {}
    for row in latest_rows:
        account_key, candidate = _row_to_candidate(row)
        if not account_key or not candidate:
            continue
        existing = collapsed_rows.get(account_key)
        if not existing:
            collapsed_rows[account_key] = candidate
            continue
        if _candidate_score(candidate) >= _candidate_score(existing):
            collapsed_rows[account_key] = candidate

    if known_account_map:
        missing_pppoes = []
        for pppoe_key, entries in known_account_map.items():
            if pppoe_key in collapsed_rows:
                continue
            pppoe_value = ""
            if entries and isinstance(entries[0], dict):
                pppoe_value = (entries[0].get("pppoe") or "").strip()
            if pppoe_value:
                missing_pppoes.append(pppoe_value)
        if missing_pppoes:
            latest_by_pppoe = get_latest_optical_by_pppoe(sorted(set(missing_pppoes)))
            for row in latest_by_pppoe.values():
                account_key, candidate = _row_to_candidate(row)
                if (
                    not account_key
                    or not candidate
                    or account_key in collapsed_rows
                    or candidate.get("_current_available")
                ):
                    continue
                collapsed_rows[account_key] = candidate

    issue_candidates = []
    stable_candidates = []
    offline_candidates = []
    acs_los_candidates = []
    for last in collapsed_rows.values():
        dev_id = last.get("device_id")
        if not dev_id:
            continue
        current_entry = last.get("_current_entry") if isinstance(last.get("_current_entry"), dict) else {}
        known_entries = last.get("_known_entries") if isinstance(last.get("_known_entries"), list) else []
        current_available = bool(last.get("_current_available"))
        router_names = sorted(
            {
                (item.get("router_name") or item.get("router_id") or "").strip()
                for item in ([current_entry] if current_entry else []) + known_entries
                if isinstance(item, dict) and (item.get("router_name") or item.get("router_id") or "").strip()
            }
        )
        rx_raw = last.get("rx")
        tx_raw = last.get("tx")
        rx_invalid = rx_raw is None or rx_raw < rx_realistic_min or rx_raw > rx_realistic_max
        tx_missing = tx_raw is None
        tx_invalid = False
        if tx_raw is not None:
            tx_invalid = tx_raw < tx_realistic_min or tx_raw > tx_realistic_max
        rx_reason = ""
        tx_reason = ""
        if rx_invalid:
            rx_reason = f"RX missing/unrealistic (raw={rx_raw})"
        if tx_missing:
            tx_reason = "TX missing"
        elif tx_invalid:
            tx_reason = f"TX missing/unrealistic (raw={tx_raw})"
        reasons = []
        status = "stable"
        status_label = "Stable"
        status_note = ""

        if not current_available:
            status = "offline"
            status_label = "Offline"
            status_note = "TR-069 is currently offline. Showing the last stored optical data."
            reasons.append("TR-069 offline")
        elif rx_invalid:
            status = "acs_los"
            status_label = "ACS-LOS"
            status_note = "TR-069 is online, but RX is missing or unrealistic."
            reasons.append("TR-069 online but RX missing/unrealistic")
        else:
            issue_hit = False
            if rx_raw is not None and rx_raw <= issue_rx:
                issue_hit = True
                reasons.append(f"RX <= {issue_rx:g}")
            if tx_raw is not None and not tx_invalid and tx_raw <= issue_tx:
                issue_hit = True
                reasons.append(f"TX <= {issue_tx:g}")
            if rx_raw is not None and rx_raw <= priority_rx:
                issue_hit = True
                reasons.append(f"Priority RX <= {priority_rx:g}")

            if issue_hit:
                status = "issue"
                status_label = "Issue"
                status_note = "Optical thresholds are currently breached."
            else:
                is_stable = rx_raw is not None and rx_raw >= stable_rx and (
                    tx_raw is None or tx_invalid or tx_raw >= stable_tx
                )
                if is_stable:
                    status = "stable"
                    status_label = "Stable"
                    status_note = "Optical readings are currently within stable range."
                else:
                    status = "monitor"
                    status_label = "Monitor"
                    status_note = "Optical readings are below stable range but not yet an issue."
                    if rx_raw is not None and rx_raw < stable_rx:
                        reasons.append(f"RX below stable {stable_rx:g}")
                    if tx_raw is not None and not tx_invalid and tx_raw < stable_tx:
                        reasons.append(f"TX below stable {stable_tx:g}")

        entry = {
            "device_id": dev_id,
            "name": last.get("pppoe") or dev_id,
            "ip": last.get("ip") or "",
            "last_ts": (last.get("timestamp") or "").strip(),
            "status": status,
            "rx": rx_raw,
            "tx": tx_raw,
            "rx_raw": rx_raw,
            "tx_raw": tx_raw,
            "rx_invalid": rx_invalid,
            "tx_invalid": tx_invalid,
            "tx_missing": tx_missing,
            "rx_reason": rx_reason,
            "tx_reason": tx_reason,
            "samples": 0,
            "last_check": format_ts_ph(last.get("timestamp")),
            # sparklines are computed after pagination to keep rendering fast
            "spark_segments_window": [],
            "reasons": reasons or ([] if status == "stable" else ["Monitor"]),
            "device_url": genie_device_url(genie_base, dev_id),
            "current_available": current_available,
            "router_names": router_names,
            "router_label": ", ".join(router_names),
            "status_label": status_label,
            "status_note": status_note,
        }
        if status == "offline":
            offline_candidates.append(entry)
        elif status == "acs_los":
            acs_los_candidates.append(entry)
        elif status == "issue":
            issue_candidates.append(entry)
        else:
            stable_candidates.append(entry)

    q = (query or "").strip().lower()
    if q:
        def matches(entry):
            hay = " ".join(
                [
                    str(entry.get("name") or ""),
                    str(entry.get("ip") or ""),
                    str(entry.get("device_id") or ""),
                    str(entry.get("router_label") or ""),
                    str(entry.get("status_label") or ""),
                    str(entry.get("status_note") or ""),
                    " ".join(entry.get("reasons") or []),
                ]
            ).lower()
            return q in hay

        issue_candidates = [row for row in issue_candidates if matches(row)]
        stable_candidates = [row for row in stable_candidates if matches(row)]
        offline_candidates = [row for row in offline_candidates if matches(row)]
        acs_los_candidates = [row for row in acs_los_candidates if matches(row)]

    def _sort_numeric(val, desc=False):
        if val is None:
            return (1, 0.0)
        try:
            num = float(val)
        except Exception:
            return (1, 0.0)
        return (0, -num if desc else num)

    def _sort_text(val, desc=False):
        text = (val or "").strip().lower()
        return (0, "".join(reversed(text)) if desc else text)

    def _sort_key_for(entry, key, desc=False):
        if key in ("customer", "name"):
            return _sort_text(entry.get("name"), desc=desc)
        if key in ("ip", "ipv4"):
            return _sort_text(entry.get("ip"), desc=desc)
        if key == "status":
            order = {"issue": 0, "acs_los": 1, "offline": 2, "monitor": 3, "stable": 4}
            return (0, -order.get(entry.get("status"), 9) if desc else order.get(entry.get("status"), 9))
        if key == "rx":
            return _sort_numeric(entry.get("rx"), desc=desc)
        if key == "tx":
            return _sort_numeric(entry.get("tx"), desc=desc)
        if key == "samples":
            return _sort_numeric(entry.get("samples"), desc=desc)
        if key in ("last_check_at", "last_ts"):
            return _sort_text(entry.get("last_ts"), desc=desc)
        if key == "reason":
            return _sort_text(", ".join(entry.get("reasons") or []), desc=desc)
        return _sort_text(entry.get("name"), desc=desc)

    issues_sort = (issues_sort or "").strip()
    stable_sort = (stable_sort or "").strip()
    offline_sort = (offline_sort or "").strip()
    acs_los_sort = (acs_los_sort or "").strip()
    issues_desc = (issues_dir or "").lower() != "asc"
    stable_desc = (stable_dir or "").lower() != "asc"
    offline_desc = (offline_dir or "").lower() != "asc"
    acs_los_desc = (acs_los_dir or "").lower() != "asc"

    # default by name
    issue_candidates = sorted(issue_candidates, key=lambda x: (x.get("name") or "").lower())
    stable_candidates = sorted(stable_candidates, key=lambda x: (x.get("name") or "").lower())
    offline_candidates = sorted(offline_candidates, key=lambda x: (x.get("name") or "").lower())
    acs_los_candidates = sorted(acs_los_candidates, key=lambda x: (x.get("name") or "").lower())

    if issues_sort == "samples" or stable_sort == "samples" or offline_sort == "samples" or acs_los_sort == "samples":
        all_ids = sorted(
            {
                e.get("device_id")
                for e in (issue_candidates + stable_candidates + offline_candidates + acs_los_candidates)
                if e.get("device_id")
            }
        )
        samples_map_all = get_optical_samples_for_devices_since(all_ids, since_iso) if all_ids else {}
        for entry in issue_candidates:
            dev = entry.get("device_id")
            entry["samples"] = int(samples_map_all.get(dev, 0) or 0)
        for entry in stable_candidates:
            dev = entry.get("device_id")
            entry["samples"] = int(samples_map_all.get(dev, 0) or 0)
        for entry in offline_candidates:
            dev = entry.get("device_id")
            entry["samples"] = int(samples_map_all.get(dev, 0) or 0)
        for entry in acs_los_candidates:
            dev = entry.get("device_id")
            entry["samples"] = int(samples_map_all.get(dev, 0) or 0)
    else:
        samples_map_all = {}

    if issues_sort:
        issue_candidates = sorted(issue_candidates, key=lambda row: _sort_key_for(row, issues_sort, desc=issues_desc))
    if stable_sort:
        stable_candidates = sorted(stable_candidates, key=lambda row: _sort_key_for(row, stable_sort, desc=stable_desc))
    if offline_sort:
        offline_candidates = sorted(offline_candidates, key=lambda row: _sort_key_for(row, offline_sort, desc=offline_desc))
    if acs_los_sort:
        acs_los_candidates = sorted(acs_los_candidates, key=lambda row: _sort_key_for(row, acs_los_sort, desc=acs_los_desc))

    paged_issue, issue_page_meta = _paginate_items(issue_candidates, issues_page, limit)
    paged_stable, stable_page_meta = _paginate_items(stable_candidates, stable_page, limit)
    paged_offline, offline_page_meta = _paginate_items(offline_candidates, offline_page, limit)
    paged_acs_los, acs_los_page_meta = _paginate_items(acs_los_candidates, acs_los_page, limit)

    page_device_ids = sorted(
        {
            row.get("device_id")
            for row in (paged_issue + paged_stable + paged_offline + paged_acs_los)
            if row.get("device_id")
        }
    )
    samples_map = (
        {dev: int(samples_map_all.get(dev, 0) or 0) for dev in page_device_ids}
        if samples_map_all
        else (get_optical_samples_for_devices_since(page_device_ids, since_iso) if page_device_ids else {})
    )
    series_map = get_optical_series_for_devices_since(page_device_ids, since_iso) if page_device_ids else {}
    gap_threshold_seconds = _optical_chart_gap_threshold_seconds(window_hours * 3600 if window_hours else 3600)

    def with_spark(entry):
        dev = entry.get("device_id")
        chart_series = _optical_with_gaps(series_map.get(dev, []), gap_threshold_seconds=gap_threshold_seconds)
        spark_segments = _sparkline_segments_from_series(chart_series, chart_min, chart_max, width=120, height=30)
        next_entry = dict(entry)
        next_entry["samples"] = int(samples_map.get(dev, 0) or 0)
        next_entry["spark_segments_window"] = spark_segments
        return next_entry

    issue_rows = [with_spark(entry) for entry in paged_issue]
    stable_rows = [with_spark(entry) for entry in paged_stable]
    offline_rows = [with_spark(entry) for entry in paged_offline]
    acs_los_rows = [with_spark(entry) for entry in paged_acs_los]
    preferred_tab = _preferred_status_tab(
        query,
        [
            ("issues", len(issue_candidates)),
            ("stable", len(stable_candidates)),
            ("offline", len(offline_candidates)),
            ("acs_los", len(acs_los_candidates)),
        ],
        "issues",
    )
    return {
        "total": len(issue_candidates) + len(stable_candidates) + len(offline_candidates) + len(acs_los_candidates),
        "issue_total": len(issue_candidates),
        "stable_total": len(stable_candidates),
        "offline_total": len(offline_candidates),
        "acs_los_total": len(acs_los_candidates),
        "preferred_tab": preferred_tab,
        "issue_rows": issue_rows,
        "stable_rows": stable_rows,
        "offline_rows": offline_rows,
        "acs_los_rows": acs_los_rows,
        "window_hours": window_hours,
        "window_label": window_label,
        "pagination": {
            "limit": limit,
            "limit_label": "ALL" if not limit else str(limit),
            "options": TABLE_PAGE_SIZE_OPTIONS,
            "issues": issue_page_meta,
            "stable": stable_page_meta,
            "offline": offline_page_meta,
            "acs_los": acs_los_page_meta,
        },
        "sort": {
            "issues": {"key": issues_sort, "dir": "desc" if issues_desc else "asc"},
            "stable": {"key": stable_sort, "dir": "desc" if stable_desc else "asc"},
            "offline": {"key": offline_sort, "dir": "desc" if offline_desc else "asc"},
            "acs_los": {"key": acs_los_sort, "dir": "desc" if acs_los_desc else "asc"},
        },
        "query": query or "",
        "rules": {
            "issue_rx_dbm": issue_rx,
            "issue_tx_dbm": issue_tx,
            "priority_rx_dbm": priority_rx,
            "stable_rx_dbm": stable_rx,
            "stable_tx_dbm": stable_tx,
        },
        "chart": {"min_dbm": chart_min, "max_dbm": chart_max},
    }


def _optical_status_cache_key(
    settings,
    window_hours,
    limit,
    issues_page,
    stable_page,
    offline_page,
    acs_los_page,
    issues_sort,
    issues_dir,
    stable_sort,
    stable_dir,
    offline_sort,
    offline_dir,
    acs_los_sort,
    acs_los_dir,
    query,
):
    payload = {
        "settings": settings,
        "window_hours": int(window_hours or 24),
        "limit": int(limit or 0),
        "issues_page": int(issues_page or 1),
        "stable_page": int(stable_page or 1),
        "offline_page": int(offline_page or 1),
        "acs_los_page": int(acs_los_page or 1),
        "issues_sort": str(issues_sort or ""),
        "issues_dir": str(issues_dir or ""),
        "stable_sort": str(stable_sort or ""),
        "stable_dir": str(stable_dir or ""),
        "offline_sort": str(offline_sort or ""),
        "offline_dir": str(offline_dir or ""),
        "acs_los_sort": str(acs_los_sort or ""),
        "acs_los_dir": str(acs_los_dir or ""),
        "query": str(query or ""),
    }
    try:
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        blob = repr(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _prune_optical_status_cache_locked(now_mono=None):
    now_mono = float(now_mono or time.monotonic())
    stale_before = now_mono - max(float(_OPTICAL_STATUS_CACHE_SECONDS) * 4.0, 60.0)
    stale_keys = [
        key
        for key, entry in _optical_status_cache.items()
        if float((entry or {}).get("at") or 0.0) < stale_before and not bool((entry or {}).get("refreshing"))
    ]
    for key in stale_keys:
        _optical_status_cache.pop(key, None)
    if len(_optical_status_cache) <= int(_OPTICAL_STATUS_CACHE_MAX_ENTRIES):
        return
    drop_keys = sorted(
        _optical_status_cache,
        key=lambda key: float((_optical_status_cache.get(key) or {}).get("at") or 0.0),
    )[: max(len(_optical_status_cache) - int(_OPTICAL_STATUS_CACHE_MAX_ENTRIES), 0)]
    for key in drop_keys:
        if bool((_optical_status_cache.get(key) or {}).get("refreshing")):
            continue
        _optical_status_cache.pop(key, None)


def _refresh_optical_status_cache(cache_key, kwargs):
    try:
        fresh = _build_optical_status_uncached(**kwargs)
    except Exception:
        with _optical_status_cache_lock:
            entry = _optical_status_cache.get(cache_key)
            if isinstance(entry, dict):
                entry["refreshing"] = False
        return
    with _optical_status_cache_lock:
        _optical_status_cache[cache_key] = {
            "at": time.monotonic(),
            "data": copy.deepcopy(fresh),
            "refreshing": False,
        }
        _prune_optical_status_cache_locked()


def build_optical_status(
    settings,
    window_hours=24,
    limit=50,
    issues_page=1,
    stable_page=1,
    offline_page=1,
    acs_los_page=1,
    issues_sort="",
    issues_dir="",
    stable_sort="",
    stable_dir="",
    offline_sort="",
    offline_dir="",
    acs_los_sort="",
    acs_los_dir="",
    query="",
):
    kwargs = {
        "settings": copy.deepcopy(settings),
        "window_hours": window_hours,
        "limit": limit,
        "issues_page": issues_page,
        "stable_page": stable_page,
        "offline_page": offline_page,
        "acs_los_page": acs_los_page,
        "issues_sort": issues_sort,
        "issues_dir": issues_dir,
        "stable_sort": stable_sort,
        "stable_dir": stable_dir,
        "offline_sort": offline_sort,
        "offline_dir": offline_dir,
        "acs_los_sort": acs_los_sort,
        "acs_los_dir": acs_los_dir,
        "query": query,
    }
    cache_key = _optical_status_cache_key(**kwargs)
    now_mono = time.monotonic()
    with _optical_status_cache_lock:
        entry = _optical_status_cache.get(cache_key)
        if isinstance(entry, dict) and entry.get("data") is not None:
            age = now_mono - float(entry.get("at") or 0.0)
            if age < float(_OPTICAL_STATUS_CACHE_SECONDS):
                return copy.deepcopy(entry.get("data"))
            if not bool(entry.get("refreshing")):
                entry["refreshing"] = True
                threading.Thread(
                    target=_refresh_optical_status_cache,
                    args=(cache_key, kwargs),
                    daemon=True,
                ).start()
            return copy.deepcopy(entry.get("data"))
    fresh = _build_optical_status_uncached(**kwargs)
    with _optical_status_cache_lock:
        _optical_status_cache[cache_key] = {
            "at": time.monotonic(),
            "data": copy.deepcopy(fresh),
            "refreshing": False,
        }
        _prune_optical_status_cache_locked()
    return fresh


def _prewarm_optical_status_cache():
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    build_optical_status(settings, window_hours=24, limit=50)


def render_optical_settings_response(request, settings, message="", active_tab="settings", settings_tab="general", window_hours=24):
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    optical_status = build_optical_status(settings, window_hours)
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": optical_status,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": active_tab,
                "settings_tab": settings_tab,
            },
        ),
    )


@app.get("/settings/optical", response_class=HTMLResponse)
async def optical_settings(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    limit = _parse_table_limit(request.query_params.get("limit"), default=50)
    issues_page = _parse_table_page(request.query_params.get("issues_page"), default=1)
    stable_page = _parse_table_page(request.query_params.get("stable_page"), default=1)
    offline_page = _parse_table_page(request.query_params.get("offline_page"), default=1)
    acs_los_page = _parse_table_page(request.query_params.get("acs_los_page"), default=1)
    issues_sort = (request.query_params.get("issues_sort") or "").strip()
    issues_dir = (request.query_params.get("issues_dir") or "").strip().lower()
    stable_sort = (request.query_params.get("stable_sort") or "").strip()
    stable_dir = (request.query_params.get("stable_dir") or "").strip().lower()
    offline_sort = (request.query_params.get("offline_sort") or "").strip()
    offline_dir = (request.query_params.get("offline_dir") or "").strip().lower()
    acs_los_sort = (request.query_params.get("acs_los_sort") or "").strip()
    acs_los_dir = (request.query_params.get("acs_los_dir") or "").strip().lower()
    query = (request.query_params.get("q") or "").strip()
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    optical_status = build_optical_status(
        settings,
        window_hours,
        limit,
        issues_page,
        stable_page,
        offline_page,
        acs_los_page,
        issues_sort=issues_sort,
        issues_dir=issues_dir,
        stable_sort=stable_sort,
        stable_dir=stable_dir,
        offline_sort=offline_sort,
        offline_dir=offline_dir,
        acs_los_sort=acs_los_sort,
        acs_los_dir=acs_los_dir,
        query=query,
    )
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "",
                "optical_status": optical_status,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "status",
                "settings_tab": "general",
            },
        ),
    )


@app.post("/settings/optical", response_class=HTMLResponse)
async def optical_settings_save(request: Request):
    form = await request.form()
    action = (form.get("action") or "").strip()
    settings_tab = form.get("settings_tab") or "general"
    settings = get_settings("optical", OPTICAL_DEFAULTS)

    genieacs = settings.get("genieacs") if isinstance(settings.get("genieacs"), dict) else {}
    settings["genieacs"] = genieacs

    telegram = settings.get("telegram") if isinstance(settings.get("telegram"), dict) else {}
    settings["telegram"] = telegram

    optical = settings.get("optical") if isinstance(settings.get("optical"), dict) else {}
    settings["optical"] = optical

    general = settings.get("general") if isinstance(settings.get("general"), dict) else {}
    settings["general"] = general

    storage = settings.get("storage") if isinstance(settings.get("storage"), dict) else {}
    settings["storage"] = storage

    classification = (
        settings.get("classification") if isinstance(settings.get("classification"), dict) else {}
    )
    settings["classification"] = classification

    if action != "test_genieacs":
        if settings_tab == "general":
            settings["enabled"] = parse_bool(form, "enabled")
            general["check_interval_minutes"] = parse_int(
                form, "check_interval_minutes", general.get("check_interval_minutes", 60)
            )

        elif settings_tab == "data":
            genieacs["base_url"] = form.get("genieacs_base_url", genieacs.get("base_url", ""))
            genieacs["username"] = form.get("genieacs_username", genieacs.get("username", ""))
            genieacs["password"] = form.get("genieacs_password", genieacs.get("password", ""))
            genieacs["page_size"] = parse_int(
                form, "genieacs_page_size", genieacs.get("page_size", 100)
            )

            optical["rx_paths"] = parse_lines(form.get("rx_paths", ""))
            optical["tx_paths"] = parse_lines(form.get("tx_paths", ""))
            optical["pppoe_paths"] = parse_lines(form.get("pppoe_paths", ""))
            optical["ip_paths"] = parse_lines(form.get("ip_paths", ""))

        elif settings_tab == "notifications":
            telegram["bot_token"] = form.get("telegram_bot_token", telegram.get("bot_token", ""))
            telegram["chat_id"] = form.get("telegram_chat_id", telegram.get("chat_id", ""))

            general["message_title"] = form.get(
                "message_title", general.get("message_title", "Optical Power Alert")
            )
            general["include_header"] = parse_bool(form, "include_header")
            general["max_chars"] = parse_int(form, "max_chars", general.get("max_chars", 3800))
            general["schedule_time_ph"] = form.get(
                "schedule_time_ph", general.get("schedule_time_ph", "07:00")
            )

        elif settings_tab == "thresholds":
            optical["rx_threshold_dbm"] = parse_float(
                form, "rx_threshold_dbm", optical.get("rx_threshold_dbm", -26.0)
            )
            optical["tx_low_threshold_dbm"] = parse_float(
                form, "tx_low_threshold_dbm", optical.get("tx_low_threshold_dbm", -1.0)
            )
            optical["priority_rx_threshold_dbm"] = parse_float(
                form,
                "priority_rx_threshold_dbm",
                optical.get("priority_rx_threshold_dbm", -29.0),
            )

        elif settings_tab == "classification":
            classification["issue_rx_dbm"] = parse_float(
                form, "optical_issue_rx_dbm", classification.get("issue_rx_dbm", -27.0)
            )
            classification["issue_tx_dbm"] = parse_float(
                form, "optical_issue_tx_dbm", classification.get("issue_tx_dbm", -2.0)
            )
            classification["stable_rx_dbm"] = parse_float(
                form, "optical_stable_rx_dbm", classification.get("stable_rx_dbm", -24.0)
            )
            classification["stable_tx_dbm"] = parse_float(
                form, "optical_stable_tx_dbm", classification.get("stable_tx_dbm", -1.0)
            )
            classification["chart_min_dbm"] = parse_float(
                form, "optical_chart_min_dbm", classification.get("chart_min_dbm", -35.0)
            )
            classification["chart_max_dbm"] = parse_float(
                form, "optical_chart_max_dbm", classification.get("chart_max_dbm", -10.0)
            )

        elif settings_tab == "storage":
            storage["raw_retention_days"] = parse_int(
                form, "optical_raw_retention_days", storage.get("raw_retention_days", 365)
            )

    if action == "test_genieacs":
        settings_tab = "data"
        genieacs["base_url"] = form.get("genieacs_base_url", genieacs.get("base_url", ""))
        genieacs["username"] = form.get("genieacs_username", genieacs.get("username", ""))
        genieacs["password"] = form.get("genieacs_password", genieacs.get("password", ""))
        genieacs["page_size"] = parse_int(form, "genieacs_page_size", genieacs.get("page_size", 100))

        optical["rx_paths"] = parse_lines(form.get("rx_paths", ""))
        optical["tx_paths"] = parse_lines(form.get("tx_paths", ""))
        optical["pppoe_paths"] = parse_lines(form.get("pppoe_paths", ""))
        optical["ip_paths"] = parse_lines(form.get("ip_paths", ""))

        message = ""
        try:
            base_url = (genieacs.get("base_url") or "").rstrip("/")
            if not base_url:
                raise ValueError("GenieACS Base URL is required.")
            username = genieacs.get("username") or ""
            password = genieacs.get("password") or ""
            headers = {}
            if username or password:
                token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {token}"

            params = {"query": "{}", "limit": "1", "skip": "0"}
            url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            count = len(payload) if isinstance(payload, list) else 0
            message = f"GenieACS API OK. Retrieved {count} device(s)."
        except Exception as exc:
            message = f"GenieACS test failed: {exc}"

        window_hours = 24
        optical_status = build_optical_status(settings, window_hours)
        job_status = {item["job_name"]: dict(item) for item in get_job_status()}
        optical_job = job_status.get("optical", {})
        optical_job = {
            "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
            "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
        }
        return templates.TemplateResponse(
            "settings_optical.html",
            make_context(
                request,
                {
                    "settings": settings,
                    "message": message,
                    "optical_status": optical_status,
                    "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                    "optical_job": optical_job,
                    "active_tab": "settings",
                    "settings_tab": settings_tab,
                },
            ),
        )

    save_settings("optical", settings)
    window_hours = 24
    optical_status = build_optical_status(settings, window_hours)
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "Saved.",
                "optical_status": optical_status,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "settings",
                "settings_tab": settings_tab or "general",
            },
        ),
    )


@app.post("/settings/optical/test", response_class=HTMLResponse)
async def optical_settings_test(request: Request):
    form = await request.form()
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    telegram = settings.get("telegram") if isinstance(settings.get("telegram"), dict) else {}
    settings["telegram"] = telegram
    general = settings.get("general") if isinstance(settings.get("general"), dict) else {}
    settings["general"] = general

    telegram["bot_token"] = form.get("telegram_bot_token", telegram.get("bot_token", ""))
    telegram["chat_id"] = form.get("telegram_chat_id", telegram.get("chat_id", ""))
    general["message_title"] = form.get(
        "message_title", general.get("message_title", "Optical Power Alert")
    )
    general["include_header"] = parse_bool(form, "include_header")
    general["max_chars"] = parse_int(form, "max_chars", general.get("max_chars", 3800))
    general["schedule_time_ph"] = form.get(
        "schedule_time_ph", general.get("schedule_time_ph", "07:00")
    )

    message = ""
    try:
        token = settings["telegram"].get("bot_token", "")
        chat_id = settings["telegram"].get("chat_id", "")
        send_telegram(token, chat_id, "ThreeJ Optical test message.")
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return render_optical_settings_response(
        request,
        settings,
        message=message,
        active_tab="settings",
        settings_tab="notifications",
    )


@app.post("/settings/optical/test_genieacs", response_class=HTMLResponse)
async def optical_settings_test_genieacs(request: Request):
    form = await request.form()
    settings = get_settings("optical", OPTICAL_DEFAULTS)

    genieacs = settings.get("genieacs") if isinstance(settings.get("genieacs"), dict) else {}
    genieacs["base_url"] = form.get("genieacs_base_url", genieacs.get("base_url", ""))
    genieacs["username"] = form.get("genieacs_username", genieacs.get("username", ""))
    genieacs["password"] = form.get("genieacs_password", genieacs.get("password", ""))
    genieacs["page_size"] = parse_int(form, "genieacs_page_size", genieacs.get("page_size", 100))
    settings["genieacs"] = genieacs

    optical = settings.get("optical") if isinstance(settings.get("optical"), dict) else {}
    optical["rx_paths"] = parse_lines(form.get("rx_paths", ""))
    optical["tx_paths"] = parse_lines(form.get("tx_paths", ""))
    optical["pppoe_paths"] = parse_lines(form.get("pppoe_paths", ""))
    optical["ip_paths"] = parse_lines(form.get("ip_paths", ""))
    settings["optical"] = optical

    message = ""
    try:
        base_url = (genieacs.get("base_url") or "").rstrip("/")
        if not base_url:
            raise ValueError("GenieACS Base URL is required.")
        username = genieacs.get("username") or ""
        password = genieacs.get("password") or ""
        headers = {}
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        params = {"query": "{}", "limit": "1", "skip": "0"}
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        count = len(payload) if isinstance(payload, list) else 0
        message = f"GenieACS API OK. Retrieved {count} device(s)."
    except Exception as exc:
        message = f"GenieACS test failed: {exc}"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": build_optical_status(settings, 24),
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "settings",
                "settings_tab": "data",
            },
        ),
    )


@app.get("/settings/optical/test_genieacs", response_class=HTMLResponse)
async def optical_settings_test_genieacs_get(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    message = ""
    started = time.monotonic()
    try:
        genieacs = settings.get("genieacs", {}) if isinstance(settings.get("genieacs"), dict) else {}
        base_url = (genieacs.get("base_url") or "").rstrip("/")
        if not base_url:
            raise ValueError("GenieACS Base URL is required.")
        username = genieacs.get("username") or ""
        password = genieacs.get("password") or ""
        headers = {}
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        params = {"query": "{}", "limit": "1", "skip": "0"}
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        count = len(payload) if isinstance(payload, list) else 0
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS API OK ({elapsed_ms} ms). Retrieved {count} device(s)."
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS test failed ({elapsed_ms} ms): {exc}"

    window_hours = _normalize_wan_window(request.query_params.get("window"))
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": build_optical_status(settings, window_hours),
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "settings",
                "settings_tab": "data",
            },
        ),
    )


@app.post("/settings/optical/run", response_class=HTMLResponse)
async def optical_settings_run(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    message = ""
    try:
        optical_notifier.run(settings)
        message = "Actual optical check sent."
    except TelegramError as exc:
        message = str(exc)
    except Exception as exc:
        message = f"Run failed: {exc}"
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": build_optical_status(settings, 24),
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": {
                    "last_run_at_ph": None,
                    "last_success_at_ph": None,
                },
                "active_tab": "settings",
                "settings_tab": "general",
            },
        ),
    )


@app.post("/settings/optical/format", response_class=HTMLResponse)
async def optical_settings_format(request: Request):
    return _render_system_danger_notice(request, "optical")


@app.get("/optical/series", response_class=JSONResponse)
async def optical_series(device_id: str, window: int = 24):
    if not (device_id or "").strip():
        return _json_no_store({"hours": 0, "series": []}, status_code=400)
    hours = _normalize_wan_window(window)
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    rows = get_optical_results_for_device_since(device_id, since_iso)
    series = _optical_with_gaps(rows, gap_threshold_seconds=_optical_chart_gap_threshold_seconds(hours * 3600))
    return _json_no_store({"hours": hours, "series": series})


@app.get("/settings/usage", response_class=HTMLResponse)
async def usage_settings(request: Request):
    settings = get_settings("usage", USAGE_DEFAULTS)
    active_tab = (request.query_params.get("tab") or "status").strip().lower()
    if active_tab not in ("status", "settings"):
        active_tab = "status"
    settings_tab = (request.query_params.get("settings_tab") or "general").strip().lower()
    can_run_danger_actions = _auth_request_has_permission(request, "usage.settings.danger.run")
    can_view_reboot_history = (
        not bool(getattr(request.state, "auth_enabled", True))
        or _auth_request_has_permission(request, "usage.status.reboot_history.view")
    )
    can_edit_modem_reboot = (
        not bool(getattr(request.state, "auth_enabled", True))
        or _auth_request_has_permission(request, "usage.settings.modem_reboot.edit")
    )
    if settings_tab not in ("general", "routers", "data", "detection", "modem_reboot", "storage"):
        settings_tab = "general"
    if settings_tab == "modem_reboot" and not can_edit_modem_reboot:
        settings_tab = "general"
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    usage_summary_data = _build_usage_summary_data(settings, state)
    usage_account_count = len(
        _build_usage_accounts_rows(
            usage_summary_data,
            list_usage_modem_reboot_account_stats() if can_view_reboot_history else [],
            normalize_usage_modem_reboot_settings(settings),
        )
    )
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "",
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "can_run_danger_actions": can_run_danger_actions,
                "usage_job": usage_job,
                "wan_settings": wan_settings,
                "usage_router_state": router_state_map,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
                "usage_counts": {
                    "issues": len(usage_summary_data.get("issues") or []),
                    "stable": len(usage_summary_data.get("stable") or []),
                    "accounts": usage_account_count,
                    "reboot_history": count_usage_modem_reboot_history()
                    if normalize_usage_modem_reboot_settings(settings).get("enabled") and can_view_reboot_history
                    else 0,
                },
                "usage_new_view_seconds": _USAGE_NEW_VIEW_SECONDS,
                "can_view_usage_reboot_history": can_view_reboot_history,
                "can_edit_usage_modem_reboot": can_edit_modem_reboot,
            },
        ),
    )


@app.post("/settings/usage", response_class=HTMLResponse)
async def usage_settings_save(request: Request):
    form = await request.form()
    settings_tab = (form.get("settings_tab") or "general").strip().lower() or "general"
    can_run_danger_actions = _auth_request_has_permission(request, "usage.settings.danger.run")
    can_view_reboot_history = (
        not bool(getattr(request.state, "auth_enabled", True))
        or _auth_request_has_permission(request, "usage.status.reboot_history.view")
    )
    can_edit_modem_reboot = (
        not bool(getattr(request.state, "auth_enabled", True))
        or _auth_request_has_permission(request, "usage.settings.modem_reboot.edit")
    )
    if settings_tab not in ("general", "routers", "data", "detection", "modem_reboot", "storage"):
        settings_tab = "general"
    settings = get_settings("usage", USAGE_DEFAULTS)

    settings["mikrotik"] = settings.get("mikrotik") if isinstance(settings.get("mikrotik"), dict) else {}
    settings["genieacs"] = settings.get("genieacs") if isinstance(settings.get("genieacs"), dict) else {}
    settings["source"] = settings.get("source") if isinstance(settings.get("source"), dict) else {}
    settings["device"] = settings.get("device") if isinstance(settings.get("device"), dict) else {}
    settings["detection"] = settings.get("detection") if isinstance(settings.get("detection"), dict) else {}
    settings["storage"] = settings.get("storage") if isinstance(settings.get("storage"), dict) else {}
    settings["mikrotik"]["router_enabled"] = (
        settings["mikrotik"].get("router_enabled")
        if isinstance(settings["mikrotik"].get("router_enabled"), dict)
        else {}
    )

    message = ""
    try:
        if settings_tab == "general":
            settings["enabled"] = parse_bool(form, "enabled")
            settings["mikrotik"]["poll_interval_seconds"] = parse_int(
                form,
                "poll_interval_seconds",
                int(settings["mikrotik"].get("poll_interval_seconds", USAGE_DEFAULTS["mikrotik"]["poll_interval_seconds"])),
            )
            settings["mikrotik"]["secrets_refresh_minutes"] = parse_int(
                form,
                "secrets_refresh_minutes",
                int(
                    settings["mikrotik"].get(
                        "secrets_refresh_minutes", USAGE_DEFAULTS["mikrotik"]["secrets_refresh_minutes"]
                    )
                ),
            )
            settings["mikrotik"]["timeout_seconds"] = parse_int(
                form,
                "timeout_seconds",
                int(settings["mikrotik"].get("timeout_seconds", USAGE_DEFAULTS["mikrotik"]["timeout_seconds"])),
            )
            settings["storage"]["sample_interval_seconds"] = parse_int(
                form,
                "sample_interval_seconds",
                int(settings["storage"].get("sample_interval_seconds", USAGE_DEFAULTS["storage"]["sample_interval_seconds"])),
            )
            message = "Usage settings saved."
        elif settings_tab == "routers":
            wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
            system_routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
            count = parse_int(form, "router_count", len(system_routers))
            enabled_map = {}
            for idx in range(count):
                router_id = (form.get(f"router_{idx}_id") or "").strip()
                if not router_id:
                    continue
                enabled_map[router_id] = parse_bool(form, f"router_{idx}_enabled")
            settings["mikrotik"]["router_enabled"] = enabled_map
            message = "Usage router selection saved."
        elif settings_tab == "data":
            settings["genieacs"]["base_url"] = (form.get("genieacs_base_url") or "").strip()
            settings["genieacs"]["username"] = (form.get("genieacs_username") or "").strip()
            settings["genieacs"]["password"] = (form.get("genieacs_password") or "").strip()
            settings["genieacs"]["page_size"] = parse_int(form, "genieacs_page_size", int(settings["genieacs"].get("page_size", 100) or 100))

            settings["source"]["refresh_minutes"] = parse_int(
                form,
                "genieacs_refresh_minutes",
                int(settings["source"].get("refresh_minutes", USAGE_DEFAULTS["source"]["refresh_minutes"])),
            )

            settings["device"]["pppoe_paths"] = parse_lines(form.get("pppoe_paths") or "")
            settings["device"]["host_count_paths"] = parse_lines(form.get("host_count_paths") or "")
            settings["device"]["host_name_paths"] = parse_lines(form.get("host_name_paths") or "")
            settings["device"]["host_ip_paths"] = parse_lines(form.get("host_ip_paths") or "")
            settings["device"]["host_active_paths"] = parse_lines(form.get("host_active_paths") or "")
            message = "Data Source settings saved."
        elif settings_tab == "detection":
            settings["detection"]["peak_start_ph"] = (form.get("peak_start_ph") or "").strip() or "17:30"
            settings["detection"]["peak_end_ph"] = (form.get("peak_end_ph") or "").strip() or "21:00"
            settings["detection"]["peak_enabled"] = parse_bool(form, "peak_enabled")
            settings["detection"]["peak_no_usage_minutes"] = parse_int(
                form,
                "peak_no_usage_minutes",
                int(
                    settings["detection"].get(
                        "peak_no_usage_minutes",
                        USAGE_DEFAULTS["detection"]["peak_no_usage_minutes"],
                    )
                ),
            )
            settings["detection"]["min_connected_devices"] = parse_int(
                form,
                "min_connected_devices",
                int(settings["detection"].get("min_connected_devices", USAGE_DEFAULTS["detection"]["min_connected_devices"])),
            )
            default_to = settings["detection"].get("total_kbps_to")
            if default_to is None:
                default_to = settings["detection"].get("min_total_kbps", USAGE_DEFAULTS["detection"]["min_total_kbps"])
            settings["detection"]["total_kbps_from"] = parse_int(
                form,
                "total_kbps_from",
                int(settings["detection"].get("total_kbps_from", USAGE_DEFAULTS["detection"]["total_kbps_from"])),
            )
            settings["detection"]["total_kbps_to"] = parse_int(
                form,
                "total_kbps_to",
                int(default_to),
            )
            # Back-compat: keep the old single threshold in sync with the range upper bound.
            settings["detection"]["min_total_kbps"] = int(settings["detection"]["total_kbps_to"])

            settings["detection"]["anytime_enabled"] = parse_bool(form, "anytime_enabled")
            settings["detection"]["anytime_work_start_ph"] = (form.get("anytime_work_start_ph") or "").strip() or "00:00"
            settings["detection"]["anytime_work_end_ph"] = (form.get("anytime_work_end_ph") or "").strip() or "23:59"
            settings["detection"]["anytime_no_usage_minutes"] = parse_int(
                form,
                "anytime_no_usage_minutes",
                int(
                    settings["detection"].get(
                        "anytime_no_usage_minutes", USAGE_DEFAULTS["detection"]["anytime_no_usage_minutes"]
                    )
                ),
            )
            settings["detection"]["anytime_min_connected_devices"] = parse_int(
                form,
                "anytime_min_connected_devices",
                int(
                    settings["detection"].get(
                        "anytime_min_connected_devices", USAGE_DEFAULTS["detection"]["anytime_min_connected_devices"]
                    )
                ),
            )
            settings["detection"]["anytime_total_kbps_from"] = parse_int(
                form,
                "anytime_total_kbps_from",
                int(
                    settings["detection"].get(
                        "anytime_total_kbps_from", USAGE_DEFAULTS["detection"]["anytime_total_kbps_from"]
                    )
                ),
            )
            settings["detection"]["anytime_total_kbps_to"] = parse_int(
                form,
                "anytime_total_kbps_to",
                int(
                    settings["detection"].get(
                        "anytime_total_kbps_to", USAGE_DEFAULTS["detection"]["anytime_total_kbps_to"]
                    )
                ),
            )
            message = "Detection settings saved."
        elif settings_tab == "storage":
            settings["storage"]["raw_retention_days"] = parse_int(
                form,
                "raw_retention_days",
                int(settings["storage"].get("raw_retention_days", USAGE_DEFAULTS["storage"]["raw_retention_days"])),
            )
            settings["storage"]["sample_interval_seconds"] = parse_int(
                form,
                "sample_interval_seconds",
                int(settings["storage"].get("sample_interval_seconds", USAGE_DEFAULTS["storage"]["sample_interval_seconds"])),
            )
            message = "Storage settings saved."
        elif settings_tab == "modem_reboot":
            if not can_edit_modem_reboot:
                return _auth_forbidden_response(request, "usage.settings.modem_reboot.edit")
            settings["modem_reboot"] = settings.get("modem_reboot") if isinstance(settings.get("modem_reboot"), dict) else {}
            settings["modem_reboot"]["enabled"] = parse_bool(form, "modem_reboot_enabled")
            settings["modem_reboot"]["buffer_hours"] = parse_int(
                form,
                "modem_reboot_buffer_hours",
                int((settings.get("modem_reboot") or {}).get("buffer_hours", USAGE_DEFAULTS["modem_reboot"]["buffer_hours"])),
            )
            settings["modem_reboot"]["retry_count"] = parse_int(
                form,
                "modem_reboot_retry_count",
                int((settings.get("modem_reboot") or {}).get("retry_count", USAGE_DEFAULTS["modem_reboot"]["retry_count"])),
            )
            settings["modem_reboot"]["retry_delay_minutes"] = parse_int(
                form,
                "modem_reboot_retry_delay_minutes",
                int(
                    (settings.get("modem_reboot") or {}).get(
                        "retry_delay_minutes",
                        USAGE_DEFAULTS["modem_reboot"]["retry_delay_minutes"],
                    )
                ),
            )
            settings["modem_reboot"]["history_retention_days"] = parse_int(
                form,
                "modem_reboot_history_retention_days",
                int(
                    (settings.get("modem_reboot") or {}).get(
                        "history_retention_days",
                        USAGE_DEFAULTS["modem_reboot"]["history_retention_days"],
                    )
                ),
            )
            settings["modem_reboot"]["verify_after_minutes"] = parse_int(
                form,
                "modem_reboot_verify_after_minutes",
                int(
                    (settings.get("modem_reboot") or {}).get(
                        "verify_after_minutes",
                        USAGE_DEFAULTS["modem_reboot"]["verify_after_minutes"],
                    )
                ),
            )
            settings["modem_reboot"]["max_attempts"] = parse_int(
                form,
                "modem_reboot_max_attempts",
                int((settings.get("modem_reboot") or {}).get("max_attempts", USAGE_DEFAULTS["modem_reboot"]["max_attempts"])),
            )
            settings["modem_reboot"]["unrebootable_check_interval_days"] = parse_int(
                form,
                "modem_reboot_unrebootable_check_interval_days",
                int(
                    (settings.get("modem_reboot") or {}).get(
                        "unrebootable_check_interval_days",
                        USAGE_DEFAULTS["modem_reboot"]["unrebootable_check_interval_days"],
                    )
                ),
            )
            message = "Modem Auto Reboot settings saved."
        else:
            message = "Settings saved."

        save_settings("usage", settings)
    except Exception as exc:
        message = f"Save failed: {exc}"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    usage_summary_data = _build_usage_summary_data(settings, state)
    usage_account_count = len(
        _build_usage_accounts_rows(
            usage_summary_data,
            list_usage_modem_reboot_account_stats() if can_view_reboot_history else [],
            normalize_usage_modem_reboot_settings(settings),
        )
    )
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": settings_tab,
                "usage_job": usage_job,
                "wan_settings": wan_settings,
                "usage_router_state": router_state_map,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
                "usage_counts": {
                    "issues": len(usage_summary_data.get("issues") or []),
                    "stable": len(usage_summary_data.get("stable") or []),
                    "accounts": usage_account_count,
                    "reboot_history": count_usage_modem_reboot_history()
                    if normalize_usage_modem_reboot_settings(settings).get("enabled") and can_view_reboot_history
                    else 0,
                },
                "usage_new_view_seconds": _USAGE_NEW_VIEW_SECONDS,
                "can_view_usage_reboot_history": can_view_reboot_history,
                "can_edit_usage_modem_reboot": can_edit_modem_reboot,
            },
        ),
    )


@app.post("/settings/usage/test_genieacs", response_class=HTMLResponse)
async def usage_test_genieacs(request: Request):
    settings = get_settings("usage", USAGE_DEFAULTS)
    message = ""
    started = time.monotonic()
    try:
        base_url = (settings.get("genieacs", {}) or {}).get("base_url", "").strip().rstrip("/")
        if not base_url:
            raise ValueError("GenieACS Base URL is required.")
        username = (settings.get("genieacs", {}) or {}).get("username") or ""
        password = (settings.get("genieacs", {}) or {}).get("password") or ""
        headers = {}
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        params = {"query": "{}", "limit": "1", "skip": "0"}
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        count = len(payload) if isinstance(payload, list) else 0
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS API OK ({elapsed_ms} ms). Retrieved {count} device(s)."
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS test failed ({elapsed_ms} ms): {exc}"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    usage_summary_data = _build_usage_summary_data(settings, state)
    can_view_reboot_history = (
        not bool(getattr(request.state, "auth_enabled", True))
        or _auth_request_has_permission(request, "usage.status.reboot_history.view")
    )
    can_edit_modem_reboot = (
        not bool(getattr(request.state, "auth_enabled", True))
        or _auth_request_has_permission(request, "usage.settings.modem_reboot.edit")
    )
    usage_account_count = len(
        _build_usage_accounts_rows(
            usage_summary_data,
            list_usage_modem_reboot_account_stats() if can_view_reboot_history else [],
            normalize_usage_modem_reboot_settings(settings),
        )
    )
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": "data",
                "usage_job": usage_job,
                "wan_settings": wan_settings,
                "usage_router_state": router_state_map,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
                "usage_counts": {
                    "issues": len(usage_summary_data.get("issues") or []),
                    "stable": len(usage_summary_data.get("stable") or []),
                    "accounts": usage_account_count,
                    "reboot_history": count_usage_modem_reboot_history()
                    if normalize_usage_modem_reboot_settings(settings).get("enabled")
                    and can_view_reboot_history
                    else 0,
                },
                "usage_new_view_seconds": _USAGE_NEW_VIEW_SECONDS,
                "can_view_usage_reboot_history": can_view_reboot_history,
                "can_edit_usage_modem_reboot": can_edit_modem_reboot,
            },
        ),
    )


@app.post("/settings/usage/routers", response_class=HTMLResponse)
async def usage_save_routers(request: Request):
    # Routers were moved from Usage settings to System Settings → Routers → Mikrotik Routers.
    form = await request.form()
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    existing = wan_settings_data.get("pppoe_routers", [])
    count = parse_int(form, "router_count", len(existing))
    routers, removed_ids = _parse_wan_pppoe_routers_from_form(form, count)
    wan_settings_data["pppoe_routers"] = routers
    if removed_ids:
        for wan in wan_settings_data.get("wans", []):
            if wan.get("pppoe_router_id") in removed_ids:
                wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(
        request,
        "Mikrotik routers saved.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/usage/routers/add", response_class=HTMLResponse)
async def usage_add_router(request: Request):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = wan_settings_data.get("pppoe_routers", [])
    existing_ids = {router.get("id") for router in routers if router.get("id")}
    next_idx = 1
    while f"router{next_idx}" in existing_ids:
        next_idx += 1
    routers.append(
        {
            "id": f"router{next_idx}",
            "name": f"Router {next_idx}",
            "host": "",
            "port": 8728,
            "username": "",
            "password": "",
            "use_tls": False,
        }
    )
    wan_settings_data["pppoe_routers"] = routers
    save_settings("wan_ping", wan_settings_data)
    return RedirectResponse(url="/settings/system?tab=routers&routers_tab=mikrotik-routers#sys-routers-mikrotik", status_code=302)


@app.post("/settings/usage/routers/test/{router_id}", response_class=HTMLResponse)
async def usage_test_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router = next((item for item in wan_settings_data.get("pppoe_routers", []) if item.get("id") == router_id), None)
    if not router:
        return render_system_settings_response(
            request,
            "Router not found.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    if router.get("use_tls"):
        return render_system_settings_response(
            request,
            "TLS test not supported yet. Disable TLS or use port 8728.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    host = (router.get("host") or "").strip()
    if not host:
        return render_system_settings_response(
            request,
            "Router host is required.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    client = RouterOSClient(
        host,
        int(router.get("port", 8728) or 8728),
        router.get("username", ""),
        router.get("password", ""),
    )
    try:
        client.connect()
        message = f"Router {router.get('name') or router_id} connected successfully."
    except Exception as exc:
        message = f"Router test failed: {exc}"
    finally:
        client.close()
    return render_system_settings_response(
        request,
        message,
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/usage/format", response_class=HTMLResponse)
async def usage_format(request: Request):
    return _render_system_danger_notice(request, "usage")


@app.get("/settings/offline", response_class=HTMLResponse)
async def offline_settings(request: Request):
    settings = normalize_offline_settings(get_settings("offline", OFFLINE_DEFAULTS))
    active_tab = (request.query_params.get("tab") or "status").strip().lower()
    if active_tab not in ("status", "settings", "telegram"):
        active_tab = "status"
    settings_tab = (request.query_params.get("settings_tab") or "general").strip().lower()
    if settings_tab not in ("general", "routers", "radius"):
        settings_tab = "general"
    radius_tab = (request.query_params.get("radius_tab") or "settings").strip().lower()
    if radius_tab not in ("settings", "accounts"):
        radius_tab = "settings"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    offline_job = job_status.get("offline", {})
    offline_job = {
        "last_run_at_ph": format_ts_ph(offline_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(offline_job.get("last_success_at")),
        "last_error": (offline_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(offline_job.get("last_error_at")),
    }

    state = get_state("offline_state", {})
    offline_state = {
        "last_check": format_ts_ph(state.get("last_check_at")),
        "active_accounts": int(state.get("active_accounts") or 0),
        "router_errors": state.get("router_errors") if isinstance(state.get("router_errors"), list) else [],
        "radius_error": (state.get("radius_error") or "").strip(),
    }
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    offline_rule_views = _build_offline_rule_views(state, settings)
    return templates.TemplateResponse(
        "settings_offline.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "",
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "radius_tab": radius_tab,
                "offline_job": offline_job,
                "offline_state": offline_state,
                "offline_router_state": router_state_map,
                "offline_rule_tabs": offline_rule_views.get("rules") if isinstance(offline_rule_views.get("rules"), list) else [],
                "offline_new_view_seconds": _OFFLINE_NEW_VIEW_SECONDS,
                "wan_settings": wan_settings,
            },
        ),
    )


@app.post("/settings/offline", response_class=HTMLResponse)
async def offline_settings_save(request: Request):
    form = await request.form()
    settings_tab = (form.get("settings_tab") or "general").strip().lower() or "general"
    if settings_tab not in ("general", "routers", "radius"):
        settings_tab = "general"
    radius_tab = (form.get("radius_tab") or "settings").strip().lower()
    if radius_tab not in ("settings", "accounts"):
        radius_tab = "settings"
    settings = normalize_offline_settings(get_settings("offline", OFFLINE_DEFAULTS))

    try:
        if settings_tab == "general":
            settings["enabled"] = parse_bool(form, "enabled")
            mode = (form.get("mode") or settings.get("mode") or "secrets").strip().lower()
            if mode not in ("secrets", "radius"):
                mode = "secrets"
            settings["mode"] = mode
            settings["general"]["poll_interval_seconds"] = parse_int(
                form,
                "poll_interval_seconds",
                int(settings["general"].get("poll_interval_seconds", OFFLINE_DEFAULTS["general"]["poll_interval_seconds"])),
            )
            tracking_rules = _parse_offline_tracking_rules_form(form, settings["general"].get("tracking_rules"))
            enabled_tracking_rules = [dict(rule) for rule in tracking_rules if bool(rule.get("enabled"))] or [dict(tracking_rules[0])]
            settings["general"]["tracking_rules"] = tracking_rules
            settings["general"]["enabled_tracking_rules"] = enabled_tracking_rules
            settings["general"]["min_offline_value"] = int(enabled_tracking_rules[0].get("value", 1) or 0)
            settings["general"]["min_offline_unit"] = (enabled_tracking_rules[0].get("unit") or "day").strip().lower()
            settings["general"]["tracking_rules_summary"] = offline_rules_summary_text(
                tracking_rules,
                fallback_value=settings["general"]["min_offline_value"],
                fallback_unit=settings["general"]["min_offline_unit"],
            )
            settings["general"]["history_retention_days"] = parse_int(
                form,
                "history_retention_days",
                int(settings["general"].get("history_retention_days", OFFLINE_DEFAULTS["general"]["history_retention_days"])),
            )
        elif settings_tab == "routers":
            wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
            system_routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
            count = parse_int(form, "router_count", len(system_routers))
            enabled_map = {}
            for idx in range(count):
                router_id = (form.get(f"router_{idx}_id") or "").strip()
                if not router_id:
                    continue
                enabled_map[router_id] = parse_bool(form, f"router_{idx}_enabled")
            settings["mikrotik"]["router_enabled"] = enabled_map
        elif settings_tab == "radius":
            settings["radius"]["enabled"] = parse_bool(form, "radius_enabled")
            ssh = settings["radius"]["ssh"]
            ssh["host"] = (form.get("radius_host") or "").strip()
            ssh["port"] = parse_int(form, "radius_port", int(ssh.get("port", 22) or 22))
            ssh["user"] = (form.get("radius_user") or "").strip()
            ssh["password"] = (form.get("radius_password") or "").strip()
            ssh["use_key"] = parse_bool(form, "radius_use_key")
            ssh["key_path"] = (form.get("radius_key_path") or "").strip()
            settings["radius"]["list_command"] = (form.get("radius_list_command") or "").strip()
        else:
            pass
        save_settings("offline", settings)
    except Exception:
        # avoid leaking secrets in messages; just fall through to redirect.
        save_settings("offline", settings)

    return RedirectResponse(
        url=f"/settings/offline?tab=settings&settings_tab={settings_tab}"
        + (f"&radius_tab={radius_tab}" if settings_tab == "radius" else "")
        + f"#offline-{settings_tab}",
        status_code=302,
    )


@app.post("/settings/offline/test-radius", response_class=HTMLResponse)
async def offline_test_radius(request: Request):
    settings = normalize_offline_settings(get_settings("offline", OFFLINE_DEFAULTS))
    message = ""
    try:
        from .notifiers import offline as offline_notifier

        accounts = offline_notifier.fetch_radius_accounts(settings.get("radius") or {})
        message = f"Radius OK: {len(accounts)} accounts returned."
    except Exception as exc:
        message = f"Radius test failed: {exc}"
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    state = get_state("offline_state", {})
    offline_state = {
        "last_check": format_ts_ph(state.get("last_check_at")),
        "router_errors": state.get("router_errors") if isinstance(state.get("router_errors"), list) else [],
        "radius_error": (state.get("radius_error") or "").strip(),
    }
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    offline_rule_views = _build_offline_rule_views(state, settings)
    return templates.TemplateResponse(
        "settings_offline.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": "radius",
                "radius_tab": "settings",
                "offline_job": {"last_run_at_ph": "n/a", "last_success_at_ph": "n/a", "last_error": "", "last_error_at_ph": ""},
                "offline_state": offline_state,
                "offline_router_state": router_state_map,
                "offline_rule_tabs": offline_rule_views.get("rules") if isinstance(offline_rule_views.get("rules"), list) else [],
                "offline_new_view_seconds": _OFFLINE_NEW_VIEW_SECONDS,
                "wan_settings": wan_settings,
            },
        ),
    )


@app.post("/settings/offline/format", response_class=HTMLResponse)
async def offline_settings_format(request: Request):
    return _render_system_danger_notice(request, "offline")


def _profile_query_matches(query, *values):
    needle = (query or "").strip().lower()
    if not needle:
        return False
    for value in values:
        text = str(value or "").strip().lower()
        if text and needle in text:
            return True
    return False


def _profile_status_rank(status):
    value = (status or "").strip().lower()
    if value in ("down", "issue"):
        return 5
    if value == "monitor":
        return 4
    if value == "tracking":
        return 3
    if value == "pending":
        return 2
    if value in ("stable", "up"):
        return 1
    return 0


def _profile_merge_search_status(item, status):
    status = (status or "").strip().lower()
    if not status:
        return
    meta = item.setdefault("meta", {})
    current = (meta.get("status") or "").strip().lower()
    if _profile_status_rank(status) >= _profile_status_rank(current):
        meta["status"] = status


def _profile_merge_search_item(
    merged,
    key,
    *,
    name="",
    pppoe="",
    ip="",
    device_id="",
    router_id="",
    router_name="",
    source="",
    last_seen="",
    status="",
):
    key = (key or "").strip()
    if not key:
        return
    row = merged.setdefault(
        key,
        {
            "name": (name or "").strip(),
            "pppoe": (pppoe or "").strip(),
            "ip": (ip or "").strip(),
            "device_id": (device_id or "").strip(),
            "router_id": (router_id or "").strip(),
            "router_name": (router_name or "").strip(),
            "sources": set(),
            "last_seen": (last_seen or "").strip(),
            "meta": {},
        },
    )
    if source:
        row["sources"].add(source)
    if name and (not row.get("name") or row.get("name") in {row.get("ip"), row.get("device_id")}):
        row["name"] = name
    if pppoe and not row.get("pppoe"):
        row["pppoe"] = pppoe
    if ip and not row.get("ip"):
        row["ip"] = ip
    if device_id and not row.get("device_id"):
        row["device_id"] = device_id
    if router_id and not row.get("router_id"):
        row["router_id"] = router_id
    if router_name and not row.get("router_name"):
        row["router_name"] = router_name
    if last_seen and last_seen > (row.get("last_seen") or ""):
        row["last_seen"] = last_seen
    _profile_merge_search_status(row, status)


def _profile_search_item_target_key(item):
    row = item if isinstance(item, dict) else {}
    router_id = (row.get("router_id") or "").strip().lower()
    pppoe = (row.get("pppoe") or "").strip().lower()
    if pppoe:
        return f"ppp:{pppoe}|router:{router_id}" if router_id else f"ppp:{pppoe}"
    ip = (row.get("ip") or "").strip()
    if ip:
        return f"ip:{ip}|router:{router_id}" if router_id else f"ip:{ip}"
    device_id = (row.get("device_id") or "").strip().lower()
    if device_id:
        return f"dev:{device_id}"
    name = (row.get("name") or "").strip().lower()
    if name:
        return f"name:{name}"
    return ""


def _profile_search_item_href(item):
    row = item if isinstance(item, dict) else {}
    params = []
    pppoe = (row.get("pppoe") or "").strip()
    ip = (row.get("ip") or "").strip()
    device_id = (row.get("device_id") or "").strip()
    router_id = (row.get("router_id") or "").strip()
    if pppoe:
        params.append(("pppoe", pppoe))
    if ip:
        params.append(("ip", ip))
    if device_id:
        params.append(("device_id", device_id))
    if router_id:
        params.append(("router_id", router_id))
    query = urllib.parse.urlencode(params)
    return f"/profile-review?{query}" if query else "/profile-review"


def _profile_highlight_markup(value, query):
    text = str(value or "").strip()
    if not text:
        return Markup("")
    needle = (query or "").strip()
    if not needle:
        return escape(text)
    parts = []
    last = 0
    for match in re.finditer(re.escape(needle), text, flags=re.IGNORECASE):
        start = match.start()
        end = match.end()
        if start > last:
            parts.append(escape(text[last:start]))
        parts.append(Markup("<mark>"))
        parts.append(escape(text[start:end]))
        parts.append(Markup("</mark>"))
        last = end
    if not parts:
        return escape(text)
    if last < len(text):
        parts.append(escape(text[last:]))
    return Markup("").join(parts)


def _profile_render_search_results(items, query):
    rendered = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row["href"] = _profile_search_item_href(row)
        row["highlight_name"] = _profile_highlight_markup(row.get("name") or row.get("pppoe") or row.get("ip") or "Customer", query)
        row["highlight_pppoe"] = _profile_highlight_markup(row.get("pppoe"), query)
        row["highlight_ip"] = _profile_highlight_markup(row.get("ip"), query)
        row["highlight_device_id"] = _profile_highlight_markup(row.get("device_id"), query)
        row["highlight_router_name"] = _profile_highlight_markup(row.get("router_name"), query)
        last_seen = (row.get("last_seen") or "").strip()
        row["last_seen_label"] = format_ts_ph(last_seen) if last_seen else ""
        rendered.append(row)
    return rendered


def _empty_profile_review_profile(window_hours, window_label):
    return {
        "window_hours": int(window_hours or 24),
        "window_label": window_label or "1D",
        "ip": "",
        "device_id": "",
        "device_url": "",
        "name": "",
        "pppoe": "",
        "sources": [],
        "accounts_ping": None,
        "optical": None,
        "usage": None,
        "surveillance": None,
        "offline": None,
        "status_cards": [],
        "overview": {},
        "kpis": [],
        "testing_focus": [],
        "account_details": [],
        "classification": {
            "tx_realistic_min_dbm": float(OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]),
            "tx_realistic_max_dbm": float(OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]),
        },
    }


def _profile_search_items(query, limit=12):
    query = (query or "").strip()
    if len(query) < 2:
        return []
    limit = max(min(int(limit or 12), 250), 1)
    since_iso = (datetime.utcnow() - timedelta(days=120)).replace(microsecond=0).isoformat() + "Z"

    optical_state = _optical_state_snapshot()
    current_optical_device_ids = _optical_current_device_ids(optical_state)
    known_optical_account_map = _optical_known_account_map(optical_state)
    current_optical_pppoe_keys = _optical_current_pppoe_keys(optical_state)
    optical_hits = search_optical_customers(query, since_iso, limit=max(limit * 4, 40))
    if known_optical_account_map:
        known_pppoe_keys = set(known_optical_account_map.keys())
        optical_hits = [
            row
            for row in optical_hits
            if isinstance(row, dict)
            and (
                ((row.get("pppoe") or "").strip().lower() in known_pppoe_keys)
                or (
                    not (row.get("pppoe") or "").strip()
                    and (row.get("device_id") or "").strip() in current_optical_device_ids
                )
            )
        ]
    elif current_optical_device_ids:
        optical_hits = [
            row
            for row in optical_hits
            if isinstance(row, dict) and (row.get("device_id") or "").strip() in current_optical_device_ids
        ]
    elif current_optical_pppoe_keys:
        optical_hits = [
            row
            for row in optical_hits
            if isinstance(row, dict) and (row.get("pppoe") or "").strip().lower() in current_optical_pppoe_keys
        ]
    optical_settings = get_settings("optical", OPTICAL_DEFAULTS)
    accounts_ping_settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    usage_settings = get_settings("usage", USAGE_DEFAULTS)
    ping_state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
    devices = _accounts_ping_state_devices(ping_state)
    state_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}
    usage_state = get_state("usage_state", {})
    usage_rows = usage_state.get("active_rows") if isinstance(usage_state.get("active_rows"), list) else []
    usage_hosts = usage_state.get("pppoe_hosts") if isinstance(usage_state.get("pppoe_hosts"), dict) else {}
    usage_anytime_issues = usage_state.get("anytime_issues") if isinstance(usage_state.get("anytime_issues"), dict) else {}
    offline_state = get_state("offline_state", {})
    offline_current_map = _profile_collect_offline_current_map(offline_state)
    surveillance_settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    surveillance_entries = _surveillance_entry_map(surveillance_settings)

    optical_class = optical_settings.get("classification", {}) or {}
    issue_rx = float(optical_class.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]))
    issue_tx = float(optical_class.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]))
    stable_rx = float(optical_class.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]))
    stable_tx = float(optical_class.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]))
    rx_realistic_min = float(optical_class.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]))
    rx_realistic_max = float(optical_class.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]))
    tx_realistic_min = float(optical_class.get("tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]))
    tx_realistic_max = float(optical_class.get("tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]))

    ping_class = _accounts_ping_applied_classification(accounts_ping_settings)
    issue_loss_pct = float(ping_class.get("issue_loss_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_loss_pct"]) or 20.0)
    issue_latency_ms = float(ping_class.get("issue_latency_ms", ACCOUNTS_PING_DEFAULTS["classification"]["issue_latency_ms"]) or 200.0)
    stable_fail_pct = float(ping_class.get("stable_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["stable_rto_pct"]) or 2.0)
    issue_fail_pct = float(ping_class.get("issue_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_rto_pct"]) or 5.0)

    merged = {}
    for row in optical_hits:
        ip = (row.get("ip") or "").strip()
        pppoe = (row.get("pppoe") or "").strip()
        current_optical_entry = _optical_current_device_entry(
            device_id=(row.get("device_id") or "").strip(),
            pppoe=pppoe,
            state=optical_state,
        )
        known_optical_entry = _optical_known_account_entry(pppoe=pppoe, state=optical_state)
        optical_router_id = (
            (current_optical_entry.get("router_id") or "").strip()
            or (known_optical_entry.get("router_id") or "").strip()
        )
        optical_router_name = (
            (current_optical_entry.get("router_name") or "").strip()
            or (known_optical_entry.get("router_name") or "").strip()
            or optical_router_id
        )
        key = (
            f"ppp:{pppoe}|{optical_router_id}"
            if pppoe and optical_router_id
            else (f"ppp:{pppoe}" if pppoe else (f"ip:{ip}" if ip else f"dev:{row.get('device_id')}"))
        )
        rx = row.get("rx")
        tx = row.get("tx")
        optical_status = "stable"
        rx_invalid = rx is None or rx < rx_realistic_min or rx > rx_realistic_max
        tx_missing = tx is None
        tx_unrealistic = (tx is not None) and (tx < tx_realistic_min or tx > tx_realistic_max)
        if rx_invalid:
            optical_status = "issue"
        elif tx_missing or tx_unrealistic:
            optical_status = "monitor"
        elif (rx is not None and rx <= issue_rx) or (tx is not None and tx <= issue_tx):
            optical_status = "issue"
        elif not (rx is not None and rx >= stable_rx and tx is not None and tx >= stable_tx):
            optical_status = "monitor"
        _profile_merge_search_item(
            merged,
            key,
            name=pppoe,
            pppoe=pppoe,
            ip=ip,
            device_id=(row.get("device_id") or "").strip(),
            router_id=optical_router_id,
            router_name=optical_router_name,
            source="optical",
            last_seen=(row.get("timestamp") or "").strip(),
            status=optical_status,
        )

    matching_devices = []
    matching_account_ids = []
    seen_account_ids = set()
    for dev in devices:
        ip = (dev.get("ip") or "").strip()
        if not ip:
            continue
        pppoe = (dev.get("pppoe") or dev.get("name") or "").strip() or ip
        router_name = (dev.get("router_name") or "").strip()
        if not _profile_query_matches(query, pppoe, ip, router_name):
            continue
        matching_devices.append(dev)
        aid = (dev.get("account_id") or "").strip() or _accounts_ping_account_id_for_device(dev)
        if aid and aid not in seen_account_ids:
            seen_account_ids.add(aid)
            matching_account_ids.append(aid)
    ping_stats_map = get_accounts_ping_window_stats(matching_account_ids, since_iso) if matching_account_ids else {}

    for dev in matching_devices:
        ip = (dev.get("ip") or "").strip()
        pppoe = (dev.get("pppoe") or dev.get("name") or "").strip() or ip
        router_name = (dev.get("router_name") or "").strip()
        aid = (dev.get("account_id") or "").strip() or _accounts_ping_account_id_for_device(dev)
        st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
        last_seen = (st.get("last_check_at") or "").strip()
        key = f"ppp:{pppoe}|{(dev.get('router_id') or '').strip()}"
        status = "pending"
        if last_seen:
            if not bool(st.get("last_ok")):
                status = "down"
            else:
                last_loss = st.get("last_loss")
                last_avg_ms = st.get("last_avg_ms")
                fail_pct = 0.0
                stats = (ping_stats_map.get(aid) or {}) if aid else {}
                total = int(stats.get("total") or 0)
                failures = int(stats.get("failures") or 0)
                if total:
                    fail_pct = (failures / total) * 100.0
                issue_hit = False
                if last_loss is not None and float(last_loss) >= issue_loss_pct:
                    issue_hit = True
                if last_avg_ms is not None and float(last_avg_ms) >= issue_latency_ms:
                    issue_hit = True
                if total and fail_pct >= issue_fail_pct:
                    issue_hit = True
                if total and fail_pct > stable_fail_pct:
                    issue_hit = True
                status = "monitor" if issue_hit else "stable"
        _profile_merge_search_item(
            merged,
            key,
            name=pppoe,
            pppoe=pppoe,
            ip=ip,
            router_id=(dev.get("router_id") or "").strip(),
            router_name=router_name,
            source="accounts_ping",
            last_seen=last_seen,
            status=status,
        )

    usage_detect = usage_settings.get("detection") if isinstance(usage_settings.get("detection"), dict) else {}
    usage_peak_issues = usage_state.get("peak_issues") if isinstance(usage_state.get("peak_issues"), dict) else {}
    for row in usage_rows:
        if not isinstance(row, dict):
            continue
        pppoe = (row.get("pppoe") or row.get("name") or "").strip()
        address = (row.get("address") or "").strip()
        router_name = (row.get("router_name") or row.get("router_id") or "").strip()
        if not _profile_query_matches(query, pppoe, address, router_name):
            continue
        pppoe_key = pppoe.lower()
        host_info = usage_hosts.get(pppoe) or usage_hosts.get(pppoe_key) or {}
        router_id = (row.get("router_id") or "").strip()
        peak_issue = bool(usage_peak_issues.get(f"{router_id}|{pppoe_key}"))
        anytime_issue = bool(usage_anytime_issues.get(f"{router_id}|{pppoe_key}"))
        _profile_merge_search_item(
            merged,
            f"ppp:{pppoe}|{router_id or 'none'}",
            name=pppoe,
            pppoe=pppoe,
            ip=address,
            router_id=router_id,
            router_name=router_name,
            source="usage",
            last_seen=(row.get("timestamp") or "").strip(),
            status="monitor" if (peak_issue or anytime_issue) else "stable",
        )

    for row in offline_current_map.values():
        if not isinstance(row, dict):
            continue
        if not _profile_query_matches(
            query,
            row.get("pppoe"),
            row.get("router_name"),
            row.get("service_profile"),
            row.get("radius_status"),
        ):
            continue
        _profile_merge_search_item(
            merged,
            (
                f"ppp:{(row.get('pppoe') or '').strip()}|{(row.get('router_id') or '').strip()}"
                if (row.get("router_id") or "").strip()
                else f"ppp:{(row.get('pppoe') or '').strip()}"
            ),
            name=(row.get("pppoe") or "").strip(),
            pppoe=(row.get("pppoe") or "").strip(),
            router_id=(row.get("router_id") or "").strip(),
            router_name=(row.get("router_name") or "").strip(),
            source="offline",
            last_seen=(row.get("last_offline_at_iso") or row.get("offline_since_iso") or "").strip(),
            status="down" if row.get("listed") else "tracking",
        )

    for entry in surveillance_entries.values():
        if not isinstance(entry, dict):
            continue
        pppoe = (entry.get("pppoe") or "").strip()
        ip = (entry.get("ip") or "").strip()
        name = (entry.get("name") or pppoe).strip()
        if not _profile_query_matches(query, pppoe, ip, name):
            continue
        surv_status = _resolve_surveillance_ai_stage(entry)
        _profile_merge_search_item(
            merged,
            f"ppp:{pppoe}",
            name=name,
            pppoe=pppoe,
            ip=ip,
            source="surveillance",
            last_seen=(entry.get("updated_at") or entry.get("added_at") or "").strip(),
            status="issue" if surv_status == "level2" else "monitor",
        )

    items = []
    for value in merged.values():
        sources = sorted(value["sources"])
        items.append(
            {
                "name": value.get("name") or value.get("ip") or value.get("device_id") or "Customer",
                "pppoe": value.get("pppoe") or "",
                "ip": value.get("ip") or "",
                "device_id": value.get("device_id") or "",
                "router_id": value.get("router_id") or "",
                "router_name": value.get("router_name") or "",
                "sources": sources,
                "last_seen": value.get("last_seen") or "",
                "meta": value.get("meta") or {},
            }
        )
    items.sort(
        key=lambda x: (
            _profile_status_rank((x.get("meta") or {}).get("status")),
            x.get("last_seen") or "",
            str(x.get("name") or "").lower(),
        ),
        reverse=True,
    )
    return items[:limit]


def _profile_collect_offline_current_map(offline_state):
    state = offline_state if isinstance(offline_state, dict) else {}
    tracker = state.get("tracker") if isinstance(state.get("tracker"), dict) else {}
    current_rows = state.get("rows") if isinstance(state.get("rows"), list) else []
    merged = {}

    def _merge_candidate(candidate):
        if not isinstance(candidate, dict):
            return
        pppoe = (candidate.get("pppoe") or "").strip()
        if not pppoe:
            return
        key = pppoe.lower()
        row = {
            "pppoe": pppoe,
            "router_id": (candidate.get("router_id") or "").strip(),
            "router_name": (candidate.get("router_name") or candidate.get("router_id") or "").strip(),
            "mode": (candidate.get("mode") or state.get("mode") or "").strip() or "secrets",
            "service_profile": (candidate.get("profile") or "").strip(),
            "disabled": bool(candidate.get("disabled")) if candidate.get("disabled") is not None else None,
            "last_logged_out": (candidate.get("last_logged_out") or "").strip(),
            "radius_status": (candidate.get("radius_status") or "").strip(),
            "offline_since_iso": (candidate.get("offline_since") or "").strip(),
            "last_offline_at_iso": (candidate.get("last_offline_at") or "").strip(),
            "listed": bool(candidate.get("listed")),
            "status": "offline" if bool(candidate.get("listed")) else "tracking",
        }
        existing = merged.get(key)
        if not existing:
            merged[key] = row
            return
        existing_score = (
            1 if existing.get("listed") else 0,
            existing.get("offline_since_iso") or "",
            existing.get("last_offline_at_iso") or "",
        )
        row_score = (
            1 if row.get("listed") else 0,
            row.get("offline_since_iso") or "",
            row.get("last_offline_at_iso") or "",
        )
        if row_score > existing_score:
            merged[key] = row
            return
        for field in (
            "router_id",
            "router_name",
            "mode",
            "service_profile",
            "last_logged_out",
            "radius_status",
            "offline_since_iso",
            "last_offline_at_iso",
        ):
            if row.get(field) and not existing.get(field):
                existing[field] = row.get(field)
        if existing.get("disabled") is None and row.get("disabled") is not None:
            existing["disabled"] = row.get("disabled")
        if row.get("listed"):
            existing["listed"] = True
            existing["status"] = "offline"

    for item in tracker.values():
        if not isinstance(item, dict):
            continue
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        _merge_candidate(
            {
                **meta,
                "mode": item.get("mode") or state.get("mode") or "",
                "offline_since": item.get("first_offline_at"),
                "last_offline_at": item.get("last_offline_at"),
                "listed": bool(item.get("listed")),
            }
        )

    for row in current_rows:
        if not isinstance(row, dict):
            continue
        _merge_candidate({**row, "listed": True})

    return merged


def _profile_find_surveillance_entry(entry_map, pppoe="", ip=""):
    entries = entry_map if isinstance(entry_map, dict) else {}
    pppoe_key = (pppoe or "").strip().lower()
    if pppoe_key:
        for key, entry in entries.items():
            if (key or "").strip().lower() == pppoe_key and isinstance(entry, dict):
                return entry
    ip_value = (ip or "").strip()
    if ip_value:
        for entry in entries.values():
            if not isinstance(entry, dict):
                continue
            if (entry.get("ip") or "").strip() == ip_value:
                return entry
    return None


def _build_profile_review_summary(profile):
    surveillance = profile.get("surveillance") if isinstance(profile.get("surveillance"), dict) else {}
    offline = profile.get("offline") if isinstance(profile.get("offline"), dict) else {}
    accounts_ping = profile.get("accounts_ping") if isinstance(profile.get("accounts_ping"), dict) else {}
    optical = profile.get("optical") if isinstance(profile.get("optical"), dict) else {}
    usage = profile.get("usage") if isinstance(profile.get("usage"), dict) else {}

    module_kpis = []
    severities = []

    def _track(severity):
        if severity is None:
            return
        severities.append(int(severity))

    surv_severity = None
    surv_value = "Not Tagged"
    surv_hint = "No active surveillance entry."
    surv_tone = "secondary"
    if surveillance.get("active"):
        if surveillance.get("status") == "level2":
            surv_severity = 2
            surv_value = "Needs Manual Fix"
            surv_hint = surveillance.get("since_label") or "Escalated for manual fix."
            surv_tone = "red"
        else:
            surv_severity = 1
            surv_value = "Under Watch"
            surv_hint = surveillance.get("since_label") or "Already tagged for observation."
            surv_tone = "yellow"
    elif surveillance.get("last_outcome_label"):
        surv_severity = 0
        surv_value = surveillance.get("last_outcome_label")
        surv_hint = surveillance.get("last_outcome_hint") or "Latest surveillance cycle is closed."
        surv_tone = "green"
    _track(surv_severity)
    module_kpis.append(
        {
            "title": "Surveillance",
            "value": surv_value,
            "hint": surv_hint,
            "tone": surv_tone,
            "icon": "ti ti-eye",
        }
    )

    offline_severity = None
    offline_value = "No hit"
    offline_hint = "No offline activity found."
    offline_tone = "secondary"
    if offline:
        if offline.get("current"):
            if offline.get("status") == "tracking":
                offline_severity = 1
                offline_value = f"Tracking {offline.get('offline_for') or ''}".strip()
                offline_hint = offline.get("status_hint") or "Below offline threshold."
                offline_tone = "yellow"
            else:
                offline_severity = 2
                offline_value = f"Offline {offline.get('offline_for') or ''}".strip()
                offline_hint = offline.get("status_hint") or "Currently listed as offline."
                offline_tone = "red"
        elif offline.get("last_restored_at"):
            offline_severity = 0
            offline_value = "Online"
            offline_hint = offline.get("status_hint") or "Last restored event is recorded."
            offline_tone = "green"
        elif not offline.get("enabled", True):
            offline_value = "Disabled"
            offline_hint = "Offline collector is disabled."
            offline_tone = "secondary"
    _track(offline_severity)
    module_kpis.append(
        {
            "title": "Offline",
            "value": offline_value or "Offline",
            "hint": offline_hint,
            "tone": offline_tone,
            "icon": "ti ti-user-off",
        }
    )

    acc_severity = None
    acc_value = "No data"
    acc_hint = "No ACC-Ping data in this window."
    acc_tone = "secondary"
    if accounts_ping:
        acc_status = (accounts_ping.get("status") or "").strip().lower()
        if acc_status == "down":
            acc_severity = 2
            acc_tone = "red"
        elif acc_status == "monitor":
            acc_severity = 1
            acc_tone = "yellow"
        elif acc_status == "stable":
            acc_severity = 0
            acc_tone = "green"
        acc_value = (
            f"{float(accounts_ping.get('uptime_pct') or 0.0):.1f}%"
            if acc_status in ("down", "monitor", "stable")
            else "Pending"
        )
        loss_text = (
            f"{float(accounts_ping.get('loss_avg')):.1f}% loss"
            if accounts_ping.get("loss_avg") is not None
            else "loss n/a"
        )
        lat_text = (
            f"{float(accounts_ping.get('avg_ms_avg')):.1f}ms"
            if accounts_ping.get("avg_ms_avg") is not None
            else "latency n/a"
        )
        acc_hint = f"{loss_text} · {lat_text}"
    _track(acc_severity)
    module_kpis.append(
        {
            "title": "ACC-Ping",
            "value": acc_value,
            "hint": acc_hint,
            "tone": acc_tone,
            "icon": "ti ti-wifi",
        }
    )

    opt_severity = None
    opt_value = "No data"
    opt_hint = "No optical readings found."
    opt_tone = "secondary"
    if optical:
        if not optical.get("current_available", True):
            opt_value = "No current result"
            opt_hint = "TR-069 is currently offline for this account. Historical optical data remains available."
        else:
            opt_status = (optical.get("status") or "").strip().lower()
            if opt_status == "issue":
                opt_severity = 2
                opt_tone = "red"
            elif opt_status == "monitor":
                opt_severity = 1
                opt_tone = "yellow"
            elif opt_status == "stable":
                opt_severity = 0
                opt_tone = "green"
            rx_value = optical.get("rx")
            opt_value = f"{float(rx_value):.2f} dBm" if rx_value is not None else "RX n/a"
            if optical.get("tx_missing"):
                tx_text = "TX missing"
            elif optical.get("tx") is None:
                tx_text = "TX n/a"
            elif optical.get("tx_unrealistic"):
                tx_text = f"TX {float(optical.get('tx')):.2f} dBm (unrealistic)"
            else:
                tx_text = f"TX {float(optical.get('tx')):.2f} dBm"
            opt_hint = tx_text
    _track(opt_severity)
    module_kpis.append(
        {
            "title": "Optical",
            "value": opt_value,
            "hint": opt_hint,
            "tone": opt_tone,
            "icon": "ti ti-sun",
        }
    )

    usage_severity = None
    usage_value = "No session"
    usage_hint = "No live PPPoE session detected."
    usage_tone = "secondary"
    if usage:
        if not usage.get("enabled"):
            usage_value = "Disabled"
            usage_hint = "Usage collector is disabled."
        elif usage.get("active"):
            total_bps = float(usage.get("dl_bps") or 0.0) + float(usage.get("ul_bps") or 0.0)
            usage_value = format_bps(total_bps) if total_bps > 0 else "Idle"
            usage_hint = f"{int(usage.get('devices') or 0)} device(s) · {usage.get('router_name') or 'Router n/a'}"
            if usage.get("issue"):
                usage_severity = 1
                usage_tone = "yellow"
            else:
                usage_severity = 0
                usage_tone = "green"
        elif usage.get("enabled"):
            usage_hint = "Account is not active in live session polling."
    _track(usage_severity)
    module_kpis.append(
        {
            "title": "Usage",
            "value": usage_value,
            "hint": usage_hint,
            "tone": usage_tone,
            "icon": "ti ti-chart-bar",
        }
    )

    tracked_signals = len(severities)
    issue_count = sum(1 for severity in severities if severity > 0)
    healthy_count = sum(1 for severity in severities if severity == 0)

    if any(severity >= 2 for severity in severities):
        overall_state = "critical"
        overall_label = "Critical"
        overall_tone = "red"
    elif any(severity == 1 for severity in severities):
        overall_state = "monitor"
        overall_label = "Monitor"
        overall_tone = "yellow"
    elif tracked_signals:
        overall_state = "stable"
        overall_label = "Stable"
        overall_tone = "green"
    else:
        overall_state = "unknown"
        overall_label = "Limited Data"
        overall_tone = "secondary"

    if tracked_signals:
        overall_summary = f"{issue_count} of {tracked_signals} tracked checks need attention."
    else:
        overall_summary = "Only partial account identity is available from the current search."

    if surveillance.get("active") and surveillance.get("status") == "level2":
        recommendation = "Account is already in Needs Manual Fix. Continue manual-fix validation before closing."
    elif surveillance.get("active"):
        recommendation = "Account is already under surveillance. Use the KPIs below to validate recovery or escalation."
    elif overall_state == "critical":
        recommendation = "This account should be tagged for Under Surveillance before or during testing."
    elif overall_state == "monitor":
        recommendation = "Review the flagged signals first. Tag the account if the condition persists across checks."
    elif overall_state == "stable":
        recommendation = "Current signals look stable in the selected window."
    else:
        recommendation = "Search results are incomplete. Extend the window or confirm the exact PPPoE/IP/device ID."

    focus_points = []
    if surveillance.get("active") and surveillance.get("status") == "level2":
        focus_points.append("Needs Manual Fix workflow is active, so this account already needs manual-fix follow-up.")
    elif surveillance.get("active"):
        focus_points.append("The account is already tagged under surveillance; compare all telemetry before clearing it.")
    elif profile.get("pppoe") and overall_state in ("critical", "monitor"):
        focus_points.append("Telemetry shows this account is a good candidate for Under Surveillance.")
    if offline.get("current"):
        focus_points.append("Check PPPoE active state, secret status, and the last logout record because the account is currently offline.")
    if (accounts_ping.get("status") or "").strip().lower() == "down":
        focus_points.append("ACC-Ping is failing now. Validate reachability from the latest matched IP before closing the case.")
    elif (accounts_ping.get("status") or "").strip().lower() == "monitor":
        focus_points.append("ACC-Ping has elevated loss or latency. Re-run path testing and compare against the selected window.")
    if (optical.get("status") or "").strip().lower() == "issue":
        focus_points.append("Optical power is outside the issue threshold. Confirm RX/TX levels before blaming the IP layer.")
    elif (optical.get("status") or "").strip().lower() == "monitor":
        focus_points.append("Optical readings are borderline. Check the trend and the latest sample before escalation.")
    if usage.get("issue"):
        focus_points.append("Usage detection flagged low or no traffic with connected devices. Validate customer activity against device count.")
    if not focus_points:
        focus_points.append("No active alarms are visible right now. Use a longer window to review earlier instability if needed.")

    kpis = [
        {
            "title": "Overall Posture",
            "value": overall_label,
            "hint": overall_summary,
            "tone": overall_tone,
            "icon": "ti ti-activity-heartbeat",
        },
        {
            "title": "Signal Health",
            "value": f"{healthy_count}/{tracked_signals}" if tracked_signals else "n/a",
            "hint": f"{issue_count} issue(s) across the tracked modules." if tracked_signals else "No scored telemetry yet.",
            "tone": overall_tone if tracked_signals else "secondary",
            "icon": "ti ti-heart-rate-monitor",
        },
    ] + module_kpis

    return {
        "state": overall_state,
        "label": overall_label,
        "tone": overall_tone,
        "summary": overall_summary,
        "recommendation": recommendation,
        "tracked_signals": tracked_signals,
        "issue_count": issue_count,
        "healthy_count": healthy_count,
    }, kpis, focus_points[:5]


def _build_profile_review_status_cards(profile):
    accounts_ping = profile.get("accounts_ping") if isinstance(profile.get("accounts_ping"), dict) else {}
    optical = profile.get("optical") if isinstance(profile.get("optical"), dict) else {}
    offline = profile.get("offline") if isinstance(profile.get("offline"), dict) else {}
    usage = profile.get("usage") if isinstance(profile.get("usage"), dict) else {}

    def _fmt_percent(value):
        if value is None:
            return "n/a"
        try:
            return f"{float(value):.1f}%"
        except Exception:
            return "n/a"

    def _fmt_ms(value):
        if value is None:
            return "n/a"
        try:
            return f"{float(value):.1f} ms"
        except Exception:
            return "n/a"

    def _fmt_dbm(value):
        if value is None:
            return "n/a"
        try:
            return f"{float(value):.2f} dBm"
        except Exception:
            return "n/a"

    cards = []

    acc_status = (accounts_ping.get("status") or "").strip().lower()
    if not accounts_ping:
        acc_value = "No Data"
        acc_tone = "secondary"
        acc_hint = "No ACC-Ping record matched this profile."
    elif acc_status == "down":
        acc_value = "Offline"
        acc_tone = "red"
        acc_hint = f"Last check {accounts_ping.get('last_seen') or 'n/a'}"
    elif acc_status == "pending":
        acc_value = "Pending"
        acc_tone = "secondary"
        acc_hint = f"Last check {accounts_ping.get('last_seen') or 'n/a'}"
    else:
        acc_value = "Online"
        acc_tone = "green" if acc_status == "stable" else "yellow"
        acc_hint = f"{_fmt_percent(accounts_ping.get('uptime_pct'))} uptime"
    acc_tooltip = " · ".join(
        [
            f"Loss { _fmt_percent(accounts_ping.get('loss_avg')) }",
            f"Latency { _fmt_ms(accounts_ping.get('avg_ms_avg')) }",
            f"Last check { accounts_ping.get('last_seen') or 'n/a' }",
        ]
    ) if accounts_ping else "No ACC-Ping history found for this profile."
    cards.append(
        {
            "key": "accounts_ping",
            "title": "ACC-Ping",
            "value": acc_value,
            "tone": acc_tone,
            "icon": "ti ti-wifi",
            "hint": acc_hint,
            "tooltip": acc_tooltip,
        }
    )

    optical_status = (optical.get("status") or "").strip().lower()
    if not optical:
        optical_value = "No Data"
        optical_tone = "secondary"
        optical_hint = "No optical record matched this profile."
        optical_tooltip = "No GenieACS optical history was found for this account."
    elif not optical.get("current_available", True):
        optical_value = "Offline"
        optical_tone = "secondary"
        optical_hint = f"Last optical {optical.get('last_seen') or 'n/a'}"
        optical_tooltip = (
            f"TR-069 is currently offline. Last optical sample {optical.get('last_seen') or 'n/a'}"
            f" · RX {_fmt_dbm(optical.get('rx'))} · TX {_fmt_dbm(optical.get('tx'))}"
        )
    elif optical.get("rx_invalid"):
        optical_value = "ACS-LOS"
        optical_tone = "red"
        optical_hint = f"RX {_fmt_dbm(optical.get('rx'))}"
        optical_tooltip = (
            f"TR-069 is online but RX is missing or unrealistic"
            f" · TX {_fmt_dbm(optical.get('tx'))} · Last check {optical.get('last_seen') or 'n/a'}"
        )
    else:
        optical_value = "Online"
        optical_tone = "green" if optical_status == "stable" else ("red" if optical_status == "issue" else "yellow")
        state_label = "Stable" if optical_status == "stable" else ("Issue" if optical_status == "issue" else "Monitor")
        optical_hint = f"{state_label} · RX {_fmt_dbm(optical.get('rx'))}"
        tx_text = "TX missing" if optical.get("tx_missing") else _fmt_dbm(optical.get("tx"))
        optical_tooltip = f"{state_label} · RX {_fmt_dbm(optical.get('rx'))} · TX {tx_text} · Last check {optical.get('last_seen') or 'n/a'}"
    cards.append(
        {
            "key": "optical",
            "title": "Optical",
            "value": optical_value,
            "tone": optical_tone,
            "icon": "ti ti-sun",
            "hint": optical_hint,
            "tooltip": optical_tooltip,
        }
    )

    if not offline:
        offline_value = "No Data"
        offline_tone = "secondary"
        offline_hint = "No offline tracking record matched this profile."
        offline_tooltip = "No Offline collector record was found for this account."
    elif not offline.get("enabled", True):
        offline_value = "Disabled"
        offline_tone = "secondary"
        offline_hint = "Offline collector is disabled."
        offline_tooltip = "Offline tracking is disabled in Settings."
    elif offline.get("status") == "offline":
        offline_value = "Listed"
        offline_tone = "red"
        offline_hint = f"{offline.get('offline_for') or 'Offline'} · threshold {offline.get('threshold_text') or 'n/a'}"
        offline_tooltip = (
            f"Currently listed in Offline monitoring since {offline.get('offline_since') or 'n/a'}"
            f" · Router {offline.get('router_name') or 'n/a'} · Threshold {offline.get('threshold_text') or 'n/a'}"
        )
    elif offline.get("status") == "tracking":
        offline_value = "Tracking"
        offline_tone = "yellow"
        offline_hint = f"{offline.get('offline_for') or 'Below threshold'} · threshold {offline.get('threshold_text') or 'n/a'}"
        offline_tooltip = (
            f"Seen offline but still below the configured threshold"
            f" · Since {offline.get('offline_since') or 'n/a'} · Threshold {offline.get('threshold_text') or 'n/a'}"
        )
    elif offline.get("status") == "source_missing":
        offline_value = "Source Missing"
        offline_tone = "red"
        offline_hint = offline.get("source_missing_since") or "No longer present in the router source"
        offline_tooltip = offline.get("status_hint") or "This account is no longer present in the current MikroTik router source."
    elif offline.get("status") == "online":
        offline_value = "Online"
        offline_tone = "green"
        offline_hint = f"Threshold {offline.get('threshold_text') or 'n/a'}"
        offline_tooltip = f"Last restored {offline.get('last_restored_at') or 'n/a'} · Last duration {offline.get('last_duration') or 'n/a'}"
    else:
        offline_value = offline.get("status_label") or "No Data"
        offline_tone = "secondary"
        offline_hint = offline.get("status_hint") or "No current offline event."
        offline_tooltip = offline_hint
    cards.append(
        {
            "key": "offline",
            "title": "Offline Tracking",
            "value": offline_value,
            "tone": offline_tone,
            "icon": "ti ti-user-off",
            "hint": offline_hint,
            "tooltip": offline_tooltip,
        }
    )

    if not usage:
        usage_value = "No Data"
        usage_tone = "secondary"
        usage_hint = "No usage record matched this profile."
        usage_tooltip = "No Usage collector record was found for this account."
    elif not usage.get("enabled"):
        usage_value = "Disabled"
        usage_tone = "secondary"
        usage_hint = "Usage collector is disabled."
        usage_tooltip = "Usage monitoring is disabled in Settings."
    elif usage.get("issue"):
        usage_value = "Issue"
        usage_tone = "yellow"
        issue_parts = []
        if usage.get("issue_peak"):
            issue_parts.append("peak-hour low-usage")
        if usage.get("issue_anytime"):
            issue_parts.append("anytime no-usage")
        issue_text = ", ".join(issue_parts) or "usage issue"
        usage_hint = f"{issue_text} · {int(usage.get('devices') or 0)} device(s)"
        usage_tooltip = (
            f"{issue_text} · Router {usage.get('router_name') or 'n/a'}"
            f" · DL {usage.get('dl_bps_fmt') or 'n/a'} · UL {usage.get('ul_bps_fmt') or 'n/a'}"
        )
    elif usage.get("active"):
        usage_value = "Normal"
        usage_tone = "green"
        usage_hint = f"{int(usage.get('devices') or 0)} device(s) · {usage.get('router_name') or 'n/a'}"
        usage_tooltip = (
            f"Router {usage.get('router_name') or 'n/a'}"
            f" · DL {usage.get('dl_bps_fmt') or 'n/a'} · UL {usage.get('ul_bps_fmt') or 'n/a'}"
            f" · Last seen {usage.get('last_seen') or 'n/a'}"
        )
    else:
        usage_value = "No Session"
        usage_tone = "secondary"
        usage_hint = "Account is not active in live usage polling."
        usage_tooltip = "No active PPPoE session is currently visible in the Usage collector."
    cards.append(
        {
            "key": "usage",
            "title": "Usage",
            "value": usage_value,
            "tone": usage_tone,
            "icon": "ti ti-chart-bar",
            "hint": usage_hint,
            "tooltip": usage_tooltip,
        }
    )

    return cards


@app.get("/profile-review/suggest", response_class=JSONResponse)
async def profile_review_suggest(q: str = "", limit: int = 12):
    query = (q or "").strip()
    limit = max(min(int(limit or 12), 25), 1)
    if len(query) < 2:
        since_iso = (datetime.utcnow() - timedelta(hours=24)).replace(microsecond=0).isoformat() + "Z"
        optical_settings = get_settings("optical", OPTICAL_DEFAULTS)
        accounts_ping_settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
        ping_state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
        devices = _accounts_ping_state_devices(ping_state)
        state_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}

        cls = _accounts_ping_applied_classification(accounts_ping_settings)
        issue_loss_pct = float(cls.get("issue_loss_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_loss_pct"]) or 20.0)
        issue_latency_ms = float(cls.get("issue_latency_ms", ACCOUNTS_PING_DEFAULTS["classification"]["issue_latency_ms"]) or 200.0)
        stable_fail_pct = float(cls.get("stable_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["stable_rto_pct"]) or 2.0)
        issue_fail_pct = float(cls.get("issue_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_rto_pct"]) or 5.0)

        rows = []
        account_ids = []
        for dev in devices:
            ip = (dev.get("ip") or "").strip()
            if not ip:
                continue
            pppoe = (dev.get("pppoe") or dev.get("name") or "").strip() or ip
            aid = (dev.get("account_id") or "").strip() or _accounts_ping_account_id_for_device(dev)
            if not aid:
                continue
            rows.append(
                {
                    "pppoe": pppoe,
                    "ip": ip,
                    "account_id": aid,
                    "router_name": (dev.get("router_name") or "").strip(),
                }
            )
            account_ids.append(aid)

        stats_by_ip_map = get_accounts_ping_window_stats_by_ip(account_ids, since_iso) if account_ids else {}

        acc_items = []
        for row in rows:
            aid = row["account_id"]
            st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
            chosen_ip = (st.get("last_ip") or row.get("ip") or "").strip()
            stats = (stats_by_ip_map.get(aid) or {}).get(chosen_ip) or {}
            total = int(stats.get("total") or 0)
            failures = int(stats.get("failures") or 0)
            fail_pct = (failures / total) * 100.0 if total else 0.0
            has_recent = bool((st.get("last_check_at") or "").strip())
            last_ok = bool(st.get("last_ok")) if has_recent else True
            last_loss = st.get("last_loss")
            last_avg_ms = st.get("last_avg_ms")

            status = ""
            if not has_recent:
                status = "pending"
            elif not last_ok:
                status = "down"
            else:
                issue_hit = False
                if last_loss is not None and float(last_loss) >= issue_loss_pct:
                    issue_hit = True
                if last_avg_ms is not None and float(last_avg_ms) >= issue_latency_ms:
                    issue_hit = True
                if total and fail_pct >= issue_fail_pct:
                    issue_hit = True
                if total and fail_pct > stable_fail_pct:
                    issue_hit = True
                status = "monitor" if issue_hit else "stable"

            if status in ("down", "monitor"):
                acc_items.append(
                    {
                        "group": "ACC-Ping",
                        "name": (
                            f"{row.get('pppoe')} ({row.get('router_name')})"
                            if row.get("router_name")
                            else (row.get("pppoe") or chosen_ip)
                        ),
                        "pppoe": row.get("pppoe") or "",
                        "ip": chosen_ip,
                        "device_id": "",
                        "sources": ["accounts_ping"],
                        "last_seen": st.get("last_check_at") or "",
                        "meta": {"status": status, "loss": last_loss, "avg_ms": last_avg_ms, "fail_pct": fail_pct},
                    }
                )

        acc_items.sort(
            key=lambda x: (
                x.get("meta", {}).get("status") != "down",
                -(float(x.get("meta", {}).get("loss") or 0.0)),
                -(float(x.get("meta", {}).get("avg_ms") or 0.0)),
                -(float(x.get("meta", {}).get("fail_pct") or 0.0)),
                str(x.get("name") or "").lower(),
            )
        )
        acc_items = acc_items[:10]

        classification = optical_settings.get("classification", {})
        issue_rx = float(classification.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]))
        issue_tx = float(classification.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]))
        stable_rx = float(classification.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]))
        stable_tx = float(classification.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]))
        rx_realistic_min = float(classification.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]))
        rx_realistic_max = float(classification.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]))
        tx_realistic_min = float(classification.get("tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]))
        tx_realistic_max = float(classification.get("tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]))

        candidates = get_optical_worst_candidates(since_iso, limit=300)
        current_optical_device_ids = _optical_current_device_ids()
        if current_optical_device_ids:
            candidates = [
                row
                for row in candidates
                if isinstance(row, dict) and (row.get("device_id") or "").strip() in current_optical_device_ids
            ]

        def optical_score(row):
            rx = row.get("rx")
            tx = row.get("tx")
            p = 0
            if rx is None or rx < rx_realistic_min or rx > rx_realistic_max:
                p += 1000
            elif rx <= issue_rx:
                p += 600 + int(abs(issue_rx - rx) * 10)
            elif rx < stable_rx:
                p += 300 + int(abs(stable_rx - rx) * 5)
            else:
                p += 50
            if tx is None:
                p += 220
            else:
                if tx < tx_realistic_min or tx > tx_realistic_max:
                    p += 200
                if tx <= issue_tx:
                    p += 180 + int(abs(issue_tx - tx) * 10)
                elif tx < stable_tx:
                    p += 90
            if bool(row.get("priority")):
                p += 80
            return p

        candidates = sorted(candidates, key=optical_score, reverse=True)[:10]
        optical_items = []
        for row in candidates:
            ip = (row.get("ip") or "").strip()
            device_id = (row.get("device_id") or "").strip()
            rx = row.get("rx")
            tx = row.get("tx")
            rx_invalid = rx is None or rx < rx_realistic_min or rx > rx_realistic_max
            tx_missing = tx is None
            tx_unrealistic = (tx is not None) and (tx < tx_realistic_min or tx > tx_realistic_max)
            status = "stable"
            if rx_invalid:
                status = "issue"
            elif tx_missing or tx_unrealistic:
                status = "monitor"
            elif (rx is not None and rx <= issue_rx) or (tx is not None and tx <= issue_tx):
                status = "issue"
            elif not (rx is not None and rx >= stable_rx and tx is not None and tx >= stable_tx):
                status = "monitor"
            optical_items.append(
                {
                    "group": "Optical",
                    "name": (row.get("pppoe") or "").strip() or device_id,
                    "ip": ip,
                    "device_id": device_id,
                    "sources": ["optical"],
                    "last_seen": row.get("timestamp") or "",
                    "meta": {"status": status, "rx": rx, "tx": tx, "tx_missing": tx_missing, "tx_unrealistic": tx_unrealistic},
                }
            )

        return JSONResponse(
            {
                "mode": "top10",
                "header": "TOP10 - Critical Connections (Last 24h)",
                "items": acc_items + optical_items,
            }
        )
    return JSONResponse({"mode": "search", "header": "Results", "items": _profile_search_items(query, limit=limit)})


@app.get("/profile-review", response_class=HTMLResponse)
async def profile_review(request: Request):
    pppoe = (request.query_params.get("pppoe") or "").strip()
    ip = (request.query_params.get("ip") or "").strip()
    device_id = (request.query_params.get("device_id") or "").strip()
    router_id = (request.query_params.get("router_id") or "").strip()
    search_query = (request.query_params.get("q") or "").strip()
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    window_label = next((label for label, hours in WAN_STATUS_WINDOW_OPTIONS if hours == window_hours), "1D")
    optical_state = _optical_state_snapshot()

    if search_query and not any((pppoe, ip, device_id)):
        search_results = []
        search_state = "too_short"
        search_account_count = 0
        if len(search_query) >= 2:
            search_results = _profile_search_items(search_query, limit=200)
            unique_targets = {}
            for item in search_results:
                key = _profile_search_item_target_key(item)
                if key and key not in unique_targets:
                    unique_targets[key] = item
            search_account_count = len(unique_targets)
            if search_account_count == 1 and unique_targets:
                first_item = next(iter(unique_targets.values()))
                return RedirectResponse(_profile_search_item_href(first_item), status_code=303)
            search_state = "results" if search_results else "empty"

        response = templates.TemplateResponse(
            "profile_review.html",
            make_context(
                request,
                {
                    "profile": _empty_profile_review_profile(window_hours, window_label),
                    "search_query": search_query,
                    "search_results": _profile_render_search_results(search_results, search_query),
                    "search_state": search_state,
                    "search_result_count": len(search_results),
                    "search_account_count": search_account_count,
                },
            ),
        )
        response.headers["Cache-Control"] = NO_STORE_HEADERS["Cache-Control"]
        return response

    now_dt = datetime.utcnow().replace(microsecond=0)
    since_iso = (now_dt - timedelta(hours=window_hours)).isoformat() + "Z"
    offline_history_since_iso = (now_dt - timedelta(days=90)).isoformat() + "Z"

    optical_settings = get_settings("optical", OPTICAL_DEFAULTS)
    accounts_ping_settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    usage_settings = get_settings("usage", USAGE_DEFAULTS)
    offline_settings = get_settings("offline", OFFLINE_DEFAULTS)
    surveillance_settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    surveillance_entries = _surveillance_entry_map(surveillance_settings)

    ping_state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
    devices = _accounts_ping_state_devices(ping_state)
    state_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}
    usage_state = get_state("usage_state", {})
    active_rows = usage_state.get("active_rows") if isinstance(usage_state.get("active_rows"), list) else []
    usage_hosts = usage_state.get("pppoe_hosts") if isinstance(usage_state.get("pppoe_hosts"), dict) else {}
    usage_anytime_issues = usage_state.get("anytime_issues") if isinstance(usage_state.get("anytime_issues"), dict) else {}
    offline_state = get_state("offline_state", {})
    offline_current_map = _profile_collect_offline_current_map(offline_state)

    def _usage_active_row_for_pppoe(pppoe_value, router_id_value=""):
        pppoe_key = (pppoe_value or "").strip().lower()
        router_value = (router_id_value or "").strip()
        if not pppoe_key:
            return None
        return next(
            (
                row
                for row in active_rows
                if (
                    (row.get("pppoe") or "").strip().lower() == pppoe_key
                    or (row.get("name") or "").strip().lower() == pppoe_key
                )
                and (not router_value or (row.get("router_id") or "").strip() == router_value)
            ),
            None,
        )

    if pppoe and not device_id:
        try:
            opt_map = get_latest_optical_by_pppoe([pppoe])
            hit = opt_map.get(pppoe) or next(
                (
                    value
                    for key, value in (opt_map or {}).items()
                    if (key or "").strip().lower() == pppoe.lower()
                ),
                {},
            )
            if hit and not device_id:
                device_id = (hit.get("device_id") or "").strip()
            if hit and not ip:
                ip = (hit.get("ip") or "").strip()
        except Exception:
            pass

    if pppoe and not ip:
        account_ids = _accounts_ping_account_ids_for_pppoe_router(pppoe, router_id=router_id, state=ping_state)
        st = _accounts_ping_best_state_entry(account_ids, state_accounts)
        ip = (st.get("last_ip") or "").strip() or ip

    if ip and not device_id:
        device_id = get_latest_optical_device_for_ip(ip) or ""
    optical_ident = get_latest_optical_identity(device_id) if device_id else None
    if optical_ident and not ip:
        ip = (optical_ident.get("ip") or "").strip()
    if optical_ident:
        optical_pppoe = (optical_ident.get("pppoe") or "").strip()
        if optical_pppoe and not pppoe:
            pppoe = optical_pppoe

    if not pppoe and ip:
        for dev in devices:
            if (dev.get("ip") or "").strip() == ip:
                pppoe = (dev.get("pppoe") or dev.get("name") or "").strip() or pppoe
                if not router_id:
                    router_id = (dev.get("router_id") or "").strip()
                break

    usage_row = _usage_active_row_for_pppoe(pppoe, router_id_value=router_id) if pppoe else None
    if not pppoe and ip:
        usage_row = next(
            (
                row
                for row in active_rows
                if (row.get("address") or "").strip() == ip
                and (not router_id or (row.get("router_id") or "").strip() == router_id)
            ),
            None,
        )
        if usage_row:
            pppoe = (usage_row.get("pppoe") or usage_row.get("name") or "").strip() or pppoe
            router_id = router_id or (usage_row.get("router_id") or "").strip()
    if usage_row and not router_id:
        router_id = (usage_row.get("router_id") or "").strip()
    if usage_row and not ip:
        ip = (usage_row.get("address") or "").strip() or ip

    if ip and not device_id:
        device_id = get_latest_optical_device_for_ip(ip) or ""
    optical_ident = get_latest_optical_identity(device_id) if device_id else None
    if optical_ident and not ip:
        ip = (optical_ident.get("ip") or "").strip()
    if optical_ident:
        optical_pppoe = (optical_ident.get("pppoe") or "").strip()
        if optical_pppoe and not pppoe:
            pppoe = optical_pppoe

    surveillance_entry = _profile_find_surveillance_entry(surveillance_entries, pppoe=pppoe, ip=ip)
    if surveillance_entry:
        if not pppoe:
            pppoe = (surveillance_entry.get("pppoe") or "").strip() or pppoe
        if not ip:
            ip = (surveillance_entry.get("ip") or "").strip() or ip

    if not usage_row and pppoe:
        usage_row = _usage_active_row_for_pppoe(pppoe, router_id_value=router_id)
    if usage_row and not router_id:
        router_id = (usage_row.get("router_id") or "").strip()
    if usage_row and not ip:
        ip = (usage_row.get("address") or "").strip() or ip

    surveillance_session = get_active_surveillance_session(pppoe) if pppoe else None
    if surveillance_session and not ip:
        ip = (surveillance_session.get("last_ip") or "").strip() or ip

    if ip and not device_id:
        device_id = get_latest_optical_device_for_ip(ip) or ""
    if device_id:
        refreshed_optical_ident = get_latest_optical_identity(device_id)
        if refreshed_optical_ident:
            optical_ident = refreshed_optical_ident
            if not ip:
                ip = (optical_ident.get("ip") or "").strip()
            optical_pppoe = (optical_ident.get("pppoe") or "").strip()
            if optical_pppoe and not pppoe:
                pppoe = optical_pppoe

    if not surveillance_entry:
        surveillance_entry = _profile_find_surveillance_entry(surveillance_entries, pppoe=pppoe, ip=ip)
    if not usage_row and pppoe:
        usage_row = _usage_active_row_for_pppoe(pppoe)

    genie_base = ""
    try:
        genie_base = (
            (optical_settings.get("optical", {}) or {}).get("genieacs_base_url")
            or (optical_settings.get("genieacs", {}) or {}).get("base_url")
            or ""
        ).rstrip("/")
    except Exception:
        genie_base = ""

    def genie_device_url(base_url, dev_id):
        if not base_url or not dev_id:
            return ""
        try:
            parsed = urllib.parse.urlparse(base_url)
            scheme = parsed.scheme or "http"
            host = parsed.hostname or parsed.netloc or ""
            device_path = f"/devices/{urllib.parse.quote(str(dev_id))}"
            netloc = f"{host}:3000" if host else ""
            return urllib.parse.urlunparse((scheme, netloc, "/", "", "", f"/{device_path.lstrip('/')}"))
        except Exception:
            return ""

    profile = {
        "window_hours": window_hours,
        "window_label": window_label,
        "ip": ip,
        "device_id": device_id,
        "device_url": genie_device_url(genie_base, device_id) if device_id else "",
        "name": "",
        "pppoe": pppoe,
        "sources": [],
        "accounts_ping": None,
        "optical": None,
        "usage": None,
        "surveillance": None,
        "offline": None,
        "status_cards": [],
        "overview": {},
        "kpis": [],
        "testing_focus": [],
        "account_details": [],
        "classification": {
            "tx_realistic_min_dbm": float(
                optical_settings.get("classification", {}).get(
                    "tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]
                )
            ),
            "tx_realistic_max_dbm": float(
                optical_settings.get("classification", {}).get(
                    "tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]
                )
            ),
        },
    }
    accounts_ping_source_missing = False
    accounts_ping_source_missing_since_iso = ""

    if optical_ident:
        optical_pppoe = (optical_ident.get("pppoe") or "").strip()
        if optical_pppoe and not profile["pppoe"]:
            profile["pppoe"] = optical_pppoe
        profile["name"] = optical_pppoe or profile["name"]
        profile["sources"].append("optical")
        current_optical_entry = _optical_current_device_entry(
            device_id=device_id,
            pppoe=profile["pppoe"] or optical_pppoe,
            state=optical_state,
        )
        current_optical_available = bool(current_optical_entry)
        classification = optical_settings.get("classification", {})
        issue_rx = float(classification.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]))
        issue_tx = float(classification.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]))
        stable_rx = float(classification.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]))
        stable_tx = float(classification.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]))
        rx_realistic_min = float(classification.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]))
        rx_realistic_max = float(classification.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]))
        tx_realistic_min = float(profile["classification"]["tx_realistic_min_dbm"])
        tx_realistic_max = float(profile["classification"]["tx_realistic_max_dbm"])

        rx = optical_ident.get("rx")
        tx = optical_ident.get("tx")
        rx_invalid = rx is None or rx < rx_realistic_min or rx > rx_realistic_max
        tx_missing = tx is None
        tx_unrealistic = (tx is not None) and (tx < tx_realistic_min or tx > tx_realistic_max)
        status = "stable"
        if rx_invalid:
            status = "issue"
        elif tx_missing or tx_unrealistic:
            status = "monitor"
        elif (rx is not None and rx <= issue_rx) or (tx is not None and tx <= issue_tx):
            status = "issue"
        elif not (rx is not None and rx >= stable_rx and tx is not None and tx >= stable_tx):
            status = "monitor"

        recent = get_recent_optical_readings(device_id, since_iso, limit=12)
        profile["optical"] = {
            "name": profile["name"],
            "ip": ip,
            "device_id": device_id,
            "last_seen": format_ts_ph(optical_ident.get("timestamp")),
            "rx": rx,
            "tx": tx,
            "rx_invalid": rx_invalid,
            "tx_missing": tx_missing,
            "tx_unrealistic": tx_unrealistic,
            "status": status,
            "samples": len(recent),
            "recent": [
                {
                    "ts": format_ts_ph(item.get("timestamp")),
                    "rx": item.get("rx"),
                    "tx": item.get("tx"),
                    "priority": bool(item.get("priority")),
                }
                for item in recent
            ],
            "chart": {
                "min_dbm": float(classification.get("chart_min_dbm", OPTICAL_DEFAULTS["classification"]["chart_min_dbm"])),
                "max_dbm": float(classification.get("chart_max_dbm", OPTICAL_DEFAULTS["classification"]["chart_max_dbm"])),
            },
            "current_available": current_optical_available,
            "router_names": list(current_optical_entry.get("router_names") or []),
            "router_label": ", ".join(current_optical_entry.get("router_names") or []),
            "last_inform_at": (current_optical_entry.get("last_inform_at") or "").strip(),
        }

    if profile["pppoe"]:
        cls = _accounts_ping_applied_classification(accounts_ping_settings)
        issue_loss_pct = float(cls.get("issue_loss_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_loss_pct"]) or 20.0)
        issue_latency_ms = float(cls.get("issue_latency_ms", ACCOUNTS_PING_DEFAULTS["classification"]["issue_latency_ms"]) or 200.0)
        stable_fail_pct = float(cls.get("stable_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["stable_rto_pct"]) or 2.0)
        issue_fail_pct = float(cls.get("issue_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_rto_pct"]) or 5.0)

        account_ids = _accounts_ping_account_ids_for_pppoe_router(profile["pppoe"], router_id=router_id, state=ping_state)
        account_id = (
            account_ids[0]
            if account_ids
            else (
                _accounts_ping_account_id_for_pppoe(
                    profile["pppoe"],
                    source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
                    router_id=router_id,
                )
                if router_id
                else _accounts_ping_account_id_for_pppoe(profile["pppoe"])
            )
        )
        st = _accounts_ping_best_state_entry(account_ids, state_accounts)
        has_recent = bool((st.get("last_check_at") or "").strip())
        last_ok = bool(st.get("last_ok")) if has_recent else True
        last_loss = st.get("last_loss")
        last_avg_ms = st.get("last_avg_ms")
        last_seen = format_ts_ph(st.get("last_check_at")) if has_recent else "n/a"

        stats = _accounts_ping_window_stats_aggregate(account_ids, since_iso)
        total = int(stats.get("total") or 0)
        failures = int(stats.get("failures") or 0)
        fail_pct = (failures / total) * 100.0 if total else 0.0
        uptime_pct = (100.0 - fail_pct) if total else 0.0

        status = "pending"
        if has_recent:
            if not last_ok:
                status = "down"
            else:
                issue_hit = False
                if last_loss is not None and float(last_loss) >= issue_loss_pct:
                    issue_hit = True
                if last_avg_ms is not None and float(last_avg_ms) >= issue_latency_ms:
                    issue_hit = True
                if total and fail_pct >= issue_fail_pct:
                    issue_hit = True
                if total and fail_pct > stable_fail_pct:
                    issue_hit = True
                status = "monitor" if issue_hit else "stable"

        latest_row = _accounts_ping_latest_row_for_account_ids(account_ids)
        chosen_ip = (latest_row.get("ip") or "").strip()
        if not chosen_ip:
            chosen_ip = (st.get("last_ip") or profile.get("ip") or "").strip()
        if chosen_ip and not profile.get("ip"):
            profile["ip"] = chosen_ip

        recent_rows = []
        try:
            rows = _accounts_ping_series_rows_for_account_ids(account_ids, since_iso)
            if chosen_ip:
                rows = [row for row in rows if (row.get("ip") or "").strip() == chosen_ip]
            recent_rows = list(reversed(rows))[:12]
        except Exception:
            recent_rows = []

        profile["sources"].append("accounts_ping")
        profile["accounts_ping"] = {
            "account_id": account_id,
            "pppoe": profile["pppoe"],
            "ip": chosen_ip,
            "last_ip": (st.get("last_ip") or "").strip(),
            "last_seen_iso": (st.get("last_check_at") or "").strip(),
            "last_seen": last_seen,
            "status": status,
            "total": total,
            "failures": failures,
            "fail_pct": fail_pct,
            "uptime_pct": uptime_pct,
            "loss_avg": stats.get("loss_avg"),
            "avg_ms_avg": stats.get("avg_ms_avg"),
            "source_missing": bool(st.get("source_missing")),
            "source_missing_since_iso": (st.get("source_missing_since") or "").strip(),
            "source_missing_since": format_ts_ph(st.get("source_missing_since")) if (st.get("source_missing_since") or "").strip() else "",
            "recent": [
                {
                    "ts": format_ts_ph(item.get("timestamp")),
                    "status": "pending" if (item.get("mode") or "").strip().lower() == "pending" else ("up" if bool(item.get("ok")) else "down"),
                    "ok": bool(item.get("ok")),
                    "loss": item.get("loss"),
                    "avg_ms": item.get("avg_ms"),
                }
                for item in recent_rows
            ],
        }
        accounts_ping_source_missing = bool(st.get("source_missing"))
        accounts_ping_source_missing_since_iso = (st.get("source_missing_since") or "").strip()

    if profile["pppoe"]:
        usage_enabled = bool(usage_settings.get("enabled"))
        usage = {
            "enabled": usage_enabled,
            "active": False,
            "router_id": "",
            "router_name": "",
            "address": "",
            "uptime": "",
            "session_id": "",
            "last_seen": "n/a",
            "dl_bps": None,
            "ul_bps": None,
            "dl_bps_fmt": "n/a",
            "ul_bps_fmt": "n/a",
            "dl_total_bytes": None,
            "ul_total_bytes": None,
            "dl_total_fmt": "n/a",
            "ul_total_fmt": "n/a",
            "devices": 0,
            "hostnames": [],
            "issue": False,
            "issue_peak": False,
            "issue_anytime": False,
            "idle_kbps_to": float((usage_settings.get("detection") or {}).get("total_kbps_to", 8) or 8),
        }
        pppoe_key = profile["pppoe"].strip().lower()
        host_info = usage_hosts.get(profile["pppoe"]) or usage_hosts.get(pppoe_key) or {}
        host_count = int(host_info.get("host_count") or 0)
        hostnames = host_info.get("hostnames") if isinstance(host_info.get("hostnames"), list) else []
        hostnames = [str(x).strip() for x in hostnames if str(x or "").strip()]
        usage["devices"] = host_count
        usage["hostnames"] = hostnames
        usage_peak_issues = usage_state.get("peak_issues") if isinstance(usage_state.get("peak_issues"), dict) else {}
        if usage_enabled:
            try:
                if usage_row:
                    ul_bps = usage_row.get("rx_bps")
                    dl_bps = usage_row.get("tx_bps")
                    router_id = (usage_row.get("router_id") or "").strip()
                    peak_issue = bool(usage_peak_issues.get(f"{router_id}|{pppoe_key}"))
                    anytime_issue = bool(usage_anytime_issues.get(f"{router_id}|{pppoe_key}"))

                    usage.update(
                        {
                            "active": True,
                            "router_id": router_id,
                            "router_name": (usage_row.get("router_name") or router_id or "").strip(),
                            "address": (usage_row.get("address") or "").strip(),
                            "uptime": (usage_row.get("uptime") or "").strip(),
                            "session_id": (usage_row.get("session_id") or "").strip(),
                            "last_seen": format_ts_ph(usage_row.get("timestamp")),
                            "dl_bps": dl_bps,
                            "ul_bps": ul_bps,
                            "dl_bps_fmt": format_bps(dl_bps),
                            "ul_bps_fmt": format_bps(ul_bps),
                            "dl_total_bytes": usage_row.get("bytes_out"),
                            "ul_total_bytes": usage_row.get("bytes_in"),
                            "dl_total_fmt": format_bytes(usage_row.get("bytes_out")),
                            "ul_total_fmt": format_bytes(usage_row.get("bytes_in")),
                            "issue_peak": peak_issue,
                            "issue_anytime": anytime_issue,
                            "issue": bool(peak_issue or anytime_issue),
                        }
                    )
                    if usage.get("address") and not profile.get("ip"):
                        profile["ip"] = usage.get("address")
            except Exception:
                pass

        profile["usage"] = usage
        if usage_enabled and (usage.get("active") or usage.get("devices") or usage.get("hostnames")):
            profile["sources"].append("usage")

    if profile["pppoe"]:
        latest_history = []
        try:
            raw_history = list_surveillance_history(query=profile["pppoe"], page=1, limit=12)
            latest_history = [
                row
                for row in (raw_history.get("rows") or [])
                if (row.get("pppoe") or "").strip().lower() == profile["pppoe"].lower()
            ]
        except Exception:
            latest_history = []

        surveillance_status = ""
        surveillance_label = ""
        surveillance_since_iso = ""
        surveillance_since = ""
        surveillance_duration = ""
        surveillance_source = ""
        stage_history = []
        if surveillance_entry or surveillance_session:
            session_status = (surveillance_session.get("last_state") if surveillance_session else "").strip().lower()
            if session_status not in ("under", "level2", "observe"):
                session_status = ""
            current_status = session_status or _resolve_surveillance_ai_stage(surveillance_entry)
            surveillance_status = (current_status or "under").strip().lower() or "under"
            if surveillance_status not in ("under", "level2", "observe"):
                surveillance_status = "under"
            if surveillance_status == "level2":
                surveillance_label = "Needs Manual Fix"
            elif surveillance_status == "observe":
                surveillance_label = "Post-Fix Observation"
            else:
                surveillance_label = "Under Surveillance"
            surveillance_since_iso = (
                (surveillance_entry.get("level2_at") if surveillance_entry and surveillance_status == "level2" else "")
                or (surveillance_entry.get("last_fixed_at") if surveillance_entry and surveillance_status == "observe" else "")
                or (surveillance_session.get("updated_at") if surveillance_session and surveillance_status == "level2" else "")
                or (surveillance_session.get("updated_at") if surveillance_session and surveillance_status == "observe" else "")
                or (surveillance_entry.get("added_at") if surveillance_entry else "")
                or (surveillance_session.get("started_at") if surveillance_session else "")
            )
            surveillance_since = format_ts_ph(surveillance_since_iso) if surveillance_since_iso else ""
            since_dt = _parse_iso_z(surveillance_since_iso)
            surveillance_duration = _format_duration_short(int(max(0, (now_dt - since_dt).total_seconds()))) if since_dt else ""
            surveillance_source = (
                (surveillance_entry.get("source") if surveillance_entry else "")
                or (surveillance_session.get("source") if surveillance_session else "")
                or (surveillance_entry.get("added_mode") if surveillance_entry else "")
            ).strip()
            stage_history = (
                list(reversed(_normalize_surveillance_stage_history((surveillance_entry or {}).get("stage_history"))))[:5]
                if surveillance_entry
                else []
            )

        last_outcome = latest_history[0] if latest_history else None
        last_outcome_reason = (last_outcome.get("end_reason") or "").strip().lower() if last_outcome else ""
        last_outcome_map = {
            "fixed": "Fixed",
            "false": "False Alarm",
            "recovered": "Recovered",
            "healed": "Healed",
            "removed": "Removed",
        }
        last_outcome_duration = ""
        if last_outcome:
            total_seconds = int(last_outcome.get("under_seconds") or 0) + int(last_outcome.get("level2_seconds") or 0) + int(last_outcome.get("observe_seconds") or 0)
            last_outcome_duration = _format_duration_short(total_seconds)

        surveillance_history = []
        for row in latest_history[:5]:
            total_seconds = int(row.get("under_seconds") or 0) + int(row.get("level2_seconds") or 0) + int(row.get("observe_seconds") or 0)
            surveillance_history.append(
                {
                    "started_at": format_ts_ph(row.get("started_at")),
                    "ended_at": format_ts_ph(row.get("ended_at")),
                    "end_reason": last_outcome_map.get((row.get("end_reason") or "").strip().lower(), ((row.get("end_reason") or "").strip().replace("_", " ") or "Closed").title()),
                    "duration": _format_duration_short(total_seconds),
                    "note": (row.get("end_note") or "").strip(),
                }
            )

        if surveillance_entry or surveillance_session or surveillance_history:
            profile["surveillance"] = {
                "active": bool(surveillance_entry or surveillance_session),
                "status": surveillance_status,
                "status_label": surveillance_label or "Not Tagged",
                "since_iso": surveillance_since_iso,
                "since": surveillance_since,
                "since_label": f"Since {surveillance_since}" if surveillance_since else "",
                "duration": surveillance_duration,
                "source": surveillance_source,
                "added_by": (surveillance_entry.get("added_by") or "").strip() if surveillance_entry else "",
                "ip": (surveillance_entry.get("ip") or "").strip() if surveillance_entry else (surveillance_session.get("last_ip") or "").strip() if surveillance_session else "",
                "level2_reason": (surveillance_entry.get("level2_reason") or "").strip() if surveillance_entry else "",
                "observed_count": int(surveillance_session.get("observed_count") or 0) if surveillance_session else 0,
                "last_updated_iso": (
                    (surveillance_session.get("updated_at") if surveillance_session else "")
                    or (surveillance_entry.get("updated_at") if surveillance_entry else "")
                ),
                "last_updated": format_ts_ph(
                    (surveillance_session.get("updated_at") if surveillance_session else "")
                    or (surveillance_entry.get("updated_at") if surveillance_entry else "")
                ),
                "last_outcome_label": last_outcome_map.get(last_outcome_reason, (last_outcome_reason.replace("_", " ") or "").title()) if last_outcome_reason else "",
                "last_outcome_hint": (
                    f"Closed {format_ts_ph(last_outcome.get('ended_at'))} after {last_outcome_duration}"
                    if last_outcome
                    else ""
                ),
                "history": surveillance_history,
                "stage_history": [
                    {
                        "at": format_ts_ph(item.get("ts")),
                        "from": ((item.get("from") or "").replace("_", " ") or "Start").title(),
                        "to": ((item.get("to") or "").replace("_", " ") or "Updated").title(),
                        "reason": (item.get("reason") or "").strip(),
                        "action": (item.get("action") or "").strip(),
                    }
                    for item in stage_history
                ],
            }
            profile["sources"].append("surveillance")

    if profile["pppoe"]:
        offline_current = offline_current_map.get(profile["pppoe"].lower())
        offline_history_rows = get_offline_history_for_pppoe(profile["pppoe"], since_iso=offline_history_since_iso, limit=6)
        latest_restore = offline_history_rows[0] if offline_history_rows else None
        offline_status = "unknown"
        offline_label = "No offline data"
        offline_hint = "No offline records found for this account."
        offline_since = ""
        offline_for = ""
        offline_current_since_iso = ""
        offline_threshold_minutes = int(
            offline_state.get("min_offline_minutes")
            or int((offline_settings.get("general") or {}).get("min_offline_value", 1) or 1)
            * (60 if ((offline_settings.get("general") or {}).get("min_offline_unit") or "day").strip().lower() == "hour" else 1440)
        )
        if not offline_settings.get("enabled"):
            offline_status = "disabled"
            offline_label = "Collector Disabled"
            offline_hint = "Offline collector is disabled in settings."
        elif offline_current:
            offline_current_since_iso = (offline_current.get("offline_since_iso") or "").strip()
            since_dt = _parse_iso_z(offline_current_since_iso)
            offline_for = _format_duration_short(int(max(0, (now_dt - since_dt).total_seconds()))) if since_dt else ""
            offline_since = format_ts_ph(offline_current_since_iso) if offline_current_since_iso else ""
            if offline_current.get("listed"):
                offline_status = "offline"
                offline_label = "Currently Offline"
                offline_hint = f"Listed by Offline monitoring since {offline_since}."
            else:
                offline_status = "tracking"
                offline_label = "Below Threshold"
                offline_hint = f"Seen offline but still below the {offline_threshold_minutes} minute threshold."
        elif accounts_ping_source_missing:
            offline_status = "source_missing"
            offline_label = "Source Missing"
            if accounts_ping_source_missing_since_iso:
                offline_hint = (
                    f"This account is no longer present in the current MikroTik router source since "
                    f"{format_ts_ph(accounts_ping_source_missing_since_iso)}."
                )
            else:
                offline_hint = "This account is no longer present in the current MikroTik router source."
        elif latest_restore:
            offline_status = "online"
            offline_label = "Online"
            offline_hint = f"Last restored {format_ts_ph(latest_restore.get('offline_ended_at'))}."

        offline_history = []
        for row in offline_history_rows:
            offline_history.append(
                {
                    "offline_started_at": (row.get("offline_started_at") or "").strip(),
                    "offline_ended_at": (row.get("offline_ended_at") or "").strip(),
                    "offline_started": format_ts_ph(row.get("offline_started_at")),
                    "offline_ended": format_ts_ph(row.get("offline_ended_at")),
                    "duration": _format_duration_short(row.get("duration_seconds")),
                    "duration_seconds": int(row.get("duration_seconds") or 0),
                    "router_name": (row.get("router_name") or row.get("router_id") or "").strip(),
                    "mode": (row.get("mode") or "").strip(),
                    "service_profile": (row.get("profile") or "").strip(),
                    "radius_status": (row.get("radius_status") or "").strip(),
                }
            )

        if offline_current or offline_history or not offline_settings.get("enabled"):
            profile["offline"] = {
                "enabled": bool(offline_settings.get("enabled")),
                "mode": (
                    (offline_current.get("mode") or "").strip()
                    if offline_current
                    else (offline_state.get("mode") or offline_settings.get("mode") or "secrets")
                ),
                "current": bool(offline_current),
                "status": offline_status,
                "status_label": offline_label,
                "status_hint": offline_hint,
                "last_check": format_ts_ph(offline_state.get("last_check_at")),
                "min_offline_minutes": offline_threshold_minutes,
                "threshold_text": _format_duration_short(offline_threshold_minutes * 60) or f"{offline_threshold_minutes}m",
                "offline_since_iso": offline_current_since_iso,
                "offline_since": offline_since,
                "offline_for": offline_for,
                "router_name": (offline_current.get("router_name") or "").strip() if offline_current else "",
                "service_profile": (offline_current.get("service_profile") or "").strip() if offline_current else "",
                "disabled": offline_current.get("disabled") if offline_current else None,
                "last_logged_out": (offline_current.get("last_logged_out") or "").strip() if offline_current else "",
                "radius_status": (offline_current.get("radius_status") or "").strip() if offline_current else "",
                "last_restored_at_iso": (latest_restore.get("offline_ended_at") or "").strip() if latest_restore else "",
                "last_restored_at": format_ts_ph(latest_restore.get("offline_ended_at")) if latest_restore else "",
                "last_duration": _format_duration_short(latest_restore.get("duration_seconds")) if latest_restore else "",
                "source_missing": accounts_ping_source_missing,
                "source_missing_since_iso": accounts_ping_source_missing_since_iso,
                "source_missing_since": format_ts_ph(accounts_ping_source_missing_since_iso) if accounts_ping_source_missing_since_iso else "",
                "history": offline_history,
            }
            profile["sources"].append("offline")

    profile["sources"] = sorted({*profile["sources"]})
    if not profile["name"]:
        profile["name"] = (
            (surveillance_entry.get("name") or "").strip()
            if surveillance_entry
            else profile["pppoe"] or profile["ip"] or profile["device_id"] or ""
        )
    if not profile["pppoe"]:
        # keep empty when we can't confidently identify the PPPoE username
        profile["pppoe"] = ""

    latest_activity_iso = ""
    for candidate in (
        optical_ident.get("timestamp") if optical_ident else "",
        (profile.get("accounts_ping") or {}).get("last_seen_iso"),
        usage_row.get("timestamp") if usage_row else "",
        (profile.get("surveillance") or {}).get("last_updated_iso"),
        (profile.get("offline") or {}).get("offline_since_iso"),
        (profile.get("offline") or {}).get("last_restored_at_iso"),
    ):
        text = (candidate or "").strip()
        if text and text > latest_activity_iso:
            latest_activity_iso = text

    account_details = []
    source_labels = {
        "accounts_ping": "ACC-Ping",
        "optical": "Optical",
        "usage": "Usage",
        "offline": "Offline",
        "surveillance": "Surveillance",
    }
    if profile["pppoe"]:
        account_details.append({"label": "PPPoE", "value": profile["pppoe"]})
    if profile["ip"]:
        account_details.append({"label": "IP Address", "value": profile["ip"]})
    if profile["device_id"]:
        account_details.append(
            {
                "label": "Device ID",
                "value": profile["device_id"],
                "href": profile.get("device_url") or "",
            }
        )
    if (profile.get("usage") or {}).get("router_name"):
        account_details.append({"label": "Router", "value": (profile.get("usage") or {}).get("router_name")})
    elif (profile.get("offline") or {}).get("router_name"):
        account_details.append({"label": "Router", "value": (profile.get("offline") or {}).get("router_name")})
    if (profile.get("usage") or {}).get("address"):
        account_details.append({"label": "Session Address", "value": (profile.get("usage") or {}).get("address")})
    if (profile.get("usage") or {}).get("session_id"):
        account_details.append({"label": "Session ID", "value": (profile.get("usage") or {}).get("session_id")})
    if latest_activity_iso:
        account_details.append({"label": "Latest Activity", "value": format_ts_ph(latest_activity_iso)})
    if profile["sources"]:
        account_details.append(
            {
                "label": "Matched Sources",
                "value": ", ".join(source_labels.get(source, source.replace("_", " ").title()) for source in profile["sources"]),
            }
        )
    account_details.append({"label": "Review Window", "value": profile["window_label"]})
    profile["account_details"] = account_details

    overview, kpis, focus_points = _build_profile_review_summary(profile)
    profile["status_cards"] = _build_profile_review_status_cards(profile)
    profile["overview"] = overview
    profile["kpis"] = kpis
    profile["testing_focus"] = focus_points

    response = templates.TemplateResponse(
        "profile_review.html",
        make_context(
            request,
            {
                "profile": profile,
                "search_query": search_query,
                "search_results": [],
                "search_state": "",
                "search_result_count": 0,
                "search_account_count": 0,
            },
        ),
    )
    response.headers["Cache-Control"] = NO_STORE_HEADERS["Cache-Control"]
    return response


def _accounts_missing_source_label(source_key):
    source_value = str(source_key or "").strip().lower()
    labels = {
        "accounts_ping": "ACC-Ping",
        "optical": "Optical",
        "optical_truth": "Optical Truth",
        "usage": "Usage",
        "usage_offline": "Usage Offline",
        "offline": "Offline",
        "offline_tracker": "Offline Tracker",
        "surveillance": "Surveillance",
        "mikrotik_secret": "MikroTik Secret",
    }
    return labels.get(source_value, source_value.replace("_", " ").title() or "Unknown")


def _accounts_missing_settings_from_form(form):
    existing = normalize_accounts_missing_settings(get_settings("accounts_missing", ACCOUNTS_MISSING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    system_routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
    router_count = parse_int(form, "router_count", len(system_routers))
    router_enabled = {}
    for idx in range(router_count):
        router_id = (form.get(f"router_{idx}_id") or "").strip()
        if not router_id:
            continue
        router_enabled[router_id] = parse_bool(form, f"router_{idx}_enabled")
    if not router_enabled and isinstance(((existing.get("source") or {}).get("mikrotik") or {}).get("router_enabled"), dict):
        router_enabled = {
            str(key).strip(): bool(value)
            for key, value in ((((existing.get("source") or {}).get("mikrotik") or {}).get("router_enabled") or {}).items())
            if str(key).strip()
        }
    enabled = bool(existing.get("enabled"))
    if form.get("enabled") is not None:
        enabled = parse_bool(form, "enabled")
    refresh_minutes = int(((existing.get("source") or {}).get("refresh_minutes") or ACCOUNTS_MISSING_DEFAULTS["source"]["refresh_minutes"]) or 1)
    if form.get("source_refresh_minutes") is not None:
        refresh_minutes = parse_int(
            form,
            "source_refresh_minutes",
            ACCOUNTS_MISSING_DEFAULTS["source"]["refresh_minutes"],
        )
    timeout_seconds = int((((existing.get("source") or {}).get("mikrotik") or {}).get("timeout_seconds") or ACCOUNTS_MISSING_DEFAULTS["source"]["mikrotik"]["timeout_seconds"]) or 1)
    if form.get("mikrotik_timeout_seconds") is not None:
        timeout_seconds = parse_int(
            form,
            "mikrotik_timeout_seconds",
            ACCOUNTS_MISSING_DEFAULTS["source"]["mikrotik"]["timeout_seconds"],
        )
    auto_delete_enabled = bool(((existing.get("auto_delete") or {}).get("enabled")))
    if form.get("auto_delete_enabled") is not None:
        auto_delete_enabled = parse_bool(form, "auto_delete_enabled")
    auto_delete_days = int(((existing.get("auto_delete") or {}).get("days") or ACCOUNTS_MISSING_DEFAULTS["auto_delete"]["days"]) or 1)
    if form.get("auto_delete_days") is not None:
        auto_delete_days = parse_int(form, "auto_delete_days", ACCOUNTS_MISSING_DEFAULTS["auto_delete"]["days"])
    return normalize_accounts_missing_settings(
        {
            "enabled": enabled,
            "source": {
                "refresh_minutes": refresh_minutes,
                "mikrotik": {
                    "router_enabled": router_enabled,
                    "timeout_seconds": timeout_seconds,
                },
            },
            "auto_delete": {
                "enabled": auto_delete_enabled,
                "days": auto_delete_days,
            },
        }
    )


def _accounts_missing_parse_bulk_pppoes(raw_value):
    raw_text = str(raw_value or "").strip()
    if not raw_text:
        return []
    parsed = []
    try:
        payload = json.loads(raw_text)
        if isinstance(payload, list):
            parsed = payload
    except Exception:
        parsed = re.split(r"[\n,]+", raw_text)
    out = []
    seen = set()
    for item in parsed:
        value = str(item or "").strip()
        value_key = value.lower()
        if not value or value_key in seen:
            continue
        seen.add(value_key)
        out.append(value)
    return out


def build_accounts_missing_status(settings, limit=50, page=1, sort="", direction="", query="", new_entry_ids=None):
    settings = normalize_accounts_missing_settings(settings)
    limit = _parse_table_limit(limit, default=50)
    page = _parse_table_page(page, default=1)
    state = get_state("accounts_missing_state", {})
    if not isinstance(state, dict):
        state = {}

    missing_entries = state.get("missing_entries") if isinstance(state.get("missing_entries"), list) else []
    source_stats = state.get("source_stats") if isinstance(state.get("source_stats"), dict) else {}
    surveillance_settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    surveillance_entries = _surveillance_entry_map(surveillance_settings)
    new_entry_id_set = {
        str(item or "").strip().lower()
        for item in (new_entry_ids or [])
        if str(item or "").strip()
    }

    rows = []
    for entry in missing_entries:
        if not isinstance(entry, dict):
            continue
        pppoe = str(entry.get("pppoe") or "").strip()
        if not pppoe:
            continue
        router_names = [
            str(item or "").strip()
            for item in (entry.get("router_names") or [])
            if str(item or "").strip()
        ]
        if not router_names and str(entry.get("last_router_name") or "").strip():
            router_names = [str(entry.get("last_router_name") or "").strip()]
        source_labels = [
            _accounts_missing_source_label(item)
            for item in (entry.get("sources") or [])
            if str(item or "").strip()
        ]
        surv_entry = _profile_find_surveillance_entry(surveillance_entries, pppoe=pppoe)
        surv_status = (surv_entry.get("status") or "").strip().lower() if isinstance(surv_entry, dict) else ""
        missing_for_seconds = int(entry.get("missing_for_seconds") or 0)
        entry_id = _accounts_missing_nav_entry_id(entry)
        row = {
            "entry_id": entry_id,
            "pppoe": pppoe,
            "last_ip": str(entry.get("last_ip") or "").strip(),
            "router_names": router_names,
            "router_label": ", ".join(router_names) if router_names else "n/a",
            "source_labels": source_labels,
            "source_label": ", ".join(source_labels) if source_labels else "n/a",
            "source_count": len(source_labels),
            "first_seen_at": str(entry.get("first_seen_at") or "").strip(),
            "first_seen": format_ts_ph(entry.get("first_seen_at")),
            "last_seen_at": str(entry.get("last_seen_at") or "").strip(),
            "last_seen": format_ts_ph(entry.get("last_seen_at")),
            "last_secret_seen_at": str(entry.get("last_secret_seen_at") or "").strip(),
            "last_secret_seen": format_ts_ph(entry.get("last_secret_seen_at")),
            "first_missing_at": str(entry.get("first_missing_at") or "").strip(),
            "first_missing": format_ts_ph(entry.get("first_missing_at")),
            "last_missing_at": str(entry.get("last_missing_at") or "").strip(),
            "last_missing": format_ts_ph(entry.get("last_missing_at")),
            "missing_for_seconds": missing_for_seconds,
            "missing_for": _format_duration_short(missing_for_seconds) or "0m",
            "surveillance_status": surv_status,
            "is_new": bool(entry_id and entry_id in new_entry_id_set),
        }
        rows.append(row)

    q = (query or "").strip().lower()
    if q:
        rows = [
            row
            for row in rows
            if q
            in " ".join(
                [
                    str(row.get("pppoe") or ""),
                    str(row.get("last_ip") or ""),
                    str(row.get("router_label") or ""),
                    str(row.get("source_label") or ""),
                    str(row.get("missing_for") or ""),
                ]
            ).lower()
        ]

    def _sort_text(value, desc=False):
        text = str(value or "").strip().lower()
        return (0, "".join(reversed(text)) if desc else text)

    def _sort_num(value, desc=False):
        try:
            number = float(value)
        except Exception:
            return (1, 0.0)
        return (0, -number if desc else number)

    def _sort_key_for(row, key, desc=False):
        if key in ("customer", "pppoe", "name"):
            return _sort_text(row.get("pppoe"), desc=desc)
        if key in ("ip", "last_ip"):
            return _sort_text(row.get("last_ip"), desc=desc)
        if key in ("router", "router_name"):
            return _sort_text(row.get("router_label"), desc=desc)
        if key in ("sources", "source_count"):
            return _sort_num(row.get("source_count"), desc=desc)
        if key in ("missing_for", "missing_for_seconds"):
            return _sort_num(row.get("missing_for_seconds"), desc=desc)
        if key in ("first_missing", "first_missing_at"):
            return _sort_text(row.get("first_missing_at"), desc=desc)
        if key in ("last_secret_seen", "last_secret_seen_at"):
            return _sort_text(row.get("last_secret_seen_at"), desc=desc)
        if key in ("first_seen", "first_seen_at"):
            return _sort_text(row.get("first_seen_at"), desc=desc)
        if key in ("last_seen", "last_seen_at"):
            return _sort_text(row.get("last_seen_at"), desc=desc)
        return _sort_text(row.get("pppoe"), desc=desc)

    sort = (sort or "").strip()
    descending = (direction or "").strip().lower() != "asc"
    rows = (
        sorted(rows, key=lambda row: _sort_key_for(row, sort, desc=descending))
        if sort
        else sorted(
            rows,
            key=lambda row: (
                -(row.get("missing_for_seconds") or 0),
                row.get("first_missing_at") or "",
                (row.get("pppoe") or "").lower(),
            ),
        )
    )

    paged_rows, page_meta = _paginate_items(rows, page, limit)
    selected_router_count = int(state.get("selected_router_count") or 0)
    connected_router_count = int(state.get("connected_router_count") or 0)
    validation_active = bool(state.get("validation_active"))
    paused_reason = str(state.get("validation_paused_reason") or "").strip()

    return {
        "rows": paged_rows,
        "total": len(rows),
        "known_total": int(source_stats.get("known_total") or len(state.get("known_accounts") or [])),
        "present_total": int(source_stats.get("present_total") or 0),
        "missing_total": len(rows),
        "secret_total": int(source_stats.get("secret_total") or 0),
        "selected_router_count": selected_router_count,
        "connected_router_count": connected_router_count,
        "validation_active": validation_active,
        "validation_label": "Validating" if validation_active else "Paused",
        "validation_tone": "green" if validation_active else "yellow",
        "validation_paused_reason": paused_reason,
        "last_check_at": format_ts_ph(state.get("last_check_at")),
        "last_success_at": format_ts_ph(state.get("last_success_at")),
        "last_auto_delete_at": format_ts_ph(state.get("last_auto_delete_at")),
        "auto_delete_enabled": bool(((settings.get("auto_delete") or {}).get("enabled"))),
        "auto_delete_days": int(((settings.get("auto_delete") or {}).get("days") or 0) or 0),
        "pagination": {
            "limit": limit,
            "limit_label": "ALL" if not limit else str(limit),
            "options": TABLE_PAGE_SIZE_OPTIONS,
            "rows": page_meta,
        },
        "sort": {"key": sort, "dir": "desc" if descending else "asc"},
        "query": query or "",
        "router_status": state.get("router_status") if isinstance(state.get("router_status"), list) else [],
    }


def _accounts_missing_detail_payload(pppoe):
    pppoe_value = str(pppoe or "").strip()
    if not pppoe_value:
        return {}

    pppoe_key = pppoe_value.lower()
    now_dt = datetime.utcnow()
    window_since_iso = (now_dt - timedelta(days=7)).replace(microsecond=0).isoformat() + "Z"
    optical_since_iso = (now_dt - timedelta(days=30)).replace(microsecond=0).isoformat() + "Z"

    missing_state = get_state("accounts_missing_state", {})
    missing_entry = next(
        (
            item
            for item in ((missing_state.get("missing_entries") or []) if isinstance(missing_state, dict) else [])
            if isinstance(item, dict) and str(item.get("pppoe") or "").strip().lower() == pppoe_key
        ),
        {},
    )

    ping_settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    ping_class = _accounts_ping_applied_classification(ping_settings)
    ping_state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
    ping_devices = _accounts_ping_state_devices(ping_state)
    ping_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}
    matching_ping_devices = [
        device for device in ping_devices if str(device.get("pppoe") or "").strip().lower() == pppoe_key
    ]
    account_ids = _accounts_ping_account_ids_for_pppoe(pppoe_value, state=ping_state)
    ping_state_entry = _accounts_ping_best_state_entry(account_ids, ping_accounts)
    ping_stats = _accounts_ping_window_stats_aggregate(account_ids, window_since_iso) if account_ids else {}
    ping_total = int(ping_stats.get("total") or 0)
    ping_failures = int(ping_stats.get("failures") or 0)
    ping_fail_pct = (ping_failures / ping_total) * 100.0 if ping_total else 0.0
    ping_uptime_pct = 100.0 - ping_fail_pct if ping_total else 0.0
    ping_status = "No Data"
    if ping_state_entry:
        if bool(ping_state_entry.get("source_missing")):
            ping_status = "Source Missing"
        elif not str(ping_state_entry.get("last_check_at") or "").strip():
            ping_status = "Pending"
        elif not bool(ping_state_entry.get("last_ok")):
            ping_status = "Down"
        else:
            issue_hit = False
            issue_loss_pct = float(ping_class.get("issue_loss_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_loss_pct"]) or 20.0)
            issue_latency_ms = float(ping_class.get("issue_latency_ms", ACCOUNTS_PING_DEFAULTS["classification"]["issue_latency_ms"]) or 200.0)
            stable_fail_pct = float(ping_class.get("stable_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["stable_rto_pct"]) or 2.0)
            issue_fail_pct = float(ping_class.get("issue_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_rto_pct"]) or 5.0)
            if ping_state_entry.get("last_loss") is not None and float(ping_state_entry.get("last_loss") or 0.0) >= issue_loss_pct:
                issue_hit = True
            if ping_state_entry.get("last_avg_ms") is not None and float(ping_state_entry.get("last_avg_ms") or 0.0) >= issue_latency_ms:
                issue_hit = True
            if ping_total and ping_fail_pct >= issue_fail_pct:
                issue_hit = True
            if ping_total and ping_fail_pct > stable_fail_pct:
                issue_hit = True
            ping_status = "Monitor" if issue_hit else "Stable"
    ping_recent_rows = []
    try:
        ping_recent_rows = list(reversed(_accounts_ping_series_rows_for_account_ids(account_ids, window_since_iso)))[:8]
    except Exception:
        ping_recent_rows = []

    optical_settings = get_settings("optical", OPTICAL_DEFAULTS)
    optical_state = _optical_state_snapshot()
    current_optical_entry = _optical_current_device_entry(pppoe=pppoe_value, state=optical_state)
    known_optical_entry = _optical_known_account_entry(pppoe=pppoe_value, state=optical_state)
    optical_map = get_latest_optical_by_pppoe([pppoe_value]) if pppoe_value else {}
    latest_optical = optical_map.get(pppoe_value) or next(
        (
            value
            for key, value in (optical_map or {}).items()
            if str(key or "").strip().lower() == pppoe_key
        ),
        {},
    )
    device_id = (
        str(current_optical_entry.get("device_id") or "").strip()
        or str(latest_optical.get("device_id") or "").strip()
        or str(known_optical_entry.get("device_id") or "").strip()
    )
    optical_recent = get_recent_optical_readings(device_id, optical_since_iso, limit=8) if device_id else []
    optical_class = optical_settings.get("classification", {}) or {}
    issue_rx = float(optical_class.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]) or -27.0)
    issue_tx = float(optical_class.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]) or -2.0)
    stable_rx = float(optical_class.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]) or -24.0)
    stable_tx = float(optical_class.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]) or -1.0)
    rx_realistic_min = float(optical_class.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]) or -40.0)
    rx_realistic_max = float(optical_class.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]) or 5.0)
    tx_realistic_min = float(optical_class.get("tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]) or -10.0)
    tx_realistic_max = float(optical_class.get("tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]) or 10.0)
    optical_rx = latest_optical.get("rx")
    optical_tx = latest_optical.get("tx")
    optical_status = "No Data"
    if latest_optical or current_optical_entry or known_optical_entry:
        if not current_optical_entry:
            optical_status = "Offline"
        else:
            rx_invalid = optical_rx is None or optical_rx < rx_realistic_min or optical_rx > rx_realistic_max
            tx_invalid = optical_tx is not None and (optical_tx < tx_realistic_min or optical_tx > tx_realistic_max)
            if rx_invalid:
                optical_status = "ACS-LOS"
            elif (optical_rx is not None and optical_rx <= issue_rx) or (optical_tx is not None and not tx_invalid and optical_tx <= issue_tx):
                optical_status = "Issue"
            elif optical_rx is not None and optical_rx >= stable_rx and (
                optical_tx is None or tx_invalid or optical_tx >= stable_tx
            ):
                optical_status = "Stable"
            else:
                optical_status = "Monitor"

    usage_settings = get_settings("usage", USAGE_DEFAULTS)
    usage_state = get_state("usage_state", {})
    usage_rows = usage_state.get("active_rows") if isinstance(usage_state.get("active_rows"), list) else []
    usage_hosts = usage_state.get("pppoe_hosts") if isinstance(usage_state.get("pppoe_hosts"), dict) else {}
    usage_anytime_issues = usage_state.get("anytime_issues") if isinstance(usage_state.get("anytime_issues"), dict) else {}
    current_usage = next(
        (
            row
            for row in usage_rows
            if str(row.get("pppoe") or row.get("name") or "").strip().lower() == pppoe_key
        ),
        None,
    )
    latest_usage = current_usage or get_latest_pppoe_usage_snapshot(
        pppoe_value,
        router_id=str(missing_entry.get("last_router_id") or "").strip(),
    ) or get_latest_pppoe_usage_snapshot(pppoe_value)
    usage_host_info = usage_hosts.get(pppoe_value) or usage_hosts.get(pppoe_key) or {}
    usage_hostnames = [
        str(item or "").strip()
        for item in ((usage_host_info.get("hostnames") or []) if isinstance(usage_host_info, dict) else [])
        if str(item or "").strip()
    ]
    usage_status = "No Session"
    usage_issue = False
    if current_usage:
        usage_status = "Active"
        router_id = str(current_usage.get("router_id") or "").strip()
        usage_issue = bool(usage_anytime_issues.get(f"{router_id}|{pppoe_key}"))
        if usage_issue:
            usage_status = "Issue"
    elif latest_usage:
        usage_status = "No Session"
    elif not bool(usage_settings.get("enabled")):
        usage_status = "Disabled"

    offline_settings = get_settings("offline", OFFLINE_DEFAULTS)
    offline_state = get_state("offline_state", {})
    offline_current_map = _profile_collect_offline_current_map(offline_state)
    offline_current = offline_current_map.get(pppoe_key) or {}
    offline_history = get_offline_history_for_pppoe(pppoe_value, limit=5)
    offline_status = "No data"
    offline_threshold_minutes = int(
        offline_state.get("min_offline_minutes")
        or int((offline_settings.get("general") or {}).get("min_offline_value", 1) or 1)
        * (60 if ((offline_settings.get("general") or {}).get("min_offline_unit") or "day").strip().lower() == "hour" else 1440)
    )
    if not bool(offline_settings.get("enabled")):
        offline_status = "Disabled"
    elif offline_current:
        if bool(offline_current.get("listed")):
            offline_status = "Listed"
        else:
            offline_status = "Tracking"
    elif offline_history:
        offline_status = "Restored"

    surveillance_settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    surveillance_entries = _surveillance_entry_map(surveillance_settings)
    surveillance_entry = _profile_find_surveillance_entry(surveillance_entries, pppoe=pppoe_value)
    active_surveillance = get_active_surveillance_session(pppoe_value)
    recent_surveillance = get_recent_surveillance_sessions_for_pppoe(pppoe_value, limit=5)
    surveillance_status = "Not Tagged"
    if surveillance_entry or active_surveillance:
        current_status = str(
            (
                (active_surveillance.get("last_state") if isinstance(active_surveillance, dict) else "")
                or _resolve_surveillance_ai_stage(surveillance_entry if isinstance(surveillance_entry, dict) else {})
                or "under"
            )
        ).strip().lower()
        if current_status == "level2":
            surveillance_status = "Needs Manual Fix"
        elif current_status == "observe":
            surveillance_status = "Post-Fix Observation"
        else:
            surveillance_status = "Active Monitoring"
    elif recent_surveillance:
        last_reason = str(recent_surveillance[0].get("end_reason") or "").strip().replace("_", " ").title()
        surveillance_status = last_reason or "Closed"

    matching_sources = [
        _accounts_missing_source_label(item)
        for item in (missing_entry.get("sources") or [])
        if str(item or "").strip()
    ]
    router_names = [
        str(item or "").strip()
        for item in (missing_entry.get("router_names") or [])
        if str(item or "").strip()
    ]
    if not router_names and str(missing_entry.get("last_router_name") or "").strip():
        router_names = [str(missing_entry.get("last_router_name") or "").strip()]

    return {
        "pppoe": pppoe_value,
        "missing": {
            "status_label": "Missing",
            "first_missing": format_ts_ph(missing_entry.get("first_missing_at")),
            "last_secret_seen": format_ts_ph(missing_entry.get("last_secret_seen_at")),
            "missing_for": _format_duration_short(missing_entry.get("missing_for_seconds")) or "0m",
            "last_ip": str(missing_entry.get("last_ip") or "").strip(),
            "router_label": ", ".join(router_names) if router_names else "n/a",
            "sources": matching_sources,
            "first_seen": format_ts_ph(missing_entry.get("first_seen_at")),
            "last_seen": format_ts_ph(missing_entry.get("last_seen_at")),
        },
        "accounts_ping": {
            "status_label": ping_status,
            "last_check": format_ts_ph(ping_state_entry.get("last_check_at")) if ping_state_entry else "n/a",
            "last_ip": str((ping_state_entry or {}).get("last_ip") or "").strip(),
            "loss_avg": ping_stats.get("loss_avg"),
            "avg_ms_avg": ping_stats.get("avg_ms_avg"),
            "fail_pct": ping_fail_pct,
            "uptime_pct": ping_uptime_pct,
            "source_missing": bool((ping_state_entry or {}).get("source_missing")),
            "source_missing_since": format_ts_ph((ping_state_entry or {}).get("source_missing_since")),
            "accounts_found": len(account_ids),
            "device_rows": [
                {
                    "router_name": str(device.get("router_name") or device.get("router_id") or "").strip(),
                    "ip": str(device.get("ip") or "").strip(),
                    "source_mode": str(device.get("source_mode") or "").strip(),
                }
                for device in matching_ping_devices[:8]
            ],
            "recent": [
                {
                    "ts": format_ts_ph(item.get("timestamp")),
                    "status": "pending" if str(item.get("mode") or "").strip().lower() == "pending" else ("Up" if bool(item.get("ok")) else "Down"),
                    "loss": item.get("loss"),
                    "avg_ms": item.get("avg_ms"),
                }
                for item in ping_recent_rows
            ],
        },
        "optical": {
            "status_label": optical_status,
            "device_id": device_id,
            "last_seen": format_ts_ph(latest_optical.get("timestamp")),
            "last_inform_at": format_ts_ph(current_optical_entry.get("last_inform_at")) if current_optical_entry else "",
            "ip": str((latest_optical or {}).get("ip") or "").strip() or str(current_optical_entry.get("ip") or "").strip(),
            "rx": optical_rx,
            "tx": optical_tx,
            "current_available": bool(current_optical_entry),
            "router_label": ", ".join(
                [
                    str(item or "").strip()
                    for item in (
                        list(current_optical_entry.get("router_names") or [])
                        or list(known_optical_entry.get("router_names") or [])
                    )
                    if str(item or "").strip()
                ]
            ),
            "recent": [
                {
                    "ts": format_ts_ph(item.get("timestamp")),
                    "rx": item.get("rx"),
                    "tx": item.get("tx"),
                    "priority": bool(item.get("priority")),
                }
                for item in optical_recent
            ],
        },
        "offline": {
            "status_label": offline_status,
            "threshold_text": _format_duration_short(offline_threshold_minutes * 60) or f"{offline_threshold_minutes}m",
            "offline_since": format_ts_ph((offline_current or {}).get("offline_since_iso")),
            "offline_for": _format_duration_short(
                int(
                    max(
                        0,
                        (
                            now_dt
                            - (_parse_iso_z((offline_current or {}).get("offline_since_iso")) or now_dt)
                        ).total_seconds(),
                    )
                )
            )
            if (offline_current or {}).get("offline_since_iso")
            else "",
            "router_name": str((offline_current or {}).get("router_name") or "").strip(),
            "service_profile": str((offline_current or {}).get("service_profile") or "").strip(),
            "radius_status": str((offline_current or {}).get("radius_status") or "").strip(),
            "history": [
                {
                    "offline_started": format_ts_ph(item.get("offline_started_at")),
                    "offline_ended": format_ts_ph(item.get("offline_ended_at")),
                    "duration": _format_duration_short(item.get("duration_seconds")),
                    "router_name": str(item.get("router_name") or item.get("router_id") or "").strip(),
                }
                for item in offline_history
            ],
        },
        "usage": {
            "status_label": usage_status,
            "last_seen": format_ts_ph((latest_usage or {}).get("timestamp")),
            "router_name": str((latest_usage or {}).get("router_name") or (latest_usage or {}).get("router_id") or "").strip(),
            "address": str((latest_usage or {}).get("address") or "").strip(),
            "uptime": str((latest_usage or {}).get("uptime") or "").strip(),
            "session_id": str((latest_usage or {}).get("session_id") or "").strip(),
            "devices": int((usage_host_info.get("host_count") or 0) if isinstance(usage_host_info, dict) else 0),
            "hostnames": usage_hostnames,
            "rx_bps_fmt": format_bps((latest_usage or {}).get("rx_bps")) if latest_usage else "n/a",
            "tx_bps_fmt": format_bps((latest_usage or {}).get("tx_bps")) if latest_usage else "n/a",
            "issue": usage_issue,
        },
        "surveillance": {
            "status_label": surveillance_status,
            "since": format_ts_ph(
                (surveillance_entry.get("level2_at") if isinstance(surveillance_entry, dict) else "")
                or (surveillance_entry.get("added_at") if isinstance(surveillance_entry, dict) else "")
                or (active_surveillance.get("started_at") if isinstance(active_surveillance, dict) else "")
            ),
            "last_updated": format_ts_ph(
                (active_surveillance.get("updated_at") if isinstance(active_surveillance, dict) else "")
                or (surveillance_entry.get("updated_at") if isinstance(surveillance_entry, dict) else "")
            ),
            "source": str(
                (surveillance_entry.get("source") if isinstance(surveillance_entry, dict) else "")
                or (active_surveillance.get("source") if isinstance(active_surveillance, dict) else "")
            ).strip(),
            "level2_reason": str((surveillance_entry.get("level2_reason") if isinstance(surveillance_entry, dict) else "") or "").strip(),
            "recent": [
                {
                    "started_at": format_ts_ph(item.get("started_at")),
                    "ended_at": format_ts_ph(item.get("ended_at")),
                    "end_reason": str(item.get("end_reason") or "").strip().replace("_", " ").title() or "Closed",
                    "last_state": str(item.get("last_state") or "").strip(),
                }
                for item in recent_surveillance
            ],
        },
        "links": {
            "profile_review": f"/profile-review?pppoe={urllib.parse.quote(pppoe_value)}",
        },
    }


def render_accounts_missing_response(
    request,
    settings,
    message="",
    active_tab="status",
    settings_tab="general",
    *,
    message_tone="info",
    limit=None,
    page=None,
    sort="",
    direction="",
    query="",
):
    settings = normalize_accounts_missing_settings(settings)
    active_tab = "settings" if str(active_tab or "").strip().lower() == "settings" else "status"
    settings_tab = (settings_tab or "general").strip().lower()
    if settings_tab not in ("general", "source", "auto_delete"):
        settings_tab = "general"
    if limit is None:
        limit = _parse_table_limit(request.query_params.get("limit"), default=50)
    if page is None:
        page = _parse_table_page(request.query_params.get("page"), default=1)
    if not sort:
        sort = (request.query_params.get("sort") or "").strip()
    if not direction:
        direction = (request.query_params.get("dir") or "").strip().lower()
    if not query:
        query = (request.query_params.get("q") or "").strip()

    status_map = {item["job_name"]: dict(item) for item in get_job_status()}
    job_status = status_map.get("accounts_missing", {})
    job_status["last_run_at_ph"] = format_ts_ph(job_status.get("last_run_at"))
    job_status["last_success_at_ph"] = format_ts_ph(job_status.get("last_success_at"))
    job_status["last_error_at_ph"] = format_ts_ph(job_status.get("last_error_at"))
    accounts_missing_state = get_state("accounts_missing_state", {})
    current_entry_ids = _accounts_missing_current_entry_ids(accounts_missing_state)
    new_entry_ids = _accounts_missing_new_ids_for_request(request, current_entry_ids, seed_if_needed=True)

    status = build_accounts_missing_status(
        settings,
        limit=limit,
        page=page,
        sort=sort,
        direction=direction,
        query=query,
        new_entry_ids=new_entry_ids,
    )
    router_state_map = {
        str(item.get("router_id") or "").strip(): item
        for item in (status.get("router_status") or [])
        if isinstance(item, dict) and str(item.get("router_id") or "").strip()
    }
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))

    response = templates.TemplateResponse(
        "settings_accounts_missing.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "message_tone": message_tone,
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "accounts_missing_status": status,
                "accounts_missing_job": job_status,
                "wan_settings": wan_settings,
                "accounts_missing_router_state": router_state_map,
                "accounts_missing_new_view_seconds": _ACCOUNTS_MISSING_NEW_VIEW_SECONDS,
            },
        ),
    )
    response.headers["Cache-Control"] = NO_STORE_HEADERS["Cache-Control"]
    return response


@app.get("/settings/accounts-missing", response_class=HTMLResponse)
async def accounts_missing_settings(request: Request):
    settings = normalize_accounts_missing_settings(get_settings("accounts_missing", ACCOUNTS_MISSING_DEFAULTS))
    active_tab = "settings" if (request.query_params.get("tab") or "").strip().lower() == "settings" else "status"
    settings_tab = (request.query_params.get("settings_tab") or "general").strip().lower()
    return render_accounts_missing_response(request, settings, "", active_tab, settings_tab)


@app.post("/settings/accounts-missing", response_class=HTMLResponse)
async def accounts_missing_settings_save(request: Request):
    form = await request.form()
    settings = _accounts_missing_settings_from_form(form)
    save_settings("accounts_missing", settings)
    try:
        next_state = reconcile_accounts_missing_state(
            settings,
            previous_state=get_state("accounts_missing_state", {}),
            wan_settings=normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS)),
            now=datetime.utcnow(),
        )
        save_state("accounts_missing_state", next_state)
    except Exception:
        pass
    _auth_log_event(
        request,
        "accounts_missing.settings_saved",
        resource="/settings/accounts-missing",
        details=f"enabled={int(bool(settings.get('enabled')))};auto_delete={int(bool((settings.get('auto_delete') or {}).get('enabled')))}",
    )
    return render_accounts_missing_response(
        request,
        settings,
        "Missing Secrets settings saved.",
        form.get("active_tab", "settings"),
        form.get("settings_tab", "general"),
        message_tone="success",
    )


@app.post("/settings/accounts-missing/test", response_class=HTMLResponse)
async def accounts_missing_settings_test(request: Request):
    form = await request.form()
    settings = _accounts_missing_settings_from_form(form)
    message = ""
    tone = "info"
    try:
        next_state = reconcile_accounts_missing_state(
            settings,
            previous_state=get_state("accounts_missing_state", {}),
            wan_settings=normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS)),
            now=datetime.utcnow(),
        )
        save_state("accounts_missing_state", next_state)
        if bool(next_state.get("validation_active")):
            message = (
                f"MikroTik source OK. Selected routers: {int(next_state.get('selected_router_count') or 0)} "
                f"· Connected: {int(next_state.get('connected_router_count') or 0)} "
                f"· Missing accounts: {len(next_state.get('missing_entries') or [])}."
            )
            tone = "success"
        else:
            message = str(next_state.get("validation_paused_reason") or "").strip() or "Missing Secrets source validation is paused."
            tone = "warning"
    except Exception as exc:
        message = f"Missing Secrets source test failed: {exc}"
        tone = "danger"
    return render_accounts_missing_response(
        request,
        settings,
        message,
        "settings",
        "source",
        message_tone=tone,
    )


@app.get("/accounts-missing/detail", response_class=JSONResponse)
async def accounts_missing_detail(pppoe: str = ""):
    payload = _accounts_missing_detail_payload(pppoe)
    if not payload:
        return _json_no_store({"ok": False, "error": "Account not found."}, status_code=404)
    return _json_no_store({"ok": True, "detail": payload})


@app.post("/settings/accounts-missing/mark_new_seen", response_class=JSONResponse)
async def accounts_missing_mark_new_seen(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    raw_entry_ids = payload.get("entry_ids") if isinstance(payload, dict) else []
    seen_ids = _mark_accounts_missing_new_entries_seen(request, raw_entry_ids)
    return _json_no_store({"ok": True, "seen_ids": seen_ids, "seen_at": utc_now_iso()})


@app.post("/settings/accounts-missing/delete", response_class=HTMLResponse)
async def accounts_missing_delete(request: Request):
    form = await request.form()
    settings = normalize_accounts_missing_settings(get_settings("accounts_missing", ACCOUNTS_MISSING_DEFAULTS))
    pppoe = str(form.get("pppoe") or "").strip()
    if not pppoe:
        return render_accounts_missing_response(
            request,
            settings,
            "No PPPoE account was selected for deletion.",
            "status",
            "general",
            message_tone="danger",
        )
    try:
        purge_pppoe_account_data(pppoe)
        _auth_log_event(request, "accounts_missing.deleted", resource=pppoe, details="purged across all modules")
        message = f"Deleted all stored data for {pppoe}."
        tone = "success"
    except Exception as exc:
        message = f"Failed to delete {pppoe}: {exc}"
        tone = "danger"
    return render_accounts_missing_response(request, settings, message, "status", "general", message_tone=tone)


@app.post("/settings/accounts-missing/delete-many", response_class=HTMLResponse)
async def accounts_missing_delete_many(request: Request):
    form = await request.form()
    settings = normalize_accounts_missing_settings(get_settings("accounts_missing", ACCOUNTS_MISSING_DEFAULTS))
    pppoes = _accounts_missing_parse_bulk_pppoes(form.get("selected_pppoes"))
    if not pppoes:
        return render_accounts_missing_response(
            request,
            settings,
            "No accounts were selected for deletion.",
            "status",
            "general",
            message_tone="danger",
        )

    deleted = []
    errors = []
    for pppoe in pppoes:
        try:
            purge_pppoe_account_data(pppoe)
            deleted.append(pppoe)
        except Exception as exc:
            errors.append(f"{pppoe}: {exc}")
    if deleted:
        _auth_log_event(
            request,
            "accounts_missing.deleted_many",
            resource=f"count={len(deleted)}",
            details=", ".join(deleted[:10]),
        )
    if errors and deleted:
        message = f"Deleted {len(deleted)} account(s). Failed: {'; '.join(errors[:3])}"
        tone = "warning"
    elif errors:
        message = f"Bulk delete failed: {'; '.join(errors[:3])}"
        tone = "danger"
    else:
        message = f"Deleted all stored data for {len(deleted)} account(s)."
        tone = "success"
    return render_accounts_missing_response(request, settings, message, "status", "general", message_tone=tone)


@app.get("/settings/accounts-ping", response_class=HTMLResponse)
async def accounts_ping_settings(request: Request):
    settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    normalized_settings, tuning = _accounts_ping_tuning_context(settings)
    if tuning.get("was_clamped"):
        save_settings("accounts_ping", normalized_settings)
    settings = normalized_settings
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    limit = _parse_table_limit(request.query_params.get("limit"), default=50)
    issues_page = _parse_table_page(request.query_params.get("issues_page"), default=1)
    stable_page = _parse_table_page(request.query_params.get("stable_page"), default=1)
    issues_sort = (request.query_params.get("issues_sort") or "").strip()
    issues_dir = (request.query_params.get("issues_dir") or "").strip().lower()
    stable_sort = (request.query_params.get("stable_sort") or "").strip()
    stable_dir = (request.query_params.get("stable_dir") or "").strip().lower()
    query = (request.query_params.get("q") or "").strip()
    return render_accounts_ping_response(
        request,
        settings,
        "",
        "status",
        "general",
        window_hours,
        limit=limit,
        issues_page=issues_page,
        stable_page=stable_page,
        issues_sort=issues_sort,
        issues_dir=issues_dir,
        stable_sort=stable_sort,
        stable_dir=stable_dir,
        query=query,
    )


def _accounts_ping_tuning_context(settings):
    normalized = copy.deepcopy(settings or {})
    ssh_cfg = normalized.get("ssh") if isinstance(normalized.get("ssh"), dict) else {}
    general = normalized.get("general") if isinstance(normalized.get("general"), dict) else {}
    ping_cfg = normalized.get("ping") if isinstance(normalized.get("ping"), dict) else {}
    source_cfg = normalized.get("source") if isinstance(normalized.get("source"), dict) else {}
    storage_cfg = normalized.get("storage") if isinstance(normalized.get("storage"), dict) else {}
    mikrotik_cfg = source_cfg.get("mikrotik") if isinstance(source_cfg.get("mikrotik"), dict) else {}
    router_enabled = mikrotik_cfg.get("router_enabled") if isinstance(mikrotik_cfg.get("router_enabled"), dict) else {}
    source_cfg["mode"] = normalize_accounts_ping_source_mode(source_cfg.get("mode"))
    try:
        refresh_minutes = int(source_cfg.get("refresh_minutes", ACCOUNTS_PING_DEFAULTS["source"]["refresh_minutes"]) or 1)
    except Exception:
        refresh_minutes = int(ACCOUNTS_PING_DEFAULTS["source"]["refresh_minutes"])
    source_cfg["refresh_minutes"] = max(refresh_minutes, 1)
    mikrotik_cfg["router_enabled"] = {
        str(key).strip(): bool(value)
        for key, value in router_enabled.items()
        if str(key).strip()
    }
    source_cfg["mikrotik"] = mikrotik_cfg

    try:
        configured_parallel = int(general.get("max_parallel", ACCOUNTS_PING_DEFAULTS["general"]["max_parallel"]) or 1)
    except Exception:
        configured_parallel = int(ACCOUNTS_PING_DEFAULTS["general"]["max_parallel"])
    configured_parallel = max(configured_parallel, 1)

    cpu_cores = max(int(os.cpu_count() or 1), 1)
    mem_total_kb = int((_memory_details_kb() or {}).get("mem_total_kb") or 0)
    ram_gb = round(mem_total_kb / (1024 * 1024), 1) if mem_total_kb > 0 else 0.0
    safe_parallel_cap = max(8, min(32, cpu_cores * 4))
    effective_parallel = configured_parallel

    general["max_parallel"] = configured_parallel
    normalized["ssh"] = ssh_cfg
    normalized["general"] = general
    normalized["ping"] = ping_cfg
    normalized["source"] = source_cfg
    normalized["storage"] = storage_cfg

    if cpu_cores <= 2 or ram_gb < 4:
        recommendation = {
            "tier": "Low Hardware",
            "max_parallel": min(8, safe_parallel_cap),
            "base_interval_seconds": 20,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 30,
            "raw_retention_days": 30,
            "bucket_seconds": 120,
        }
    elif cpu_cores <= 4 or ram_gb < 8:
        recommendation = {
            "tier": "Balanced Hardware",
            "max_parallel": min(12, safe_parallel_cap),
            "base_interval_seconds": 10,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 20,
            "raw_retention_days": 90,
            "bucket_seconds": 60,
        }
    elif cpu_cores <= 8 or ram_gb < 16:
        recommendation = {
            "tier": "High Hardware",
            "max_parallel": min(16, safe_parallel_cap),
            "base_interval_seconds": 5,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 15,
            "raw_retention_days": 180,
            "bucket_seconds": 60,
        }
    else:
        recommendation = {
            "tier": "Very High Hardware",
            "max_parallel": min(24, safe_parallel_cap),
            "base_interval_seconds": 3,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 10,
            "raw_retention_days": 365,
            "bucket_seconds": 30,
        }

    tiers = [
        {
            "label": "Low (2 cores / 4GB)",
            "max_parallel": "4–8",
            "base_interval_seconds": "20–30s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "30m",
            "raw_retention_days": "30d",
            "bucket_seconds": "120s",
        },
        {
            "label": "Balanced (4 cores / 8GB)",
            "max_parallel": "8–12",
            "base_interval_seconds": "10–20s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "15–20m",
            "raw_retention_days": "90d",
            "bucket_seconds": "60s",
        },
        {
            "label": "High (8 cores / 16GB)",
            "max_parallel": "12–16",
            "base_interval_seconds": "5–10s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "10–15m",
            "raw_retention_days": "180d",
            "bucket_seconds": "60s",
        },
        {
            "label": "Very High (12+ cores / 24GB+)",
            "max_parallel": "16–24",
            "base_interval_seconds": "3–5s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "10m",
            "raw_retention_days": "365d",
            "bucket_seconds": "30–60s",
        },
    ]

    return normalized, {
        "cpu_cores": cpu_cores,
        "ram_gb": ram_gb,
        "safe_parallel_cap": safe_parallel_cap,
        "configured_parallel": configured_parallel,
        "effective_parallel": effective_parallel,
        "was_clamped": False,
        "recommendation": recommendation,
        "tiers": tiers,
    }


@app.get("/accounts-ping/series", response_class=JSONResponse)
async def accounts_ping_series(account_id: str, window: int = 24):
    hours = _normalize_wan_window(window)
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    chosen_ip = (get_accounts_ping_latest_ip_since(account_id, since_iso) or "").strip()
    rows = get_accounts_ping_series(account_id, since_iso)
    if chosen_ip:
        rows = [row for row in rows if (row.get("ip") or "").strip() == chosen_ip]
    series = [
        {
            "ts": row.get("timestamp"),
            "ok": bool(row.get("ok")),
            "loss": row.get("loss"),
            "avg_ms": row.get("avg_ms"),
        }
        for row in rows
    ]
    return _json_no_store({"hours": hours, "series": series})


def _parse_iso_z(value):
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1]
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _format_duration_short(seconds):
    if seconds is None:
        return ""
    try:
        seconds = int(seconds)
    except Exception:
        return ""
    if seconds < 0:
        seconds = 0
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


ACCOUNTS_PING_CLASSIFICATION_LABELS = {
    "issue_loss_pct": "Issue Loss %",
    "issue_latency_ms": "Issue Latency",
    "down_loss_pct": "Down Loss %",
    "stable_rto_pct": "Stable Fail %",
    "issue_rto_pct": "Issue Fail %",
    "issue_streak": "Issue Streak",
}


def _normalize_accounts_ping_classification(raw):
    defaults = ACCOUNTS_PING_DEFAULTS.get("classification", {}) or {}
    source = raw if isinstance(raw, dict) else {}
    return {
        "issue_loss_pct": parse_float(source, "issue_loss_pct", defaults.get("issue_loss_pct", 20.0)),
        "issue_latency_ms": parse_float(source, "issue_latency_ms", defaults.get("issue_latency_ms", 200.0)),
        "down_loss_pct": parse_float(source, "down_loss_pct", defaults.get("down_loss_pct", 100.0)),
        "stable_rto_pct": parse_float(source, "stable_rto_pct", defaults.get("stable_rto_pct", 2.0)),
        "issue_rto_pct": parse_float(source, "issue_rto_pct", defaults.get("issue_rto_pct", 5.0)),
        "issue_streak": parse_int(source, "issue_streak", defaults.get("issue_streak", 2)),
    }


def _accounts_ping_applied_classification(settings=None, state=None):
    settings = settings if isinstance(settings, dict) else get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    saved = _normalize_accounts_ping_classification(settings.get("classification"))
    state = state if isinstance(state, dict) else get_state("accounts_ping_state", {})
    applied = state.get("classification_applied") if isinstance(state.get("classification_applied"), dict) else {}
    if not applied:
        return dict(saved)
    return _normalize_accounts_ping_classification(applied)


def _accounts_ping_settings_with_classification(settings, classification):
    merged = copy.deepcopy(settings or {})
    merged["classification"] = _normalize_accounts_ping_classification(classification)
    return merged


def _format_accounts_ping_classification_value(key, value):
    if value is None:
        return "n/a"
    if key == "issue_streak":
        try:
            return str(int(value))
        except Exception:
            return str(value)
    try:
        numeric = float(value)
    except Exception:
        return str(value)
    if key.endswith("_ms"):
        return f"{numeric:g} ms"
    if key.endswith("_pct"):
        return f"{numeric:g}%"
    return f"{numeric:g}"


def _accounts_ping_classification_changes(saved, applied):
    saved = _normalize_accounts_ping_classification(saved)
    applied = _normalize_accounts_ping_classification(applied)
    changes = []
    for key, label in ACCOUNTS_PING_CLASSIFICATION_LABELS.items():
        old_value = applied.get(key)
        new_value = saved.get(key)
        if old_value == new_value:
            continue
        changes.append(
            {
                "key": key,
                "label": label,
                "from": _format_accounts_ping_classification_value(key, old_value),
                "to": _format_accounts_ping_classification_value(key, new_value),
            }
        )
    return changes


def build_accounts_ping_status(
    settings,
    window_hours=24,
    limit=50,
    issues_page=1,
    stable_page=1,
    issues_sort="",
    issues_dir="",
    stable_sort="",
    stable_dir="",
    query="",
    include_sparklines=True,
):
    window_hours = max(int(window_hours or 24), 1)
    limit = _parse_table_limit(limit, default=50)
    issues_page = _parse_table_page(issues_page, default=1)
    stable_page = _parse_table_page(stable_page, default=1)
    state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
    devices = _accounts_ping_state_devices(state)
    account_map = {}
    for device in devices:
        ip = (device.get("ip") or "").strip()
        pppoe = (device.get("pppoe") or device.get("name") or "").strip() or ip
        aid = (device.get("account_id") or "").strip() or _accounts_ping_account_id_for_device(device)
        if not aid:
            continue
        account_map[aid] = {
            "id": aid,
            "name": pppoe,
            "ip": ip,
            "router_id": (device.get("router_id") or "").strip(),
            "router_name": (device.get("router_name") or "").strip(),
            "source_mode": normalize_accounts_ping_source_mode(device.get("source_mode")),
            "source_missing": bool(device.get("source_missing")),
        }

    account_rows = list(account_map.values())
    account_ids = [row["id"] for row in account_rows]
    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).replace(microsecond=0).isoformat() + "Z"
    stats_by_ip_map = get_accounts_ping_window_stats_by_ip(account_ids, since_iso)

    state_accounts = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}

    cls = _normalize_accounts_ping_classification(settings.get("classification"))
    issue_loss_pct = float(cls.get("issue_loss_pct", 20.0) or 20.0)
    issue_latency_ms = float(cls.get("issue_latency_ms", 200.0) or 200.0)
    stable_rto_pct = float(cls.get("stable_rto_pct", 2.0) or 2.0)
    issue_rto_pct = float(cls.get("issue_rto_pct", 5.0) or 5.0)
    issue_streak = int(cls.get("issue_streak", 2) or 2)
    down_loss_pct = float(cls.get("down_loss_pct", 100.0) or 100.0)

    chosen_ip_map = {}
    for account in account_rows:
        aid = account["id"]
        st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
        chosen_ip_map[aid] = (st.get("last_ip") or account.get("ip") or "").strip()

    issue_rows = []
    stable_rows = []
    pending_total = 0
    for account in account_rows:
        aid = account["id"]
        st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
        chosen_ip = chosen_ip_map.get(aid) or (st.get("last_ip") or account.get("ip") or "").strip()
        stats = (stats_by_ip_map.get(aid) or {}).get(chosen_ip) or {}
        loss = st.get("last_loss")
        avg_ms = st.get("last_avg_ms")
        has_recent = bool(st.get("last_check_at"))
        last_ok = bool(st.get("last_ok")) if has_recent else True
        if has_recent and last_ok and loss is not None:
            try:
                if float(loss) >= down_loss_pct:
                    last_ok = False
            except Exception:
                pass
        last_seen = format_ts_ph(st.get("last_check_at")) if has_recent else "n/a"
        last_seen_raw = (st.get("last_check_at") or "").strip()

        total = int(stats.get("total") or 0)
        failures = int(stats.get("failures") or 0)
        rto_pct = (failures / total) * 100.0 if total else 0.0
        uptime_pct = 100.0 - rto_pct

        streak = int(st.get("streak") or 0)
        down_since_dt = _parse_iso_z(st.get("down_since"))
        down_for = _format_duration_short((datetime.utcnow() - down_since_dt).total_seconds()) if down_since_dt else ""
        down_seconds = int((datetime.utcnow() - down_since_dt).total_seconds()) if down_since_dt else 0

        issue_hit = False
        reasons = []
        if not has_recent:
            pending_total += 1
            status = "pending"
            reasons = ["Not yet checked"]
        else:
            if not last_ok:
                issue_hit = True
                reasons.append("Currently down")
            if loss is not None and float(loss) >= issue_loss_pct:
                issue_hit = True
                reasons.append(f"Loss >= {issue_loss_pct:g}%")
            if avg_ms is not None and float(avg_ms) >= issue_latency_ms:
                issue_hit = True
                reasons.append(f"Latency >= {issue_latency_ms:g}ms")
            if total and rto_pct >= issue_rto_pct:
                issue_hit = True
                reasons.append(f"Fail % >= {issue_rto_pct:g}%")
            if streak >= issue_streak and not last_ok:
                issue_hit = True
                reasons.append(f"Streak {streak}")

            is_stable = last_ok and (not issue_hit) and ((not total) or rto_pct <= stable_rto_pct)
            status = "down" if not last_ok else ("up" if is_stable else "monitor")

            if status == "monitor" and total and rto_pct > stable_rto_pct:
                reasons.append(f"Fail % > {stable_rto_pct:g}%")

        if status not in ("pending", "down", "up", "monitor"):
            status = "pending"
            reasons = ["Not yet checked"]

        row = {
            "id": aid,
            "name": account["name"],
            "ip": chosen_ip or account["ip"],
            "router_id": account.get("router_id") or (st.get("router_id") or "").strip(),
            "router_name": account.get("router_name") or (st.get("router_name") or "").strip(),
            "display_name": (
                f"{account['name']} ({account.get('router_name') or st.get('router_name')})"
                if (account.get("router_name") or st.get("router_name"))
                else account["name"]
            ),
            "status": status,
            "loss": loss,
            "avg_ms": avg_ms,
            "total": total,
            "failures": failures,
            "rto_pct": rto_pct,
            "uptime_pct": uptime_pct,
            "streak": streak,
            "down_for": down_for,
            "down_seconds": down_seconds,
            "last_check": last_seen,
            "last_check_at": last_seen_raw,
            "reasons": reasons or (["OK"] if status == "up" else ["Monitor"]),
            "spark_points_24h": "",
            "spark_points_24h_large": "",
            "pending": status == "pending",
        }
        if bool(st.get("source_missing")) and status == "down":
            row["reasons"] = ["Not in active connections"] + [
                reason for reason in row["reasons"] if reason != "Currently down"
            ]
        if status in ("up", "pending"):
            stable_rows.append(row)
        else:
            issue_rows.append(row)

    def _sort_numeric(val, desc=False):
        if val is None:
            return (1, 0.0)
        try:
            num = float(val)
        except Exception:
            return (1, 0.0)
        return (0, -num if desc else num)

    def _sort_text(val, desc=False):
        text = (val or "").strip().lower()
        return (0, "".join(reversed(text)) if desc else text)

    def _sort_key_for(row, key, desc=False):
        if key in ("customer", "name"):
            label = row.get("display_name") or row.get("name")
            return _sort_text(label, desc=desc)
        if key in ("ip", "ipv4"):
            return _sort_text(row.get("ip"), desc=desc)
        if key in ("router", "router_name"):
            return _sort_text(row.get("router_name"), desc=desc)
        if key == "status":
            order = {"down": 0, "monitor": 1, "up": 2, "pending": 3}
            return (0, -order.get(row.get("status"), 9) if desc else order.get(row.get("status"), 9))
        if key in ("loss", "loss_pct"):
            return _sort_numeric(row.get("loss"), desc=desc)
        if key in ("latency", "avg_ms"):
            return _sort_numeric(row.get("avg_ms"), desc=desc)
        if key in ("fail", "fail_pct", "rto_pct"):
            return _sort_numeric(row.get("rto_pct"), desc=desc)
        if key in ("uptime", "uptime_pct"):
            return _sort_numeric(row.get("uptime_pct"), desc=desc)
        if key == "streak":
            return _sort_numeric(row.get("streak"), desc=desc)
        if key in ("down_for", "down_seconds"):
            return _sort_numeric(row.get("down_seconds"), desc=desc)
        if key in ("last_check", "last_check_at"):
            return _sort_text(row.get("last_check_at"), desc=desc)
        if key == "reason":
            return _sort_text("; ".join(row.get("reasons") or []), desc=desc)
        return _sort_text(row.get("name"), desc=desc)

    q = (query or "").strip().lower()
    if q:
        def match_row(row):
            hay = " ".join(
                [
                    str(row.get("name") or ""),
                    str(row.get("router_name") or ""),
                    str(row.get("ip") or ""),
                    " ".join(row.get("reasons") or []),
                ]
            ).lower()
            return q in hay

        issue_rows = [row for row in issue_rows if match_row(row)]
        stable_rows = [row for row in stable_rows if match_row(row)]
        pending_total = sum(1 for row in stable_rows if row.get("status") == "pending")

    # defaults
    default_issue = sorted(
        issue_rows,
        key=lambda x: (
            x["status"] != "down",
            -(x["loss"] or 0),
            -(x["avg_ms"] or 0),
            (x.get("name") or "").lower(),
            (x.get("router_name") or "").lower(),
        ),
    )
    default_stable = sorted(
        stable_rows,
        key=lambda x: (x.get("pending", False), (x.get("name") or "").lower(), (x.get("router_name") or "").lower()),
    )

    issues_sort = (issues_sort or "").strip()
    stable_sort = (stable_sort or "").strip()
    issues_desc = (issues_dir or "").lower() != "asc"
    stable_desc = (stable_dir or "").lower() != "asc"

    issue_rows = (
        sorted(issue_rows, key=lambda row: _sort_key_for(row, issues_sort, desc=issues_desc))
        if issues_sort
        else default_issue
    )
    stable_rows = (
        sorted(stable_rows, key=lambda row: _sort_key_for(row, stable_sort, desc=stable_desc))
        if stable_sort
        else default_stable
    )

    stable_up_total = sum(1 for row in stable_rows if row.get("status") == "up")
    down_total = sum(1 for row in issue_rows if row.get("status") == "down")
    monitor_total = sum(1 for row in issue_rows if row.get("status") == "monitor")

    paged_issue, issue_page_meta = _paginate_items(issue_rows, issues_page, limit)
    paged_stable, stable_page_meta = _paginate_items(stable_rows, stable_page, limit)

    spark_map = {}
    if include_sparklines:
        paged_ids = sorted({row["id"] for row in (paged_issue + paged_stable) if row.get("id")})
        if paged_ids:
            spark_since_iso = (datetime.utcnow() - timedelta(hours=24)).replace(microsecond=0).isoformat() + "Z"
            spark_rows = get_accounts_ping_rollups_since(spark_since_iso, paged_ids)
            for row in spark_rows:
                aid = (row.get("account_id") or "").strip()
                if not aid:
                    continue
                chosen_ip = chosen_ip_map.get(aid) or ""
                if chosen_ip and (row.get("ip") or "").strip() != chosen_ip:
                    continue
                sample_count = int(row.get("sample_count") or 0)
                ok_count = int(row.get("ok_count") or 0)
                pct = (ok_count / sample_count) * 100.0 if sample_count > 0 else 0.0
                spark_map.setdefault(aid, []).append(pct)

    def with_spark(row):
        aid = row.get("id")
        if row.get("pending"):
            next_row = dict(row)
            next_row["spark_points_24h"] = ""
            next_row["spark_points_24h_large"] = ""
            return next_row
        spark_values = spark_map.get(aid, [])
        next_row = dict(row)
        next_row["spark_points_24h"] = _sparkline_points_fixed(spark_values or [0], 0, 100, width=140, height=28)
        next_row["spark_points_24h_large"] = _sparkline_points_fixed(spark_values or [0], 0, 100, width=640, height=200)
        return next_row

    paged_issue = [with_spark(row) for row in paged_issue]
    paged_stable = [with_spark(row) for row in paged_stable]

    window_label = next((label for label, hours in WAN_STATUS_WINDOW_OPTIONS if hours == window_hours), "1D")
    preferred_tab = "issues"
    if str(query or "").strip():
        if stable_rows and not issue_rows:
            preferred_tab = "stable"
        elif issue_rows:
            preferred_tab = "issues"
    return {
        "total": len(issue_rows) + len(stable_rows),
        "issue_total": len(issue_rows),
        "down_total": down_total,
        "monitor_total": monitor_total,
        "stable_total": stable_up_total,
        "pending_total": pending_total,
        "preferred_tab": preferred_tab,
        "issue_rows": paged_issue,
        "stable_rows": paged_stable,
        "window_hours": window_hours,
        "window_label": window_label,
        "pagination": {
            "limit": limit,
            "limit_label": "ALL" if not limit else str(limit),
            "options": TABLE_PAGE_SIZE_OPTIONS,
            "issues": issue_page_meta,
            "stable": stable_page_meta,
        },
        "sort": {
            "issues": {"key": issues_sort, "dir": "desc" if issues_desc else "asc"},
            "stable": {"key": stable_sort, "dir": "desc" if stable_desc else "asc"},
        },
        "query": query or "",
        "rules": {
            "issue_loss_pct": issue_loss_pct,
            "issue_latency_ms": issue_latency_ms,
            "down_loss_pct": down_loss_pct,
            "stable_rto_pct": stable_rto_pct,
            "issue_rto_pct": issue_rto_pct,
            "issue_streak": issue_streak,
        },
    }


def _build_accounts_ping_classification_patch_context(settings, window_hours):
    state = get_state("accounts_ping_state", {})
    saved_classification = _normalize_accounts_ping_classification(settings.get("classification"))
    applied_classification = _accounts_ping_applied_classification(settings, state)
    patch_available = saved_classification != applied_classification
    context = {
        "patch_available": patch_available,
        "saved_classification": saved_classification,
        "applied_classification": applied_classification,
        "changes": _accounts_ping_classification_changes(saved_classification, applied_classification),
        "applied_at": format_ts_ph((state.get("classification_applied_at") or "").strip()),
        "window_label": next(
            (label for label, hours in WAN_STATUS_WINDOW_OPTIONS if int(hours or 0) == int(window_hours or 24)),
            f"{int(window_hours or 24)}h",
        ),
        "preview": None,
    }
    if not patch_available:
        return context

    before_status = build_accounts_ping_status(
        _accounts_ping_settings_with_classification(settings, applied_classification),
        window_hours,
        limit=0,
        query="",
        include_sparklines=False,
    )
    after_status = build_accounts_ping_status(
        _accounts_ping_settings_with_classification(settings, saved_classification),
        window_hours,
        limit=0,
        query="",
        include_sparklines=False,
    )
    before_rows = (before_status.get("issue_rows") or []) + (before_status.get("stable_rows") or [])
    after_rows = (after_status.get("issue_rows") or []) + (after_status.get("stable_rows") or [])
    before_map = {str(row.get("id") or ""): row for row in before_rows if str(row.get("id") or "")}
    after_map = {str(row.get("id") or ""): row for row in after_rows if str(row.get("id") or "")}
    affected_rows = []
    moved_to_stable = 0
    moved_to_issues = 0
    moved_to_down = 0
    moved_out_of_down = 0
    for account_id in sorted(set(before_map.keys()) | set(after_map.keys())):
        before_row = before_map.get(account_id) or {}
        after_row = after_map.get(account_id) or {}
        before_status_name = (before_row.get("status") or "pending").strip().lower()
        after_status_name = (after_row.get("status") or "pending").strip().lower()
        if before_status_name == after_status_name:
            continue
        before_issue = before_status_name in ("down", "monitor")
        after_issue = after_status_name in ("down", "monitor")
        if before_issue and not after_issue:
            moved_to_stable += 1
        elif (not before_issue) and after_issue:
            moved_to_issues += 1
        if before_status_name != "down" and after_status_name == "down":
            moved_to_down += 1
        elif before_status_name == "down" and after_status_name != "down":
            moved_out_of_down += 1
        affected_rows.append(
            {
                "name": after_row.get("display_name") or before_row.get("display_name") or after_row.get("name") or before_row.get("name") or account_id,
                "from_status": before_status_name,
                "to_status": after_status_name,
                "from_fail_pct": float(before_row.get("rto_pct") or 0.0),
                "to_fail_pct": float(after_row.get("rto_pct") or 0.0),
            }
        )
    status_order = {"down": 0, "monitor": 1, "up": 2, "pending": 3}
    affected_rows.sort(
        key=lambda row: (
            status_order.get(row.get("to_status"), 9),
            status_order.get(row.get("from_status"), 9),
            (row.get("name") or "").lower(),
        )
    )
    context["preview"] = {
        "affected_total": len(affected_rows),
        "moved_to_stable": moved_to_stable,
        "moved_to_issues": moved_to_issues,
        "moved_to_down": moved_to_down,
        "moved_out_of_down": moved_out_of_down,
        "before": {
            "issue_total": int(before_status.get("issue_total") or 0),
            "stable_total": int(before_status.get("stable_total") or 0),
            "down_total": int(before_status.get("down_total") or 0),
            "monitor_total": int(before_status.get("monitor_total") or 0),
            "pending_total": int(before_status.get("pending_total") or 0),
        },
        "after": {
            "issue_total": int(after_status.get("issue_total") or 0),
            "stable_total": int(after_status.get("stable_total") or 0),
            "down_total": int(after_status.get("down_total") or 0),
            "monitor_total": int(after_status.get("monitor_total") or 0),
            "pending_total": int(after_status.get("pending_total") or 0),
        },
        "sample_rows": affected_rows[:8],
    }
    return context


def render_accounts_ping_response(
    request,
    settings,
    message,
    active_tab,
    settings_tab,
    window_hours=24,
    limit=None,
    issues_page=None,
    stable_page=None,
    issues_sort="",
    issues_dir="",
    stable_sort="",
    stable_dir="",
    query="",
):
    can_run_danger_actions = _auth_request_has_permission(request, "accounts_ping.settings.danger.run")
    settings_tab = (settings_tab or "general").strip().lower()
    if settings_tab not in ("general", "source", "classification", "storage"):
        settings_tab = "general"
    settings, tuning = _accounts_ping_tuning_context(settings)
    applied_classification = _accounts_ping_applied_classification(settings)
    status_settings = _accounts_ping_settings_with_classification(settings, applied_classification)
    status_map = {item["job_name"]: dict(item) for item in get_job_status()}
    job_status = status_map.get("accounts_ping", {})
    job_status["last_run_at_ph"] = format_ts_ph(job_status.get("last_run_at"))
    job_status["last_success_at_ph"] = format_ts_ph(job_status.get("last_success_at"))
    if limit is None:
        limit = _parse_table_limit(request.query_params.get("limit"), default=50)
    if issues_page is None:
        issues_page = _parse_table_page(request.query_params.get("issues_page"), default=1)
    if stable_page is None:
        stable_page = _parse_table_page(request.query_params.get("stable_page"), default=1)
    if not issues_sort:
        issues_sort = (request.query_params.get("issues_sort") or "").strip()
    if not issues_dir:
        issues_dir = (request.query_params.get("issues_dir") or "").strip().lower()
    if not stable_sort:
        stable_sort = (request.query_params.get("stable_sort") or "").strip()
    if not stable_dir:
        stable_dir = (request.query_params.get("stable_dir") or "").strip().lower()
    if not query:
        query = (request.query_params.get("q") or "").strip()
    status = build_accounts_ping_status(
        status_settings,
        window_hours,
        limit=limit,
        issues_page=issues_page,
        stable_page=stable_page,
        issues_sort=issues_sort,
        issues_dir=issues_dir,
        stable_sort=stable_sort,
        stable_dir=stable_dir,
        query=query,
    )
    classification_patch = _build_accounts_ping_classification_patch_context(settings, window_hours)
    ping_state = get_state("accounts_ping_state", {})
    router_state_rows = ping_state.get("router_status") if isinstance(ping_state.get("router_status"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row
        for row in router_state_rows
        if isinstance(row, dict) and (row.get("router_id") or "").strip()
    }
    return templates.TemplateResponse(
        "settings_accounts_ping.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "accounts_ping_status": status,
                "accounts_ping_job": job_status,
                "accounts_ping_window_options": WAN_STATUS_WINDOW_OPTIONS,
                "accounts_ping_tuning": tuning,
                "can_run_danger_actions": can_run_danger_actions,
                "wan_settings": normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS)),
                "accounts_ping_router_state": router_state_map,
                "accounts_ping_classification_patch": classification_patch,
            },
        ),
    )


def _accounts_ping_render_params_from_form(request: Request, form) -> dict:
    window_hours = _normalize_wan_window((form.get("window") or "").strip() or request.query_params.get("window"))
    limit = _parse_table_limit(form.get("limit"), default=_parse_table_limit(request.query_params.get("limit"), default=50))
    issues_page = _parse_table_page(form.get("issues_page"), default=_parse_table_page(request.query_params.get("issues_page"), default=1))
    stable_page = _parse_table_page(form.get("stable_page"), default=_parse_table_page(request.query_params.get("stable_page"), default=1))
    issues_sort = (form.get("issues_sort") or request.query_params.get("issues_sort") or "").strip()
    issues_dir = (form.get("issues_dir") or request.query_params.get("issues_dir") or "").strip().lower()
    stable_sort = (form.get("stable_sort") or request.query_params.get("stable_sort") or "").strip()
    stable_dir = (form.get("stable_dir") or request.query_params.get("stable_dir") or "").strip().lower()
    query = (form.get("q") or request.query_params.get("q") or "").strip()
    return {
        "window_hours": window_hours,
        "limit": limit,
        "issues_page": issues_page,
        "stable_page": stable_page,
        "issues_sort": issues_sort,
        "issues_dir": issues_dir,
        "stable_sort": stable_sort,
        "stable_dir": stable_dir,
        "query": query,
    }


def _accounts_ping_state_devices(state=None):
    state = state if isinstance(state, dict) else get_state("accounts_ping_state", {"devices": []})
    raw_devices = state.get("devices") if isinstance(state.get("devices"), list) else []
    devices = []
    for raw_device in raw_devices:
        device = normalize_accounts_ping_device(raw_device)
        if device:
            devices.append(device)
    return devices


def _accounts_ping_account_id_for_pppoe(pppoe, source_mode=ACCOUNTS_PING_SOURCE_SSH_CSV, router_id=""):
    return build_accounts_ping_account_id(pppoe, source_mode=source_mode, router_id=router_id)


def _accounts_ping_account_id_for_device(device):
    normalized = normalize_accounts_ping_device(device)
    if not normalized:
        return ""
    return (normalized.get("account_id") or "").strip()


def _accounts_ping_account_ids_for_pppoe(pppoe, state=None):
    pppoe_value = (pppoe or "").strip()
    if not pppoe_value:
        return []
    devices = _accounts_ping_state_devices(state)
    mapping = build_accounts_ping_account_ids_by_pppoe(devices)
    account_ids = list(mapping.get(pppoe_value.lower()) or [])
    fallback = _accounts_ping_account_id_for_pppoe(pppoe_value)
    if not account_ids and fallback:
        account_ids = [fallback]
    return account_ids


def _accounts_ping_account_ids_for_pppoe_router(pppoe, router_id="", state=None):
    pppoe_value = (pppoe or "").strip()
    router_value = (router_id or "").strip()
    if not pppoe_value:
        return []
    if not router_value:
        return _accounts_ping_account_ids_for_pppoe(pppoe_value, state=state)
    devices = _accounts_ping_state_devices(state)
    account_ids = []
    for device in devices:
        if (device.get("pppoe") or "").strip().lower() != pppoe_value.lower():
            continue
        if (device.get("router_id") or "").strip() != router_value:
            continue
        account_id = (device.get("account_id") or "").strip()
        if account_id and account_id not in account_ids:
            account_ids.append(account_id)
    fallback = _accounts_ping_account_id_for_pppoe(
        pppoe_value,
        source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
        router_id=router_value,
    )
    if not account_ids and fallback:
        account_ids = [fallback]
    return account_ids


def _accounts_ping_window_stats_aggregate(account_ids, since_iso):
    account_ids = [aid for aid in (account_ids or []) if (aid or "").strip()]
    if not account_ids:
        return {}
    stats_map = get_accounts_ping_window_stats(account_ids, since_iso)
    total = 0
    failures = 0
    avg_ms_sum = 0.0
    avg_ms_weight = 0.0
    loss_sum = 0.0
    loss_weight = 0.0
    for account_id in account_ids:
        row = (stats_map.get(account_id) or {}) if isinstance(stats_map, dict) else {}
        row_total = int(row.get("total") or 0)
        total += row_total
        failures += int(row.get("failures") or 0)
        avg_ms_avg = row.get("avg_ms_avg")
        if avg_ms_avg is not None:
            try:
                avg_ms_sum += float(avg_ms_avg) * max(row_total, 1)
                avg_ms_weight += max(row_total, 1)
            except Exception:
                pass
        loss_avg = row.get("loss_avg")
        if loss_avg is not None:
            try:
                loss_sum += float(loss_avg) * max(row_total, 1)
                loss_weight += max(row_total, 1)
            except Exception:
                pass
    return {
        "total": total,
        "failures": failures,
        "avg_ms_avg": (avg_ms_sum / avg_ms_weight) if avg_ms_weight > 0 else None,
        "loss_avg": (loss_sum / loss_weight) if loss_weight > 0 else None,
    }


def _accounts_ping_latest_row_for_account_ids(account_ids):
    account_ids = [aid for aid in (account_ids or []) if (aid or "").strip()]
    if not account_ids:
        return {}
    latest_map = get_latest_accounts_ping_map(account_ids)
    rows = [latest_map.get(aid) for aid in account_ids] if isinstance(latest_map, dict) else []
    rows = [row for row in rows if isinstance(row, dict)]
    if not rows:
        return {}
    return max(rows, key=lambda row: ((row.get("timestamp") or "").strip(), (row.get("account_id") or "").strip()))


def _accounts_ping_series_rows_for_account_ids(account_ids, since_iso, until_iso=""):
    rows = []
    account_ids = [aid for aid in (account_ids or []) if (aid or "").strip()]
    for account_id in account_ids:
        if until_iso:
            rows.extend(get_accounts_ping_series_range(account_id, since_iso, until_iso) or [])
        else:
            rows.extend(get_accounts_ping_series(account_id, since_iso) or [])
    return sorted(rows, key=lambda row: ((row.get("timestamp") or "").strip(), (row.get("account_id") or "").strip()))


def _accounts_ping_rollup_rows_for_account_ids(account_ids, since_iso, until_iso):
    account_ids = [aid for aid in (account_ids or []) if (aid or "").strip()]
    merged = {}
    for account_id in account_ids:
        for row in get_accounts_ping_rollups_range(account_id, since_iso, until_iso) or []:
            bucket_ts = (row.get("bucket_ts") or "").strip()
            if not bucket_ts:
                continue
            item = merged.setdefault(
                bucket_ts,
                {
                    "bucket_ts": bucket_ts,
                    "sample_count": 0,
                    "ok_count": 0,
                    "avg_sum": 0.0,
                    "avg_count": 0,
                    "loss_sum": 0.0,
                    "loss_count": 0,
                    "min_ms": None,
                    "max_ms": None,
                    "max_avg_ms": None,
                },
            )
            item["sample_count"] += int(row.get("sample_count") or 0)
            item["ok_count"] += int(row.get("ok_count") or 0)
            try:
                item["avg_sum"] += float(row.get("avg_sum") or 0.0)
            except Exception:
                pass
            item["avg_count"] += int(row.get("avg_count") or 0)
            try:
                item["loss_sum"] += float(row.get("loss_sum") or 0.0)
            except Exception:
                pass
            item["loss_count"] += int(row.get("loss_count") or 0)
            for field, reducer in (("min_ms", min), ("max_ms", max), ("max_avg_ms", max)):
                value = row.get(field)
                if value is None:
                    continue
                current = item.get(field)
                try:
                    item[field] = value if current is None else reducer(float(current), float(value))
                except Exception:
                    item[field] = current if current is not None else value
    return [merged[key] for key in sorted(merged)]


def _accounts_ping_best_state_entry(account_ids, state_accounts):
    order = {"down": 0, "issue": 1, "up": 2}
    candidates = []
    for account_id in account_ids or []:
        entry = state_accounts.get(account_id) if isinstance(state_accounts.get(account_id), dict) else {}
        if not entry:
            continue
        status = (entry.get("last_status") or "").strip().lower()
        rank = order.get(status, 3)
        candidates.append((rank, (entry.get("last_check_at") or "").strip(), entry))
    if not candidates:
        return {}
    best_rank = min(item[0] for item in candidates)
    ranked = [item for item in candidates if item[0] == best_rank]
    return max(ranked, key=lambda item: item[1])[2]


def _accounts_ping_account_id_for_ip(ip):
    # Backward-compatible wrapper (legacy callers still pass an IP string).
    return _accounts_ping_account_id_for_pppoe(ip)


def _accounts_ping_settings_from_form(form):
    existing = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    existing, _ = _accounts_ping_tuning_context(existing)
    existing_source = existing.get("source") if isinstance(existing.get("source"), dict) else {}
    existing_mikrotik = existing_source.get("mikrotik") if isinstance(existing_source.get("mikrotik"), dict) else {}
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    system_routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
    router_count = parse_int(form, "router_count", len(system_routers))
    router_enabled = {}
    for idx in range(router_count):
        router_id = (form.get(f"router_{idx}_id") or "").strip()
        if not router_id:
            continue
        router_enabled[router_id] = parse_bool(form, f"router_{idx}_enabled")
    if not router_enabled and isinstance(existing_mikrotik.get("router_enabled"), dict):
        router_enabled = {
            str(key).strip(): bool(value)
            for key, value in existing_mikrotik.get("router_enabled", {}).items()
            if str(key).strip()
        }
    return {
        "enabled": parse_bool(form, "enabled"),
        "ssh": {
            "host": (form.get("ssh_host") or "").strip(),
            "port": parse_int(form, "ssh_port", 22),
            "user": (form.get("ssh_user") or "").strip(),
            "password": (form.get("ssh_password") or "").strip(),
            "use_key": parse_bool(form, "ssh_use_key"),
            "key_path": (form.get("ssh_key_path") or "").strip(),
            "remote_csv_path": (form.get("ssh_remote_csv_path") or "").strip() or "/opt/libreqos/src/ShapedDevices.csv",
        },
        "source": {
            "mode": normalize_accounts_ping_source_mode(form.get("source_mode")),
            "refresh_minutes": parse_int(form, "source_refresh_minutes", 15),
            "mikrotik": {
                "router_enabled": router_enabled,
            },
        },
        "general": {
            "base_interval_seconds": parse_int(form, "base_interval_seconds", 30),
            "max_parallel": parse_int(form, "max_parallel", ACCOUNTS_PING_DEFAULTS["general"]["max_parallel"]),
        },
        "ping": {
            "count": parse_int(form, "ping_count", 3),
            "timeout_seconds": parse_int(form, "ping_timeout_seconds", 1),
        },
        "classification": {
            "issue_loss_pct": parse_float(form, "issue_loss_pct", 20.0),
            "issue_latency_ms": parse_float(form, "issue_latency_ms", 200.0),
            "down_loss_pct": parse_float(form, "down_loss_pct", 100.0),
            "stable_rto_pct": parse_float(form, "stable_rto_pct", 2.0),
            "issue_rto_pct": parse_float(form, "issue_rto_pct", 5.0),
            "issue_streak": parse_int(form, "issue_streak", 2),
        },
        "storage": {
            "raw_retention_days": parse_int(form, "raw_retention_days", 30),
            "rollup_retention_days": parse_int(form, "rollup_retention_days", 365),
            "bucket_seconds": parse_int(form, "bucket_seconds", 60),
        },
    }


@app.post("/settings/accounts-ping", response_class=HTMLResponse)
async def accounts_ping_settings_save(request: Request):
    form = await request.form()
    existing_settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    existing_settings, _ = _accounts_ping_tuning_context(existing_settings)
    state = get_state("accounts_ping_state", {})
    settings_tab = (form.get("settings_tab") or "general").strip().lower()
    if settings_tab == "classification" and not isinstance(state.get("classification_applied"), dict):
        state["classification_applied"] = _normalize_accounts_ping_classification(existing_settings.get("classification"))
        state["classification_applied_at"] = (state.get("classification_applied_at") or "").strip() or utc_now_iso()
        save_state("accounts_ping_state", state)
    settings = _accounts_ping_settings_from_form(form)
    settings, tuning = _accounts_ping_tuning_context(settings)
    save_settings("accounts_ping", settings)
    render_params = _accounts_ping_render_params_from_form(request, form)
    active_tab = form.get("active_tab", "settings")
    if settings_tab not in ("general", "source", "classification", "storage"):
        settings_tab = "general"
    applied_classification = _accounts_ping_applied_classification(settings, state)
    if settings_tab == "classification" and _normalize_accounts_ping_classification(settings.get("classification")) != applied_classification:
        message = "Accounts Ping settings saved. Patch Classification to apply the new rules to live results."
    else:
        message = "Accounts Ping settings saved."
    return render_accounts_ping_response(request, settings, message, active_tab, settings_tab, **render_params)


@app.post("/settings/accounts-ping/test", response_class=HTMLResponse)
async def accounts_ping_settings_test(request: Request):
    form = await request.form()
    cfg = _accounts_ping_settings_from_form(form)
    cfg, _ = _accounts_ping_tuning_context(cfg)
    render_params = _accounts_ping_render_params_from_form(request, form)
    message = ""
    try:
        state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
        wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
        routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
        source_mode, devices, router_status = build_accounts_ping_source_devices(
            cfg,
            routers=routers,
            previous_devices=state.get("devices") if isinstance(state.get("devices"), list) else [],
            now=datetime.utcnow(),
        )
        state["devices"] = devices
        state["router_status"] = router_status
        state["devices_refreshed_at"] = utc_now_iso()
        save_state("accounts_ping_state", state)
        if source_mode == ACCOUNTS_PING_SOURCE_MIKROTIK:
            active_total = sum(1 for item in devices if not bool(item.get("source_missing")))
            preserved_total = sum(1 for item in devices if bool(item.get("source_missing")))
            ok_routers = sum(1 for row in router_status if isinstance(row, dict) and bool(row.get("connected")))
            message = (
                f"MikroTik source OK. Loaded {active_total} active session(s) from {ok_routers} router(s) "
                f"and kept {preserved_total} inactive tracked session(s) visible as down candidates."
            )
        else:
            message = f"SSH OK. Loaded {len(state['devices'])} accounts from CSV."
    except Exception as exc:
        message = f"Accounts Ping source test failed: {exc}"
    return render_accounts_ping_response(request, cfg, message, "settings", "source", **render_params)


@app.post("/settings/accounts-ping/patch-classification", response_class=HTMLResponse)
async def accounts_ping_patch_classification(request: Request):
    form = await request.form()
    settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    settings, _ = _accounts_ping_tuning_context(settings)
    state = get_state("accounts_ping_state", {})
    state["classification_applied"] = _normalize_accounts_ping_classification(settings.get("classification"))
    state["classification_applied_at"] = utc_now_iso()
    save_state("accounts_ping_state", state)
    render_params = _accounts_ping_render_params_from_form(request, form)
    window_hours = int(render_params.get("window_hours") or 24)
    window_label = next((label for label, hours in WAN_STATUS_WINDOW_OPTIONS if int(hours or 0) == window_hours), f"{window_hours}h")
    message = f"Accounts Ping classification patched for the current {window_label} window."
    return render_accounts_ping_response(request, settings, message, "status", "classification", **render_params)


@app.post("/settings/accounts-ping/format", response_class=HTMLResponse)
async def accounts_ping_settings_format(request: Request):
    return _render_system_danger_notice(request, "accounts_ping")


@app.post("/accounts-ping/investigate", response_class=HTMLResponse)
async def accounts_ping_investigate(request: Request):
    form = await request.form()
    account_id = (form.get("account_id") or "").strip()
    minutes = parse_int(form, "minutes", 15)
    if not account_id:
        return RedirectResponse(url="/settings/accounts-ping", status_code=303)
    state = get_state("accounts_ping_state", {"accounts": {}})
    accounts = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}
    entry = accounts.get(account_id) if isinstance(accounts.get(account_id), dict) else {}
    until = (datetime.utcnow() + timedelta(minutes=max(int(minutes or 1), 1))).replace(microsecond=0).isoformat() + "Z"
    entry["investigate_until"] = until
    accounts[account_id] = entry
    state["accounts"] = accounts
    save_state("accounts_ping_state", state)
    return RedirectResponse(url="/settings/accounts-ping", status_code=303)


def normalize_system_settings(raw):
    cfg = copy.deepcopy(SYSTEM_DEFAULTS)
    if isinstance(raw, dict):
        branding = raw.get("branding")
        if isinstance(branding, dict):
            app_name = (branding.get("app_name") or "").strip()
            if app_name:
                cfg["branding"]["app_name"] = app_name
            cfg["branding"]["company_logo"].update(branding.get("company_logo") or {})
            cfg["branding"]["browser_logo"].update(branding.get("browser_logo") or {})
        ai = raw.get("ai")
        if isinstance(ai, dict):
            cfg["ai"]["enabled"] = bool(ai.get("enabled", cfg["ai"]["enabled"]))
            provider = (ai.get("provider") or cfg["ai"]["provider"]).strip().lower()
            if provider not in ("chatgpt", "gemini"):
                provider = "chatgpt"
            cfg["ai"]["provider"] = provider
            if isinstance(ai.get("chatgpt"), dict):
                cfg["ai"]["chatgpt"].update(ai.get("chatgpt") or {})
            if isinstance(ai.get("gemini"), dict):
                cfg["ai"]["gemini"].update(ai.get("gemini") or {})
            if isinstance(ai.get("report"), dict):
                cfg["ai"]["report"].update(ai.get("report") or {})
        auth = raw.get("auth")
        if isinstance(auth, dict):
            cfg["auth"]["enabled"] = bool(auth.get("enabled", cfg["auth"]["enabled"]))
            if "session_idle_hours" in auth:
                cfg["auth"]["session_idle_hours"] = auth.get("session_idle_hours")
            if "audit_retention_days" in auth:
                cfg["auth"]["audit_retention_days"] = auth.get("audit_retention_days")
            smtp = auth.get("smtp")
            if isinstance(smtp, dict):
                cfg["auth"]["smtp"].update(smtp)

    branding_cfg = cfg.get("branding") if isinstance(cfg.get("branding"), dict) else {}
    app_name = (branding_cfg.get("app_name") or "ThreeJ Notifier").strip() or "ThreeJ Notifier"
    if len(app_name) > 80:
        app_name = app_name[:80].strip()
    branding_cfg["app_name"] = app_name or "ThreeJ Notifier"
    cfg["branding"] = branding_cfg

    for provider in ("chatgpt", "gemini"):
        block = cfg["ai"].get(provider) if isinstance(cfg["ai"].get(provider), dict) else {}
        block["api_key"] = (block.get("api_key") or "").strip()
        block["model"] = (block.get("model") or "").strip() or (
            "gpt-4o-mini" if provider == "chatgpt" else "gemini-2.5-flash-preview-09-2025"
        )
        block["model"] = _normalize_provider_model_id(provider, block["model"])
        try:
            timeout_seconds = int(block.get("timeout_seconds") or 30)
        except Exception:
            timeout_seconds = 30
        try:
            max_tokens = int(block.get("max_tokens") or 900)
        except Exception:
            max_tokens = 900
        block["timeout_seconds"] = max(5, min(timeout_seconds, 180))
        block["max_tokens"] = max(200, min(max_tokens, 4000))
        cfg["ai"][provider] = block

    report = cfg["ai"].get("report") if isinstance(cfg["ai"].get("report"), dict) else {}
    try:
        lookback = int(report.get("lookback_hours") or 24)
    except Exception:
        lookback = 24
    try:
        max_samples = int(report.get("max_samples") or 60)
    except Exception:
        max_samples = 60
    report["lookback_hours"] = max(1, min(lookback, 168))
    report["max_samples"] = max(10, min(max_samples, 300))
    cfg["ai"]["report"] = report
    cfg["ai"]["enabled"] = bool(cfg["ai"].get("enabled"))
    provider = (cfg["ai"].get("provider") or "chatgpt").strip().lower()
    cfg["ai"]["provider"] = provider if provider in ("chatgpt", "gemini") else "chatgpt"

    auth_cfg = cfg.get("auth") if isinstance(cfg.get("auth"), dict) else {}
    auth_cfg["enabled"] = bool(auth_cfg.get("enabled", True))
    try:
        session_idle_hours = int(auth_cfg.get("session_idle_hours") or 8)
    except Exception:
        session_idle_hours = 8
    try:
        audit_retention_days = int(auth_cfg.get("audit_retention_days") or 180)
    except Exception:
        audit_retention_days = 180
    auth_cfg["session_idle_hours"] = max(1, min(session_idle_hours, 72))
    auth_cfg["audit_retention_days"] = max(30, min(audit_retention_days, 3650))

    smtp = auth_cfg.get("smtp") if isinstance(auth_cfg.get("smtp"), dict) else {}
    smtp["host"] = (smtp.get("host") or "").strip()
    try:
        smtp_port = int(smtp.get("port") or 587)
    except Exception:
        smtp_port = 587
    smtp["port"] = max(1, min(smtp_port, 65535))
    smtp["username"] = (smtp.get("username") or "").strip()
    smtp["password"] = (smtp.get("password") or "").strip()
    smtp["from_email"] = (smtp.get("from_email") or "").strip()
    smtp["from_name"] = (smtp.get("from_name") or app_name or "ThreeJ Notifier").strip() or (app_name or "ThreeJ Notifier")
    smtp["use_ssl"] = bool(smtp.get("use_ssl"))
    smtp["use_tls"] = False if smtp["use_ssl"] else bool(smtp.get("use_tls", True))
    auth_cfg["smtp"] = smtp
    cfg["auth"] = auth_cfg
    return cfg


def _format_model_price(value):
    if value is None:
        return "n/a"
    try:
        amount = float(value)
    except Exception:
        return "n/a"
    if amount >= 1:
        return f"${amount:.2f}"
    if amount >= 0.1:
        return f"${amount:.3f}".rstrip("0").rstrip(".")
    return f"${amount:.4f}".rstrip("0").rstrip(".")


def _normalize_provider_model_id(provider, model):
    provider = (provider or "").strip().lower()
    model = (model or "").strip()
    if provider == "gemini":
        if model.startswith("models/"):
            model = model.split("/", 1)[1].strip()
    return model


def _fetch_chatgpt_model_ids(api_key, timeout_seconds=8):
    api_key = (api_key or "").strip()
    if not api_key:
        return [], ""
    try:
        req = urllib.request.Request(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=max(int(timeout_seconds or 8), 5)) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        rows = payload.get("data") if isinstance(payload, dict) else []
        out = []
        for row in rows or []:
            model_id = (row.get("id") or "").strip() if isinstance(row, dict) else ""
            if not model_id:
                continue
            low = model_id.lower()
            if low.startswith(("gpt-", "o1", "o3", "o4", "o5")):
                out.append(model_id)
        out = sorted(set(out), key=lambda x: x.lower())
        return out, ""
    except Exception:
        return [], "Unable to auto-load ChatGPT model list from API key."


def _fetch_gemini_model_ids(api_key, timeout_seconds=8):
    api_key = (api_key or "").strip()
    if not api_key:
        return [], ""
    out = set()
    next_token = ""
    pages = 0
    try:
        while pages < 5:
            pages += 1
            query = {"key": api_key, "pageSize": 1000}
            if next_token:
                query["pageToken"] = next_token
            url = "https://generativelanguage.googleapis.com/v1beta/models?" + urllib.parse.urlencode(query)
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=max(int(timeout_seconds or 8), 5)) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            rows = payload.get("models") if isinstance(payload, dict) else []
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                model_name = _normalize_provider_model_id("gemini", row.get("name") or "")
                methods = row.get("supportedGenerationMethods") if isinstance(row.get("supportedGenerationMethods"), list) else []
                if not model_name.lower().startswith("gemini-"):
                    continue
                if methods and "generateContent" not in methods:
                    continue
                out.add(model_name)
            next_token = (payload.get("nextPageToken") or "").strip() if isinstance(payload, dict) else ""
            if not next_token:
                break
        return sorted(out, key=lambda x: x.lower()), ""
    except Exception:
        return [], "Unable to auto-load Gemini model list from API key."


def _build_ai_model_options(ai_settings, active_tab):
    ai_settings = ai_settings or {}
    catalog_map = {}
    catalog_order = {}
    for provider, rows in AI_MODEL_PRICING.items():
        local_map = {}
        local_order = []
        for item in rows or []:
            model_id = _normalize_provider_model_id(provider, item.get("id") or "")
            if not model_id:
                continue
            local_map[model_id] = {
                "id": model_id,
                "label": (item.get("label") or model_id).strip(),
                "input_per_1m": item.get("input_per_1m"),
                "output_per_1m": item.get("output_per_1m"),
                "free_tier": item.get("free_tier"),
                "recommended_max_tokens": int(item.get("recommended_max_tokens") or 900),
                "max_tokens_hint": (item.get("max_tokens_hint") or "").strip(),
            }
            local_order.append(model_id)
        catalog_map[provider] = local_map
        catalog_order[provider] = local_order

    discovered = {"chatgpt": [], "gemini": []}
    fetch_errors = {"chatgpt": "", "gemini": ""}
    if active_tab == "ai":
        chatgpt_key = ((ai_settings.get("chatgpt") or {}).get("api_key") or "").strip()
        gemini_key = ((ai_settings.get("gemini") or {}).get("api_key") or "").strip()
        discovered["chatgpt"], fetch_errors["chatgpt"] = _fetch_chatgpt_model_ids(chatgpt_key)
        discovered["gemini"], fetch_errors["gemini"] = _fetch_gemini_model_ids(gemini_key)

    options = {}
    for provider in ("chatgpt", "gemini"):
        selected = _normalize_provider_model_id(provider, ((ai_settings.get(provider) or {}).get("model") or ""))
        ids = set(catalog_map.get(provider, {}).keys())
        ids.update([_normalize_provider_model_id(provider, x) for x in discovered.get(provider, []) if x])
        if selected:
            ids.add(selected)

        ordered = []
        for known in catalog_order.get(provider, []):
            if known in ids:
                ordered.append(known)
        for model_id in sorted(ids, key=lambda x: x.lower()):
            if model_id not in ordered:
                ordered.append(model_id)

        provider_options = []
        for model_id in ordered:
            cat = (catalog_map.get(provider) or {}).get(model_id) or {}
            input_cost = cat.get("input_per_1m")
            output_cost = cat.get("output_per_1m")
            free_tier = cat.get("free_tier")
            recommended = int(cat.get("recommended_max_tokens") or 900)
            hint = (cat.get("max_tokens_hint") or "").strip()
            if input_cost is not None and output_cost is not None:
                cost_text = f"In { _format_model_price(input_cost) } / Out { _format_model_price(output_cost) } per 1M tokens"
            else:
                cost_text = "Pricing n/a (check provider billing page)"
            if free_tier is True:
                free_tier_text = "Free Tier: Available"
            elif free_tier is False:
                free_tier_text = "Free Tier: Paid only"
            else:
                free_tier_text = "Free Tier: Unknown"
            provider_options.append(
                {
                    "id": model_id,
                    "label": (cat.get("label") or model_id).strip(),
                    "input_cost_text": _format_model_price(input_cost),
                    "output_cost_text": _format_model_price(output_cost),
                    "cost_text": cost_text,
                    "free_tier": free_tier,
                    "free_tier_text": free_tier_text,
                    "recommended_max_tokens": recommended,
                    "max_tokens_hint": hint or "Set lower values to control report size and cost.",
                }
            )
        options[provider] = provider_options

    return {"options": options, "errors": fetch_errors}


def _ai_report_status_badge(status: str):
    status = (status or "").strip().lower()
    if status in ("queued", "running"):
        return "Generating"
    if status in ("ready", "done"):
        return "Ready"
    if status in ("disabled",):
        return "Disabled"
    if status in ("error",):
        return "Error"
    if status in ("missing_api_key", "missing_key"):
        return "Missing API Key"
    return "n/a"


def _ai_safe_error(exc: Exception):
    text = str(exc or "").strip() or "Unknown error"
    lowered = text.lower()
    if "unauthorized" in lowered or "invalid api key" in lowered or "permission denied" in lowered:
        return "Authentication failed. Check API key and model access."
    if "http 429" in lowered:
        return "AI rate limit reached. Wait a bit, then generate again."
    if "http 503" in lowered or "http 502" in lowered or "http 504" in lowered or "http 500" in lowered:
        return "AI provider is temporarily unavailable. Retry in a few seconds."
    if len(text) > 220:
        text = text[:220].rstrip() + "…"
    return text


def _sample_rows_for_ai(rows, max_samples):
    rows = list(rows or [])
    if len(rows) <= max_samples:
        return rows
    if max_samples <= 1:
        return [rows[-1]]
    out = []
    last_idx = len(rows) - 1
    for idx in range(max_samples):
        pick = round((idx * last_idx) / (max_samples - 1))
        out.append(rows[pick])
    return out


def _normalize_ai_recommendation(value):
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "y", "recommend", "recommended"):
        return "yes"
    if text in ("0", "false", "no", "n", "not_recommended", "not-recommended"):
        return "no"
    return "unknown"


def _normalize_ai_potential_problems(value):
    if isinstance(value, str):
        rows = [line.strip("-• ").strip() for line in value.splitlines() if line.strip()]
    elif isinstance(value, list):
        rows = [str(item or "").strip() for item in value if str(item or "").strip()]
    else:
        rows = []
    return rows[:8]


def _empty_surveillance_ai_report():
    return {
        "status": "",
        "error": "",
        "generated_at": "",
        "cycle_index": 1,
        "provider": "",
        "model": "",
        "text": "",
        "recommend_needs_manual_fix": "unknown",
        "recommendation_reason": "",
        "potential_problems": [],
        "provider_override": "",
        "model_override": "",
    }


def _normalize_surveillance_ai_report(raw):
    report = _empty_surveillance_ai_report()
    if isinstance(raw, dict):
        report["status"] = (raw.get("status") or "").strip().lower()
        report["error"] = (raw.get("error") or "").strip()
        report["generated_at"] = (raw.get("generated_at") or "").strip()
        try:
            report["cycle_index"] = max(int(raw.get("cycle_index") or 1), 1)
        except Exception:
            report["cycle_index"] = 1
        report["provider"] = (raw.get("provider") or "").strip()
        report["model"] = (raw.get("model") or "").strip()
        report["text"] = (raw.get("text") or "").strip()
        report["recommend_needs_manual_fix"] = _normalize_ai_recommendation(raw.get("recommend_needs_manual_fix"))
        report["recommendation_reason"] = (raw.get("recommendation_reason") or "").strip()
        report["potential_problems"] = _normalize_ai_potential_problems(raw.get("potential_problems"))
        report["provider_override"] = (raw.get("provider_override") or "").strip().lower()
        report["model_override"] = (raw.get("model_override") or "").strip()
    if report["text"] and report["status"] in ("error", "missing_api_key", "missing_key", "disabled"):
        report["status"] = "ready"
        report["error"] = ""
    return report


def _surveillance_ai_report_has_content(report):
    report = report or {}
    return bool(
        (report.get("status") or "").strip()
        or (report.get("error") or "").strip()
        or (report.get("generated_at") or "").strip()
        or int(report.get("cycle_index") or 0) > 1
        or (report.get("provider") or "").strip()
        or (report.get("model") or "").strip()
        or (report.get("text") or "").strip()
    )


def _normalize_surveillance_ai_history(raw):
    out = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        stage = (item.get("stage") or "").strip().lower()
        if stage not in _SURV_AI_STAGES:
            continue
        generated_at = (item.get("generated_at") or "").strip()
        text = (item.get("text") or "").strip()
        if not generated_at and not text:
            continue
        try:
            cycle_index = max(int(item.get("cycle_index") or 1), 1)
        except Exception:
            cycle_index = 1
        out.append(
            {
                "stage": stage,
                "cycle_index": cycle_index,
                "generated_at": generated_at,
                "provider": (item.get("provider") or "").strip(),
                "model": (item.get("model") or "").strip(),
                "status": (item.get("status") or "").strip().lower(),
                "error": (item.get("error") or "").strip(),
                "text": text,
                "recommend_needs_manual_fix": _normalize_ai_recommendation(item.get("recommend_needs_manual_fix")),
                "recommendation_reason": (item.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(item.get("potential_problems")),
            }
        )
    if len(out) > 400:
        out = out[-400:]
    return out


def _surveillance_fixed_cycle_count(entry):
    history = _normalize_surveillance_stage_history((entry or {}).get("stage_history"))
    count = 0
    for item in history:
        action = (item.get("action") or "").strip().lower()
        from_stage = (item.get("from") or "").strip().lower()
        to_stage = (item.get("to") or "").strip().lower()
        if action == "mark_fixed" or (from_stage == "level2" and to_stage == "observe"):
            count += 1
    if count <= 0 and (entry or {}).get("last_fixed_at"):
        count = 1
    return max(count, 0)


def _surveillance_cycle_index_for_stage(entry, stage):
    stage = _resolve_surveillance_ai_stage(entry, stage)
    fixed_count = _surveillance_fixed_cycle_count(entry)
    if stage == "observe":
        return max(fixed_count, 1)
    return max(fixed_count + 1, 1)


def _legacy_surveillance_ai_report(entry):
    if not isinstance(entry, dict):
        return _empty_surveillance_ai_report()
    raw = {
        "status": (entry.get("ai_report_status") or "").strip().lower(),
        "error": (entry.get("ai_report_error") or "").strip(),
        "generated_at": (entry.get("ai_report_generated_at") or "").strip(),
        "provider": (entry.get("ai_report_provider") or "").strip(),
        "model": (entry.get("ai_report_model") or "").strip(),
        "text": (entry.get("ai_report_text") or "").strip(),
        "recommend_needs_manual_fix": entry.get("ai_recommend_needs_manual_fix"),
        "recommendation_reason": (entry.get("ai_recommendation_reason") or "").strip(),
        "potential_problems": entry.get("ai_potential_problems"),
        "provider_override": (entry.get("ai_report_provider_override") or "").strip().lower(),
        "model_override": (entry.get("ai_report_model_override") or "").strip(),
    }
    return _normalize_surveillance_ai_report(raw)


def _legacy_surveillance_ai_stage(entry, legacy_report):
    status = ((entry or {}).get("status") or "under").strip().lower()
    if status not in _SURV_AI_STAGES:
        status = "under"
    generated_at = _parse_iso_z((legacy_report or {}).get("generated_at"))
    level2_at = _parse_iso_z((entry or {}).get("level2_at"))
    fixed_at = _parse_iso_z((entry or {}).get("last_fixed_at"))
    if status == "level2":
        if generated_at and level2_at and generated_at < level2_at:
            return "under"
        return "level2"
    if status == "under" and fixed_at:
        if generated_at and generated_at >= fixed_at:
            return "observe"
        return "under"
    return "under"


def _entry_surveillance_ai_reports(entry):
    if not isinstance(entry, dict):
        return {stage: _empty_surveillance_ai_report() for stage in _SURV_AI_STAGES}
    raw_reports = entry.get("ai_reports") if isinstance(entry.get("ai_reports"), dict) else {}
    reports = {stage: _normalize_surveillance_ai_report(raw_reports.get(stage)) for stage in _SURV_AI_STAGES}
    has_stage_content = any(_surveillance_ai_report_has_content(reports.get(stage)) for stage in _SURV_AI_STAGES)
    if not has_stage_content:
        legacy = _legacy_surveillance_ai_report(entry)
        if _surveillance_ai_report_has_content(legacy):
            stage = _legacy_surveillance_ai_stage(entry, legacy)
            reports[stage] = legacy
    entry["ai_reports"] = reports
    entry["ai_report_history"] = _normalize_surveillance_ai_history(entry.get("ai_report_history"))
    pending_stage = (entry.get("ai_report_pending_stage") or "").strip().lower()
    if pending_stage not in _SURV_AI_STAGES:
        pending_stage = ""
    entry["ai_report_pending_stage"] = pending_stage
    return reports


def _resolve_surveillance_ai_stage(entry, fallback_stage=""):
    fallback_stage = (fallback_stage or "").strip().lower()
    if fallback_stage in _SURV_AI_STAGES:
        return fallback_stage
    if isinstance(entry, dict):
        pending = (entry.get("ai_report_pending_stage") or "").strip().lower()
        if pending in _SURV_AI_STAGES:
            return pending
        reports = _entry_surveillance_ai_reports(entry)
        for stage in _SURV_AI_STAGES:
            if (reports.get(stage, {}).get("status") or "").strip().lower() == "queued":
                return stage
        status = (entry.get("status") or "under").strip().lower()
        if status == "level2":
            return "level2"
        if status == "under" and (entry.get("last_fixed_at") or "").strip():
            return "observe"
    return "under"


def _queue_surveillance_ai_report(entry, stage="under", now_iso=None, reset_text=True):
    if not isinstance(entry, dict):
        return
    now_iso = (now_iso or "").strip() or utc_now_iso()
    stage = _resolve_surveillance_ai_stage(entry, stage)
    cycle_index = _surveillance_cycle_index_for_stage(entry, stage)
    reports = _entry_surveillance_ai_reports(entry)
    report = reports.get(stage) or _empty_surveillance_ai_report()
    report["status"] = "queued"
    report["error"] = ""
    report["generated_at"] = ""
    report["cycle_index"] = cycle_index
    report["provider"] = ""
    report["model"] = ""
    report["recommend_needs_manual_fix"] = "unknown"
    report["recommendation_reason"] = ""
    report["potential_problems"] = []
    report["provider_override"] = ""
    report["model_override"] = ""
    if reset_text:
        report["text"] = ""
    reports[stage] = report
    entry["ai_reports"] = reports
    entry["ai_report_pending_stage"] = stage
    entry["updated_at"] = now_iso


def _build_surveillance_ai_context(pppoe, entry, ai_cfg):
    pppoe = (pppoe or "").strip()
    entry = entry or {}
    lookback_hours = int((ai_cfg.get("report") or {}).get("lookback_hours") or 24)
    max_samples = int((ai_cfg.get("report") or {}).get("max_samples") or 60)
    now = datetime.utcnow().replace(microsecond=0)
    since = now - timedelta(hours=max(lookback_hours, 1))
    since_iso = since.isoformat() + "Z"
    until_iso = now.isoformat() + "Z"
    account_ids = _accounts_ping_account_ids_for_pppoe(pppoe)

    latest = _accounts_ping_latest_row_for_account_ids(account_ids)
    ping_series = _accounts_ping_series_rows_for_account_ids(account_ids, since_iso, until_iso)
    ping_series = _sample_rows_for_ai(ping_series, max_samples)
    ping_samples = []
    down_samples = 0
    for row in ping_series:
        ok = bool(row.get("ok"))
        if not ok:
            down_samples += 1
        ping_samples.append(
            {
                "ts": row.get("timestamp"),
                "ok": ok,
                "loss": row.get("loss"),
                "avg_ms": row.get("avg_ms"),
                "mode": row.get("mode"),
                "ip": row.get("ip"),
            }
        )

    ping_window = _accounts_ping_window_stats_aggregate(account_ids, since_iso)

    optical_latest_map = get_latest_optical_by_pppoe([pppoe])
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_samples_raw = get_optical_results_for_device_since(device_id, since_iso) if device_id else []
    optical_samples_raw = _sample_rows_for_ai(optical_samples_raw, max_samples)
    optical_samples = [
        {"ts": row.get("timestamp"), "rx": row.get("rx"), "tx": row.get("tx")} for row in optical_samples_raw
    ]

    usage_series = get_pppoe_usage_series_since("", pppoe, since_iso)
    usage_series = _sample_rows_for_ai(usage_series, max_samples)
    usage_points = []
    usage_zero_count = 0
    usage_max_total = 0.0
    for row in usage_series:
        rx_bps = float(row.get("rx_bps") or 0.0)
        tx_bps = float(row.get("tx_bps") or 0.0)
        total_bps = max(rx_bps, 0.0) + max(tx_bps, 0.0)
        if total_bps < 1.0:
            usage_zero_count += 1
        usage_max_total = max(usage_max_total, total_bps)
        usage_points.append(
            {
                "ts": row.get("timestamp"),
                "rx_bps": rx_bps,
                "tx_bps": tx_bps,
                "total_bps": total_bps,
                "host_count": row.get("host_count"),
            }
        )

    return {
        "timeframe": {
            "from_utc": since_iso,
            "to_utc": until_iso,
            "lookback_hours": lookback_hours,
        },
        "account": {
            "pppoe": pppoe,
            "status": (entry.get("status") or "").strip(),
            "source": (entry.get("source") or "").strip(),
            "added_mode": (entry.get("added_mode") or "").strip(),
            "added_at": (entry.get("added_at") or "").strip(),
            "moved_to_needs_manual_fix_at": (entry.get("level2_at") or "").strip(),
            "needs_manual_fix_reason": (entry.get("level2_reason") or "").strip(),
            "last_ip": (entry.get("ip") or "").strip(),
        },
        "accounts_ping": {
            "latest": {
                "timestamp": latest.get("timestamp") if isinstance(latest, dict) else None,
                "ok": latest.get("ok") if isinstance(latest, dict) else None,
                "loss": latest.get("loss") if isinstance(latest, dict) else None,
                "avg_ms": latest.get("avg_ms") if isinstance(latest, dict) else None,
                "ip": latest.get("ip") if isinstance(latest, dict) else None,
                "mode": latest.get("mode") if isinstance(latest, dict) else None,
            },
            "window_summary": {
                "sample_total": int((ping_window or {}).get("total") or 0),
                "failure_total": int((ping_window or {}).get("failures") or 0),
                "loss_avg": (ping_window or {}).get("loss_avg"),
                "latency_avg_ms": (ping_window or {}).get("avg_ms_avg"),
                "down_sample_total": down_samples,
            },
            "series": ping_samples,
        },
        "optical": {
            "latest": optical_latest if isinstance(optical_latest, dict) else {},
            "series": optical_samples,
        },
        "usage": {
            "series": usage_points,
            "max_total_bps": usage_max_total,
            "zero_usage_samples": usage_zero_count,
            "total_samples": len(usage_points),
        },
    }


def _set_surveillance_ai_fields(pppoe, stage, report_fields=None, entry_fields=None, append_history=None):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return False
    stage = _resolve_surveillance_ai_stage({}, stage)
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe)
    if not isinstance(entry, dict):
        return False
    reports = _entry_surveillance_ai_reports(entry)
    report = reports.get(stage) or _empty_surveillance_ai_report()
    for key, value in (report_fields or {}).items():
        report[key] = value
    reports[stage] = _normalize_surveillance_ai_report(report)
    entry["ai_reports"] = reports
    if isinstance(append_history, dict):
        history = _normalize_surveillance_ai_history(entry.get("ai_report_history"))
        try:
            history_cycle_index = max(int(append_history.get("cycle_index") or report.get("cycle_index") or 1), 1)
        except Exception:
            history_cycle_index = 1
        item = {
            "stage": stage,
            "cycle_index": history_cycle_index,
            "generated_at": (append_history.get("generated_at") or report.get("generated_at") or "").strip(),
            "provider": (append_history.get("provider") or report.get("provider") or "").strip(),
            "model": (append_history.get("model") or report.get("model") or "").strip(),
            "status": (append_history.get("status") or report.get("status") or "").strip().lower(),
            "error": (append_history.get("error") or report.get("error") or "").strip(),
            "text": (append_history.get("text") or report.get("text") or "").strip(),
            "recommend_needs_manual_fix": _normalize_ai_recommendation(
                append_history.get("recommend_needs_manual_fix") or report.get("recommend_needs_manual_fix")
            ),
            "recommendation_reason": (append_history.get("recommendation_reason") or report.get("recommendation_reason") or "").strip(),
            "potential_problems": _normalize_ai_potential_problems(
                append_history.get("potential_problems") or report.get("potential_problems")
            ),
        }
        if item.get("generated_at") or item.get("text"):
            history.append(item)
            entry["ai_report_history"] = _normalize_surveillance_ai_history(history)
    for key, value in (entry_fields or {}).items():
        entry[key] = value
    entry["updated_at"] = utc_now_iso()
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    return True


def _run_surveillance_ai_report(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return
    stage = "under"
    try:
        system_cfg = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
        ai_cfg = system_cfg.get("ai") if isinstance(system_cfg.get("ai"), dict) else {}

        settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entry_map = _surveillance_entry_map(settings)
        entry = entry_map.get(pppoe) or {}
        stage = _resolve_surveillance_ai_stage(entry)
        cycle_index = _surveillance_cycle_index_for_stage(entry, stage)

        if not ai_cfg or not ai_cfg.get("enabled"):
            _set_surveillance_ai_fields(
                pppoe,
                stage,
                report_fields={
                    "status": "disabled",
                    "error": "AI Investigator is disabled in System Settings.",
                    "generated_at": utc_now_iso(),
                    "cycle_index": cycle_index,
                    "recommend_needs_manual_fix": "unknown",
                    "recommendation_reason": "",
                    "potential_problems": [],
                },
                entry_fields={"ai_report_pending_stage": ""},
            )
            return

        effective_ai_cfg = copy.deepcopy(ai_cfg if isinstance(ai_cfg, dict) else {})
        reports = _entry_surveillance_ai_reports(entry)
        stage_report = reports.get(stage) or _empty_surveillance_ai_report()
        override_provider = (stage_report.get("provider_override") or "").strip().lower()
        override_model = (stage_report.get("model_override") or "").strip()
        if override_provider in ("chatgpt", "gemini"):
            effective_ai_cfg["provider"] = override_provider
        provider = (effective_ai_cfg.get("provider") or "chatgpt").strip().lower()
        if provider not in ("chatgpt", "gemini"):
            provider = "chatgpt"
            effective_ai_cfg["provider"] = provider
        provider_cfg = effective_ai_cfg.get(provider) if isinstance(effective_ai_cfg.get(provider), dict) else {}
        if override_model:
            provider_cfg["model"] = _normalize_provider_model_id(provider, override_model)
            effective_ai_cfg[provider] = provider_cfg
        if not (provider_cfg.get("api_key") or "").strip():
            _set_surveillance_ai_fields(
                pppoe,
                stage,
                report_fields={
                    "status": "missing_api_key",
                    "error": f"Missing API key for {provider}.",
                    "generated_at": utc_now_iso(),
                    "cycle_index": cycle_index,
                    "recommend_needs_manual_fix": "unknown",
                    "recommendation_reason": "",
                    "potential_problems": [],
                    "provider_override": "",
                    "model_override": "",
                },
                entry_fields={"ai_report_pending_stage": ""},
            )
            return

        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "running",
                "error": "",
                "generated_at": "",
                "cycle_index": cycle_index,
                "recommend_needs_manual_fix": "unknown",
                "recommendation_reason": "",
                "potential_problems": [],
            },
        )
        settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entry_map = _surveillance_entry_map(settings)
        entry = entry_map.get(pppoe) or {}
        context = _build_surveillance_ai_context(pppoe, entry, effective_ai_cfg)
        try:
            report = generate_investigation_report(effective_ai_cfg, context)
        except AIInvestigatorError as exc:
            err_text = str(exc or "").lower()
            if "timed out" not in err_text:
                raise
            retry_ai_cfg = copy.deepcopy(effective_ai_cfg if isinstance(effective_ai_cfg, dict) else {})
            retry_report_cfg = retry_ai_cfg.get("report") if isinstance(retry_ai_cfg.get("report"), dict) else {}
            current_samples = int(retry_report_cfg.get("max_samples") or 60)
            current_hours = int(retry_report_cfg.get("lookback_hours") or 24)
            retry_report_cfg["max_samples"] = max(10, min(current_samples // 2 if current_samples > 20 else 20, 40))
            retry_report_cfg["lookback_hours"] = max(1, min(current_hours, 48))
            retry_ai_cfg["report"] = retry_report_cfg
            context = _build_surveillance_ai_context(pppoe, entry, retry_ai_cfg)
            report = generate_investigation_report(retry_ai_cfg, context)
        ready_at_iso = utc_now_iso()
        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "ready",
                "error": "",
                "generated_at": ready_at_iso,
                "cycle_index": cycle_index,
                "provider": report.get("provider") or provider,
                "model": report.get("model") or (provider_cfg.get("model") or ""),
                "text": (report.get("text") or "").strip(),
                "recommend_needs_manual_fix": _normalize_ai_recommendation(report.get("recommend_needs_manual_fix")),
                "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
                "provider_override": "",
                "model_override": "",
            },
            entry_fields={"ai_report_pending_stage": ""},
            append_history={
                "stage": stage,
                "cycle_index": cycle_index,
                "generated_at": ready_at_iso,
                "provider": report.get("provider") or provider,
                "model": report.get("model") or (provider_cfg.get("model") or ""),
                "status": "ready",
                "error": "",
                "text": (report.get("text") or "").strip(),
                "recommend_needs_manual_fix": _normalize_ai_recommendation(report.get("recommend_needs_manual_fix")),
                "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
            },
        )
    except AIInvestigatorError as exc:
        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "error",
                "error": _ai_safe_error(exc),
                "generated_at": utc_now_iso(),
                "cycle_index": cycle_index,
                "recommend_needs_manual_fix": "unknown",
                "recommendation_reason": "",
                "potential_problems": [],
                "provider_override": "",
                "model_override": "",
            },
            entry_fields={"ai_report_pending_stage": ""},
        )
    except Exception as exc:
        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "error",
                "error": _ai_safe_error(exc),
                "generated_at": utc_now_iso(),
                "cycle_index": cycle_index,
                "recommend_needs_manual_fix": "unknown",
                "recommendation_reason": "",
                "potential_problems": [],
                "provider_override": "",
                "model_override": "",
            },
            entry_fields={"ai_report_pending_stage": ""},
        )
    finally:
        with _surv_ai_lock:
            _surv_ai_running.discard(pppoe)
        _start_next_queued_surveillance_ai_report(exclude_pppoe=pppoe)


def _start_surveillance_ai_report(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return False
    with _surv_ai_lock:
        if pppoe in _surv_ai_running:
            return False
        if len(_surv_ai_running) >= max(int(_SURV_AI_MAX_PARALLEL), 1):
            return False
        _surv_ai_running.add(pppoe)
    worker = threading.Thread(target=_run_surveillance_ai_report, args=(pppoe,), daemon=True)
    worker.start()
    return True


def _start_next_queued_surveillance_ai_report(exclude_pppoe=""):
    exclude_pppoe = (exclude_pppoe or "").strip()
    try:
        settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entry_map = _surveillance_entry_map(settings)
    except Exception:
        return False
    for pppoe, entry in entry_map.items():
        if not isinstance(entry, dict):
            continue
        pppoe = (pppoe or "").strip()
        if not pppoe or pppoe == exclude_pppoe:
            continue
        status = (entry.get("status") or "under").strip().lower()
        if status not in ("under", "level2", "observe"):
            continue
        reports = _entry_surveillance_ai_reports(entry)
        queued_stage = ""
        for stage in _SURV_AI_STAGES:
            if (reports.get(stage, {}).get("status") or "").strip().lower() == "queued":
                queued_stage = stage
                break
        if not queued_stage:
            continue
        entry["ai_report_pending_stage"] = queued_stage
        settings["entries"] = list(entry_map.values())
        save_settings("surveillance", settings)
        if _start_surveillance_ai_report(pppoe):
            return True
    return False


def normalize_surveillance_settings(raw):
    cfg = copy.deepcopy(SURVEILLANCE_DEFAULTS)
    if isinstance(raw, dict):
        cfg["enabled"] = bool(raw.get("enabled", cfg["enabled"]))
        for key in ("ping", "burst", "backoff", "stability", "auto_add"):
            if isinstance(raw.get(key), dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(raw[key])
        if isinstance(raw.get("entries"), list):
            cfg["entries"] = raw["entries"]

    normalized = []
    now_iso = utc_now_iso()
    cfg.setdefault("stability", {})
    cfg["stability"]["require_optical"] = True
    try:
        fixed_minutes = int(cfg["stability"].get("fixed_observation_minutes", cfg["stability"].get("stable_window_minutes", 10)) or 10)
    except Exception:
        fixed_minutes = int(cfg["stability"].get("stable_window_minutes", 10) or 10)
    if fixed_minutes < 1:
        fixed_minutes = 1
    cfg["stability"]["fixed_observation_minutes"] = fixed_minutes
    try:
        loss_max_minutes = float(cfg["stability"].get("loss_max_minutes", 10.0) or 10.0)
    except Exception:
        loss_max_minutes = 10.0
    if loss_max_minutes < 0:
        loss_max_minutes = 0.0
    cfg["stability"]["loss_max_minutes"] = loss_max_minutes
    try:
        loss_event_max_count = int(cfg["stability"].get("loss_event_max_count", 5) or 5)
    except Exception:
        loss_event_max_count = 5
    if loss_event_max_count < 0:
        loss_event_max_count = 0
    cfg["stability"]["loss_event_max_count"] = loss_event_max_count
    urgency_point_defaults = {
        "urgency_no_data_points": 25.0,
        "urgency_current_down_points": 50.0,
        "urgency_down_minutes_cap_points": 30.0,
        "urgency_loss_budget_breach_points": 20.0,
        "urgency_loss_minutes_scale_cap_points": 12.0,
        "urgency_loss_events_breach_points": 15.0,
        "urgency_loss_events_scale_cap_points": 10.0,
        "urgency_high_latency_points": 6.0,
        "urgency_very_high_latency_points": 12.0,
        "urgency_packet_loss_points": 5.0,
        "urgency_severe_packet_loss_points": 10.0,
        "urgency_optical_issue_points": 12.0,
        "urgency_manual_fix_stage_points": 10.0,
    }
    for key, default_value in urgency_point_defaults.items():
        try:
            point_value = float(cfg["stability"].get(key, default_value) or default_value)
        except Exception:
            point_value = default_value
        if point_value < 0:
            point_value = 0.0
        cfg["stability"][key] = point_value
    try:
        latency_mult = float(cfg["stability"].get("urgency_very_high_latency_multiplier", 2.0) or 2.0)
    except Exception:
        latency_mult = 2.0
    if latency_mult < 1.1:
        latency_mult = 1.1
    cfg["stability"]["urgency_very_high_latency_multiplier"] = latency_mult

    try:
        loss_warn_pct = float(cfg["stability"].get("urgency_packet_loss_warn_pct", 5.0) or 5.0)
    except Exception:
        loss_warn_pct = 5.0
    try:
        loss_critical_pct = float(cfg["stability"].get("urgency_packet_loss_critical_pct", 20.0) or 20.0)
    except Exception:
        loss_critical_pct = 20.0
    if loss_warn_pct < 0:
        loss_warn_pct = 0.0
    if loss_critical_pct < loss_warn_pct:
        loss_critical_pct = loss_warn_pct
    cfg["stability"]["urgency_packet_loss_warn_pct"] = loss_warn_pct
    cfg["stability"]["urgency_packet_loss_critical_pct"] = loss_critical_pct

    def _threshold_value(raw_key, default_value):
        try:
            threshold = int(float(cfg["stability"].get(raw_key, default_value) or default_value))
        except Exception:
            threshold = default_value
        if threshold < 0:
            threshold = 0
        if threshold > 100:
            threshold = 100
        return threshold

    critical_threshold = _threshold_value("urgency_critical_threshold", 70)
    high_threshold = _threshold_value("urgency_high_threshold", 45)
    watch_threshold = _threshold_value("urgency_watch_threshold", 25)
    if high_threshold > critical_threshold:
        high_threshold = critical_threshold
    if watch_threshold > high_threshold:
        watch_threshold = high_threshold
    cfg["stability"]["urgency_critical_threshold"] = critical_threshold
    cfg["stability"]["urgency_high_threshold"] = high_threshold
    cfg["stability"]["urgency_watch_threshold"] = watch_threshold
    cfg["stability"].pop("loss_max_pct", None)
    cfg["stability"].pop("level2_autofix_after_minutes", None)
    cfg["stability"].pop("escalate_after_minutes", None)
    cfg.setdefault("auto_add", {})
    if not isinstance(cfg["auto_add"], dict):
        cfg["auto_add"] = copy.deepcopy(SURVEILLANCE_DEFAULTS.get("auto_add") or {})
    sources = cfg["auto_add"].get("sources")
    if not isinstance(sources, dict):
        cfg["auto_add"]["sources"] = {"accounts_ping": True}
    cfg["auto_add"]["sources"].setdefault("accounts_ping", True)
    try:
        wd = float(cfg["auto_add"].get("window_days", 3) or 3)
    except Exception:
        wd = 3.0
    if wd <= 0:
        wd = 3.0
    cfg["auto_add"]["window_days"] = wd
    try:
        mde = int(cfg["auto_add"].get("min_down_events", 5) or 5)
    except Exception:
        mde = 5
    if mde < 1:
        mde = 1
    cfg["auto_add"]["min_down_events"] = mde
    try:
        sim = int(cfg["auto_add"].get("scan_interval_minutes", 5) or 5)
    except Exception:
        sim = 5
    if sim < 1:
        sim = 1
    cfg["auto_add"]["scan_interval_minutes"] = sim
    try:
        mae = int(cfg["auto_add"].get("max_add_per_eval", 3))
    except Exception:
        mae = 3
    if mae is None:
        mae = 3
    if mae < 0:
        mae = 0
    cfg["auto_add"]["max_add_per_eval"] = mae
    for entry in cfg.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        pppoe = (entry.get("pppoe") or entry.get("name") or "").strip()
        if not pppoe:
            continue
        status = (entry.get("status") or "under").strip().lower()
        if status not in ("under", "level2", "observe"):
            status = "under"
        ai_reports = _entry_surveillance_ai_reports(entry)
        pending_stage = _resolve_surveillance_ai_stage(entry, entry.get("ai_report_pending_stage") or "")
        if (ai_reports.get(pending_stage, {}).get("status") or "").strip().lower() != "queued":
            pending_stage = ""
        normalized.append(
            {
                "pppoe": pppoe,
                "name": (entry.get("name") or pppoe).strip(),
                "ip": (entry.get("ip") or "").strip(),
                "source": (entry.get("source") or "").strip(),
                "status": status,
                "added_at": (entry.get("added_at") or "").strip() or now_iso,
                "first_added_at": (entry.get("first_added_at") or entry.get("added_at") or "").strip() or now_iso,
                "updated_at": (entry.get("updated_at") or "").strip() or now_iso,
                "level2_at": (entry.get("level2_at") or "").strip(),
                "level2_reason": (entry.get("level2_reason") or "").strip(),
                "last_fixed_at": (entry.get("last_fixed_at") or "").strip(),
                "last_fixed_reason": (entry.get("last_fixed_reason") or "").strip(),
                "last_fixed_mode": (entry.get("last_fixed_mode") or "").strip(),
                "added_mode": (entry.get("added_mode") or "").strip().lower() or "manual",
                "added_by": (entry.get("added_by") or "").strip()[:64],
                "auto_source": (entry.get("auto_source") or "").strip(),
                "auto_reason": (entry.get("auto_reason") or "").strip(),
                "stage_history": _normalize_surveillance_stage_history(entry.get("stage_history")),
                "ai_reports": ai_reports,
                "ai_report_history": _normalize_surveillance_ai_history(entry.get("ai_report_history")),
                "ai_report_pending_stage": pending_stage,
            }
        )
    cfg["entries"] = normalized
    return cfg


def _surveillance_entry_map(settings):
    entries = settings.get("entries") if isinstance(settings.get("entries"), list) else []
    merged = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pppoe = (entry.get("pppoe") or "").strip()
        if not pppoe:
            continue
        merged[pppoe] = entry
    settings["entries"] = list(merged.values())
    return merged


def _surveillance_entry_from_active_session(session):
    if not isinstance(session, dict):
        return None
    pppoe = (session.get("pppoe") or "").strip()
    if not pppoe or (session.get("ended_at") or "").strip():
        return None
    now_iso = utc_now_iso()
    started_at = (session.get("started_at") or "").strip() or now_iso
    updated_at = (session.get("updated_at") or "").strip() or started_at
    source = (session.get("source") or "").strip()
    status = (session.get("last_state") or "under").strip().lower()
    if status not in ("under", "level2", "observe"):
        status = "under"
    added_mode = "auto" if source == "accounts_ping" else "manual"
    auto_source = source if added_mode == "auto" else ""
    level2_at = ""
    level2_reason = ""
    stage_history = [
        {
            "ts": started_at,
            "from": "",
            "to": "under",
            "reason": "Recovered from active surveillance session.",
            "action": "restore_active_session",
            "actor": "system",
        }
    ]
    if status == "level2":
        stage_ts = updated_at or started_at
        level2_at = stage_ts
        level2_reason = "Recovered from active manual-fix session."
        stage_history.append(
            {
                "ts": stage_ts,
                "from": "under",
                "to": "level2",
                "reason": level2_reason,
                "action": "restore_active_session",
                "actor": "system",
            }
        )
    return {
        "pppoe": pppoe,
        "name": pppoe,
        "ip": (session.get("last_ip") or "").strip(),
        "source": source,
        "status": status,
        "added_at": started_at,
        "first_added_at": started_at,
        "updated_at": updated_at,
        "level2_at": level2_at,
        "level2_reason": level2_reason,
        "last_fixed_at": "",
        "last_fixed_reason": "",
        "last_fixed_mode": "",
        "added_mode": added_mode,
        "added_by": "",
        "auto_source": auto_source,
        "auto_reason": "Recovered from active surveillance session." if auto_source else "",
        "stage_history": _normalize_surveillance_stage_history(stage_history),
        "ai_reports": {stage: _empty_surveillance_ai_report() for stage in _SURV_AI_STAGES},
        "ai_report_history": [],
        "ai_report_pending_stage": "",
    }


def _reconcile_surveillance_active_entries(settings, entry_map=None, persist=False):
    settings = settings if isinstance(settings, dict) else {}
    merged = entry_map if isinstance(entry_map, dict) else _surveillance_entry_map(settings)
    changed = False
    try:
        active_sessions = list_active_surveillance_sessions(limit=5000)
    except Exception:
        active_sessions = []
    for session in active_sessions or []:
        if not isinstance(session, dict):
            continue
        pppoe = (session.get("pppoe") or "").strip()
        if not pppoe or pppoe in merged:
            continue
        recovered = _surveillance_entry_from_active_session(session)
        if not recovered:
            continue
        merged[pppoe] = recovered
        changed = True
    if changed:
        settings["entries"] = list(merged.values())
        if persist:
            save_settings("surveillance", settings)
    return merged, changed


def _normalize_surveillance_stage_history(raw_items):
    out = []
    if not isinstance(raw_items, list):
        return out
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        ts = (item.get("ts") or item.get("at") or "").strip()
        if not ts:
            ts = utc_now_iso()
        from_stage = (item.get("from") or item.get("from_stage") or "").strip().lower()
        to_stage = (item.get("to") or item.get("to_stage") or "").strip().lower()
        reason = (item.get("reason") or item.get("note") or "").strip()
        action = (item.get("action") or "").strip().lower()
        actor = (item.get("actor") or "admin").strip() or "admin"
        out.append(
            {
                "ts": ts,
                "from": from_stage,
                "to": to_stage,
                "reason": reason[:500],
                "action": action[:64],
                "actor": actor[:120],
            }
        )
    if len(out) > 250:
        out = out[-250:]
    return out


def _append_surveillance_stage_history(entry, from_stage, to_stage, reason="", action="", at_iso="", actor="admin"):
    if not isinstance(entry, dict):
        return
    history = _normalize_surveillance_stage_history(entry.get("stage_history"))
    history.append(
        {
            "ts": (at_iso or "").strip() or utc_now_iso(),
            "from": (from_stage or "").strip().lower(),
            "to": (to_stage or "").strip().lower(),
            "reason": (reason or "").strip()[:500],
            "action": (action or "").strip().lower()[:64],
            "actor": (actor or "admin").strip()[:120] or "admin",
        }
    )
    entry["stage_history"] = _normalize_surveillance_stage_history(history)


def _surveillance_added_by_user(entry):
    if not isinstance(entry, dict):
        return ""
    direct = (entry.get("added_by") or "").strip()
    if direct and direct.lower() not in ("system", "auto"):
        return direct[:64]
    history = _normalize_surveillance_stage_history(entry.get("stage_history"))
    for item in history:
        action = (item.get("action") or "").strip().lower()
        to_stage = (item.get("to") or "").strip().lower()
        actor = (item.get("actor") or "").strip()
        if not actor or actor.lower() in ("system", "auto"):
            continue
        if action == "add_manual" or (to_stage == "under" and action in ("", "add")):
            return actor[:64]
    for item in history:
        to_stage = (item.get("to") or "").strip().lower()
        actor = (item.get("actor") or "").strip()
        if to_stage == "under" and actor and actor.lower() not in ("system", "auto"):
            return actor[:64]
    return ""


def _surveillance_stage_seconds(entry, ended_at=None):
    end_dt = ended_at if isinstance(ended_at, datetime) else datetime.utcnow()
    added_at = _parse_iso_z((entry or {}).get("added_at"))
    level2_at = _parse_iso_z((entry or {}).get("level2_at"))
    fixed_at = _parse_iso_z((entry or {}).get("last_fixed_at"))
    status = ((entry or {}).get("status") or "under").strip().lower()

    under_seconds = 0
    level2_seconds = 0
    observe_seconds = 0

    if not added_at:
        return under_seconds, level2_seconds, observe_seconds

    if status == "level2":
        if level2_at and level2_at > added_at:
            under_seconds = max(int((level2_at - added_at).total_seconds()), 0)
            level2_seconds = max(int((end_dt - level2_at).total_seconds()), 0)
        else:
            level2_seconds = max(int((end_dt - added_at).total_seconds()), 0)
        return under_seconds, level2_seconds, observe_seconds

    is_observation = bool(fixed_at and fixed_at >= added_at)
    if is_observation:
        observe_seconds = max(int((end_dt - fixed_at).total_seconds()), 0)
    else:
        under_seconds = max(int((end_dt - added_at).total_seconds()), 0)
    return under_seconds, level2_seconds, observe_seconds


def _normalize_surveillance_stage(stage_value):
    stage = (stage_value or "").strip().lower()
    if stage in ("under", "level2", "observe"):
        return stage
    return "under"


def _surveillance_entry_anchors(entry, stage="under", now_utc=None):
    now = now_utc if isinstance(now_utc, datetime) else datetime.utcnow().replace(microsecond=0)
    stage = _normalize_surveillance_stage(stage)
    entry = entry if isinstance(entry, dict) else {}

    added_iso = (entry.get("added_at") or "").strip()
    fixed_iso = (entry.get("last_fixed_at") or "").strip()
    first_added_iso = (entry.get("first_added_at") or "").strip() or added_iso

    added_dt = _parse_iso_z(added_iso)
    fixed_dt = _parse_iso_z(fixed_iso)
    first_added_dt = _parse_iso_z(first_added_iso)

    if not added_dt:
        added_dt = now
        added_iso = now.isoformat() + "Z"
    if not first_added_dt:
        first_added_dt = added_dt
        first_added_iso = added_iso

    checker_anchor_iso = added_iso
    checker_anchor_dt = added_dt
    checker_anchor_source = "added"
    if fixed_dt and fixed_iso and fixed_dt <= now:
        checker_anchor_iso = fixed_iso
        checker_anchor_dt = fixed_dt
        checker_anchor_source = "fixed"

    stage_anchor_iso = added_iso
    stage_anchor_dt = added_dt
    stage_anchor_source = "added"
    if stage == "observe" and fixed_dt and fixed_iso and fixed_dt <= now:
        stage_anchor_iso = fixed_iso
        stage_anchor_dt = fixed_dt
        stage_anchor_source = "fixed"

    return {
        "stage": stage,
        "added_iso": added_iso,
        "added_dt": added_dt,
        "fixed_iso": fixed_iso,
        "fixed_dt": fixed_dt,
        "first_added_iso": first_added_iso,
        "first_added_dt": first_added_dt,
        "checker_anchor_iso": checker_anchor_iso,
        "checker_anchor_dt": checker_anchor_dt,
        "checker_anchor_source": checker_anchor_source,
        "stage_anchor_iso": stage_anchor_iso,
        "stage_anchor_dt": stage_anchor_dt,
        "stage_anchor_source": stage_anchor_source,
    }


def _surveillance_checker_stats_zero():
    return {
        "total": 0,
        "failures": 0,
        "loss_avg": None,
        "avg_ms_avg": None,
        "downtime_seconds": 0,
        "loss_events": 0,
    }


def _surveillance_checker_maps(entry_map, now_utc=None):
    if not isinstance(entry_map, dict):
        entry_map = {}
    now = now_utc if isinstance(now_utc, datetime) else datetime.utcnow().replace(microsecond=0)
    now_iso = now.isoformat() + "Z"
    checker_anchor_by_pppoe = {}
    checker_since_by_account = {}
    for pppoe, raw_entry in entry_map.items():
        if not pppoe:
            continue
        entry = raw_entry if isinstance(raw_entry, dict) else {}
        added_iso = (entry.get("added_at") or "").strip()
        fixed_iso = (entry.get("last_fixed_at") or "").strip()
        added_dt = _parse_iso_z(added_iso)
        fixed_dt = _parse_iso_z(fixed_iso)

        anchor_iso = added_iso or now_iso
        anchor_dt = added_dt or now
        anchor_source = "added"
        if fixed_dt and fixed_iso and fixed_dt <= now:
            anchor_iso = fixed_iso
            anchor_dt = fixed_dt
            anchor_source = "fixed"

        checker_anchor_by_pppoe[pppoe] = {
            "since_iso": anchor_iso,
            "since_dt": anchor_dt,
            "source": anchor_source,
        }

        account_id = _accounts_ping_account_id_for_ip(pppoe)
        if not account_id:
            continue
        current_since = checker_since_by_account.get(account_id)
        if not current_since:
            checker_since_by_account[account_id] = anchor_iso
            continue
        current_dt = _parse_iso_z(current_since)
        if current_dt is None or anchor_dt > current_dt:
            checker_since_by_account[account_id] = anchor_iso
    return checker_anchor_by_pppoe, checker_since_by_account


def _surveillance_checker_refresh_async(target_key, payload, target_until_iso):
    try:
        fresh_rows = get_accounts_ping_checker_stats_map(payload, target_until_iso)
        if not isinstance(fresh_rows, dict):
            fresh_rows = {}
        with _surveillance_checker_cache_lock:
            if _surveillance_checker_cache.get("key") == target_key:
                _surveillance_checker_cache["at"] = time.monotonic()
                _surveillance_checker_cache["data"] = copy.deepcopy(fresh_rows)
    finally:
        with _surveillance_checker_cache_lock:
            if _surveillance_checker_cache.get("key") == target_key:
                _surveillance_checker_cache["refreshing"] = False


def _prime_surveillance_checker_cache(entry_map, reset_pppoes=None, now_utc=None):
    checker_anchor_by_pppoe, checker_since_by_account = _surveillance_checker_maps(entry_map, now_utc=now_utc)
    if not checker_since_by_account:
        return checker_anchor_by_pppoe, checker_since_by_account

    reset_account_ids = set()
    for raw in reset_pppoes or []:
        pppoe = (raw or "").strip()
        if not pppoe:
            continue
        account_id = _accounts_ping_account_id_for_ip(pppoe)
        if account_id:
            reset_account_ids.add(account_id)

    cache_key = tuple(sorted(checker_since_by_account.items()))
    primed_data = {}
    should_refresh = False
    now_mono = time.monotonic()
    with _surveillance_checker_cache_lock:
        cached_key = _surveillance_checker_cache.get("key")
        cached_data = _surveillance_checker_cache.get("data") if isinstance(_surveillance_checker_cache.get("data"), dict) else {}
        old_pairs = cached_key if isinstance(cached_key, tuple) else tuple(cached_key or [])
        old_map = {}
        for item in old_pairs:
            if isinstance(item, tuple) and len(item) == 2:
                aid = (item[0] or "").strip()
                since_iso = (item[1] or "").strip()
                if aid and since_iso:
                    old_map[aid] = since_iso

        can_prime = bool(old_map)
        if can_prime:
            for account_id, since_iso in checker_since_by_account.items():
                if account_id in reset_account_ids:
                    primed_data[account_id] = _surveillance_checker_stats_zero()
                    continue
                if old_map.get(account_id) != since_iso:
                    can_prime = False
                    primed_data = {}
                    break
                row = cached_data.get(account_id)
                if isinstance(row, dict):
                    primed_data[account_id] = copy.deepcopy(row)
                else:
                    primed_data[account_id] = _surveillance_checker_stats_zero()

        if primed_data:
            _surveillance_checker_cache["key"] = cache_key
            _surveillance_checker_cache["at"] = now_mono
            _surveillance_checker_cache["data"] = primed_data
            _surveillance_checker_cache["refreshing"] = True
            should_refresh = True

    if should_refresh:
        until_dt = now_utc if isinstance(now_utc, datetime) else datetime.utcnow().replace(microsecond=0)
        until_iso = until_dt.isoformat() + "Z"
        threading.Thread(
            target=_surveillance_checker_refresh_async,
            args=(cache_key, dict(checker_since_by_account), until_iso),
            daemon=True,
        ).start()

    return checker_anchor_by_pppoe, checker_since_by_account


def _get_surveillance_checker_stats_cached(account_since_map, until_iso):
    if not isinstance(account_since_map, dict) or not account_since_map:
        return {}

    normalized = {}
    for account_id, since_iso in (account_since_map or {}).items():
        aid = (account_id or "").strip()
        since = (since_iso or "").strip()
        if not aid or not since:
            continue
        normalized[aid] = since
    if not normalized:
        return {}

    cache_key = tuple(sorted(normalized.items()))
    now_mono = time.monotonic()

    with _surveillance_checker_cache_lock:
        cached_key = _surveillance_checker_cache.get("key")
        cached_at = float(_surveillance_checker_cache.get("at") or 0.0)
        cached_data = _surveillance_checker_cache.get("data") if isinstance(_surveillance_checker_cache.get("data"), dict) else {}
        refreshing = bool(_surveillance_checker_cache.get("refreshing"))
        if cached_key == cache_key and cached_data:
            age = now_mono - cached_at
            if age < float(_SURVEILLANCE_CHECKER_CACHE_SECONDS):
                return copy.deepcopy(cached_data)
            if not refreshing:
                _surveillance_checker_cache["refreshing"] = True
                threading.Thread(
                    target=_surveillance_checker_refresh_async,
                    args=(cache_key, dict(normalized), until_iso),
                    daemon=True,
                ).start()
            return copy.deepcopy(cached_data)

    with _surveillance_checker_compute_lock:
        with _surveillance_checker_cache_lock:
            cached_key = _surveillance_checker_cache.get("key")
            cached_at = float(_surveillance_checker_cache.get("at") or 0.0)
            cached_data = _surveillance_checker_cache.get("data") if isinstance(_surveillance_checker_cache.get("data"), dict) else {}
            if cached_key == cache_key and cached_data and (time.monotonic() - cached_at) < float(_SURVEILLANCE_CHECKER_CACHE_SECONDS):
                return copy.deepcopy(cached_data)
        fresh = get_accounts_ping_checker_stats_map(normalized, until_iso)
        if not isinstance(fresh, dict):
            fresh = {}
        with _surveillance_checker_cache_lock:
            _surveillance_checker_cache["key"] = cache_key
            _surveillance_checker_cache["at"] = time.monotonic()
            _surveillance_checker_cache["data"] = copy.deepcopy(fresh)
            _surveillance_checker_cache["refreshing"] = False
    return fresh


def _get_surveillance_optical_latest_cached(pppoes):
    if not isinstance(pppoes, list):
        pppoes = list(pppoes or [])
    normalized = sorted({(pppoe or "").strip() for pppoe in pppoes if (pppoe or "").strip()})
    if not normalized:
        return {}
    cache_key = tuple(normalized)
    now_mono = time.monotonic()
    with _surveillance_optical_cache_lock:
        cached_key = _surveillance_optical_cache.get("key")
        cached_at = float(_surveillance_optical_cache.get("at") or 0.0)
        cached_data = _surveillance_optical_cache.get("data") if isinstance(_surveillance_optical_cache.get("data"), dict) else {}
        if cached_key == cache_key and (now_mono - cached_at) < float(_SURVEILLANCE_OPTICAL_CACHE_SECONDS):
            return copy.deepcopy(cached_data)
    fresh = get_latest_optical_by_pppoe(normalized)
    if not isinstance(fresh, dict):
        fresh = {}
    with _surveillance_optical_cache_lock:
        _surveillance_optical_cache["key"] = cache_key
        _surveillance_optical_cache["at"] = now_mono
        _surveillance_optical_cache["data"] = copy.deepcopy(fresh)
    return fresh


def _prewarm_surveillance_checker_cache():
    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    if not entry_map:
        return

    now = datetime.utcnow().replace(microsecond=0)
    now_iso = now.isoformat() + "Z"
    _, checker_since_by_account = _surveillance_checker_maps(entry_map, now_utc=now)

    if checker_since_by_account:
        _get_surveillance_checker_stats_cached(checker_since_by_account, now_iso)
    _get_surveillance_optical_latest_cached(list(entry_map.keys()))


@app.get("/surveillance", response_class=HTMLResponse)
async def surveillance_page(request: Request):
    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry_map, reconciled_entries = _reconcile_surveillance_active_entries(settings, entry_map=entry_map, persist=False)
    if settings != raw or reconciled_entries:
        save_settings("surveillance", settings)

    active_tab = (request.query_params.get("tab") or "").strip().lower()
    focus = (request.query_params.get("focus") or "").strip()
    if active_tab not in ("under", "observe", "level2", "history", "logs", "settings"):
        active_tab = ""
    if focus and focus in entry_map and not active_tab:
        active_tab = "level2" if (entry_map.get(focus, {}).get("status") == "level2") else "under"
    if not active_tab:
        active_tab = "under"

    pppoes = sorted(entry_map.keys(), key=lambda x: x.lower())
    account_ids = [_accounts_ping_account_id_for_ip(pppoe) for pppoe in pppoes]

    stab_cfg = settings.get("stability", {}) or {}
    stable_window_minutes = max(int(stab_cfg.get("stable_window_minutes", 10) or 10), 1)
    stable_window_days = stable_window_minutes / 1440.0
    fixed_observation_minutes = max(
        int(stab_cfg.get("fixed_observation_minutes", stable_window_minutes) or stable_window_minutes),
        1,
    )
    fixed_observation_days = fixed_observation_minutes / 1440.0
    try:
        latency_max_ms = float(stab_cfg.get("latency_max_ms", 15.0) or 15.0)
    except Exception:
        latency_max_ms = 15.0
    if latency_max_ms <= 0:
        latency_max_ms = 15.0
    try:
        loss_max_minutes = float(stab_cfg.get("loss_max_minutes", 10.0) or 10.0)
    except Exception:
        loss_max_minutes = 10.0
    if loss_max_minutes < 0:
        loss_max_minutes = 0.0
    loss_budget_seconds = int(loss_max_minutes * 60)
    try:
        loss_event_max_count = int(stab_cfg.get("loss_event_max_count", 5) or 5)
    except Exception:
        loss_event_max_count = 5
    if loss_event_max_count < 1:
        loss_event_max_count = 1
    try:
        optical_rx_min_dbm = float(stab_cfg.get("optical_rx_min_dbm", -24.0) or -24.0)
    except Exception:
        optical_rx_min_dbm = -24.0
    require_optical = bool(stab_cfg.get("require_optical", True))

    def _urgency_point(name, default_value):
        try:
            value = float(stab_cfg.get(name, default_value) or default_value)
        except Exception:
            value = default_value
        if value < 0:
            value = 0.0
        return value

    urgency_no_data_points = _urgency_point("urgency_no_data_points", 25.0)
    urgency_current_down_points = _urgency_point("urgency_current_down_points", 50.0)
    urgency_down_minutes_cap_points = _urgency_point("urgency_down_minutes_cap_points", 30.0)
    urgency_loss_budget_breach_points = _urgency_point("urgency_loss_budget_breach_points", 20.0)
    urgency_loss_minutes_scale_cap_points = _urgency_point("urgency_loss_minutes_scale_cap_points", 12.0)
    urgency_loss_events_breach_points = _urgency_point("urgency_loss_events_breach_points", 15.0)
    urgency_loss_events_scale_cap_points = _urgency_point("urgency_loss_events_scale_cap_points", 10.0)
    urgency_high_latency_points = _urgency_point("urgency_high_latency_points", 6.0)
    urgency_very_high_latency_points = _urgency_point("urgency_very_high_latency_points", 12.0)
    urgency_very_high_latency_multiplier = _urgency_point("urgency_very_high_latency_multiplier", 2.0)
    if urgency_very_high_latency_multiplier < 1.1:
        urgency_very_high_latency_multiplier = 1.1
    urgency_packet_loss_points = _urgency_point("urgency_packet_loss_points", 5.0)
    urgency_severe_packet_loss_points = _urgency_point("urgency_severe_packet_loss_points", 10.0)
    urgency_packet_loss_warn_pct = _urgency_point("urgency_packet_loss_warn_pct", 5.0)
    urgency_packet_loss_critical_pct = _urgency_point("urgency_packet_loss_critical_pct", 20.0)
    if urgency_packet_loss_critical_pct < urgency_packet_loss_warn_pct:
        urgency_packet_loss_critical_pct = urgency_packet_loss_warn_pct
    urgency_optical_issue_points = _urgency_point("urgency_optical_issue_points", 12.0)
    urgency_manual_fix_stage_points = _urgency_point("urgency_manual_fix_stage_points", 10.0)

    def _urgency_threshold(name, default_value):
        try:
            value = int(float(stab_cfg.get(name, default_value) or default_value))
        except Exception:
            value = default_value
        if value < 0:
            value = 0
        if value > 100:
            value = 100
        return value

    urgency_critical_threshold = _urgency_threshold("urgency_critical_threshold", 70)
    urgency_high_threshold = _urgency_threshold("urgency_high_threshold", 45)
    urgency_watch_threshold = _urgency_threshold("urgency_watch_threshold", 25)
    if urgency_high_threshold > urgency_critical_threshold:
        urgency_high_threshold = urgency_critical_threshold
    if urgency_watch_threshold > urgency_high_threshold:
        urgency_watch_threshold = urgency_high_threshold
    now = datetime.utcnow().replace(microsecond=0)
    now_iso = now.isoformat() + "Z"

    checker_anchor_by_pppoe, checker_since_by_account = _surveillance_checker_maps(entry_map, now_utc=now)

    latest_map = get_latest_accounts_ping_map(account_ids)
    checker_stats_map = _get_surveillance_checker_stats_cached(checker_since_by_account, now_iso)
    optical_latest_map = _get_surveillance_optical_latest_cached(pppoes)
    fixed_cycles_map = get_surveillance_fixed_cycles_map(pppoes, limit_per_pppoe=250)
    ping_state = get_state("accounts_ping_state", {"accounts": {}})
    ping_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}

    def build_row(pppoe):
        entry = entry_map.get(pppoe, {})
        account_id = _accounts_ping_account_id_for_ip(pppoe)
        latest = latest_map.get(account_id) or {}
        checker_meta = checker_anchor_by_pppoe.get(pppoe) or {}
        checker_since_iso = (checker_meta.get("since_iso") or "").strip() or now_iso
        checker_since_dt = checker_meta.get("since_dt")
        if not isinstance(checker_since_dt, datetime):
            checker_since_dt = _parse_iso_z(checker_since_iso) or now
        checker_since_source = (checker_meta.get("source") or "added").strip().lower()
        stats = checker_stats_map.get(account_id) or {}
        opt = optical_latest_map.get(pppoe) or {}
        st = ping_accounts.get(account_id) if isinstance(ping_accounts.get(account_id), dict) else {}

        total = int(stats.get("total") or 0)
        failures = int(stats.get("failures") or 0)
        uptime_pct = (100.0 - (failures / total) * 100.0) if total else 0.0
        checker_downtime_seconds = int(stats.get("downtime_seconds") or 0)
        checker_loss_events = int(stats.get("loss_events") or 0)
        latest_loss = latest.get("loss")
        latest_avg_ms = latest.get("avg_ms")
        try:
            latest_loss_val = float(latest_loss) if latest_loss is not None else None
        except Exception:
            latest_loss_val = None
        try:
            latest_avg_ms_val = float(latest_avg_ms) if latest_avg_ms is not None else None
        except Exception:
            latest_avg_ms_val = None
        try:
            stable_loss_avg_val = float(stats.get("loss_avg")) if stats.get("loss_avg") is not None else None
        except Exception:
            stable_loss_avg_val = None
        added_mode = (entry.get("added_mode") or "manual").strip().lower()
        added_by = _surveillance_added_by_user(entry)
        added_by_display = "Auto" if added_mode == "auto" else (added_by or "Manual")
        has_latest_sample = bool((latest.get("timestamp") or "").strip())
        current_is_down = bool(has_latest_sample and not bool(latest.get("ok")))
        no_ping_data = (not has_latest_sample) and total <= 0

        down_since_dt = _parse_iso_z(st.get("down_since"))
        down_for = _format_duration_short((now - down_since_dt).total_seconds()) if down_since_dt else ""
        down_seconds_now = max(int((now - down_since_dt).total_seconds()), 0) if down_since_dt else 0
        if current_is_down and not down_for and down_seconds_now > 0:
            down_for = _format_duration_short(down_seconds_now)
        optical_rx_value = opt.get("rx")
        try:
            optical_rx_val = float(optical_rx_value) if optical_rx_value is not None else None
        except Exception:
            optical_rx_val = None
        optical_issue_now = bool(
            require_optical
            and optical_rx_val is not None
            and optical_rx_val <= optical_rx_min_dbm
        )
        fixed_at_iso = (entry.get("last_fixed_at") or "").strip()
        fixed_at_dt = _parse_iso_z(fixed_at_iso)
        fixed_cycles = fixed_cycles_map.get(pppoe) or []
        fixed_cycle = fixed_cycles[0] if fixed_cycles else {}
        prefixed_cycle_start_iso = (fixed_cycle.get("started_at") or "").strip()
        prefixed_cycle_end_iso = (fixed_cycle.get("ended_at") or "").strip()
        stage_history = _normalize_surveillance_stage_history(entry.get("stage_history"))
        if not stage_history:
            level2_reason = (entry.get("level2_reason") or "").strip()
            level2_at_iso = (entry.get("level2_at") or "").strip()
            if level2_reason and level2_at_iso:
                stage_history.append(
                    {
                        "ts": level2_at_iso,
                        "from": "under",
                        "to": "level2",
                        "reason": level2_reason[:500],
                        "action": "move_to_manual_fix",
                        "actor": "admin",
                    }
                )
            fixed_reason = (entry.get("last_fixed_reason") or "").strip()
            if fixed_reason and fixed_at_iso:
                stage_history.append(
                    {
                        "ts": fixed_at_iso,
                        "from": "level2",
                        "to": "observe",
                        "reason": fixed_reason[:500],
                        "action": "mark_fixed",
                        "actor": "admin",
                    }
                )
            stage_history = _normalize_surveillance_stage_history(stage_history)
        observation_due_iso = ""
        observation_due_ph = ""
        observation_seconds_left = None
        observation_left_text = ""
        if fixed_at_dt:
            due_dt = fixed_at_dt + timedelta(minutes=fixed_observation_minutes)
            observation_due_iso = due_dt.replace(microsecond=0).isoformat() + "Z"
            observation_due_ph = format_ts_ph(observation_due_iso)
            observation_seconds_left = int((due_dt - now).total_seconds())
            if observation_seconds_left > 0:
                observation_left_text = _format_duration_short(observation_seconds_left)
            else:
                observation_left_text = "Done"
        reports = _entry_surveillance_ai_reports(entry)
        ai_reports = {}
        for stage_key in _SURV_AI_STAGES:
            report = reports.get(stage_key) or _empty_surveillance_ai_report()
            ai_status = (report.get("status") or "").strip().lower()
            ai_report_text = (report.get("text") or "").strip()
            ai_report_error = (report.get("error") or "").strip()
            ai_has_report = bool(ai_report_text)
            if ai_has_report and ai_status in ("error", "missing_api_key", "missing_key", "disabled"):
                ai_status = "ready"
                ai_report_error = ""
            ai_is_generating = ai_status in ("queued", "running")
            ai_has_error = (ai_status in ("error", "missing_api_key", "missing_key") or bool(ai_report_error)) and not ai_has_report
            ai_reports[stage_key] = {
                "stage": stage_key,
                "stage_label": _SURV_AI_STAGE_LABELS.get(stage_key) or stage_key,
                "status": ai_status,
                "status_label": _ai_report_status_badge(ai_status),
                "error": ai_report_error,
                "generated_at_iso": (report.get("generated_at") or "").strip(),
                "generated_at_ph": format_ts_ph(report.get("generated_at")),
                "provider": (report.get("provider") or "").strip(),
                "model": (report.get("model") or "").strip(),
                "text": ai_report_text,
                "recommend_needs_manual_fix": _normalize_ai_recommendation(report.get("recommend_needs_manual_fix")),
                "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
                "has_report": ai_has_report,
                "is_generating": ai_is_generating,
                "has_error": ai_has_error,
            }

        if no_ping_data:
            current_state_label = "No Data"
            current_state_badge = "secondary"
        elif current_is_down:
            current_state_label = "Down"
            current_state_badge = "red"
        elif checker_loss_events > 0 or checker_downtime_seconds > 0:
            current_state_label = "Intermittent"
            current_state_badge = "yellow"
        elif latest_avg_ms_val is not None and latest_avg_ms_val >= latency_max_ms:
            current_state_label = "Slow"
            current_state_badge = "orange"
        else:
            current_state_label = "Stable"
            current_state_badge = "green"

        primary_problem_label = "No active issue"
        primary_problem_badge = "green"
        if no_ping_data:
            primary_problem_label = "No ping samples"
            primary_problem_badge = "secondary"
        elif current_is_down:
            primary_problem_label = "No response"
            primary_problem_badge = "red"
        elif optical_issue_now:
            primary_problem_label = "Optical RX issue"
            primary_problem_badge = "orange"
        elif checker_loss_events >= loss_event_max_count or (
            loss_budget_seconds > 0 and checker_downtime_seconds >= loss_budget_seconds
        ):
            primary_problem_label = "Frequent loss events"
            primary_problem_badge = "red"
        elif (latest_loss_val is not None and latest_loss_val >= urgency_packet_loss_warn_pct) or (
            stable_loss_avg_val is not None and stable_loss_avg_val >= urgency_packet_loss_warn_pct
        ):
            primary_problem_label = "Packet loss"
            primary_problem_badge = "orange"
        elif latest_avg_ms_val is not None and latest_avg_ms_val >= latency_max_ms:
            primary_problem_label = "High latency"
            primary_problem_badge = "yellow"

        impact_sort_seconds = max(checker_downtime_seconds, 0)
        checker_since_ph = format_ts_ph(checker_since_iso)
        checker_window_hint = checker_since_ph or checker_since_iso or "checker window start"
        if no_ping_data:
            impact_label = "No baseline"
            impact_tooltip = (
                f"No ping samples yet since {checker_window_hint}. "
                "Impact is computed from estimated loss time and down-event count in this checker window."
            )
        elif current_is_down and down_for:
            impact_label = f"Down {down_for} · {checker_loss_events} down events"
            impact_sort_seconds = max(impact_sort_seconds, down_seconds_now)
            impact_tooltip = (
                f"Currently down for {down_for}. "
                f"Down events = {checker_loss_events} separate down incidents since {checker_window_hint}."
            )
        else:
            loss_time_text = _format_duration_short(checker_downtime_seconds) if checker_downtime_seconds > 0 else "0m"
            if latest_avg_ms_val is not None and checker_downtime_seconds <= 0 and checker_loss_events <= 0:
                impact_label = f"{latest_avg_ms_val:.1f}ms now · 0 down events"
                impact_tooltip = (
                    f"Current latency is {latest_avg_ms_val:.1f}ms with no down incidents "
                    f"since {checker_window_hint}."
                )
            else:
                impact_label = f"Loss {loss_time_text} · {checker_loss_events} down events"
                impact_tooltip = (
                    f"Estimated accumulated loss time is {loss_time_text}. "
                    f"Down events = {checker_loss_events} separate down incidents since {checker_window_hint}."
                )

        urgency_score = 0.0
        if no_ping_data:
            urgency_score += urgency_no_data_points
        if current_is_down:
            urgency_score += urgency_current_down_points
            urgency_score += min(float(down_seconds_now) / 60.0, urgency_down_minutes_cap_points)
        if loss_budget_seconds > 0 and checker_downtime_seconds >= loss_budget_seconds:
            urgency_score += urgency_loss_budget_breach_points
        elif checker_downtime_seconds > 0:
            urgency_score += min(float(checker_downtime_seconds) / 60.0, urgency_loss_minutes_scale_cap_points)
        if checker_loss_events >= loss_event_max_count:
            urgency_score += urgency_loss_events_breach_points
        elif checker_loss_events > 0:
            urgency_score += min(float(checker_loss_events) * 2.0, urgency_loss_events_scale_cap_points)
        if latest_avg_ms_val is not None:
            if latest_avg_ms_val >= (latency_max_ms * urgency_very_high_latency_multiplier):
                urgency_score += urgency_very_high_latency_points
            elif latest_avg_ms_val >= latency_max_ms:
                urgency_score += urgency_high_latency_points
        if latest_loss_val is not None:
            if latest_loss_val >= urgency_packet_loss_critical_pct:
                urgency_score += urgency_severe_packet_loss_points
            elif latest_loss_val >= urgency_packet_loss_warn_pct:
                urgency_score += urgency_packet_loss_points
        if optical_issue_now:
            urgency_score += urgency_optical_issue_points
        if (entry.get("status") or "").strip().lower() == "level2":
            urgency_score += urgency_manual_fix_stage_points
        urgency_score = max(0, min(int(round(urgency_score)), 100))
        if urgency_score >= urgency_critical_threshold:
            urgency_label = "Critical"
            urgency_badge = "red"
            urgency_sort_rank = 1
        elif urgency_score >= urgency_high_threshold:
            urgency_label = "High"
            urgency_badge = "orange"
            urgency_sort_rank = 2
        elif urgency_score >= urgency_watch_threshold:
            urgency_label = "Watch"
            urgency_badge = "yellow"
            urgency_sort_rank = 3
        else:
            urgency_label = "Normal"
            urgency_badge = "secondary"
            urgency_sort_rank = 4

        return {
            "pppoe": pppoe,
            "name": entry.get("name") or pppoe,
            "entry_id": _surveillance_nav_entry_id(entry),
            "optical_device_id": (opt.get("device_id") or "").strip(),
            "ip": entry.get("ip") or latest.get("ip") or opt.get("ip") or "",
            "status": entry.get("status") or "under",
            "added_mode": added_mode,
            "added_by": added_by,
            "added_by_display": added_by_display,
            "auto_source": (entry.get("auto_source") or "").strip(),
            "auto_reason": (entry.get("auto_reason") or "").strip(),
            "added_at": format_ts_ph(entry.get("added_at")),
            "added_at_iso": (entry.get("added_at") or "").strip(),
            "first_added_at_iso": (entry.get("first_added_at") or entry.get("added_at") or "").strip(),
            "first_added_at_ph": format_ts_ph(entry.get("first_added_at") or entry.get("added_at")),
            "level2_at_iso": (entry.get("level2_at") or "").strip(),
            "level2_at_ph": format_ts_ph(entry.get("level2_at")),
            "level2_reason": (entry.get("level2_reason") or "").strip(),
            "last_check": format_ts_ph(latest.get("timestamp")),
            "loss": latest.get("loss"),
            "avg_ms": latest.get("avg_ms"),
            "mode": latest.get("mode") or "",
            "ok": bool(latest.get("ok")) if latest else False,
            "uptime_pct": uptime_pct,
            "stable_total": total,
            "stable_failures": failures,
            "stable_loss_avg": stats.get("loss_avg"),
            "stable_avg_ms_avg": stats.get("avg_ms_avg"),
            "stable_downtime_seconds": checker_downtime_seconds,
            "stable_loss_events": checker_loss_events,
            "current_state_label": current_state_label,
            "current_state_badge": current_state_badge,
            "primary_problem_label": primary_problem_label,
            "primary_problem_badge": primary_problem_badge,
            "impact_label": impact_label,
            "impact_tooltip": impact_tooltip,
            "impact_sort_seconds": impact_sort_seconds,
            "urgency_label": urgency_label,
            "urgency_badge": urgency_badge,
            "urgency_score": urgency_score,
            "urgency_sort_rank": urgency_sort_rank,
            "checker_since_iso": checker_since_iso,
            "checker_since_ph": checker_since_ph,
            "checker_since_source": checker_since_source,
            "checker_elapsed_seconds": max(int((now - checker_since_dt).total_seconds()), 0),
            "down_for": down_for,
            "down_since_iso": (st.get("down_since") or "").strip(),
            "optical_rx": opt.get("rx"),
            "optical_tx": opt.get("tx"),
            "optical_last": format_ts_ph(opt.get("timestamp")),
            "optical_last_iso": (opt.get("timestamp") or "").strip(),
            "last_fixed_at_iso": fixed_at_iso,
            "last_fixed_at_ph": format_ts_ph(fixed_at_iso),
            "last_fixed_reason": (entry.get("last_fixed_reason") or "").strip(),
            "last_fixed_mode": (entry.get("last_fixed_mode") or "").strip(),
            "stage_history": stage_history,
            "prefixed_cycle_start_iso": prefixed_cycle_start_iso,
            "prefixed_cycle_end_iso": prefixed_cycle_end_iso,
            "prefixed_cycle_start_ph": format_ts_ph(prefixed_cycle_start_iso),
            "prefixed_cycle_end_ph": format_ts_ph(prefixed_cycle_end_iso),
            "prefixed_cycles": fixed_cycles,
            "fixed_cycle_count": len(fixed_cycles),
            "ai_reports": ai_reports,
            "observation_due_iso": observation_due_iso,
            "observation_due_ph": observation_due_ph,
            "observation_seconds_left": observation_seconds_left,
            "observation_left_text": observation_left_text,
        }

    def _apply_ai_stage(row, stage_key):
        stage_key = stage_key if stage_key in _SURV_AI_STAGES else "under"
        report = ((row or {}).get("ai_reports") or {}).get(stage_key) or {}
        out = dict(row or {})
        out["ai_stage"] = stage_key
        out["ai_report_status"] = (report.get("status") or "").strip()
        out["ai_report_status_label"] = report.get("status_label") or _ai_report_status_badge(report.get("status") or "")
        out["ai_report_error"] = (report.get("error") or "").strip()
        out["ai_report_generated_at_iso"] = (report.get("generated_at_iso") or "").strip()
        out["ai_report_generated_at_ph"] = (report.get("generated_at_ph") or "").strip()
        out["ai_report_provider"] = (report.get("provider") or "").strip()
        out["ai_report_model"] = (report.get("model") or "").strip()
        out["ai_report_text"] = (report.get("text") or "").strip()
        out["ai_recommend_needs_manual_fix"] = _normalize_ai_recommendation(report.get("recommend_needs_manual_fix"))
        out["ai_recommendation_reason"] = (report.get("recommendation_reason") or "").strip()
        out["ai_potential_problems"] = _normalize_ai_potential_problems(report.get("potential_problems"))
        out["ai_has_report"] = bool(report.get("has_report"))
        out["ai_is_generating"] = bool(report.get("is_generating"))
        out["ai_has_error"] = bool(report.get("has_error"))
        return out

    all_under_rows = [build_row(pppoe) for pppoe in pppoes if (entry_map.get(pppoe, {}).get("status") or "under") == "under"]
    observation_base_rows = [
        row
        for row in all_under_rows
        if row.get("last_fixed_at_iso")
    ]
    observation_set = {row.get("pppoe") for row in observation_base_rows if row.get("pppoe")}
    under_rows = [_apply_ai_stage(row, "under") for row in all_under_rows if row.get("pppoe") not in observation_set]
    observation_rows = [_apply_ai_stage(row, "observe") for row in observation_base_rows]
    level2_rows = [
        _apply_ai_stage(build_row(pppoe), "level2")
        for pppoe in pppoes
        if (entry_map.get(pppoe, {}).get("status") or "") == "level2"
    ]
    under_rows = _sort_surveillance_rows_recent(under_rows, "added_at_iso")
    observation_rows = _sort_surveillance_rows_recent(observation_rows, "last_fixed_at_iso", "added_at_iso")
    level2_rows = _sort_surveillance_rows_recent(level2_rows, "level2_at_iso", "added_at_iso")
    under_new_ids = _surveillance_new_ids_for_request(
        request,
        [row.get("entry_id") for row in under_rows],
        seed_if_needed=True,
    )
    under_new_id_set = set(under_new_ids)
    for row in under_rows:
        row["is_new"] = bool(row.get("entry_id") and row.get("entry_id") in under_new_id_set)

    def _ai_status_panel(rows):
        rows = list(rows or [])
        grouped = {"generating": [], "ready": [], "error": [], "missing": []}
        for row in rows:
            pppoe = (row.get("pppoe") or "").strip()
            if not pppoe:
                continue
            if bool(row.get("ai_is_generating")):
                grouped["generating"].append(pppoe)
            elif bool(row.get("ai_has_error")):
                grouped["error"].append(pppoe)
            elif bool(row.get("ai_has_report")):
                grouped["ready"].append(pppoe)
            else:
                grouped["missing"].append(pppoe)
        for key in grouped:
            grouped[key] = sorted(grouped[key], key=lambda value: value.lower())
        return {
            "generating": {"label": "Generating", "accounts": grouped["generating"], "count": len(grouped["generating"])},
            "ready": {"label": "Ready", "accounts": grouped["ready"], "count": len(grouped["ready"])},
            "error": {"label": "Error", "accounts": grouped["error"], "count": len(grouped["error"])},
            "missing": {"label": "No Report", "accounts": grouped["missing"], "count": len(grouped["missing"])},
        }

    history_query = (request.query_params.get("q") or "").strip() if active_tab == "history" else ""
    history_action = (request.query_params.get("action") or "closed").strip().lower() if active_tab == "history" else "closed"
    if history_action not in ("closed", "all", "false", "fixed", "recovered", "healed", "removed"):
        history_action = "closed"
    history_page = _parse_table_page(request.query_params.get("page"), default=1) if active_tab == "history" else 1
    history_rows = []
    history_pagination = {"page": 1, "pages": 1, "total": 0}
    if active_tab == "history":
        history = list_surveillance_history(
            query=history_query,
            page=history_page,
            limit=50,
            end_reason=history_action,
        )
        if history.get("rows"):
            for row in history["rows"]:
                started_iso = (row.get("started_at") or "").strip()
                ended_iso = (row.get("ended_at") or "").strip()
                history_rows.append(
                    {
                        "id": row.get("id"),
                        "pppoe": row.get("pppoe") or "",
                        "source": row.get("source") or "",
                        "last_ip": row.get("last_ip") or "",
                        "last_state": row.get("last_state") or "",
                        "observed_count": int(row.get("observed_count") or 0),
                        "end_reason": (row.get("end_reason") or "").strip().lower(),
                        "end_note": (row.get("end_note") or "").strip(),
                        "under_seconds": int(row.get("under_seconds") or 0),
                        "level2_seconds": int(row.get("level2_seconds") or 0),
                        "observe_seconds": int(row.get("observe_seconds") or 0),
                        "under_for_text": _format_duration_short(row.get("under_seconds") or 0) or "0m",
                        "level2_for_text": _format_duration_short(row.get("level2_seconds") or 0) or "0m",
                        "observe_for_text": _format_duration_short(row.get("observe_seconds") or 0) or "0m",
                        "started_at_iso": started_iso,
                        "ended_at_iso": ended_iso,
                        "started_at_ph": format_ts_ph(started_iso),
                        "ended_at_ph": format_ts_ph(ended_iso),
                        "active": not bool(ended_iso),
                    }
                )
        total = int(history.get("total") or 0)
        limit = int(history.get("limit") or 50)
        page = int(history.get("page") or 1)
        pages = max((total + limit - 1) // limit, 1) if limit else 1
        history_pagination = {"page": page, "pages": pages, "total": total}

    message = (request.query_params.get("msg") or "").strip()

    optical_cfg = get_settings("optical", OPTICAL_DEFAULTS)
    optical_class = (optical_cfg.get("classification") or {}) if isinstance(optical_cfg.get("classification"), dict) else {}
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    ai_settings = system_settings.get("ai") if isinstance(system_settings.get("ai"), dict) else {}
    ai_model_options_payload = _build_ai_model_options(ai_settings, active_tab="")
    ai_model_options = ai_model_options_payload.get("options") if isinstance(ai_model_options_payload, dict) else {}
    if not isinstance(ai_model_options, dict):
        ai_model_options = {}

    surveillance_logs_query = (request.query_params.get("logs_q") or "").strip() if active_tab == "logs" else ""
    surveillance_logs_page = _parse_table_page(request.query_params.get("logs_page"), default=1) if active_tab == "logs" else 1
    surveillance_logs_limit = _parse_table_limit(request.query_params.get("logs_limit"), default=100) if active_tab == "logs" else 100
    surveillance_logs_rows = []
    surveillance_logs_pagination = {
        "page": 1,
        "pages": 1,
        "limit": surveillance_logs_limit,
        "total": 0,
        "start": 0,
        "end": 0,
        "has_prev": False,
        "has_next": False,
        "options": TABLE_PAGE_SIZE_OPTIONS,
        "limit_label": str(surveillance_logs_limit),
    }
    if active_tab == "logs":
        logs_rows = _audit_log_rows(limit=20000, surveillance_only=True)
        if surveillance_logs_query:
            query_text = surveillance_logs_query.lower()
            logs_rows = [
                row
                for row in logs_rows
                if query_text in (row.get("username") or "").lower()
                or query_text in (row.get("action") or "").lower()
                or query_text in (row.get("resource") or "").lower()
                or query_text in (row.get("details") or "").lower()
                or query_text in (row.get("ip_address") or "").lower()
            ]
        surveillance_logs_rows, surveillance_logs_pagination = _paginate_items(logs_rows, surveillance_logs_page, surveillance_logs_limit)
        surveillance_logs_pagination["options"] = TABLE_PAGE_SIZE_OPTIONS
        surveillance_logs_pagination["limit_label"] = str(surveillance_logs_pagination.get("limit") or surveillance_logs_limit or "ALL")

    return templates.TemplateResponse(
        "surveillance.html",
        make_context(
            request,
            {
                "settings": settings,
                "active_tab": active_tab,
                "under_rows": under_rows,
                "observation_rows": observation_rows,
                "level2_rows": level2_rows,
                "under_ai_panel": _ai_status_panel(under_rows),
                "level2_ai_panel": _ai_status_panel(level2_rows),
                "observe_ai_panel": _ai_status_panel(observation_rows),
                "stable_window_minutes": stable_window_minutes,
                "stable_window_days": stable_window_days,
                "fixed_observation_minutes": fixed_observation_minutes,
                "fixed_observation_days": fixed_observation_days,
                "history_rows": history_rows,
                "history_query": history_query,
                "history_action": history_action,
                "history_pagination": history_pagination,
                "message": message,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "surv_optical_chart_min_dbm": float(optical_class.get("chart_min_dbm", -35.0) or -35.0),
                "surv_optical_chart_max_dbm": float(optical_class.get("chart_max_dbm", -10.0) or -10.0),
                "surv_optical_tx_realistic_min_dbm": float(optical_class.get("tx_realistic_min_dbm", -10.0) or -10.0),
                "surv_optical_tx_realistic_max_dbm": float(optical_class.get("tx_realistic_max_dbm", 10.0) or 10.0),
                "surveillance_ai_model_options": ai_model_options,
                "surveillance_logs_rows": surveillance_logs_rows,
                "surveillance_logs_query": surveillance_logs_query,
                "surveillance_logs_pagination": surveillance_logs_pagination,
                "under_new_view_seconds": _SURVEILLANCE_NEW_VIEW_SECONDS,
            },
        ),
    )


@app.post("/surveillance/mark_new_seen", response_class=JSONResponse)
async def surveillance_mark_new_seen(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    raw_entry_ids = payload.get("entry_ids") if isinstance(payload, dict) else []
    seen_ids = _mark_surveillance_new_entries_seen(request, raw_entry_ids)
    return _json_no_store({"ok": True, "seen_ids": seen_ids, "seen_at": utc_now_iso()})


def _surv_float_or_none(value):
    try:
        return float(value)
    except Exception:
        return None


def _surv_optical_threshold_dbm(settings):
    try:
        return float((settings.get("stability") or {}).get("optical_rx_min_dbm", -24.0) or -24.0)
    except Exception:
        return -24.0


def _surv_empty_optical_payload(optical_device_id="", threshold_dbm=-24.0):
    return {
        "device_id": (optical_device_id or "").strip(),
        "samples": 0,
        "latest_rx": None,
        "latest_tx": None,
        "avg_rx": None,
        "worst_rx": None,
        "best_rx": None,
        "last_sample_at_iso": "",
        "last_sample_at_ph": "n/a",
        "rx_threshold_dbm": float(threshold_dbm),
        "status": "na",
        "status_label": "No Data",
        "series": [],
        "stats": {
            "optical_sample_count": 0,
            "latest_optical_rx_dbm": None,
            "latest_optical_tx_dbm": None,
            "avg_optical_rx_dbm": None,
            "worst_optical_rx_dbm": None,
            "best_optical_rx_dbm": None,
        },
    }


def _surv_optical_payload_from_rows(optical_device_id, optical_rows, since_dt, until_dt, threshold_dbm=-24.0):
    payload = _surv_empty_optical_payload(optical_device_id=optical_device_id, threshold_dbm=threshold_dbm)
    if not isinstance(since_dt, datetime) or not isinstance(until_dt, datetime):
        return payload
    if until_dt < since_dt:
        until_dt = since_dt

    filtered_rows = []
    rx_values = []
    rx_sum = 0.0
    rx_count = 0
    for item in optical_rows or []:
        if not isinstance(item, dict):
            continue
        ts = (item.get("timestamp") or "").strip()
        dt = _parse_iso_z(ts)
        if not ts or not isinstance(dt, datetime):
            continue
        if dt < since_dt or dt > until_dt:
            continue
        rx_val = _surv_float_or_none(item.get("rx"))
        tx_val = _surv_float_or_none(item.get("tx"))
        filtered_rows.append({"timestamp": ts, "rx": rx_val, "tx": tx_val})
        if rx_val is not None:
            rx_values.append(rx_val)
            rx_sum += rx_val
            rx_count += 1
    payload["series"] = _optical_with_gaps(filtered_rows)

    payload["samples"] = len(filtered_rows)
    latest_row = filtered_rows[-1] if filtered_rows else {}
    latest_rx = _surv_float_or_none(latest_row.get("rx")) if latest_row else None
    latest_tx = _surv_float_or_none(latest_row.get("tx")) if latest_row else None
    avg_rx = (rx_sum / rx_count) if rx_count else None
    worst_rx = min(rx_values) if rx_values else None
    best_rx = max(rx_values) if rx_values else None
    status = "na"
    status_label = "No Data"
    if latest_rx is not None:
        if latest_rx >= float(threshold_dbm):
            status = "pass"
            status_label = "Pass"
        else:
            status = "fail"
            status_label = "Below Goal"

    payload.update(
        {
            "latest_rx": latest_rx,
            "latest_tx": latest_tx,
            "avg_rx": avg_rx,
            "worst_rx": worst_rx,
            "best_rx": best_rx,
            "last_sample_at_iso": (latest_row.get("timestamp") or "").strip() if latest_row else "",
            "last_sample_at_ph": format_ts_ph(latest_row.get("timestamp")) if latest_row and latest_row.get("timestamp") else "n/a",
            "status": status,
            "status_label": status_label,
            "stats": {
                "optical_sample_count": int(payload["samples"]),
                "latest_optical_rx_dbm": latest_rx,
                "latest_optical_tx_dbm": latest_tx,
                "avg_optical_rx_dbm": avg_rx,
                "worst_optical_rx_dbm": worst_rx,
                "best_optical_rx_dbm": best_rx,
            },
        }
    )
    return payload


@app.get("/surveillance/series", response_class=JSONResponse)
async def surveillance_series(pppoe: str, window: str = "24", stage: str = "under"):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return JSONResponse({"hours": 0, "series": []})
    stage = _normalize_surveillance_stage(stage)
    raw_window = (window or "").strip().lower()
    if raw_window in ("pre7d", "baseline", "pre"):
        window_key = "pre7d"
    else:
        try:
            parsed_hours = int(raw_window)
        except Exception:
            parsed_hours = 24
        if parsed_hours not in {1, 6, 12, 24, 168}:
            parsed_hours = 24
        window_key = str(parsed_hours)

    now = datetime.utcnow().replace(microsecond=0)

    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    anchors = _surveillance_entry_anchors(entry, stage=stage, now_utc=now)

    if window_key == "pre7d":
        until_dt = min(anchors["first_added_dt"], now).replace(microsecond=0)
        since_dt = (until_dt - timedelta(hours=168)).replace(microsecond=0)
        anchor_iso = anchors["first_added_iso"]
        anchor_source = "first_added"
    else:
        hours = int(window_key)
        until_dt = now
        since_dt = max((until_dt - timedelta(hours=hours)).replace(microsecond=0), anchors["stage_anchor_dt"])
        anchor_iso = anchors["stage_anchor_iso"]
        anchor_source = anchors["stage_anchor_source"]
    if until_dt < since_dt:
        since_dt = until_dt

    until_iso = until_dt.isoformat() + "Z"
    since_iso = since_dt.isoformat() + "Z"
    if since_dt > until_dt:
        since_iso = until_iso

    account_ids = _accounts_ping_account_ids_for_pppoe(pppoe)
    rows = _accounts_ping_series_rows_for_account_ids(account_ids, since_iso, until_iso)

    def _merge_rows(rows_in):
        merged = []
        cur = None
        cur_ts = None
        for row in rows_in or []:
            ts = (row.get("timestamp") or "").strip()
            if not ts:
                continue
            ok = bool(row.get("ok"))
            loss = row.get("loss")
            avg_ms = row.get("avg_ms")
            mode = row.get("mode")
            if cur is None or ts != cur_ts:
                if cur is not None:
                    merged.append(cur)
                cur_ts = ts
                cur = {"ts": ts, "ok": ok, "loss": loss, "avg_ms": avg_ms, "mode": mode}
                continue
            cur["ok"] = bool(cur.get("ok")) or ok
            # Preserve worst-case values per second.
            for k, v in (("loss", loss), ("avg_ms", avg_ms)):
                a = cur.get(k)
                b = v
                try:
                    av = float(a) if a is not None else None
                except Exception:
                    av = None
                try:
                    bv = float(b) if b is not None else None
                except Exception:
                    bv = None
                if av is None:
                    cur[k] = b
                elif bv is None:
                    pass
                else:
                    cur[k] = b if bv > av else a
        if cur is not None:
            merged.append(cur)
        return merged

    series = _merge_rows(rows)
    optical_threshold_dbm = _surv_optical_threshold_dbm(settings)
    optical_latest_map = get_latest_optical_by_pppoe([pppoe]) if pppoe else {}
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    optical_device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_rows = get_optical_results_for_device_since(optical_device_id, since_iso) if optical_device_id else []
    optical_payload = _surv_optical_payload_from_rows(optical_device_id, optical_rows, since_dt, until_dt, optical_threshold_dbm)
    return JSONResponse(
        {
            "pppoe": pppoe,
            "stage": stage,
            "hours": int(window_key) if window_key != "pre7d" else 168,
            "window_key": window_key,
            "since": since_iso,
            "until": until_iso,
            "anchor_since": anchor_iso,
            "anchor_source": anchor_source,
            "series": series,
            "optical": optical_payload,
        }
    )


@app.get("/surveillance/inspect_activity", response_class=JSONResponse)
async def surveillance_inspect_activity(pppoe: str, stage: str = "under"):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return _json_no_store({"ok": False, "error": "Missing PPPoE account."}, status_code=400)
    stage = _normalize_surveillance_stage(stage)
    now_dt = datetime.utcnow().replace(microsecond=0)

    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    anchors = _surveillance_entry_anchors(entry, stage=stage, now_utc=now_dt)

    until_dt = min(anchors["first_added_dt"], now_dt).replace(microsecond=0)
    since_dt = (until_dt - timedelta(hours=168)).replace(microsecond=0)
    if until_dt < since_dt:
        since_dt = until_dt

    since_iso = since_dt.isoformat() + "Z"
    until_iso = until_dt.isoformat() + "Z"
    account_ids = _accounts_ping_account_ids_for_pppoe(pppoe)
    rows = _accounts_ping_series_rows_for_account_ids(account_ids, since_iso, until_iso)

    def _merge_rows(rows_in):
        merged = []
        cur = None
        cur_ts = None
        for row in rows_in or []:
            ts = (row.get("timestamp") or "").strip()
            if not ts:
                continue
            ok = bool(row.get("ok"))
            loss = row.get("loss")
            avg_ms = row.get("avg_ms")
            mode = row.get("mode")
            if cur is None or ts != cur_ts:
                if cur is not None:
                    merged.append(cur)
                cur_ts = ts
                cur = {"ts": ts, "ok": ok, "loss": loss, "avg_ms": avg_ms, "mode": mode}
                continue
            cur["ok"] = bool(cur.get("ok")) or ok
            for k, v in (("loss", loss), ("avg_ms", avg_ms)):
                a = cur.get(k)
                b = v
                try:
                    av = float(a) if a is not None else None
                except Exception:
                    av = None
                try:
                    bv = float(b) if b is not None else None
                except Exception:
                    bv = None
                if av is None:
                    cur[k] = b
                elif bv is None:
                    pass
                else:
                    cur[k] = b if bv > av else a
        if cur is not None:
            merged.append(cur)
        return merged

    merged_series = _merge_rows(rows)
    stats_payload = _surv_raw_points_and_stats(
        [
            {
                "timestamp": item.get("ts"),
                "ok": item.get("ok"),
                "loss": item.get("loss"),
                "avg_ms": item.get("avg_ms"),
            }
            for item in merged_series
        ]
    )
    stats = dict((stats_payload or {}).get("stats") or {})

    def _to_float(value):
        try:
            return float(value)
        except Exception:
            return None

    down_samples = 0
    parsed_points = []
    for item in merged_series:
        ts_raw = (item.get("ts") or "").strip()
        if not ts_raw:
            continue
        dt = _parse_iso_z(ts_raw)
        if not isinstance(dt, datetime):
            continue
        loss_v = _to_float(item.get("loss"))
        is_down = bool(loss_v is not None and loss_v >= 99.999) or (not bool(item.get("ok")))
        if is_down:
            down_samples += 1
        parsed_points.append({"dt": dt, "is_down": is_down})

    parsed_points.sort(key=lambda row: row["dt"])
    bucket_seconds = int(stats.get("bucket_seconds") or 60)
    if bucket_seconds <= 0:
        bucket_seconds = 60
    longest_down_streak = 0.0
    current_down_streak = 0.0
    for idx, point in enumerate(parsed_points):
        if idx < len(parsed_points) - 1:
            duration = (parsed_points[idx + 1]["dt"] - point["dt"]).total_seconds()
        else:
            duration = float(bucket_seconds)
        if duration <= 0:
            duration = float(bucket_seconds)
        duration = max(1.0, min(float(duration), 300.0))
        if point["is_down"]:
            current_down_streak += duration
            if current_down_streak > longest_down_streak:
                longest_down_streak = current_down_streak
        else:
            current_down_streak = 0.0

    stats["down_samples"] = int(down_samples)
    stats["longest_down_streak_seconds"] = int(round(longest_down_streak))
    stats["last_sample_ts"] = merged_series[-1].get("ts") if merged_series else ""

    optical_threshold_dbm = _surv_optical_threshold_dbm(settings)
    optical_latest_map = get_latest_optical_by_pppoe([pppoe]) if pppoe else {}
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    optical_device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_rows = get_optical_results_for_device_since(optical_device_id, since_iso) if optical_device_id else []
    optical_payload = _surv_optical_payload_from_rows(optical_device_id, optical_rows, since_dt, until_dt, optical_threshold_dbm)

    return _json_no_store(
        {
            "ok": True,
            "pppoe": pppoe,
            "stage": stage,
            "window_key": "pre7d",
            "hours": 168,
            "since": since_iso,
            "until": until_iso,
            "anchor_since": anchors["first_added_iso"],
            "anchor_source": "first_added",
            "series": merged_series,
            "stats": stats,
            "optical": optical_payload,
        }
    )


def _surv_rollup_points_and_stats(rollups, bucket_seconds=60):
    points = []
    sample_total = 0
    ok_total = 0
    avg_sum_total = 0.0
    avg_count_total = 0
    loss_sum_total = 0.0
    loss_count_total = 0
    max_latency = None
    max_loss = None
    loss100_seconds = 0
    downtime_seconds = 0.0
    loss_events = 0
    prev_down = 0

    for row in rollups or []:
        ts = (row.get("bucket_ts") or "").strip()
        if not ts:
            continue
        sc = int(row.get("sample_count") or 0)
        oc = int(row.get("ok_count") or 0)
        sample_total += sc
        ok_total += oc

        a_sum = row.get("avg_sum")
        a_cnt = int(row.get("avg_count") or 0)
        l_sum = row.get("loss_sum")
        l_cnt = int(row.get("loss_count") or 0)

        if a_sum is not None:
            try:
                avg_sum_total += float(a_sum)
            except Exception:
                pass
        avg_count_total += a_cnt

        if l_sum is not None:
            try:
                loss_sum_total += float(l_sum)
            except Exception:
                pass
        loss_count_total += l_cnt

        avg_ms = (float(a_sum) / a_cnt) if (a_sum is not None and a_cnt) else None
        loss_pct = (float(l_sum) / l_cnt) if (l_sum is not None and l_cnt) else None
        points.append({"ts": ts, "avg_ms": avg_ms, "loss": loss_pct})

        if avg_ms is not None:
            max_latency = avg_ms if max_latency is None else max(max_latency, avg_ms)
        if loss_pct is not None:
            max_loss = loss_pct if max_loss is None else max(max_loss, loss_pct)
            is_down = 1 if loss_pct >= 99.999 else 0
            if is_down and not prev_down:
                loss_events += 1
            prev_down = is_down
            # Downtime is an "equivalent downtime" derived from loss%.
            # Example: 10% loss over a 60s bucket contributes ~6 seconds of downtime.
            try:
                downtime_seconds += (float(loss_pct) / 100.0) * float(bucket_seconds)
            except Exception:
                pass
            if loss_pct >= 99.999:
                loss100_seconds += int(bucket_seconds)
        else:
            prev_down = 0

    avg_latency = (avg_sum_total / avg_count_total) if avg_count_total else None
    avg_loss = (loss_sum_total / loss_count_total) if loss_count_total else None
    uptime_pct = (ok_total / sample_total * 100.0) if sample_total else 0.0
    return {
        "points": points,
        "stats": {
            "samples": sample_total,
            "uptime_pct": uptime_pct,
            "avg_latency_ms": avg_latency,
            "max_latency_ms": max_latency,
            "avg_loss_pct": avg_loss,
            "max_loss_pct": max_loss,
            "loss100_seconds": loss100_seconds,
            "downtime_seconds": int(round(downtime_seconds)),
            "loss_events": int(loss_events),
            "bucket_seconds": int(bucket_seconds),
        },
    }


def _surv_raw_points_and_stats(rows):
    items = []
    for row in rows or []:
        ts = (row.get("timestamp") or "").strip()
        if not ts:
            continue
        dt = _parse_iso_z(ts)
        if not dt:
            continue
        items.append(
            {
                "ts": ts,
                "dt": dt,
                "ok": bool(row.get("ok")),
                "loss": row.get("loss"),
                "avg_ms": row.get("avg_ms"),
            }
        )
    items.sort(key=lambda x: x["dt"])
    if not items:
        return {
            "points": [],
            "stats": {
                "samples": 0,
                "uptime_pct": 0.0,
                "avg_latency_ms": None,
                "max_latency_ms": None,
                "avg_loss_pct": None,
                "max_loss_pct": None,
                "loss100_seconds": 0,
                "downtime_seconds": 0,
                "loss_events": 0,
                "bucket_seconds": 0,
            },
        }

    # Collapse duplicate timestamps (common when multiple checks happen within the same second)
    # by keeping the "worst" values for that timestamp. Without this, spike samples can be
    # de-duplicated away later and mini charts can misleadingly look "clean".
    merged = []
    cur = None
    for it in items:
        if cur is None or it["dt"] != cur["dt"]:
            if cur is not None:
                merged.append(cur)
            cur = dict(it)
            continue
        # Same timestamp: merge (worst-case).
        cur["ok"] = bool(cur.get("ok")) or bool(it.get("ok"))
        for k in ("loss", "avg_ms"):
            a = cur.get(k)
            b = it.get(k)
            try:
                av = float(a) if a is not None else None
            except Exception:
                av = None
            try:
                bv = float(b) if b is not None else None
            except Exception:
                bv = None
            if av is None:
                cur[k] = b
            elif bv is None:
                pass
            else:
                cur[k] = b if bv > av else a
    if cur is not None:
        merged.append(cur)
    items = merged

    deltas = []
    for i in range(len(items) - 1):
        d = (items[i + 1]["dt"] - items[i]["dt"]).total_seconds()
        if d <= 0:
            continue
        deltas.append(d)
    deltas_sorted = sorted(deltas)
    if deltas_sorted:
        mid = deltas_sorted[len(deltas_sorted) // 2]
        default_dt = max(1.0, min(float(mid), 300.0))
    else:
        default_dt = 60.0

    sample_total = 0
    ok_total = 0
    avg_sum_total = 0.0
    avg_count_total = 0
    loss_sum_total = 0.0
    loss_count_total = 0
    max_latency = None
    max_loss = None
    loss100_seconds = 0.0
    downtime_seconds = 0.0
    loss_events = 0
    prev_down = 0

    for i, it in enumerate(items):
        sample_total += 1
        if it["ok"]:
            ok_total += 1
        avg_ms = it["avg_ms"]
        if avg_ms is not None:
            try:
                v = float(avg_ms)
                avg_sum_total += v
                avg_count_total += 1
                max_latency = v if max_latency is None else max(max_latency, v)
            except Exception:
                pass
        loss = it["loss"]
        loss_pct = None
        if loss is not None:
            try:
                loss_pct = float(loss)
                loss_sum_total += loss_pct
                loss_count_total += 1
                max_loss = loss_pct if max_loss is None else max(max_loss, loss_pct)
            except Exception:
                loss_pct = None

        if i < len(items) - 1:
            duration = (items[i + 1]["dt"] - it["dt"]).total_seconds()
        else:
            duration = default_dt
        if duration <= 0:
            duration = default_dt
        duration = max(1.0, min(float(duration), 300.0))

        if loss_pct is not None:
            is_down = 1 if loss_pct >= 99.999 else 0
            if is_down and not prev_down:
                loss_events += 1
            prev_down = is_down
            downtime_seconds += (loss_pct / 100.0) * duration
            if loss_pct >= 99.999:
                loss100_seconds += duration
        else:
            prev_down = 0

    avg_latency = (avg_sum_total / avg_count_total) if avg_count_total else None
    avg_loss = (loss_sum_total / loss_count_total) if loss_count_total else None
    uptime_pct = (ok_total / sample_total * 100.0) if sample_total else 0.0
    points = [{"ts": it["ts"], "avg_ms": (float(it["avg_ms"]) if it["avg_ms"] is not None else None), "loss": (float(it["loss"]) if it["loss"] is not None else None)} for it in items]
    return {
        "points": points,
        "stats": {
            "samples": sample_total,
            "uptime_pct": uptime_pct,
            "avg_latency_ms": avg_latency,
            "max_latency_ms": max_latency,
            "avg_loss_pct": avg_loss,
            "max_loss_pct": max_loss,
            "loss100_seconds": int(round(loss100_seconds)),
            "downtime_seconds": int(round(downtime_seconds)),
            "loss_events": int(loss_events),
            "bucket_seconds": int(round(default_dt)),
        },
    }


def _surv_downsample_points(points, max_points=96):
    pts = list(points or [])
    if len(pts) <= max_points:
        return pts
    # Preserve spikes by including max-loss point per chunk (plus endpoints).
    # This is important for mini charts where rare loss spikes would otherwise be skipped.
    step = max(1, int((len(pts) + max_points - 1) // max_points))
    out = []
    for i in range(0, len(pts), step):
        chunk = pts[i : i + step]
        if not chunk:
            continue
        out.append(chunk[0])

        # Add peak loss point (if any).
        best_loss = None
        for p in chunk:
            loss = p.get("loss")
            if loss is None:
                continue
            try:
                v = float(loss)
            except Exception:
                continue
            if best_loss is None or v > best_loss[0]:
                best_loss = (v, p)
        if best_loss is not None:
            out.append(best_loss[1])

        # Add peak latency point (if any).
        best_lat = None
        for p in chunk:
            avg_ms = p.get("avg_ms")
            if avg_ms is None:
                continue
            try:
                v = float(avg_ms)
            except Exception:
                continue
            if best_lat is None or v > best_lat[0]:
                best_lat = (v, p)
        if best_lat is not None:
            out.append(best_lat[1])

        out.append(chunk[-1])

    # De-duplicate by timestamp while preserving order, but keep the "worst" values
    # when duplicates exist so we don't lose spikes.
    seen = {}
    order = []
    for p in out:
        ts = (p.get("ts") or "").strip()
        if not ts:
            continue
        if ts not in seen:
            seen[ts] = dict(p)
            order.append(ts)
            continue
        existing = seen[ts]
        for k in ("loss", "avg_ms"):
            a = existing.get(k)
            b = p.get(k)
            try:
                av = float(a) if a is not None else None
            except Exception:
                av = None
            try:
                bv = float(b) if b is not None else None
            except Exception:
                bv = None
            if av is None:
                existing[k] = b
            elif bv is None:
                pass
            else:
                existing[k] = b if bv > av else a
    return [seen[ts] for ts in order]


@app.get("/surveillance/series_range", response_class=JSONResponse)
async def surveillance_series_range(pppoe: str, since: str, until: str, stage: str = "under"):
    pppoe = (pppoe or "").strip()
    since = (since or "").strip()
    until = (until or "").strip()
    stage = _normalize_surveillance_stage(stage)
    if not pppoe or not since or not until:
        return JSONResponse({"pppoe": pppoe, "series": []})
    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    now_dt = datetime.utcnow().replace(microsecond=0)
    anchors = _surveillance_entry_anchors(entry, stage=stage, now_utc=now_dt)
    anchor_source = anchors["stage_anchor_source"]
    anchor_dt = anchors["stage_anchor_dt"]
    anchor_iso = anchors["stage_anchor_iso"]

    since_dt = _parse_iso_z(since)
    until_dt = _parse_iso_z(until)
    if not since_dt or not until_dt:
        return JSONResponse({"pppoe": pppoe, "series": []})
    if since_dt < anchor_dt:
        since_dt = anchor_dt
    if until_dt > now_dt:
        until_dt = now_dt
    if until_dt < since_dt:
        until_dt = since_dt
    since = since_dt.replace(microsecond=0).isoformat() + "Z"
    until = until_dt.replace(microsecond=0).isoformat() + "Z"

    account_ids = _accounts_ping_account_ids_for_pppoe(pppoe)
    rows = _accounts_ping_series_rows_for_account_ids(account_ids, since, until)
    # Keep the range chart consistent with the dropdown chart by using the same raw dataset.
    series = []
    cur = None
    cur_ts = None
    for row in rows or []:
        ts = (row.get("timestamp") or "").strip()
        if not ts:
            continue
        ok = bool(row.get("ok"))
        loss = row.get("loss")
        avg_ms = row.get("avg_ms")
        mode = row.get("mode")
        if cur is None or ts != cur_ts:
            if cur is not None:
                series.append(cur)
            cur_ts = ts
            cur = {"ts": ts, "ok": ok, "loss": loss, "avg_ms": avg_ms, "mode": mode}
            continue
        cur["ok"] = bool(cur.get("ok")) or ok
        for k, v in (("loss", loss), ("avg_ms", avg_ms)):
            a = cur.get(k)
            b = v
            try:
                av = float(a) if a is not None else None
            except Exception:
                av = None
            try:
                bv = float(b) if b is not None else None
            except Exception:
                bv = None
            if av is None:
                cur[k] = b
            elif bv is None:
                pass
            else:
                cur[k] = b if bv > av else a
    if cur is not None:
        series.append(cur)
    optical_threshold_dbm = _surv_optical_threshold_dbm(settings)
    optical_latest_map = get_latest_optical_by_pppoe([pppoe]) if pppoe else {}
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    optical_device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_rows = get_optical_results_for_device_since(optical_device_id, since) if optical_device_id else []
    optical_payload = _surv_optical_payload_from_rows(optical_device_id, optical_rows, since_dt, until_dt, optical_threshold_dbm)
    return JSONResponse(
        {
            "pppoe": pppoe,
            "stage": stage,
            "since": since,
            "until": until,
            "anchor_since": anchor_iso,
            "anchor_source": anchor_source,
            "series": series,
            "optical": optical_payload,
        }
    )


@app.get("/surveillance/timeline", response_class=JSONResponse)
async def surveillance_timeline(pppoe: str, stage: str = "under", until: str = "", anchor: str = ""):
    pppoe = (pppoe or "").strip()
    stage = _normalize_surveillance_stage(stage)
    if not pppoe:
        return JSONResponse({"pppoe": "", "days": [], "summary": {}, "total": {}})

    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    now_utc = datetime.utcnow().replace(microsecond=0)
    anchors = _surveillance_entry_anchors(entry, stage=stage, now_utc=now_utc)
    added_at_iso = anchors["added_iso"]
    anchor_source = anchors["stage_anchor_source"]
    anchor_iso = anchors["stage_anchor_iso"]
    anchor_dt = anchors["stage_anchor_dt"]
    anchor_override = (anchor or "").strip()
    if anchor_override:
        anchor_override_dt = _parse_iso_z(anchor_override)
        if anchor_override_dt and anchor_override_dt <= now_utc:
            anchor_dt = anchor_override_dt.replace(microsecond=0)
            anchor_iso = anchor_dt.isoformat() + "Z"
            anchor_source = "custom"

    timeline_until_dt = now_utc
    until_override = (until or "").strip()
    if until_override:
        parsed_until = _parse_iso_z(until_override)
        if parsed_until:
            timeline_until_dt = min(parsed_until.replace(microsecond=0), now_utc)
    if timeline_until_dt < anchor_dt:
        timeline_until_dt = anchor_dt

    tz = ZoneInfo("Asia/Manila")
    anchor_local = anchor_dt.replace(tzinfo=timezone.utc).astimezone(tz)
    now_local = timeline_until_dt.replace(tzinfo=timezone.utc).astimezone(tz)

    # Day 1 is the calendar day the stage anchor starts in Asia/Manila.
    start_day = anchor_local.date()
    current_day_index = (now_local.date() - start_day).days + 1
    if current_day_index < 1:
        current_day_index = 1
    total_days = max(7, current_day_index + 1)

    def day_start_local(day_date):
        return datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0, tzinfo=tz)

    def to_utc_iso(dt_local):
        return dt_local.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    account_ids = _accounts_ping_account_ids_for_pppoe(pppoe)
    optical_threshold_dbm = _surv_optical_threshold_dbm(settings)
    optical_latest_map = get_latest_optical_by_pppoe([pppoe]) if pppoe else {}
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    optical_device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_rows = get_optical_results_for_device_since(optical_device_id, anchor_iso) if optical_device_id else []

    day_items = []

    # Total since stage anchor (rounded down to minute boundary).
    anchor_floor = anchor_dt.replace(second=0, microsecond=0)
    total_rollups = _accounts_ping_rollup_rows_for_account_ids(
        account_ids,
        anchor_floor.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        to_utc_iso(now_local + timedelta(minutes=1)),
    )
    total_stats = _surv_rollup_points_and_stats(total_rollups, bucket_seconds=60)["stats"]
    total_optical = _surv_optical_payload_from_rows(optical_device_id, optical_rows, anchor_dt, timeline_until_dt, optical_threshold_dbm)
    total_stats.update(total_optical.get("stats") or {})

    def _local_to_utc_naive(dt_local):
        if not isinstance(dt_local, datetime):
            return anchor_dt
        return dt_local.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)

    for idx in range(1, total_days + 1):
        day_date = start_day + timedelta(days=idx - 1)
        kind = "future"
        if day_date < now_local.date():
            kind = "past"
        elif day_date == now_local.date():
            kind = "today"

        start_local = day_start_local(day_date)
        until_local = day_start_local(day_date + timedelta(days=1))
        # For today, stop at "now" for partial rendering.
        query_until_local = until_local if kind == "past" else min(until_local, now_local + timedelta(minutes=1))
        query_start_local = start_local
        if idx == 1:
            query_start_local = max(start_local, anchor_local)

        series = []
        stats = None
        optical_payload = _surv_empty_optical_payload(optical_device_id=optical_device_id, threshold_dbm=optical_threshold_dbm)
        if kind != "future":
            rollups = _accounts_ping_rollup_rows_for_account_ids(account_ids, to_utc_iso(query_start_local), to_utc_iso(query_until_local))
            payload = _surv_rollup_points_and_stats(rollups, bucket_seconds=60)
            stats = dict(payload["stats"] or {})
            series = _surv_downsample_points(payload["points"], max_points=96)
            optical_payload = _surv_optical_payload_from_rows(
                optical_device_id,
                optical_rows,
                _local_to_utc_naive(query_start_local),
                _local_to_utc_naive(query_until_local),
                optical_threshold_dbm,
            )
            stats.update(optical_payload.get("stats") or {})

        hours_so_far = None
        if kind == "today":
            seconds = max(0, (now_local - start_local).total_seconds())
            hours_so_far = round(seconds / 3600.0, 1)

        day_items.append(
            {
                "index": idx,
                "date": day_date.isoformat(),
                "label": f"Day {idx}",
                "date_label": start_local.strftime("%b %d"),
                "kind": kind,
                "hours_so_far": hours_so_far,
                "start_iso": to_utc_iso(query_start_local),
                "until_iso": to_utc_iso(until_local),
                "series": [{"ts": p["ts"], "loss": p["loss"], "avg_ms": p["avg_ms"]} for p in series],
                "stats": stats,
                "optical": optical_payload,
            }
        )

    return JSONResponse(
        {
            "pppoe": pppoe,
            "stage": stage,
            "added_at": added_at_iso,
            "first_added_at": anchors["first_added_iso"],
            "anchor_since": anchor_iso,
            "anchor_source": anchor_source,
            "until": timeline_until_dt.isoformat() + "Z",
            "start_day": start_day.isoformat(),
            "current_day_index": current_day_index,
            "total_days": total_days,
            "days": day_items,
            "total": total_stats,
            "optical_total": total_optical,
        }
    )


@app.post("/surveillance/settings", response_class=HTMLResponse)
async def surveillance_settings_save(request: Request):
    form = await request.form()
    current = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(current)

    def _float(name, default):
        try:
            return float(form.get(name, default))
        except Exception:
            return float(default)

    def _minutes_from_days(field, default_minutes, min_minutes=1):
        default_days = float(default_minutes) / 1440.0
        days = _float(field, default_days)
        if days <= 0:
            days = default_days
        minutes = int(round(days * 1440.0))
        if minutes < min_minutes:
            minutes = min_minutes
        return minutes

    settings = {
        **current,
        "enabled": parse_bool(form, "enabled"),
        "auto_add": {
            "enabled": parse_bool(form, "auto_add_enabled"),
            "window_days": _float("auto_add_window_days", (current.get("auto_add", {}) or {}).get("window_days", 3)),
            "min_down_events": parse_int(
                form,
                "auto_add_min_down_events",
                (current.get("auto_add", {}) or {}).get("min_down_events", 5),
            ),
            "scan_interval_minutes": parse_int(
                form,
                "auto_add_scan_interval_minutes",
                (current.get("auto_add", {}) or {}).get("scan_interval_minutes", 5),
            ),
            "max_add_per_eval": parse_int(
                form,
                "auto_add_max_add_per_eval",
                (current.get("auto_add", {}) or {}).get("max_add_per_eval", 3),
            ),
            "sources": {
                "accounts_ping": parse_bool(form, "auto_add_source_accounts_ping"),
            },
        },
        "ping": {
            **(current.get("ping") or {}),
            "interval_seconds": parse_int(form, "interval_seconds", current["ping"].get("interval_seconds", 1)),
            "count": parse_int(form, "ping_count", current["ping"].get("count", 1)),
            "timeout_seconds": parse_int(form, "ping_timeout_seconds", current["ping"].get("timeout_seconds", 1)),
            "burst_count": parse_int(form, "burst_count", current["ping"].get("burst_count", 1)),
            "burst_timeout_seconds": parse_int(form, "burst_timeout_seconds", current["ping"].get("burst_timeout_seconds", 1)),
            "max_parallel": parse_int(form, "max_parallel", current["ping"].get("max_parallel", 64)),
        },
        "burst": {
            **(current.get("burst") or {}),
            "enabled": parse_bool(form, "burst_enabled"),
            "burst_interval_seconds": parse_int(form, "burst_interval_seconds", current["burst"].get("burst_interval_seconds", 1)),
            "burst_duration_seconds": parse_int(form, "burst_duration_seconds", current["burst"].get("burst_duration_seconds", 120)),
            "trigger_on_issue": parse_bool(form, "trigger_on_issue"),
        },
        "backoff": {
            **(current.get("backoff") or {}),
            "long_down_seconds": parse_int(form, "long_down_seconds", current["backoff"].get("long_down_seconds", 7200)),
            "long_down_interval_seconds": parse_int(
                form, "long_down_interval_seconds", current["backoff"].get("long_down_interval_seconds", 300)
            ),
        },
        "stability": {
            **(current.get("stability") or {}),
            "stable_window_minutes": _minutes_from_days(
                "stable_window_days",
                current["stability"].get("stable_window_minutes", 10),
                min_minutes=1,
            ),
            "uptime_threshold_pct": _float("uptime_threshold_pct", current["stability"].get("uptime_threshold_pct", 95.0)),
            "latency_max_ms": _float("latency_max_ms", current["stability"].get("latency_max_ms", 15.0)),
            "loss_max_minutes": max(_float("loss_max_minutes", current["stability"].get("loss_max_minutes", 10.0)), 0.0),
            "loss_event_max_count": max(
                parse_int(form, "loss_event_max_count", current["stability"].get("loss_event_max_count", 5)),
                0,
            ),
            "optical_rx_min_dbm": _float("optical_rx_min_dbm", current["stability"].get("optical_rx_min_dbm", -24.0)),
            "require_optical": True,
            "fixed_observation_minutes": _minutes_from_days(
                "fixed_observation_days",
                current["stability"].get("fixed_observation_minutes", current["stability"].get("stable_window_minutes", 10)),
                min_minutes=1,
            ),
            "urgency_no_data_points": max(
                _float("urgency_no_data_points", current["stability"].get("urgency_no_data_points", 25.0)),
                0.0,
            ),
            "urgency_current_down_points": max(
                _float("urgency_current_down_points", current["stability"].get("urgency_current_down_points", 50.0)),
                0.0,
            ),
            "urgency_down_minutes_cap_points": max(
                _float("urgency_down_minutes_cap_points", current["stability"].get("urgency_down_minutes_cap_points", 30.0)),
                0.0,
            ),
            "urgency_loss_budget_breach_points": max(
                _float("urgency_loss_budget_breach_points", current["stability"].get("urgency_loss_budget_breach_points", 20.0)),
                0.0,
            ),
            "urgency_loss_minutes_scale_cap_points": max(
                _float("urgency_loss_minutes_scale_cap_points", current["stability"].get("urgency_loss_minutes_scale_cap_points", 12.0)),
                0.0,
            ),
            "urgency_loss_events_breach_points": max(
                _float("urgency_loss_events_breach_points", current["stability"].get("urgency_loss_events_breach_points", 15.0)),
                0.0,
            ),
            "urgency_loss_events_scale_cap_points": max(
                _float("urgency_loss_events_scale_cap_points", current["stability"].get("urgency_loss_events_scale_cap_points", 10.0)),
                0.0,
            ),
            "urgency_high_latency_points": max(
                _float("urgency_high_latency_points", current["stability"].get("urgency_high_latency_points", 6.0)),
                0.0,
            ),
            "urgency_very_high_latency_points": max(
                _float("urgency_very_high_latency_points", current["stability"].get("urgency_very_high_latency_points", 12.0)),
                0.0,
            ),
            "urgency_very_high_latency_multiplier": max(
                _float(
                    "urgency_very_high_latency_multiplier",
                    current["stability"].get("urgency_very_high_latency_multiplier", 2.0),
                ),
                1.1,
            ),
            "urgency_packet_loss_points": max(
                _float("urgency_packet_loss_points", current["stability"].get("urgency_packet_loss_points", 5.0)),
                0.0,
            ),
            "urgency_severe_packet_loss_points": max(
                _float("urgency_severe_packet_loss_points", current["stability"].get("urgency_severe_packet_loss_points", 10.0)),
                0.0,
            ),
            "urgency_packet_loss_warn_pct": max(
                _float("urgency_packet_loss_warn_pct", current["stability"].get("urgency_packet_loss_warn_pct", 5.0)),
                0.0,
            ),
            "urgency_packet_loss_critical_pct": max(
                _float("urgency_packet_loss_critical_pct", current["stability"].get("urgency_packet_loss_critical_pct", 20.0)),
                0.0,
            ),
            "urgency_optical_issue_points": max(
                _float("urgency_optical_issue_points", current["stability"].get("urgency_optical_issue_points", 12.0)),
                0.0,
            ),
            "urgency_manual_fix_stage_points": max(
                _float("urgency_manual_fix_stage_points", current["stability"].get("urgency_manual_fix_stage_points", 10.0)),
                0.0,
            ),
            "urgency_critical_threshold": max(
                min(parse_int(form, "urgency_critical_threshold", current["stability"].get("urgency_critical_threshold", 70)), 100),
                0,
            ),
            "urgency_high_threshold": max(
                min(parse_int(form, "urgency_high_threshold", current["stability"].get("urgency_high_threshold", 45)), 100),
                0,
            ),
            "urgency_watch_threshold": max(
                min(parse_int(form, "urgency_watch_threshold", current["stability"].get("urgency_watch_threshold", 25)), 100),
                0,
            ),
        },
        "entries": list(entry_map.values()),
    }
    if settings["stability"]["urgency_packet_loss_critical_pct"] < settings["stability"]["urgency_packet_loss_warn_pct"]:
        settings["stability"]["urgency_packet_loss_critical_pct"] = settings["stability"]["urgency_packet_loss_warn_pct"]
    if settings["stability"]["urgency_high_threshold"] > settings["stability"]["urgency_critical_threshold"]:
        settings["stability"]["urgency_high_threshold"] = settings["stability"]["urgency_critical_threshold"]
    if settings["stability"]["urgency_watch_threshold"] > settings["stability"]["urgency_high_threshold"]:
        settings["stability"]["urgency_watch_threshold"] = settings["stability"]["urgency_high_threshold"]
    # normalize auto-add numeric bounds
    try:
        wd = float(settings["auto_add"].get("window_days", 3) or 3)
    except Exception:
        wd = 3.0
    if wd <= 0:
        wd = 3.0
    settings["auto_add"]["window_days"] = wd
    settings["auto_add"]["min_down_events"] = max(int(settings["auto_add"].get("min_down_events", 5) or 5), 1)
    settings["auto_add"]["scan_interval_minutes"] = max(int(settings["auto_add"].get("scan_interval_minutes", 5) or 5), 1)
    try:
        mae = int(settings["auto_add"].get("max_add_per_eval", 3))
    except Exception:
        mae = 3
    if mae < 0:
        mae = 0
    settings["auto_add"]["max_add_per_eval"] = mae

    save_settings("surveillance", settings)
    _auth_log_event(
        request,
        action="surveillance.settings_saved",
        resource="/surveillance/settings",
        details=(
            f"enabled={1 if settings.get('enabled') else 0};"
            f"auto_add={1 if (settings.get('auto_add') or {}).get('enabled') else 0};"
            f"interval={int((settings.get('ping') or {}).get('interval_seconds') or 0)}s;"
            f"max_parallel={int((settings.get('ping') or {}).get('max_parallel') or 0)}"
        ),
    )
    return RedirectResponse(url="/surveillance?tab=settings", status_code=303)


@app.post("/surveillance/format", response_class=HTMLResponse)
async def surveillance_format(request: Request):
    return _render_system_danger_notice(request, "surveillance")


@app.post("/surveillance/add", response_class=JSONResponse)
async def surveillance_add(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    name = (form.get("name") or pppoe).strip()
    ip = (form.get("ip") or "").strip()
    source = (form.get("source") or "").strip()
    if not pppoe:
        return JSONResponse({"ok": False, "error": "Missing PPPoE"}, status_code=400)

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    now_iso = utc_now_iso()
    actor_name = _auth_actor_name(request, default="admin")
    existing = entry_map.get(pppoe)
    if existing:
        existing["name"] = name or existing.get("name") or pppoe
        existing["ip"] = ip or existing.get("ip") or ""
        existing["updated_at"] = now_iso
        if not (existing.get("first_added_at") or "").strip():
            existing["first_added_at"] = (existing.get("added_at") or now_iso).strip() or now_iso
        if source and not existing.get("source"):
            existing["source"] = source
        if (existing.get("added_mode") or "manual").strip().lower() != "auto":
            existing_added_by = (existing.get("added_by") or "").strip()
            if not existing_added_by:
                existing["added_by"] = actor_name[:64]
        entry_map[pppoe] = existing
    else:
        new_entry = {
            "pppoe": pppoe,
            "name": name or pppoe,
            "ip": ip,
            "source": source,
            "status": "under",
            "added_at": now_iso,
            "first_added_at": now_iso,
            "updated_at": now_iso,
            "level2_at": "",
            "level2_reason": "",
            "last_fixed_at": "",
            "last_fixed_reason": "",
            "last_fixed_mode": "",
            "added_mode": "manual",
            "added_by": actor_name[:64],
            "auto_source": "",
            "auto_reason": "",
            "stage_history": [
                {
                    "ts": now_iso,
                    "from": "",
                    "to": "under",
                    "reason": f"Added manually by {actor_name}",
                    "action": "add_manual",
                    "actor": actor_name.lower()[:32] or "admin",
                }
            ],
            "ai_reports": {stage: _empty_surveillance_ai_report() for stage in _SURV_AI_STAGES},
            "ai_report_history": [],
            "ai_report_pending_stage": "",
        }
        entry_map[pppoe] = new_entry
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    try:
        ensure_surveillance_session(pppoe, started_at=now_iso, source=source, ip=ip, state="under")
    except Exception:
        pass
    _auth_log_event(
        request,
        action="surveillance.add_manual",
        resource=pppoe,
        details=(
            f"mode={'update' if existing else 'new'};"
            f"source={(source or 'manual')[:80]};"
            f"ip={(ip or 'n/a')[:80]}"
        ),
    )
    return JSONResponse({"ok": True, "pppoe": pppoe})


@app.post("/surveillance/undo", response_class=JSONResponse)
async def surveillance_undo(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    if not pppoe:
        return JSONResponse({"ok": False, "error": "Missing PPPoE"}, status_code=400)
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe)
    if not entry:
        return JSONResponse({"ok": True, "pppoe": pppoe})
    added = _parse_iso_z(entry.get("added_at"))
    if not added:
        return JSONResponse({"ok": False, "error": "Cannot undo"}, status_code=400)
    if (datetime.utcnow() - added).total_seconds() > 5:
        return JSONResponse({"ok": False, "error": "Undo window expired"}, status_code=400)
    under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
    try:
        end_surveillance_session(
            pppoe,
            "removed",
            started_at=(entry.get("added_at") or "").strip(),
            source=(entry.get("source") or "").strip(),
            ip=(entry.get("ip") or "").strip(),
            state=(entry.get("status") or "under"),
            under_seconds=under_seconds,
            level2_seconds=level2_seconds,
            observe_seconds=observe_seconds,
            create_if_missing=False,
        )
    except Exception:
        pass
    entry_map.pop(pppoe, None)
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    _auth_log_event(
        request,
        action="surveillance.undo_add",
        resource=pppoe,
        details="removed within undo window",
    )
    return JSONResponse({"ok": True, "pppoe": pppoe})


@app.post("/surveillance/remove", response_class=HTMLResponse)
async def surveillance_remove(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    if pppoe:
        entry = entry_map.get(pppoe) or {}
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                pppoe,
                "removed",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
                create_if_missing=False,
            )
        except Exception:
            pass
        entry_map.pop(pppoe, None)
        _auth_log_event(
            request,
            action="surveillance.remove",
            resource=pppoe,
            details=f"tab={(form.get('tab') or 'under').strip() or 'under'}",
        )
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    tab = (form.get("tab") or "under").strip() or "under"
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/mark_false", response_class=HTMLResponse)
async def surveillance_mark_false(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    raw_pppoes = (form.get("pppoes") or "").strip()
    remarks = (form.get("remarks") or form.get("reason") or "").strip()
    tab = (form.get("tab") or "under").strip().lower()
    if tab not in ("under", "level2", "observe"):
        tab = "under"
    pppoes: list[str] = []
    if pppoe:
        pppoes.append(pppoe)
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            pppoes.extend([item.strip() for item in raw_pppoes.split(",") if item.strip()])
    seen = set()
    unique_pppoes: list[str] = []
    for item in pppoes:
        if item in seen:
            continue
        seen.add(item)
        unique_pppoes.append(item)
    if len(remarks) < 3:
        params = {"tab": tab, "msg": "False-mark remarks are required (minimum 3 characters)."}
        if unique_pppoes:
            params["focus"] = unique_pppoes[0]
        return RedirectResponse(url=f"/surveillance?{urllib.parse.urlencode(params)}", status_code=303)
    if len(remarks) > 500:
        params = {"tab": tab, "msg": "False-mark remarks are too long (max 500 characters)."}
        if unique_pppoes:
            params["focus"] = unique_pppoes[0]
        return RedirectResponse(url=f"/surveillance?{urllib.parse.urlencode(params)}", status_code=303)
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    is_bulk = len(unique_pppoes) > 1
    selected_count = len(unique_pppoes)
    processed = 0
    processed_pppoes: list[str] = []
    for pppoe in unique_pppoes:
        entry = entry_map.get(pppoe) or {}
        if not entry:
            continue
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                pppoe,
                "false",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                note=(
                    f"Marked as False via Select Multiple ({selected_count} selected). Shared remarks: {remarks}"
                    if is_bulk
                    else f"Marked as False: {remarks}"
                ),
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
                create_if_missing=False,
            )
        except Exception:
            pass
        entry_map.pop(pppoe, None)
        processed += 1
        processed_pppoes.append(pppoe)
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    if processed > 0:
        if is_bulk:
            for processed_pppoe in processed_pppoes:
                _auth_log_event(
                    request,
                    action="surveillance.mark_false_bulk",
                    resource=processed_pppoe,
                    details=f"count={processed};selected={selected_count};tab={tab};mode=select_multiple;remarks={remarks[:200]}",
                )
        else:
            _auth_log_event(
                request,
                action="surveillance.mark_false",
                resource=processed_pppoes[0] if processed_pppoes else unique_pppoes[0],
                details=f"count={processed};tab={tab};remarks={remarks[:200]}",
            )
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/move_level2", response_class=HTMLResponse)
async def surveillance_move_level2(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    tab = (form.get("tab") or "under").strip().lower()
    if tab not in ("under", "level2", "observe"):
        tab = "under"
    reason = (form.get("reason") or "").strip()
    if len(reason) > 500:
        reason = reason[:500]
    if not pppoe:
        qs = urllib.parse.urlencode({"tab": tab, "msg": "Missing PPPoE account for Needs Manual Fix."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)
    if len(reason) < 3:
        qs = urllib.parse.urlencode({"tab": tab, "focus": pppoe, "msg": "Investigation report is required (minimum 3 characters)."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    if not entry:
        qs = urllib.parse.urlencode({"tab": tab, "msg": f"Account `{pppoe}` is no longer active."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    now_iso = utc_now_iso()
    added_at = (entry.get("added_at") or "").strip() or now_iso
    first_added_at = (entry.get("first_added_at") or added_at).strip() or added_at
    from_stage = "observe" if tab == "observe" else ((entry.get("status") or "under").strip().lower() or "under")
    if from_stage not in ("under", "level2", "observe"):
        from_stage = "under"
    _append_surveillance_stage_history(
        entry,
        from_stage=from_stage,
        to_stage="level2",
        reason=reason,
        action="move_to_manual_fix",
        at_iso=now_iso,
        actor=_auth_actor_name(request, default="admin"),
    )
    entry["status"] = "level2"
    entry["level2_at"] = now_iso
    entry["level2_reason"] = reason
    entry["updated_at"] = now_iso
    entry["added_at"] = added_at
    entry["first_added_at"] = first_added_at
    try:
        increment_surveillance_observed(
            pppoe,
            started_at=added_at,
            source=(entry.get("source") or "").strip(),
            ip=(entry.get("ip") or "").strip(),
        )
    except Exception:
        try:
            touch_surveillance_session(
                pppoe,
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state="level2",
            )
        except Exception:
            pass
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    _auth_log_event(
        request,
        action="surveillance.move_to_manual_fix",
        resource=pppoe,
        details=f"from={from_stage};reason={reason}",
    )
    qs = urllib.parse.urlencode({"tab": "level2", "focus": pppoe})
    return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)


@app.post("/surveillance/ai_regenerate", response_class=HTMLResponse)
async def surveillance_ai_regenerate(request: Request):
    form = await request.form()
    tab = (form.get("tab") or "under").strip().lower()
    if tab not in ("under", "level2", "observe", "history", "logs", "settings"):
        tab = "under"
    qs = urllib.parse.urlencode(
        {
            "tab": tab,
            "msg": "AI Investigator was removed from Under Surveillance.",
        }
    )
    return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)


@app.get("/surveillance/ai_reports", response_class=JSONResponse)
async def surveillance_ai_reports(pppoe: str):
    return JSONResponse(
        {
            "ok": False,
            "pppoe": (pppoe or "").strip(),
            "error": "AI Investigator was removed from Under Surveillance.",
        },
        status_code=410,
    )


_SURVEILLANCE_HISTORY_STAGE_META = {
    "under": {"label": "Active Monitoring", "badge": "yellow"},
    "level2": {"label": "Needs Manual Fix", "badge": "red"},
    "observe": {"label": "Post-Fix Observation", "badge": "blue"},
}


def _surveillance_history_stage_label(stage_key: str) -> str:
    return (_SURVEILLANCE_HISTORY_STAGE_META.get((stage_key or "").strip().lower()) or {}).get("label") or "Unknown Stage"


def _surveillance_history_stage_badge(stage_key: str) -> str:
    return (_SURVEILLANCE_HISTORY_STAGE_META.get((stage_key or "").strip().lower()) or {}).get("badge") or "secondary"


def _clean_surveillance_session_note(note: str) -> str:
    text = (note or "").strip()
    for prefix in ("Marked as fully recovered:", "Marked as False:"):
        if text.lower().startswith(prefix.lower()):
            return text[len(prefix):].strip()
    return text


def _surveillance_session_stage_segments(session_row: dict) -> list[dict]:
    if not isinstance(session_row, dict):
        return []
    started_iso = (session_row.get("started_at") or "").strip()
    ended_iso = (session_row.get("ended_at") or "").strip()
    started_dt = _parse_iso_z(started_iso)
    ended_dt = _parse_iso_z(ended_iso) if ended_iso else datetime.utcnow().replace(microsecond=0)
    if not isinstance(started_dt, datetime) or not isinstance(ended_dt, datetime):
        return []
    if ended_dt < started_dt:
        ended_dt = started_dt
    try:
        under_seconds = max(int(session_row.get("under_seconds") or 0), 0)
    except Exception:
        under_seconds = 0
    try:
        level2_seconds = max(int(session_row.get("level2_seconds") or 0), 0)
    except Exception:
        level2_seconds = 0
    try:
        observe_seconds = max(int(session_row.get("observe_seconds") or 0), 0)
    except Exception:
        observe_seconds = 0
    actual_seconds = max(int((ended_dt - started_dt).total_seconds()), 0)
    stage_seconds = {
        "under": under_seconds,
        "level2": level2_seconds,
        "observe": observe_seconds,
    }
    total_seconds = under_seconds + level2_seconds + observe_seconds
    inferred_stage = "observe" if observe_seconds > 0 else ("level2" if level2_seconds > 0 or (session_row.get("last_state") or "").strip().lower() == "level2" else "under")
    if total_seconds <= 0 and actual_seconds > 0:
        stage_seconds[inferred_stage] = actual_seconds
        total_seconds = actual_seconds
    elif actual_seconds > total_seconds:
        for stage_key in ("observe", "level2", "under"):
            if stage_seconds.get(stage_key, 0) > 0:
                stage_seconds[stage_key] += actual_seconds - total_seconds
                break
        else:
            stage_seconds[inferred_stage] += actual_seconds - total_seconds

    segments = []
    cursor = started_dt
    for stage_key in ("under", "level2", "observe"):
        seconds = max(int(stage_seconds.get(stage_key) or 0), 0)
        if seconds <= 0:
            continue
        segment_end = cursor + timedelta(seconds=seconds)
        if segment_end > ended_dt:
            segment_end = ended_dt
        if segment_end <= cursor and ended_dt > cursor:
            segment_end = ended_dt
        if segment_end <= cursor:
            continue
        segment_seconds = max(int((segment_end - cursor).total_seconds()), 0)
        segments.append(
            {
                "stage": stage_key,
                "label": _surveillance_history_stage_label(stage_key),
                "badge": _surveillance_history_stage_badge(stage_key),
                "start_dt": cursor,
                "end_dt": segment_end,
                "start_at_iso": cursor.replace(microsecond=0).isoformat() + "Z",
                "end_at_iso": segment_end.replace(microsecond=0).isoformat() + "Z",
                "start_at_ph": format_ts_ph(cursor.replace(microsecond=0).isoformat() + "Z"),
                "end_at_ph": format_ts_ph(segment_end.replace(microsecond=0).isoformat() + "Z"),
                "seconds": segment_seconds,
                "duration_text": _format_duration_short(segment_seconds) or "0m",
                "session_id": int(session_row.get("id") or 0),
            }
        )
        cursor = segment_end
    if segments and cursor < ended_dt:
        last = segments[-1]
        last["end_dt"] = ended_dt
        last["end_at_iso"] = ended_dt.replace(microsecond=0).isoformat() + "Z"
        last["end_at_ph"] = format_ts_ph(last["end_at_iso"])
        last["seconds"] = max(int((ended_dt - last["start_dt"]).total_seconds()), 0)
        last["duration_text"] = _format_duration_short(last["seconds"]) or "0m"
    return segments


def _row_in_surveillance_segment(ts: str, segment: dict, is_last_segment: bool = False) -> bool:
    dt = _parse_iso_z(ts)
    if not isinstance(dt, datetime):
        return False
    start_dt = segment.get("start_dt")
    end_dt = segment.get("end_dt")
    if not isinstance(start_dt, datetime) or not isinstance(end_dt, datetime):
        return False
    if dt < start_dt:
        return False
    if is_last_segment:
        return dt <= end_dt
    return dt < end_dt


def _filter_rows_for_stage_segments(rows: list[dict], segments: list[dict], ts_key: str = "timestamp") -> list[dict]:
    if not rows or not segments:
        return []
    out = []
    for row in rows:
        ts = (row.get(ts_key) or "").strip() if isinstance(row, dict) else ""
        if not ts:
            continue
        for idx, segment in enumerate(segments):
            if _row_in_surveillance_segment(ts, segment, is_last_segment=(idx == len(segments) - 1)):
                out.append(row)
                break
    return out


def _summarize_surveillance_ping_rows(rows: list[dict]) -> dict:
    samples = 0
    down_samples = 0
    loss_values = []
    avg_values = []
    loss_events = 0
    last_ts = ""
    prev_full_down = False
    for item in rows or []:
        samples += 1
        ok = bool(item.get("ok"))
        loss_val = item.get("loss")
        avg_val = item.get("avg_ms")
        if not ok:
            down_samples += 1
        try:
            if loss_val is not None:
                loss_values.append(float(loss_val))
        except Exception:
            pass
        try:
            if avg_val is not None:
                avg_values.append(float(avg_val))
        except Exception:
            pass
        full_down = (not ok) or (
            loss_val is not None and isinstance(loss_val, (int, float)) and float(loss_val) >= 100.0
        )
        if full_down and not prev_full_down:
            loss_events += 1
        prev_full_down = full_down
        last_ts = (item.get("timestamp") or "").strip() or last_ts
    uptime_pct = (100.0 - (down_samples / samples * 100.0)) if samples else None
    return {
        "samples": samples,
        "down_samples": down_samples,
        "loss_events": loss_events,
        "uptime_pct": uptime_pct,
        "avg_loss": (sum(loss_values) / len(loss_values)) if loss_values else None,
        "avg_ms": (sum(avg_values) / len(avg_values)) if avg_values else None,
        "worst_ms": max(avg_values) if avg_values else None,
        "last_sample_at_iso": last_ts,
        "last_sample_at_ph": format_ts_ph(last_ts) if last_ts else "n/a",
    }


def _summarize_surveillance_optical_rows(rows: list[dict], device_id: str = "") -> dict:
    rx_values = []
    last_row = rows[-1] if rows else {}
    for item in rows or []:
        try:
            value = item.get("rx")
            if value is not None:
                rx_values.append(float(value))
        except Exception:
            pass
    last_ts = (last_row.get("timestamp") or "").strip() if isinstance(last_row, dict) else ""
    return {
        "device_id": (device_id or "").strip() or "n/a",
        "samples": len(rows or []),
        "latest_rx": last_row.get("rx") if isinstance(last_row, dict) else None,
        "latest_tx": last_row.get("tx") if isinstance(last_row, dict) else None,
        "worst_rx": min(rx_values) if rx_values else None,
        "last_sample_at_iso": last_ts,
        "last_sample_at_ph": format_ts_ph(last_ts) if last_ts else "n/a",
    }


def _summarize_surveillance_usage_rows(rows: list[dict]) -> dict:
    rx_vals = []
    tx_vals = []
    total_vals = []
    active_device_max = 0
    last_ts = ""
    for item in rows or []:
        try:
            rx = float(item.get("rx_bps") or 0.0)
        except Exception:
            rx = 0.0
        try:
            tx = float(item.get("tx_bps") or 0.0)
        except Exception:
            tx = 0.0
        rx_vals.append(rx)
        tx_vals.append(tx)
        total_vals.append(max(rx, 0.0) + max(tx, 0.0))
        last_ts = (item.get("timestamp") or "").strip() or last_ts
        try:
            active_device_max = max(active_device_max, int(item.get("host_count") or 0))
        except Exception:
            pass
    return {
        "samples": len(rows or []),
        "avg_rx_bps": (sum(rx_vals) / len(rx_vals)) if rx_vals else None,
        "avg_tx_bps": (sum(tx_vals) / len(tx_vals)) if tx_vals else None,
        "peak_total_bps": max(total_vals) if total_vals else None,
        "active_device_max": active_device_max,
        "last_sample_at_iso": last_ts,
        "last_sample_at_ph": format_ts_ph(last_ts) if last_ts else "n/a",
    }


def _build_surveillance_stage_events(audit_rows: list[dict], cycle_rows: list[dict]) -> tuple[dict, dict]:
    stage_events = {"under": None, "level2": None, "observe": None}
    final_event = None
    for row in audit_rows or []:
        action = (row.get("action") or "").strip().lower()
        username = (row.get("username") or "system").strip() or "system"
        details_text = (row.get("details") or "").strip()
        details_map = _audit_details_map(details_text)
        note = (
            (details_map.get("reason") or "").strip()
            or (details_map.get("remarks") or "").strip()
            or details_text
        )
        event = {
            "at_iso": (row.get("timestamp") or "").strip(),
            "at_ph": format_ts_ph(row.get("timestamp")),
            "actor": username,
            "note": note,
            "action": action,
            "action_label": "",
        }
        if action in ("surveillance.add_manual", "surveillance.add_auto") and not stage_events["under"]:
            event["action_label"] = "Added to Active Monitoring" if action.endswith("manual") else "Auto-added to Active Monitoring"
            stage_events["under"] = event
        elif action == "surveillance.move_to_manual_fix" and not stage_events["level2"]:
            event["action_label"] = "Moved to Needs Manual Fix"
            stage_events["level2"] = event
        elif action in ("surveillance.mark_fixed", "surveillance.mark_fixed_bulk") and not stage_events["observe"]:
            event["action_label"] = "Moved to Post-Fix Observation"
            stage_events["observe"] = event
        elif action in ("surveillance.mark_false", "surveillance.mark_false_bulk", "surveillance.mark_fully_recovered", "surveillance.remove", "surveillance.remove_bulk"):
            if action == "surveillance.mark_false":
                event["action_label"] = "Marked False"
            elif action == "surveillance.mark_false_bulk":
                event["action_label"] = "Marked False (Select Multiple)"
            elif action == "surveillance.mark_fully_recovered":
                event["action_label"] = "Marked Fully Recovered"
            else:
                event["action_label"] = "Removed from Surveillance"
            final_event = event
    if not stage_events["observe"]:
        fixed_row = next((item for item in cycle_rows if (item.get("end_reason") or "").strip().lower() == "fixed"), None)
        if isinstance(fixed_row, dict):
            ended_iso = (fixed_row.get("ended_at") or "").strip()
            stage_events["observe"] = {
                "at_iso": ended_iso,
                "at_ph": format_ts_ph(ended_iso),
                "actor": "",
                "note": _clean_surveillance_session_note(fixed_row.get("end_note") or ""),
                "action": "surveillance.mark_fixed",
                "action_label": "Moved to Post-Fix Observation",
            }
    return stage_events, final_event


@app.get("/surveillance/history_detail", response_class=JSONResponse)
async def surveillance_history_detail(id: int):
    row = get_surveillance_session_by_id(id)
    if not isinstance(row, dict):
        return JSONResponse({"ok": False, "error": "Session not found."}, status_code=404)

    pppoe = (row.get("pppoe") or "").strip()
    observed_count = int(row.get("observed_count") or 0)
    cycle_rows = list_surveillance_cycle_sessions(pppoe, observed_count) if pppoe and observed_count > 0 else []
    if not cycle_rows:
        cycle_rows = [row]
    elif not any(int(item.get("id") or 0) == int(row.get("id") or 0) for item in cycle_rows):
        cycle_rows.append(row)
    cycle_rows = sorted(
        cycle_rows,
        key=lambda item: (
            (_parse_iso_z(item.get("started_at")) or _parse_iso_z(item.get("ended_at")) or datetime.min.replace(tzinfo=timezone.utc)),
            int(item.get("id") or 0),
        ),
    )

    segment_rows = []
    for cycle_row in cycle_rows:
        segment_rows.extend(_surveillance_session_stage_segments(cycle_row))
    segment_rows = sorted(segment_rows, key=lambda item: item.get("start_dt") or datetime.min.replace(tzinfo=timezone.utc))

    started_dt = segment_rows[0]["start_dt"] if segment_rows else _parse_iso_z((row.get("started_at") or "").strip())
    ended_dt = segment_rows[-1]["end_dt"] if segment_rows else (_parse_iso_z((row.get("ended_at") or "").strip()) if (row.get("ended_at") or "").strip() else datetime.utcnow().replace(microsecond=0))
    if not isinstance(started_dt, datetime):
        started_dt = datetime.utcnow().replace(microsecond=0)
    if not isinstance(ended_dt, datetime):
        ended_dt = started_dt
    if ended_dt < started_dt:
        ended_dt = started_dt

    since_iso = started_dt.replace(microsecond=0).isoformat() + "Z"
    until_iso = ended_dt.replace(microsecond=0).isoformat() + "Z"

    action = (row.get("end_reason") or "").strip().lower()
    action_label_map = {
        "healed": "Auto Healed",
        "false": "Marked False",
        "fixed": "Fixed",
        "recovered": "Fully Recovered",
        "removed": "Removed",
    }

    account_ids = _accounts_ping_account_ids_for_pppoe(pppoe)
    ping_series = _accounts_ping_series_rows_for_account_ids(account_ids, since_iso, until_iso)

    optical_latest_map = get_latest_optical_by_pppoe([pppoe]) if pppoe else {}
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    optical_device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_rows = get_optical_results_for_device_since(optical_device_id, since_iso) if optical_device_id else []

    usage_rows = get_pppoe_usage_series_since("", pppoe, since_iso) if pppoe else []
    audit_rows = list_surveillance_audit_logs_for_pppoe(pppoe, since_iso=since_iso, until_iso=until_iso, limit=300) if pppoe else []
    stage_events, final_event = _build_surveillance_stage_events(audit_rows, cycle_rows)

    stage_summaries = []
    stage_totals = {"under": 0, "level2": 0, "observe": 0}
    for stage_key in ("under", "level2", "observe"):
        stage_segments = [item for item in segment_rows if (item.get("stage") or "") == stage_key]
        total_stage_seconds = sum(max(int(item.get("seconds") or 0), 0) for item in stage_segments)
        stage_totals[stage_key] = total_stage_seconds
        entered_event = stage_events.get(stage_key) or {}
        ping_stage_rows = _filter_rows_for_stage_segments(ping_series, stage_segments)
        optical_stage_rows = _filter_rows_for_stage_segments(optical_rows, stage_segments)
        usage_stage_rows = _filter_rows_for_stage_segments(usage_rows, stage_segments)
        stage_summaries.append(
            {
                "stage": stage_key,
                "label": _surveillance_history_stage_label(stage_key),
                "badge": _surveillance_history_stage_badge(stage_key),
                "present": total_stage_seconds > 0,
                "seconds": total_stage_seconds,
                "duration_text": _format_duration_short(total_stage_seconds) or "0m",
                "started_at_iso": stage_segments[0]["start_at_iso"] if stage_segments else "",
                "started_at_ph": stage_segments[0]["start_at_ph"] if stage_segments else "n/a",
                "ended_at_iso": stage_segments[-1]["end_at_iso"] if stage_segments else "",
                "ended_at_ph": stage_segments[-1]["end_at_ph"] if stage_segments else "n/a",
                "entered_by": (entered_event.get("actor") or "").strip() or "n/a",
                "entered_at_iso": (entered_event.get("at_iso") or "").strip(),
                "entered_at_ph": (entered_event.get("at_ph") or "").strip() or "n/a",
                "entered_action": (entered_event.get("action") or "").strip(),
                "entered_action_label": (entered_event.get("action_label") or "").strip() or "Entered stage",
                "note": (entered_event.get("note") or "").strip(),
                "accounts_ping": _summarize_surveillance_ping_rows(ping_stage_rows),
                "optical": _summarize_surveillance_optical_rows(optical_stage_rows, device_id=optical_device_id),
                "usage": _summarize_surveillance_usage_rows(usage_stage_rows),
            }
        )

    total_seconds = sum(stage_totals.values())
    if total_seconds <= 0:
        total_seconds = max(int((ended_dt - started_dt).total_seconds()), 0)

    movement_rows = []
    for item in stage_summaries:
        if not item.get("present") and not item.get("entered_at_iso"):
            continue
        movement_rows.append(
            {
                "stage": item.get("stage") or "",
                "stage_label": item.get("label") or "Stage",
                "badge": item.get("badge") or "secondary",
                "window": f"{item.get('started_at_ph') or 'n/a'} → {item.get('ended_at_ph') or 'n/a'}" if item.get("present") else "Not entered in this cycle",
                "duration_text": item.get("duration_text") or "0m",
                "updated_by": item.get("entered_by") or "n/a",
                "updated_at_ph": item.get("entered_at_ph") or "n/a",
                "action_label": item.get("entered_action_label") or "Entered stage",
                "note": item.get("note") or "—",
            }
        )
    if final_event:
        movement_rows.append(
            {
                "stage": "final",
                "stage_label": "Final Action",
                "badge": "secondary",
                "window": f"{format_ts_ph((row.get('started_at') or '').strip()) or 'n/a'} → {format_ts_ph((row.get('ended_at') or '').strip()) or 'n/a'}",
                "duration_text": _format_duration_short(total_seconds) or "0m",
                "updated_by": (final_event.get("actor") or "").strip() or "n/a",
                "updated_at_ph": (final_event.get("at_ph") or "").strip() or "n/a",
                "action_label": (final_event.get("action_label") or "").strip() or action_label_map.get(action, "Closed"),
                "note": (final_event.get("note") or "").strip() or _clean_surveillance_session_note(row.get("end_note") or "") or "—",
            }
        )

    return JSONResponse(
        {
            "ok": True,
            "session": {
                "id": int(row.get("id") or 0),
                "pppoe": pppoe,
                "source": next((str((item.get("source") or "")).strip() for item in cycle_rows if (item.get("source") or "").strip()), (row.get("source") or "").strip()),
                "last_ip": (row.get("last_ip") or "").strip(),
                "last_state": (row.get("last_state") or "").strip(),
                "observed_count": observed_count,
                "started_at_iso": since_iso,
                "ended_at_iso": until_iso,
                "started_at_ph": format_ts_ph(since_iso),
                "ended_at_ph": format_ts_ph(until_iso),
                "updated_at_iso": (row.get("updated_at") or "").strip(),
                "updated_at_ph": format_ts_ph(row.get("updated_at")),
                "end_reason": action,
                "end_reason_label": action_label_map.get(action, "Removed"),
                "end_note": _clean_surveillance_session_note(row.get("end_note") or ""),
                "under_seconds": stage_totals["under"],
                "level2_seconds": stage_totals["level2"],
                "observe_seconds": stage_totals["observe"],
                "under_for_text": _format_duration_short(stage_totals["under"]) or "0m",
                "level2_for_text": _format_duration_short(stage_totals["level2"]) or "0m",
                "observe_for_text": _format_duration_short(stage_totals["observe"]) or "0m",
                "total_seconds": total_seconds,
                "total_for_text": _format_duration_short(total_seconds) or "0m",
                "cycle_session_count": len(cycle_rows),
            },
            "stage_summaries": stage_summaries,
            "movement": movement_rows,
        }
    )


@app.post("/surveillance/observe_recovered", response_class=HTMLResponse)
async def surveillance_observe_recovered(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    raw_pppoes = (form.get("pppoes") or "").strip()
    tab = (form.get("tab") or "observe").strip().lower()
    remarks = (form.get("remarks") or "").strip()
    if tab not in ("under", "level2", "observe"):
        tab = "observe"

    def _redirect_with_msg(message: str):
        params = {"tab": tab, "msg": message}
        if pppoe:
            params["focus"] = pppoe
        return RedirectResponse(url=f"/surveillance?{urllib.parse.urlencode(params)}", status_code=303)

    pppoes: list[str] = []
    if pppoe:
        pppoes.append(pppoe)
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            pppoes.extend([item.strip() for item in raw_pppoes.split(",") if item.strip()])
    seen = set()
    unique_pppoes: list[str] = []
    for item in pppoes:
        if item in seen:
            continue
        seen.add(item)
        unique_pppoes.append(item)

    if not unique_pppoes:
        return _redirect_with_msg("Missing PPPoE account.")
    if not remarks or len(remarks) < 3:
        return _redirect_with_msg("Recovery remarks are required (min 3 characters).")
    if len(remarks) > 500:
        return _redirect_with_msg("Recovery remarks are too long (max 500 characters).")

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    processed = 0
    for target in unique_pppoes:
        entry = entry_map.get(target) or {}
        if not entry:
            continue
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                target,
                "recovered",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                note=f"Marked as fully recovered: {remarks}",
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
                create_if_missing=False,
            )
        except Exception:
            pass
        entry_map.pop(target, None)
        processed += 1
    if processed <= 0:
        return _redirect_with_msg("Selected accounts are no longer active in Post-Fix Observation.")
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    preview = ",".join(unique_pppoes[:10])
    if len(unique_pppoes) > 10:
        preview += f",+{len(unique_pppoes) - 10}"
    _auth_log_event(
        request,
        action="surveillance.mark_fully_recovered",
        resource=preview,
        details=f"count={processed};remarks={remarks}",
    )
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/remove_many", response_class=HTMLResponse)
async def surveillance_remove_many(request: Request):
    form = await request.form()
    raw_pppoes = (form.get("pppoes") or "").strip()
    tab = (form.get("tab") or "under").strip() or "under"

    pppoes: list[str] = []
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            # Fallback: comma-separated
            pppoes = [p.strip() for p in raw_pppoes.split(",") if p.strip()]

    if not pppoes:
        return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    # De-dupe while keeping order.
    seen = set()
    unique_pppoes = []
    for p in pppoes:
        if p in seen:
            continue
        seen.add(p)
        unique_pppoes.append(p)

    for pppoe in unique_pppoes:
        entry = entry_map.get(pppoe) or {}
        if not entry:
            continue
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                pppoe,
                "removed",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
                create_if_missing=False,
            )
        except Exception:
            pass
        entry_map.pop(pppoe, None)

    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    if unique_pppoes:
        preview = ",".join(unique_pppoes[:10])
        if len(unique_pppoes) > 10:
            preview += f",+{len(unique_pppoes) - 10}"
        _auth_log_event(
            request,
            action="surveillance.remove_bulk",
            resource=preview,
            details=f"count={len(unique_pppoes)};tab={tab}",
        )
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/fixed", response_class=HTMLResponse)
async def surveillance_fixed(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    reason = (form.get("reason") or "").strip()
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    if pppoe and pppoe in entry_map:
        old = dict(entry_map.get(pppoe) or {})
        if not reason or len(reason) < 3:
            return RedirectResponse(
                url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is required for Account Fixed.')}",
                status_code=303,
            )
        if len(reason) > 500:
            return RedirectResponse(
                url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is too long (max 500 characters).')}",
                status_code=303,
            )
        now_iso = utc_now_iso()
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(old)
        try:
            ended_session = end_surveillance_session(
                pppoe,
                "fixed",
                started_at=(old.get("added_at") or "").strip(),
                source=(old.get("source") or "").strip(),
                ip=(old.get("ip") or "").strip(),
                state=(old.get("status") or "level2"),
                note=reason,
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
            )
        except Exception:
            ended_session = {}

        _append_surveillance_stage_history(
            entry_map[pppoe],
            from_stage="level2",
            to_stage="observe",
            reason=reason,
            action="mark_fixed",
            at_iso=now_iso,
            actor=_auth_actor_name(request, default="admin"),
        )
        entry_map[pppoe]["status"] = "under"
        entry_map[pppoe]["added_at"] = now_iso
        entry_map[pppoe]["first_added_at"] = (entry_map[pppoe].get("first_added_at") or old.get("first_added_at") or old.get("added_at") or now_iso).strip() or now_iso
        entry_map[pppoe]["updated_at"] = now_iso
        entry_map[pppoe]["level2_at"] = ""
        entry_map[pppoe]["level2_reason"] = ""
        entry_map[pppoe]["last_fixed_at"] = now_iso
        entry_map[pppoe]["last_fixed_reason"] = reason
        entry_map[pppoe]["last_fixed_mode"] = "manual"
        try:
            ensure_surveillance_session(
                pppoe,
                started_at=now_iso,
                source=(entry_map[pppoe].get("source") or "").strip(),
                ip=(entry_map[pppoe].get("ip") or "").strip(),
                state="under",
                observed_total_hint=(ended_session or {}).get("observed_count"),
            )
        except Exception:
            pass
        _auth_log_event(
            request,
            action="surveillance.mark_fixed",
            resource=pppoe,
            details=f"reason={reason}",
        )
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    try:
        _prime_surveillance_checker_cache(entry_map, reset_pppoes=[pppoe])
    except Exception:
        pass
    return RedirectResponse(url="/surveillance?tab=observe", status_code=303)


@app.post("/surveillance/fixed_many", response_class=HTMLResponse)
async def surveillance_fixed_many(request: Request):
    form = await request.form()
    raw_pppoes = (form.get("pppoes") or "").strip()
    reason = (form.get("reason") or "").strip()

    pppoes: list[str] = []
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            pppoes = [p.strip() for p in raw_pppoes.split(",") if p.strip()]

    if not pppoes:
        return RedirectResponse(url="/surveillance?tab=level2", status_code=303)

    if not reason or len(reason) < 3:
        return RedirectResponse(
            url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is required for Account Fixed.')}",
            status_code=303,
        )
    if len(reason) > 500:
        return RedirectResponse(
            url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is too long (max 500 characters).')}",
            status_code=303,
        )

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    now_iso = utc_now_iso()

    seen = set()
    unique_pppoes: list[str] = []
    for p in pppoes:
        if p in seen:
            continue
        seen.add(p)
        unique_pppoes.append(p)

    for pppoe in unique_pppoes:
        if pppoe not in entry_map:
            continue
        old = dict(entry_map.get(pppoe) or {})
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(old)
        try:
            ended_session = end_surveillance_session(
                pppoe,
                "fixed",
                started_at=(old.get("added_at") or "").strip(),
                source=(old.get("source") or "").strip(),
                ip=(old.get("ip") or "").strip(),
                state=(old.get("status") or "level2"),
                note=reason,
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
            )
        except Exception:
            ended_session = {}
        _append_surveillance_stage_history(
            entry_map[pppoe],
            from_stage="level2",
            to_stage="observe",
            reason=reason,
            action="mark_fixed",
            at_iso=now_iso,
            actor=_auth_actor_name(request, default="admin"),
        )
        entry_map[pppoe]["status"] = "under"
        entry_map[pppoe]["added_at"] = now_iso
        entry_map[pppoe]["first_added_at"] = (entry_map[pppoe].get("first_added_at") or old.get("first_added_at") or old.get("added_at") or now_iso).strip() or now_iso
        entry_map[pppoe]["updated_at"] = now_iso
        entry_map[pppoe]["level2_at"] = ""
        entry_map[pppoe]["level2_reason"] = ""
        entry_map[pppoe]["last_fixed_at"] = now_iso
        entry_map[pppoe]["last_fixed_reason"] = reason
        entry_map[pppoe]["last_fixed_mode"] = "manual"
        try:
            ensure_surveillance_session(
                pppoe,
                started_at=now_iso,
                source=(entry_map[pppoe].get("source") or "").strip(),
                ip=(entry_map[pppoe].get("ip") or "").strip(),
                state="under",
                observed_total_hint=(ended_session or {}).get("observed_count"),
            )
        except Exception:
            pass

    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    try:
        _prime_surveillance_checker_cache(entry_map, reset_pppoes=unique_pppoes)
    except Exception:
        pass
    if unique_pppoes:
        preview = ",".join(unique_pppoes[:10])
        if len(unique_pppoes) > 10:
            preview += f",+{len(unique_pppoes) - 10}"
        _auth_log_event(
            request,
            action="surveillance.mark_fixed_bulk",
            resource=preview,
            details=f"count={len(unique_pppoes)};reason={reason}",
        )
    return RedirectResponse(url="/surveillance?tab=observe", status_code=303)

def render_wan_ping_response(request, pulse_settings, wan_settings, message, active_tab, wan_window_hours=24, wan_settings_tab="telegram"):
    if (active_tab or "").strip().lower() in ("add", "routers"):
        active_tab = "settings"
    active_tab = (active_tab or "status").strip().lower()
    if active_tab not in ("status", "settings", "messages"):
        active_tab = "settings"
    wan_settings_tab = (wan_settings_tab or "telegram").strip().lower()
    if wan_settings_tab not in ("telegram", "targets", "interval", "database"):
        wan_settings_tab = "telegram"
    can_run_danger_actions = _auth_request_has_permission(request, "wan.settings.danger.run")
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_state = get_state("wan_ping_state", {})
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=24)
    start_iso = window_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    end_iso = window_end.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    status_start = (datetime.now(timezone.utc) - timedelta(hours=max(int(wan_window_hours or 24), 1)))
    combined_start = min(window_start - timedelta(days=1), status_start)
    history_start_iso = combined_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    wan_ids = [row.get("wan_id") for row in wan_rows if row.get("wan_id")]
    history_map = fetch_wan_history_map(wan_ids, history_start_iso, end_iso)
    wan_latency_series = build_wan_latency_series(
        wan_rows,
        wan_state,
        hours=24,
        window_start=window_start,
        window_end=window_end,
        history_map=history_map,
    )
    wan_status = build_wan_status_summary(wan_rows, wan_state, history_map, window_hours=max(int(wan_window_hours or 24), 1))
    wan_targets = sorted({item.get("target") for item in wan_latency_series if item.get("target")})
    wan_refresh_seconds = int(wan_settings.get("general", {}).get("interval_seconds", 30) or 30)
    wan_target_refresh_seconds = int(
        wan_settings.get("general", {}).get("target_latency_interval_seconds", wan_refresh_seconds) or wan_refresh_seconds or 30
    )
    wan_target_rotation_raw = wan_settings.get("general", {}).get("target_rotation_enabled", False)
    if isinstance(wan_target_rotation_raw, str):
        wan_target_rotation_enabled = wan_target_rotation_raw.strip().lower() in ("1", "true", "yes", "on")
    else:
        wan_target_rotation_enabled = bool(wan_target_rotation_raw)
    wan_targets_per_wan_per_run_raw = wan_settings.get("general", {}).get("targets_per_wan_per_run", 1)
    if wan_targets_per_wan_per_run_raw in (None, ""):
        wan_targets_per_wan_per_run_raw = 1
    try:
        wan_targets_per_wan_per_run = max(int(wan_targets_per_wan_per_run_raw), 0)
    except Exception:
        wan_targets_per_wan_per_run = 1

    general_cfg = wan_settings.get("general") if isinstance(wan_settings.get("general"), dict) else {}
    enabled_targets = [
        item
        for item in (general_cfg.get("targets") or [])
        if isinstance(item, dict)
        and (item.get("id") or "").strip()
        and (item.get("host") or "").strip()
        and bool(item.get("enabled", True))
    ]

    def _target_order(item):
        host = (item.get("host") or "").strip()
        try:
            ipaddress.ip_address(host)
            is_ip = 0
        except ValueError:
            is_ip = 1
        return (is_ip, (item.get("label") or "").strip().lower(), (item.get("id") or "").strip().lower())

    enabled_targets.sort(key=_target_order)
    wan_target_default_host = (enabled_targets[0].get("host") or "").strip() if enabled_targets else ""
    wan_target_extra_targets = max(len(enabled_targets) - 1, 0)
    return templates.TemplateResponse(
        "settings_wan_ping.html",
        make_context(
            request,
            {
                "pulsewatch_settings": pulse_settings,
                "settings": wan_settings,
                "wan_rows": wan_rows,
                "wan_state": wan_state,
                "wan_latency_series": wan_latency_series,
                "wan_targets": wan_targets,
                "wan_refresh_seconds": wan_refresh_seconds,
                "wan_target_refresh_seconds": wan_target_refresh_seconds,
                "wan_target_rotation_enabled": wan_target_rotation_enabled,
                "wan_targets_per_wan_per_run": wan_targets_per_wan_per_run,
                "wan_status": wan_status,
                "wan_window_options": WAN_STATUS_WINDOW_OPTIONS,
                "wan_message_defaults": WAN_MESSAGE_DEFAULTS,
                "wan_summary_defaults": WAN_SUMMARY_DEFAULTS,
                "wan_target_default_host": wan_target_default_host,
                "wan_target_extra_targets": wan_target_extra_targets,
                "message": message,
                "active_tab": active_tab,
                "wan_settings_tab": wan_settings_tab,
                "can_run_danger_actions": can_run_danger_actions,
            },
        ),
    )


def _render_isp_status_response(request, message="", active_tab="status", settings_tab="general"):
    settings = normalize_isp_status_settings(get_settings("isp_status", ISP_STATUS_DEFAULTS))
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    state = get_state("isp_status_state", {})
    rows = _build_isp_status_rows(pulse_settings, wan_settings, state=state)
    configured_rows = [row for row in rows if (row.get("traffic_interface") or "").strip()]
    capacity_counts = {"1g": 0, "100m": 0, "observing": 0, "not_configured": 0, "error": 0}
    for row in rows:
        status = (row.get("capacity_status") or "observing").strip().lower()
        capacity_counts[status if status in capacity_counts else "observing"] += 1
    active_tab = (active_tab or "status").strip().lower()
    if active_tab == "telegram":
        active_tab = "settings"
        settings_tab = "telegram"
    if active_tab not in ("status", "settings"):
        active_tab = "status"
    settings_tab = (settings_tab or "general").strip().lower()
    if settings_tab not in ("general", "capacity", "telegram"):
        settings_tab = "general"
    status_map = {item["job_name"]: dict(item) for item in get_job_status()}
    job = status_map.get("isp_status", {})
    job["last_run_at_ph"] = format_ts_ph(job.get("last_run_at"))
    job["last_success_at_ph"] = format_ts_ph(job.get("last_success_at"))
    job["last_error_at_ph"] = format_ts_ph(job.get("last_error_at"))
    return templates.TemplateResponse(
        "settings_isp_status.html",
        make_context(
            request,
            {
                "settings": settings,
                "wan_rows": rows,
                "configured_count": len(configured_rows),
                "capacity_counts": capacity_counts,
                "job_status": job,
                "state": state if isinstance(state, dict) else {},
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "message": message,
                "window_options": WAN_STATUS_WINDOW_OPTIONS,
                "wan_telegram": wan_settings.get("telegram") if isinstance(wan_settings.get("telegram"), dict) else {},
            },
        ),
    )


@app.get("/settings/isp-status", response_class=HTMLResponse)
async def isp_status_settings(request: Request):
    tab = (request.query_params.get("tab") or "status").strip().lower()
    settings_tab = (request.query_params.get("settings_tab") or "general").strip().lower()
    return _render_isp_status_response(request, active_tab=tab, settings_tab=settings_tab)


@app.post("/settings/isp-status/settings", response_class=HTMLResponse)
async def isp_status_settings_save(request: Request):
    form = await request.form()
    settings = normalize_isp_status_settings(get_settings("isp_status", ISP_STATUS_DEFAULTS))
    settings_tab = (form.get("settings_tab") or "general").strip().lower()
    if settings_tab not in ("general", "capacity"):
        settings_tab = "general"
    if settings_tab == "general":
        settings["enabled"] = parse_bool(form, "isp_status_enabled")
        general = settings.setdefault("general", {})
        general["poll_interval_seconds"] = max(parse_int(form, "poll_interval_seconds", general.get("poll_interval_seconds", 30)), 5)
        general["history_retention_days"] = max(parse_int(form, "history_retention_days", general.get("history_retention_days", 400)), 1)
        general["chart_window_hours"] = max(parse_int(form, "chart_window_hours", general.get("chart_window_hours", 24)), 1)
    elif settings_tab == "capacity":
        capacity = settings.setdefault("capacity", {})
        try:
            capacity["hundred_mbps_min"] = max(float(form.get("hundred_mbps_min") or capacity.get("hundred_mbps_min") or 90), 1.0)
        except Exception:
            capacity["hundred_mbps_min"] = 90.0
        try:
            capacity["hundred_mbps_max"] = max(float(form.get("hundred_mbps_max") or capacity.get("hundred_mbps_max") or 105), capacity["hundred_mbps_min"])
        except Exception:
            capacity["hundred_mbps_max"] = max(105.0, capacity["hundred_mbps_min"])
        capacity["window_minutes"] = max(parse_int(form, "window_minutes", capacity.get("window_minutes", 10)), 1)
        capacity["average_detection_enabled"] = parse_bool(form, "average_detection_enabled")
        capacity["average_window_hours"] = max(parse_int(form, "average_window_hours", capacity.get("average_window_hours", 4)), 1)
    settings = normalize_isp_status_settings(settings)
    save_settings("isp_status", settings)
    return _render_isp_status_response(request, "ISP Port Status settings saved.", active_tab="settings", settings_tab=settings_tab)


@app.post("/settings/isp-status/telegram", response_class=HTMLResponse)
async def isp_status_telegram_save(request: Request):
    form = await request.form()
    settings = normalize_isp_status_settings(get_settings("isp_status", ISP_STATUS_DEFAULTS))
    telegram = settings.setdefault("telegram", {})
    telegram["daily_enabled"] = parse_bool(form, "telegram_daily_enabled")
    telegram["daily_time"] = (form.get("telegram_daily_time") or telegram.get("daily_time") or "07:00").strip()
    telegram["immediate_100m_enabled"] = parse_bool(form, "telegram_immediate_100m_enabled")
    telegram["recovery_confirm_minutes"] = max(parse_int(form, "telegram_recovery_confirm_minutes", telegram.get("recovery_confirm_minutes", 2)), 1)
    settings = normalize_isp_status_settings(settings)
    save_settings("isp_status", settings)
    return _render_isp_status_response(request, "ISP Port Status Telegram settings saved.", active_tab="settings", settings_tab="telegram")


def _send_isp_status_test_telegram(wan_settings, message):
    telegram = wan_settings.get("telegram") if isinstance(wan_settings.get("telegram"), dict) else {}
    send_telegram((telegram.get("bot_token") or "").strip(), (telegram.get("chat_id") or "").strip(), message)


def _build_isp_status_daily_test_message(rows, capacity_counts):
    rows = rows or []
    review_count = (
        capacity_counts.get("observing", 0)
        + capacity_counts.get("not_configured", 0)
        + capacity_counts.get("error", 0)
    )
    if capacity_counts.get("100m", 0) > 0:
        summary_status = "🔴 100M detected"
    elif review_count > 0:
        summary_status = "🟡 Some ISPs need review"
    else:
        summary_status = "🟢 All ISPs are 1G"
    now_local = datetime.now(ZoneInfo("Asia/Manila"))
    lines = [
        "ISP Port Status Daily Report (Test)",
        f"🕖 {now_local.strftime('%Y-%m-%d %I:%M %p')}",
        f"(1G/100M): {capacity_counts.get('1g', 0)}/{capacity_counts.get('100m', 0)} - {summary_status}",
        "",
    ]
    for row in rows[:20]:
        label = row.get("identifier") or row.get("list_name") or row.get("wan_id") or "ISP"
        status = (row.get("capacity_label") or row.get("capacity_status") or "Observing").strip()
        lines.append(f"{label}: {status}")
    if len(rows) > 20:
        lines.append(f"+{len(rows) - 20} more ISP row(s)")
    return "\n".join(lines)


def _build_isp_status_100m_test_message(rows):
    row = next((item for item in (rows or []) if (item.get("traffic_interface") or "").strip()), None)
    if not row and rows:
        row = rows[0]
    identifier = (row or {}).get("identifier") or (row or {}).get("list_name") or (row or {}).get("wan_id") or "Sample ISP"
    list_name = (row or {}).get("list_name") or "sample-to-isp"
    core = (row or {}).get("core_label") or (row or {}).get("core_id") or "Sample Core"
    iface = (row or {}).get("traffic_interface") or "sample-interface"
    return "\n".join(
        [
            "⚠️ ISP Port Status detected possible 100M capacity (Test)",
            f"Identifier: {identifier}",
            f"TO-ISP: {list_name}",
            f"Core: {core}",
            f"Interface: {iface}",
            "RX: 94.00 Mbps",
            "TX: 3.00 Mbps",
            "Total: 97.00 Mbps",
            "Peak: 94.00 Mbps",
            "Reason: Test message for the immediate 100M alert.",
        ]
    )


@app.post("/settings/isp-status/telegram/test-daily", response_class=HTMLResponse)
async def isp_status_telegram_test_daily(request: Request):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    rows = _build_isp_status_rows(pulse_settings, wan_settings, state=get_state("isp_status_state", {}))
    capacity_counts = {"1g": 0, "100m": 0, "observing": 0, "not_configured": 0, "error": 0}
    for row in rows:
        status = (row.get("capacity_status") or "observing").strip().lower()
        capacity_counts[status if status in capacity_counts else "observing"] += 1
    try:
        _send_isp_status_test_telegram(wan_settings, _build_isp_status_daily_test_message(rows, capacity_counts))
        message = "Daily report test message sent."
    except TelegramError as exc:
        message = str(exc)
    return _render_isp_status_response(request, message, active_tab="settings", settings_tab="telegram")


@app.post("/settings/isp-status/telegram/test-100m", response_class=HTMLResponse)
async def isp_status_telegram_test_100m(request: Request):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    rows = _build_isp_status_rows(pulse_settings, wan_settings, state=get_state("isp_status_state", {}))
    try:
        _send_isp_status_test_telegram(wan_settings, _build_isp_status_100m_test_message(rows))
        message = "Immediate 100M alert test message sent."
    except TelegramError as exc:
        message = str(exc)
    return _render_isp_status_response(request, message, active_tab="settings", settings_tab="telegram")


@app.get("/isp-status/status", response_class=JSONResponse)
async def isp_status_status():
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    state = get_state("isp_status_state", {})
    rows = _build_isp_status_rows(pulse_settings, wan_settings, state=state)
    capacity_counts = {"1g": 0, "100m": 0, "observing": 0, "not_configured": 0, "error": 0}
    configured_count = 0
    for row in rows:
        status = (row.get("capacity_status") or "observing").strip().lower()
        capacity_counts[status if status in capacity_counts else "observing"] += 1
        if (row.get("traffic_interface") or "").strip():
            configured_count += 1
    status_map = {item["job_name"]: dict(item) for item in get_job_status()}
    job = status_map.get("isp_status", {})
    job["last_run_at_ph"] = format_ts_ph(job.get("last_run_at"))
    job["last_success_at_ph"] = format_ts_ph(job.get("last_success_at"))
    job["last_error_at_ph"] = format_ts_ph(job.get("last_error_at"))
    return _json_no_store(
        {
            "rows": rows,
            "capacity_counts": capacity_counts,
            "configured_count": configured_count,
            "job_status": job,
            "updated_at": utc_now_iso(),
        }
    )


@app.get("/isp-status/series", response_class=JSONResponse)
async def isp_status_series(hours: int = 24):
    hours = _normalize_wan_window(hours)
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    start_dt = now_dt - timedelta(hours=hours)
    start_iso = start_dt.isoformat().replace("+00:00", "Z")
    end_iso = now_dt.isoformat().replace("+00:00", "Z")
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    rows = _build_isp_status_rows(pulse_settings, wan_settings)
    wan_ids = [row.get("wan_id") for row in rows if row.get("wan_id") and (row.get("traffic_interface") or "").strip()]
    series_payload = fetch_isp_status_series_map(wan_ids, start_iso, end_iso, bucket_seconds=_isp_status_bucket_seconds(hours))
    series_map = series_payload.get("series") if isinstance(series_payload, dict) else {}
    total_points = series_payload.get("total") if isinstance(series_payload, dict) else []
    chart_series = [
        {
            "id": "all",
            "name": "All ISP",
            "color": "#206bc4",
            "points": [{"x": item.get("timestamp"), "y": item.get("total_mbps")} for item in total_points],
        }
    ]
    for row in rows:
        wan_id = row.get("wan_id")
        if not wan_id or wan_id not in series_map:
            continue
        chart_series.append(
            {
                "id": wan_id,
                "name": " · ".join(
                    part
                    for part in [
                        row.get("identifier") or row.get("list_name") or wan_id,
                        row.get("core_label") or row.get("core_id"),
                        row.get("traffic_interface"),
                    ]
                    if part
                ),
                "color": row.get("color") or "#6c7a91",
                "points": [
                    {"x": item.get("timestamp"), "y": item.get("total_mbps")}
                    for item in (series_map.get(wan_id) or [])
                ],
            }
        )
    return JSONResponse({"series": chart_series, "window": {"start": start_iso, "end": end_iso}, "hours": hours})


@app.post("/settings/isp-status/format", response_class=HTMLResponse)
async def isp_status_format_db(request: Request):
    return _render_system_danger_notice(request, "isp_status")


@app.get("/settings/wan", response_class=HTMLResponse)
async def wan_settings(request: Request):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    window_hours = _normalize_wan_window(request.query_params.get("wan_window"))
    active_tab = (request.query_params.get("tab") or "status").strip().lower()
    wan_settings_tab = (request.query_params.get("wan_settings_tab") or "telegram").strip().lower()
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "", active_tab, window_hours, wan_settings_tab=wan_settings_tab)


@app.post("/settings/wan/wans", response_class=HTMLResponse)
async def wan_settings_save_wans(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "wan_count", 0)
    existing_wan_map = {
        ((item.get("core_id") or "").strip(), (item.get("list_name") or "").strip()): item
        for item in wan_settings_data.get("wans", [])
        if isinstance(item, dict) and (item.get("core_id") or "").strip() and (item.get("list_name") or "").strip()
    }
    wans = []
    for idx in range(count):
        core_id = (form.get(f"wan_{idx}_core_id") or "").strip()
        list_name = (form.get(f"wan_{idx}_list") or "").strip()
        if not core_id or not list_name:
            continue
        existing = existing_wan_map.get((core_id, list_name), {}) or {}
        raw_traffic_interface = form.get(f"wan_{idx}_traffic_interface")
        mode = (form.get(f"wan_{idx}_mode") or "routed").strip().lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"
        local_ip = (form.get(f"wan_{idx}_local_ip") or "").strip()
        netwatch_host = (form.get(f"wan_{idx}_netwatch_host") or "").strip()
        if mode == "bridged" and not netwatch_host:
            netwatch_host = local_ip
        enabled = parse_bool(form, f"wan_{idx}_enabled")
        if not local_ip:
            enabled = False
        wans.append(
            {
                "id": wan_row_id(core_id, list_name),
                "core_id": core_id,
                "list_name": list_name,
                "identifier": (form.get(f"wan_{idx}_identifier") or "").strip(),
                "color": _sanitize_hex_color(form.get(f"wan_{idx}_color") or ""),
                "enabled": enabled,
                "mode": mode,
                "local_ip": local_ip,
                "gateway_ip": "",
                "netwatch_host": netwatch_host,
                "pppoe_router_id": (form.get(f"wan_{idx}_pppoe_router_id") or "").strip(),
                "traffic_interface": (
                    raw_traffic_interface.strip()
                    if raw_traffic_interface is not None
                    else (existing.get("traffic_interface") or "").strip()
                ),
            }
        )
    wan_settings_data["wans"] = wans
    save_settings("wan_ping", wan_settings_data)
    sync_errors = wan_ping_notifier.sync_netwatch(wan_settings_data, pulse_settings)
    save_settings("wan_ping", wan_settings_data)
    if sync_errors:
        message = "WAN list saved with Netwatch warnings: " + "; ".join(sync_errors)
    else:
        message = "WAN list saved and Netwatch synced."
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="isps")


@app.post("/settings/wan/routers", response_class=HTMLResponse)
async def wan_settings_save_routers(request: Request):
    form = await request.form()
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "router_count", 0)
    routers, removed_ids = _parse_wan_pppoe_routers_from_form(form, count)
    wan_settings_data["pppoe_routers"] = routers
    if removed_ids:
        for wan in wan_settings_data.get("wans", []):
            if wan.get("pppoe_router_id") in removed_ids:
                wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(request, "Mikrotik routers saved.", active_tab="routers", routers_tab="mikrotik-routers")


@app.post("/settings/wan/routers/add", response_class=HTMLResponse)
async def wan_settings_add_router(request: Request):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = wan_settings_data.get("pppoe_routers", [])
    existing_ids = {router.get("id") for router in routers if router.get("id")}
    next_idx = 1
    while f"router{next_idx}" in existing_ids:
        next_idx += 1
    routers.append(
        {
            "id": f"router{next_idx}",
            "name": f"Router {next_idx}",
            "host": "",
            "port": 8728,
            "username": "",
            "password": "",
            "use_tls": False,
        }
    )
    wan_settings_data["pppoe_routers"] = routers
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(request, "Mikrotik router added.", active_tab="routers", routers_tab="mikrotik-routers")


@app.post("/settings/wan/routers/remove/{router_id}", response_class=HTMLResponse)
async def wan_settings_remove_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = [router for router in wan_settings_data.get("pppoe_routers", []) if router.get("id") != router_id]
    wan_settings_data["pppoe_routers"] = routers
    for wan in wan_settings_data.get("wans", []):
        if wan.get("pppoe_router_id") == router_id:
            wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(request, "Mikrotik router removed.", active_tab="routers", routers_tab="mikrotik-routers")


@app.post("/settings/wan/routers/test/{router_id}", response_class=HTMLResponse)
async def wan_settings_test_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router = next(
        (item for item in wan_settings_data.get("pppoe_routers", []) if item.get("id") == router_id),
        None,
    )
    if not router:
        return render_system_settings_response(request, "Router not found.", active_tab="routers", routers_tab="mikrotik-routers")
    if router.get("use_tls"):
        return render_system_settings_response(
            request,
            "TLS test not supported yet. Disable TLS or use port 8728.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    host = (router.get("host") or "").strip()
    if not host:
        return render_system_settings_response(request, "Router host is required.", active_tab="routers", routers_tab="mikrotik-routers")
    client = RouterOSClient(
        host,
        int(router.get("port", 8728)),
        router.get("username", ""),
        router.get("password", ""),
    )
    try:
        client.connect()
        message = f"Router {router.get('name') or router_id} connected successfully."
    except Exception as exc:
        message = f"Router test failed: {exc}"
    finally:
        client.close()
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="mikrotik-routers")


@app.post("/settings/wan/telegram", response_class=HTMLResponse)
async def wan_settings_save_telegram(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_settings_data["telegram"] = {
        "bot_token": form.get("telegram_bot_token", ""),
        "chat_id": form.get("telegram_chat_id", ""),
    }
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Telegram settings saved.", "settings", wan_settings_tab="telegram")


@app.post("/settings/wan/telegram/test", response_class=HTMLResponse)
async def wan_settings_test_telegram(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_settings_data["telegram"] = {
        "bot_token": form.get("telegram_bot_token", ""),
        "chat_id": form.get("telegram_chat_id", ""),
    }
    try:
        send_telegram(
            wan_settings_data["telegram"].get("bot_token", ""),
            wan_settings_data["telegram"].get("chat_id", ""),
            "ThreeJ WAN Ping Telegram test message.",
        )
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return render_wan_ping_response(
        request,
        pulse_settings,
        wan_settings_data,
        message,
        "settings",
        wan_settings_tab="telegram",
    )


@app.post("/settings/wan/targets", response_class=HTMLResponse)
async def wan_settings_save_targets(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "target_count", 0)
    raw_targets = []
    deleted_target_ids = []
    for idx in range(max(count, 0)):
        if parse_bool(form, f"target_{idx}_delete"):
            target_id = (form.get(f"target_{idx}_id") or "").strip()
            if target_id:
                deleted_target_ids.append(target_id)
            continue
        host = (form.get(f"target_{idx}_host") or "").strip()
        label = (form.get(f"target_{idx}_label") or "").strip()
        enabled = parse_bool(form, f"target_{idx}_enabled")
        if not host:
            continue
        target_id = (form.get(f"target_{idx}_id") or "").strip()
        if not target_id:
            base = re.sub(r"[^a-z0-9]+", "-", (label or host).lower()).strip("-")
            target_id = base or f"target-{idx+1}"
        raw_targets.append({"id": target_id, "label": label or host, "host": host, "enabled": enabled})

    seen = set()
    targets = []
    for item in raw_targets:
        base = item["id"]
        candidate = base
        suffix = 2
        while candidate in seen:
            candidate = f"{base}-{suffix}"
            suffix += 1
        seen.add(candidate)
        targets.append({**item, "id": candidate})

    wan_settings_data.setdefault("general", {})["targets"] = targets
    wan_settings_data.setdefault("general", {})["targets_configured"] = True
    save_settings("wan_ping", wan_settings_data)
    try:
        delete_wan_target_ping_results_for_targets(deleted_target_ids)
    except Exception:
        pass
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Targets saved.", "settings", wan_settings_tab="targets")


@app.post("/settings/wan/messages", response_class=HTMLResponse)
async def wan_settings_save_messages(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    summary = wan_settings_data.setdefault("summary", {})
    summary["enabled"] = parse_bool(form, "summary_enabled")
    summary["daily_time"] = (form.get("summary_daily_time") or WAN_SUMMARY_DEFAULTS["daily_time"]).strip()
    summary["all_up_msg"] = form.get("summary_all_up_msg") or WAN_SUMMARY_DEFAULTS["all_up_msg"]
    summary["partial_msg"] = form.get("summary_partial_msg") or WAN_SUMMARY_DEFAULTS["partial_msg"]
    summary["line_template"] = form.get("summary_line_template") or WAN_SUMMARY_DEFAULTS["line_template"]
    count = parse_int(form, "message_count", 0)
    messages = {}
    for idx in range(count):
        wan_id = (form.get(f"message_{idx}_id") or "").strip()
        if not wan_id:
            continue
        send_down_once = parse_bool(form, f"message_{idx}_send_down_once")
        messages[wan_id] = {
            "down_msg": form.get(f"message_{idx}_down_msg", ""),
            "up_msg": form.get(f"message_{idx}_up_msg", ""),
            "still_down_msg": form.get(f"message_{idx}_still_down_msg", ""),
            "send_down_once": send_down_once,
            "repeat_down_interval_minutes": parse_int(form, f"message_{idx}_repeat_minutes", 30),
            "still_down_interval_hours": parse_int(form, f"message_{idx}_still_hours", 8),
        }
    wan_settings_data["messages"] = messages
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Messages saved.", "messages")


@app.post("/settings/wan/interval", response_class=HTMLResponse)
async def wan_settings_save_interval(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    interval = parse_int(form, "wan_interval_seconds", 30)
    general = wan_settings_data.setdefault("general", {})
    general["interval_seconds"] = max(interval, 5)
    target_interval = parse_int(form, "wan_target_latency_interval_seconds", general.get("interval_seconds", 30))
    general["target_latency_interval_seconds"] = max(target_interval, 1)
    general["target_rotation_enabled"] = parse_bool(form, "wan_target_rotation_enabled")
    parallel_workers = parse_int(form, "wan_target_parallel_workers", general.get("target_parallel_workers", 0))
    general["target_parallel_workers"] = max(min(parallel_workers, 64), 0)
    targets_per_wan = parse_int(form, "wan_targets_per_wan_per_run", general.get("targets_per_wan_per_run", 1))
    general["targets_per_wan_per_run"] = max(targets_per_wan, 0)
    timeout_ms = parse_int(form, "wan_target_ping_timeout_ms", general.get("target_ping_timeout_ms", 1000))
    general["target_ping_timeout_ms"] = max(min(timeout_ms, 60000), 100)
    ping_count = parse_int(form, "wan_target_ping_count", general.get("target_ping_count", 1))
    general["target_ping_count"] = max(min(ping_count, 20), 1)
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Polling settings saved.", "settings", wan_settings_tab="interval")


@app.post("/settings/wan/database", response_class=HTMLResponse)
async def wan_settings_save_database(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    retention = parse_int(form, "wan_history_retention_days", 400)
    retention = max(min(retention, 1460), 1)
    wan_settings_data.setdefault("general", {})["history_retention_days"] = retention
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Database settings saved.", "settings", wan_settings_tab="database")


@app.post("/settings/wan/format", response_class=HTMLResponse)
async def wan_format_db(request: Request):
    return _render_system_danger_notice(request, "wan")


@app.get("/settings/pulsewatch")
async def legacy_pulsewatch_settings_redirect():
    return RedirectResponse(url="/settings/wan", status_code=302)


@app.api_route("/settings/pulsewatch/{legacy_path:path}", methods=["GET", "POST"])
async def legacy_pulsewatch_settings_path_redirect(legacy_path: str):
    return RedirectResponse(url="/settings/wan", status_code=302)


@app.api_route("/isp/pulsewatch/{legacy_path:path}", methods=["GET", "POST"])
async def legacy_pulsewatch_action_removed(legacy_path: str):
    return JSONResponse(
        {
            "ok": False,
            "message": "ISP Pulsewatch has been removed. Use WAN Ping instead.",
            "path": legacy_path,
        },
        status_code=410,
    )


@app.api_route("/pulsewatch/{legacy_path:path}", methods=["GET", "POST"])
async def legacy_pulsewatch_api_removed(legacy_path: str):
    return JSONResponse(
        {
            "ok": False,
            "message": "ISP Pulsewatch APIs were removed. Use WAN endpoints instead.",
            "path": legacy_path,
        },
        status_code=410,
    )


@app.get("/system/resources")
async def system_resources(details: int = 0):
    mem = _memory_details_kb()
    mem_total_kb = int(mem.get("mem_total_kb") or 0)
    mem_avail_kb = int(mem.get("mem_available_kb") or 0)
    mem_free_kb = int(mem.get("mem_free_kb") or 0)
    mem_cached_kb = int(mem.get("cached_kb") or 0)
    mem_buffers_kb = int(mem.get("buffers_kb") or 0)
    payload = {
        "cpu_pct": round(_cpu_percent(), 1),
        # ram_pct remains backward-compatible (pressure view, based on MemAvailable)
        "ram_pct": round(_memory_percent(), 1),
        # explicit fields:
        "ram_pressure_pct": round(_memory_percent(), 1),
        "ram_used_incl_cache_pct": round(_memory_used_including_cache_percent(), 1),
        # raw figures for debugging/UI (KB from /proc/meminfo)
        "ram_total_kb": mem_total_kb,
        "ram_available_kb": mem_avail_kb,
        "ram_free_kb": mem_free_kb,
        "ram_cached_kb": mem_cached_kb,
        "ram_buffers_kb": mem_buffers_kb,
        "disk_pct": round(_disk_percent(), 1),
        "uptime_seconds": _uptime_seconds(),
    }
    include_details = False
    try:
        include_details = int(details or 0) > 0
    except Exception:
        include_details = False
    if include_details:
        proc_root = _process_proc_root()
        sampled = _sample_process_usage(limit=0, sample_seconds=0.25, proc_root=proc_root)
        all_processes = list(sampled.get("rows") or [])
        top_processes = all_processes[:12]
        tracked_cpu_pct = float(sampled.get("total_cpu_pct") or 0.0)
        tracked_count = int(sampled.get("process_count") or 0)
        if not top_processes:
            top_processes = _top_process_usage(limit=12)
            tracked_cpu_pct = round(sum(float(item.get("cpu_pct") or 0.0) for item in top_processes), 1)
            tracked_count = len(top_processes)
            all_processes = list(top_processes)
        payload["top_processes"] = top_processes
        payload["feature_usage"] = _aggregate_feature_usage(all_processes, limit=8)
        runtime_features = sample_feature_cpu_percent(cpu_count=max(int(os.cpu_count() or 1), 1))
        payload["threej_feature_cpu"] = runtime_features
        payload["threej_summary"] = _build_runtime_threej_summary(
            runtime_features,
            all_processes,
            payload.get("cpu_pct") or 0.0,
        )
        payload["cpu_tracked_pct"] = round(max(0.0, min(100.0, tracked_cpu_pct)), 1)
        payload["tracked_process_count"] = tracked_count
        payload["cpu_scope"] = "Host processes" if proc_root == "/host_proc" else "Container processes"
        payload["captured_at"] = utc_now_iso()
    return JSONResponse(payload)


@app.post("/settings/system/mikrotik/test", response_class=HTMLResponse)
async def isp_mikrotik_test(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    pulse_cfg = settings.get("pulsewatch", {})
    routers = pulse_cfg.get("mikrotik", {}).get("cores", [])
    results = []
    for router in routers:
        core_id = router.get("id") or "core"
        host = router.get("host", "")
        if not host:
            results.append(f"{core_id}: skipped (no host)")
            continue
        client = RouterOSClient(
            host,
            int(router.get("port", 8728)),
            router.get("username", ""),
            router.get("password", ""),
        )
        try:
            client.connect()
            entries = client.list_address_list()
            results.append(f"{core_id}: OK ({len(entries)} entries)")
        except Exception as exc:
            results.append(f"{core_id}: failed ({exc})")
        finally:
            client.close()
    message = " | ".join(results)
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="cores")


@app.get("/settings", response_class=HTMLResponse)
async def settings_root():
    return RedirectResponse(url="/settings/optical", status_code=302)


_SYSTEM_DANGER_FEATURE_ORDER = ("surveillance", "optical", "accounts_ping", "usage", "offline", "wan", "isp_status", "mikrotik_logs")
_SYSTEM_DANGER_ACTIONS = {
    "surveillance": {
        "label": "Under Surveillance",
        "button_label": "Format Under Surveillance",
        "permission": "surveillance.settings.danger.run",
        "summary": "Clears Active Monitoring, Needs Manual Fix, Post-Fix Observation, and Surveillance History data. Settings are preserved.",
        "path": "/surveillance?tab=settings",
    },
    "optical": {
        "label": "Optical",
        "button_label": "Format Optical",
        "permission": "optical.settings.danger.run",
        "summary": "Clears stored optical history and trend samples. Settings are preserved.",
        "path": "/settings/optical?tab=settings",
    },
    "accounts_ping": {
        "label": "Accounts Ping",
        "button_label": "Format Accounts Ping",
        "permission": "accounts_ping.settings.danger.run",
        "summary": "Clears stored Accounts Ping history and cached account states. Settings are preserved.",
        "path": "/settings/accounts-ping?tab=settings",
    },
    "usage": {
        "label": "Usage",
        "button_label": "Format Usage",
        "permission": "usage.settings.danger.run",
        "summary": "Clears stored usage history, trend samples, and modem auto reboot history/runtime state. Settings are preserved.",
        "path": "/settings/usage?tab=settings",
    },
    "offline": {
        "label": "Offline",
        "button_label": "Format Offline",
        "permission": "offline.settings.danger.run",
        "summary": "Clears offline history and current offline tracker state. Settings are preserved.",
        "path": "/settings/offline?tab=settings",
    },
    "wan": {
        "label": "WAN Ping",
        "button_label": "Format WAN Ping",
        "permission": "wan.settings.danger.run",
        "summary": "Clears WAN status history, target latency history, and cached WAN states. Settings are preserved.",
        "path": "/settings/wan?tab=settings",
    },
    "isp_status": {
        "label": "ISP Port Status",
        "button_label": "Format ISP Port Status",
        "permission": "isp_status.settings.danger.run",
        "summary": "Clears stored ISP Port Status bandwidth samples and runtime classification state. Settings and ISP interface assignments are preserved.",
        "path": "/settings/isp-status?tab=settings",
    },
    "mikrotik_logs": {
        "label": "MikroTik Logs",
        "button_label": "Format MikroTik Logs",
        "permission": "logs.mikrotik.danger.run",
        "summary": "Clears centralized MikroTik syslog entries. Receiver settings are preserved.",
        "path": "/logs/mikrotik",
    },
    "all": {
        "label": "All Monitoring Features",
        "button_label": "Format All Features",
        "permission": "settings.danger",
        "summary": "Formats Under Surveillance, Optical, Accounts Ping, Usage, Offline, WAN Ping, ISP Port Status, and MikroTik Logs in one step. Settings are preserved.",
        "path": "/settings/system?tab=danger",
    },
    "uninstall": {
        "label": "Uninstall System",
        "button_label": "Uninstall Everything",
        "permission": "system.danger.uninstall.run",
        "summary": "Removes Docker, containers, images, volumes, and the application files. This action is irreversible.",
        "path": "/settings/system?tab=danger",
        "confirm_text": "UNINSTALL",
    },
}
_SYSTEM_DANGER_GROUPS = (
    {
        "key": "subscriber_monitoring",
        "title": "Subscriber Monitoring",
        "description": "Feature data tied to account health and recovery workflows.",
        "actions": ("surveillance", "accounts_ping", "offline"),
    },
    {
        "key": "traffic_and_link",
        "title": "Traffic & Link Telemetry",
        "description": "Feature data tied to optical, usage, and WAN history.",
        "actions": ("optical", "usage", "wan", "isp_status", "mikrotik_logs"),
    },
)
_SYSTEM_DANGER_ROLE_TRIGGER_CODES = (
    "settings.danger",
    "RUN_DangerActions",
    "surveillance.settings.danger.run",
    "optical.settings.danger.run",
    "accounts_ping.settings.danger.run",
    "usage.settings.danger.run",
    "offline.settings.danger.run",
    "wan.settings.danger.run",
    "isp_status.settings.danger.run",
    "logs.mikrotik.danger.run",
    "system.danger.uninstall.run",
)
_SYSTEM_DANGER_ROLE_GRANTED_CODES = ("system.view", "system.tab.danger.view")


def _system_danger_requires_password(request: Request) -> bool:
    current_user = getattr(request.state, "current_user", None)
    return bool(getattr(request.state, "auth_enabled", True) and isinstance(current_user, dict) and current_user.get("id"))


def _auth_sync_centralized_danger_role_permissions():
    updated_roles = []
    try:
        roles = list_auth_roles(include_permissions=True)
    except Exception:
        return updated_roles

    for role in roles or []:
        role_id = int(role.get("id") or 0)
        role_name = (role.get("name") or "").strip().lower()
        if role_id <= 0 or role_name == "owner":
            continue
        permission_codes = [
            str(code or "").strip()
            for code in (role.get("permission_codes") or [])
            if str(code or "").strip()
        ]
        raw_keys = {code.lower() for code in permission_codes}
        if not any(str(code or "").strip().lower() in raw_keys for code in _SYSTEM_DANGER_ROLE_TRIGGER_CODES):
            continue

        next_codes = list(permission_codes)
        changed = False
        for grant_code in _SYSTEM_DANGER_ROLE_GRANTED_CODES:
            if str(grant_code).strip().lower() in raw_keys:
                continue
            next_codes.append(grant_code)
            raw_keys.add(str(grant_code).strip().lower())
            changed = True
        if not changed:
            continue
        try:
            set_auth_role_permissions(role_id, next_codes)
            updated_roles.append(role_name or f"id={role_id}")
        except Exception:
            continue
    return updated_roles


def _auth_sync_builtin_role_permissions():
    updated_roles = []
    try:
        roles = list_auth_roles(include_permissions=True)
    except Exception:
        return updated_roles

    role_map = {
        str(role.get("name") or "").strip().lower(): role
        for role in (roles or [])
        if isinstance(role, dict) and str(role.get("name") or "").strip()
    }

    for role_name, default_codes in (AUTH_DEFAULT_ROLE_PERMS or {}).items():
        normalized_role_name = str(role_name or "").strip().lower()
        if not normalized_role_name or normalized_role_name == "owner":
            continue
        role = role_map.get(normalized_role_name)
        if not isinstance(role, dict):
            continue
        try:
            role_id = int(role.get("id") or 0)
        except Exception:
            role_id = 0
        if role_id <= 0:
            continue

        current_codes = [
            str(code or "").strip()
            for code in (role.get("permission_codes") or [])
            if str(code or "").strip()
        ]
        current_keys = {code.lower() for code in current_codes}
        missing_codes = [
            str(code or "").strip()
            for code in (default_codes or [])
            if str(code or "").strip() and str(code or "").strip().lower() not in current_keys
        ]
        if not missing_codes:
            continue

        try:
            set_auth_role_permissions(role_id, current_codes + missing_codes)
            updated_roles.append(normalized_role_name)
        except Exception:
            continue

    return updated_roles


def _system_danger_verify_password(request: Request, password: str):
    if not _system_danger_requires_password(request):
        return True, ""
    current_user = getattr(request.state, "current_user", None)
    if not isinstance(current_user, dict) or not current_user.get("id"):
        return False, "Your session is missing. Sign in again before running danger actions."
    user = get_auth_user_by_id(current_user.get("id"))
    if not user:
        return False, "Your account could not be loaded. Sign in again before running danger actions."
    if not _auth_verify_password((password or "").strip(), user.get("password_hash"), user.get("password_salt")):
        return False, "Current password is incorrect."
    return True, ""


def _system_danger_format_surveillance():
    clear_surveillance_history()
    clear_surveillance_audit_logs()
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    settings["entries"] = []
    save_settings("surveillance", settings)

    state = get_state("accounts_ping_state", {})
    if not isinstance(state, dict):
        state = {}
    state.pop("surveillance_sessions_seeded", None)
    state.pop("surveillance_autoadd_seen", None)
    state.pop("surveillance_autoadd_last_scan_at", None)
    state.pop("surveillance_last_eval_at", None)
    save_state(_SURVEILLANCE_NEW_SEEN_STATE_KEY, {})
    save_state("accounts_ping_state", state)


def _system_danger_format_optical():
    clear_optical_results()


def _system_danger_format_accounts_ping():
    clear_accounts_ping_data()
    state = get_state("accounts_ping_state", {})
    devices = state.get("devices") if isinstance(state.get("devices"), list) else []
    router_status = state.get("router_status") if isinstance(state.get("router_status"), list) else []
    devices_refreshed_at = state.get("devices_refreshed_at") or ""
    save_state(
        "accounts_ping_state",
        {
            "accounts": {},
            "devices": devices,
            "router_status": router_status,
            "devices_refreshed_at": devices_refreshed_at,
            "last_prune_at": None,
        },
    )


def _system_danger_format_usage():
    clear_pppoe_usage_samples()
    clear_usage_modem_reboot_history()
    state = get_state("usage_state", {})
    if not isinstance(state, dict):
        state = {}
    state.pop("modem_reboot", None)
    save_state("usage_state", state)


def _system_danger_format_offline():
    clear_offline_history()
    save_state("offline_state", {})


def _system_danger_format_wan():
    save_state("wan_ping_state", {"reset_at": utc_now_iso(), "wans": {}})
    clear_wan_history()


def _system_danger_format_isp_status():
    clear_isp_status_data()
    save_state("isp_status_state", {"reset_at": utc_now_iso(), "latest": {}, "capacity_windows": {}, "capacity_alerts": {}})


def _system_danger_format_mikrotik_logs():
    clear_mikrotik_logs()
    state = get_state("mikrotik_logs_state", {})
    if not isinstance(state, dict):
        state = {}
    state["formatted_at"] = utc_now_iso()
    state["inserted_total"] = 0
    save_state("mikrotik_logs_state", state)


def _system_danger_start_uninstall():
    host_repo = os.environ.get("THREEJ_HOST_REPO", "/opt/threejnotif")
    command = (
        "docker run --rm --privileged "
        "-v /:/host "
        f"-v {shlex.quote(host_repo)}:/repo "
        "ubuntu bash -c "
        "\"cp /repo/scripts/uninstall_all.sh /host/tmp/threej_uninstall.sh && "
        "chroot /host /bin/bash /tmp/threej_uninstall.sh "
        f"{shlex.quote(host_repo)}\""
    )
    subprocess.Popen(
        ["/bin/sh", "-c", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _system_danger_capabilities(request: Request):
    caps = {
        "can_view_danger_tab": _auth_request_has_permission(request, "system.tab.danger.view"),
        "can_format_surveillance": _auth_request_has_permission(request, "surveillance.settings.danger.run"),
        "can_format_optical": _auth_request_has_permission(request, "optical.settings.danger.run"),
        "can_format_accounts_ping": _auth_request_has_permission(request, "accounts_ping.settings.danger.run"),
        "can_format_usage": _auth_request_has_permission(request, "usage.settings.danger.run"),
        "can_format_offline": _auth_request_has_permission(request, "offline.settings.danger.run"),
        "can_format_wan": _auth_request_has_permission(request, "wan.settings.danger.run"),
        "can_format_isp_status": _auth_request_has_permission(request, "isp_status.settings.danger.run"),
        "can_format_mikrotik_logs": _auth_request_has_permission(request, "logs.mikrotik.danger.run"),
        "can_uninstall_system": _auth_request_has_permission(request, "system.danger.uninstall.run"),
    }
    caps["can_format_all_features"] = all(
        caps.get(key)
        for key in (
            "can_format_surveillance",
            "can_format_optical",
            "can_format_accounts_ping",
            "can_format_usage",
            "can_format_offline",
            "can_format_wan",
            "can_format_isp_status",
            "can_format_mikrotik_logs",
        )
    )
    caps["can_run_danger_actions"] = bool(
        caps["can_format_surveillance"]
        or caps["can_format_optical"]
        or caps["can_format_accounts_ping"]
        or caps["can_format_usage"]
        or caps["can_format_offline"]
        or caps["can_format_wan"]
        or caps["can_format_isp_status"]
        or caps["can_format_mikrotik_logs"]
        or caps["can_format_all_features"]
        or caps["can_uninstall_system"]
    )
    caps["can_view_danger_tab"] = bool(caps["can_view_danger_tab"] or caps["can_run_danger_actions"])
    return caps


def _system_update_capabilities(request: Request):
    can_view = _auth_request_has_permission(request, "system.tab.update.view")
    can_check = _auth_request_has_permission(request, "system.update.check.run")
    can_run = _auth_request_has_permission(request, "system.update.run")
    return {
        "can_view_update_tab": bool(can_view or can_check or can_run),
        "can_check_system_update": bool(can_check or can_run),
        "can_run_system_update": bool(can_run),
    }


def _build_system_danger_groups(caps: dict):
    groups = []
    for group in _SYSTEM_DANGER_GROUPS:
        items = []
        for action_key in group.get("actions") or []:
            meta = _SYSTEM_DANGER_ACTIONS.get(action_key)
            if not isinstance(meta, dict):
                continue
            cap_key = f"can_format_{action_key}"
            if not caps.get(cap_key):
                continue
            item = dict(meta)
            item["action"] = action_key
            items.append(item)
        if items:
            groups.append(
                {
                    "key": group.get("key"),
                    "title": group.get("title"),
                    "description": group.get("description"),
                    "items": items,
                }
            )
    return groups


def _render_system_danger_notice(request: Request, action_key: str):
    meta = _SYSTEM_DANGER_ACTIONS.get(action_key) or {}
    label = meta.get("label") or "This action"
    return render_system_settings_response(
        request,
        f"{label} formatting moved to System Settings -> Danger. Re-enter your password there to continue.",
        active_tab="danger",
    )


def _run_system_danger_action(action_key: str):
    if action_key == "surveillance":
        _system_danger_format_surveillance()
        return "Under Surveillance data formatted. Settings preserved."
    if action_key == "optical":
        _system_danger_format_optical()
        return "Optical history formatted. Settings preserved."
    if action_key == "accounts_ping":
        _system_danger_format_accounts_ping()
        return "Accounts Ping data formatted. Settings preserved."
    if action_key == "usage":
        _system_danger_format_usage()
        return "Usage history formatted. Settings preserved."
    if action_key == "offline":
        _system_danger_format_offline()
        return "Offline history and tracker state formatted. Settings preserved."
    if action_key == "wan":
        _system_danger_format_wan()
        return "WAN history and cached state formatted. Settings preserved."
    if action_key == "isp_status":
        _system_danger_format_isp_status()
        return "ISP Port Status bandwidth samples and cached state formatted. Settings preserved."
    if action_key == "mikrotik_logs":
        _system_danger_format_mikrotik_logs()
        return "MikroTik logs formatted. Receiver settings preserved."
    if action_key == "all":
        for feature_key in _SYSTEM_DANGER_FEATURE_ORDER:
            _run_system_danger_action(feature_key)
        return "All monitoring feature data formatted. Settings preserved."
    raise ValueError("Unsupported danger action.")


def _handle_system_danger_submission(request: Request, form, default_action: str = ""):
    action_key = ((form.get("danger_action") or default_action or "").strip().lower())
    meta = _SYSTEM_DANGER_ACTIONS.get(action_key)
    if not isinstance(meta, dict):
        return render_system_settings_response(request, "Unknown danger action.", active_tab="danger")

    danger_caps = _system_danger_capabilities(request)
    if action_key == "all":
        if not danger_caps.get("can_format_all_features"):
            return render_system_settings_response(
                request,
                "Format All requires access to every feature danger action.",
                active_tab="danger",
            )
    else:
        required_code = meta.get("permission") or "settings.danger"
        if not _auth_request_has_permission(request, required_code):
            return _auth_forbidden_response(request, required_code)

    ok, password_error = _system_danger_verify_password(request, form.get("confirm_password") or "")
    if not ok:
        return render_system_settings_response(request, password_error, active_tab="danger")

    if action_key == "uninstall":
        confirm_text = (form.get("confirm_text") or "").strip().upper()
        expected = str(meta.get("confirm_text") or "").strip().upper()
        if confirm_text != expected:
            return render_system_settings_response(
                request,
                f"Confirmation text does not match. Type {expected} to proceed.",
                active_tab="danger",
            )
        try:
            _system_danger_start_uninstall()
            _auth_log_event(
                request,
                action="system.uninstall_started",
                resource="/settings/system/danger/run",
                details="source=system_settings",
            )
            return render_system_settings_response(
                request,
                "Uninstall started. This will remove Docker and all app data.",
                active_tab="danger",
            )
        except Exception as exc:
            return render_system_settings_response(request, f"Uninstall failed: {exc}", active_tab="danger")

    try:
        message = _run_system_danger_action(action_key)
    except Exception as exc:
        return render_system_settings_response(request, f"{meta.get('label') or 'Action'} failed: {exc}", active_tab="danger")

    if action_key == "all":
        audit_action = "system.danger.formatted_all"
    elif action_key == "surveillance":
        audit_action = "system.danger.formatted_surveillance"
    else:
        audit_action = f"{action_key}.formatted"
    _auth_log_event(
        request,
        action=audit_action,
        resource=meta.get("label") or action_key,
        details="source=system_settings",
    )
    return render_system_settings_response(request, message, active_tab="danger")


def _system_settings_caps(request: Request):
    auth_enabled = bool(getattr(request.state, "auth_enabled", True))
    user_perms = {str(p or "").strip() for p in (getattr(request.state, "auth_permission_codes", []) or [])}

    def _allow(code: str) -> bool:
        if not auth_enabled:
            return True
        return _auth_check_permission(user_perms, code)

    caps = {
        "can_view_system_branding": _allow("system.general.branding.view"),
        "can_edit_system_branding": _allow("system.general.branding.edit"),
        "can_view_system_telegram": _allow("system.general.telegram.view"),
        "can_edit_system_telegram": _allow("system.general.telegram.edit"),
        "can_view_system_router_cores": _allow("system.routers.cores.view"),
        "can_edit_system_router_cores": _allow("system.routers.cores.edit"),
        "can_view_system_router_mikrotik": _allow("system.routers.mikrotik.view"),
        "can_edit_system_router_mikrotik": _allow("system.routers.mikrotik.edit"),
        "can_view_system_router_isp": _allow("system.routers.isp.view"),
        "can_edit_system_router_isp": _allow("system.routers.isp.edit"),
        "can_test_system_routers": _allow("system.routers.test.run"),
        "can_view_access_auth": _allow("system.access.auth.view"),
        "can_edit_access_auth": _allow("system.access.auth.edit"),
        "can_view_access_permissions": _allow("system.access.permissions.view"),
        "can_view_access_roles": _allow("system.access.roles.view"),
        "can_edit_access_roles": _allow("system.access.roles.edit"),
        "can_view_access_users": _allow("system.access.users.view"),
        "can_edit_access_users": _allow("system.access.users.edit"),
        "can_manage_import_export": _allow("system.backup.import_export.run"),
    }
    caps.update(_system_danger_capabilities(request))
    caps.update(_system_update_capabilities(request))
    caps["can_view_general_tab"] = caps["can_view_system_branding"]
    caps["can_view_telegram_tab"] = caps["can_view_system_telegram"]
    caps["can_view_routers_tab"] = (
        caps["can_view_system_router_cores"]
        or caps["can_view_system_router_mikrotik"]
        or caps["can_view_system_router_isp"]
    )
    caps["can_view_access_tab"] = (
        caps["can_view_access_auth"]
        or caps["can_view_access_permissions"]
        or caps["can_view_access_roles"]
        or caps["can_view_access_users"]
    )
    return caps


def _normalize_system_settings_tabs(active_tab: str, routers_tab: str, access_tab: str, caps: dict):
    active_tab = (active_tab or "general").strip().lower()
    routers_tab = (routers_tab or "cores").strip().lower()
    access_tab = (access_tab or "auth").strip().lower()

    if active_tab not in {"general", "telegram", "routers", "access", "update", "backup", "danger"}:
        active_tab = "general"
    if routers_tab not in {"cores", "mikrotik-routers", "isps", "isp-port-tagging"}:
        routers_tab = "cores"
    if access_tab not in {"auth", "permissions", "roles", "users"}:
        access_tab = "auth"

    allowed_main_tabs = []
    if caps.get("can_view_general_tab"):
        allowed_main_tabs.append("general")
    if caps.get("can_view_telegram_tab"):
        allowed_main_tabs.append("telegram")
    if caps.get("can_view_routers_tab"):
        allowed_main_tabs.append("routers")
    if caps.get("can_view_access_tab"):
        allowed_main_tabs.append("access")
    if caps.get("can_view_update_tab"):
        allowed_main_tabs.append("update")
    if caps.get("can_manage_import_export"):
        allowed_main_tabs.append("backup")
    if caps.get("can_view_danger_tab"):
        allowed_main_tabs.append("danger")

    if allowed_main_tabs and active_tab not in allowed_main_tabs:
        active_tab = allowed_main_tabs[0]

    allowed_routers_tabs = []
    if caps.get("can_view_system_router_cores"):
        allowed_routers_tabs.append("cores")
    if caps.get("can_view_system_router_mikrotik"):
        allowed_routers_tabs.append("mikrotik-routers")
    if caps.get("can_view_system_router_isp"):
        allowed_routers_tabs.append("isps")
        allowed_routers_tabs.append("isp-port-tagging")
    if active_tab == "routers" and allowed_routers_tabs and routers_tab not in allowed_routers_tabs:
        routers_tab = allowed_routers_tabs[0]

    allowed_access_tabs = []
    if caps.get("can_view_access_auth"):
        allowed_access_tabs.append("auth")
    if caps.get("can_view_access_permissions"):
        allowed_access_tabs.append("permissions")
    if caps.get("can_view_access_roles"):
        allowed_access_tabs.append("roles")
    if caps.get("can_view_access_users"):
        allowed_access_tabs.append("users")
    if active_tab == "access" and allowed_access_tabs and access_tab not in allowed_access_tabs:
        access_tab = allowed_access_tabs[0]

    return active_tab, routers_tab, access_tab


@app.get("/settings/system", response_class=HTMLResponse)
async def system_settings(request: Request):
    active_tab = (request.query_params.get("tab") or "general").strip().lower()
    routers_tab = (request.query_params.get("routers_tab") or "cores").strip().lower()
    access_tab = (request.query_params.get("access_tab") or "auth").strip().lower()
    return render_system_settings_response(request, "", active_tab=active_tab, routers_tab=routers_tab, access_tab=access_tab)


def render_system_settings_response(
    request: Request,
    message: str,
    active_tab: str = "general",
    routers_tab: str = "cores",
    access_tab: str = "auth",
):
    caps = _system_settings_caps(request)
    active_tab, routers_tab, access_tab = _normalize_system_settings_tabs(active_tab, routers_tab, access_tab, caps)
    can_run_danger_actions = bool(caps.get("can_run_danger_actions"))
    danger_groups = _build_system_danger_groups(caps)
    danger_bulk_actions = []
    if caps.get("can_format_all_features"):
        bulk_meta = dict(_SYSTEM_DANGER_ACTIONS.get("all") or {})
        bulk_meta["action"] = "all"
        danger_bulk_actions.append(bulk_meta)
    danger_system_actions = []
    if caps.get("can_uninstall_system"):
        system_meta = dict(_SYSTEM_DANGER_ACTIONS.get("uninstall") or {})
        system_meta["action"] = "uninstall"
        danger_system_actions.append(system_meta)
    system_update_status = _system_update_status_payload(include_log=False) if caps.get("can_view_update_tab") else _normalize_system_update_status({})
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    auth_settings = system_settings.get("auth") if isinstance(system_settings.get("auth"), dict) else {}
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    # Back-compat: Usage originally had its own MikroTik router list. If System Settings is empty,
    # migrate those legacy routers into the shared list so other modules keep working.
    if not (wan_settings_data.get("pppoe_routers") or []):
        try:
            usage_settings = get_settings("usage", USAGE_DEFAULTS)
            legacy = (usage_settings.get("mikrotik") or {}).get("routers") or []
            migrated = []
            for item in legacy:
                if not isinstance(item, dict):
                    continue
                rid = (item.get("id") or "").strip()
                host = (item.get("host") or "").strip()
                if not rid or not host:
                    continue
                try:
                    port = int(item.get("port", 8728) or 8728)
                except Exception:
                    port = 8728
                migrated.append(
                    {
                        "id": rid,
                        "name": (item.get("name") or "").strip(),
                        "host": host,
                        "port": port,
                        "username": item.get("username", ""),
                        "password": item.get("password", ""),
                        "use_tls": False,
                    }
                )
            if migrated:
                wan_settings_data["pppoe_routers"] = migrated
                save_settings("wan_ping", wan_settings_data)
        except Exception:
            pass
    telegram_state = get_state("telegram_state", {})
    auth_permissions = []
    auth_permission_groups = []
    role_permission_groups = []
    auth_roles = []
    auth_users = []
    if caps.get("can_view_access_tab"):
        try:
            if caps.get("can_view_access_permissions") or caps.get("can_edit_access_roles"):
                auth_permissions = list_auth_permissions()
                auth_permissions = [
                    item
                    for item in auth_permissions
                    if not _auth_is_ui_hidden_permission(str((item or {}).get("code") or "").strip())
                ]
                auth_permissions = sorted(
                    auth_permissions,
                    key=lambda item: (1 if "." in str(item.get("code") or "") else 0, str(item.get("code") or "").lower()),
                )
                auth_permissions = _auth_annotate_permissions_with_dependencies(auth_permissions)
                auth_permission_groups = _build_auth_permission_groups(auth_permissions)
                role_permission_groups = _build_role_editor_permission_groups(auth_permission_groups)

            if (
                caps.get("can_view_access_roles")
                or caps.get("can_edit_access_roles")
                or caps.get("can_view_access_users")
                or caps.get("can_edit_access_users")
            ):
                auth_roles = list_auth_roles(include_permissions=True)
                for role in auth_roles:
                    codes = _auth_visible_permission_codes(role.get("permission_codes") or [])
                    role["permission_codes"] = codes
                    role["permission_count"] = len(codes)
                    preview_size = 3
                    if len(codes) <= preview_size:
                        role["permission_preview"] = ", ".join(codes)
                    else:
                        role["permission_preview"] = ", ".join(codes[:preview_size]) + f", +{len(codes) - preview_size} more"
                    role["permission_groups"] = _build_role_permission_groups(codes)

            if caps.get("can_view_access_users") or caps.get("can_edit_access_users"):
                auth_users = list_auth_users()
        except Exception:
            auth_permissions = []
            auth_permission_groups = []
            role_permission_groups = []
            auth_roles = []
            auth_users = []

    wan_rows_loaded = bool(active_tab == "routers" and routers_tab in {"isps", "isp-port-tagging"})
    wan_rows = []
    wan_autodetect_warnings = []
    if wan_rows_loaded:
        try:
            wan_rows = build_wan_rows(pulse_settings, wan_settings_data)
            cores = ((pulse_settings.get("pulsewatch") or {}).get("mikrotik") or {}).get("cores") or []
            interface_map, interface_warnings = fetch_mikrotik_interfaces(cores)
            detect_map, detect_warnings = detect_routed_wan_autofill(pulse_settings, wan_rows, probe_public=False)
            wan_autodetect_warnings = list(interface_warnings or []) if routers_tab == "isp-port-tagging" else list(detect_warnings or [])
            for row in wan_rows:
                key = ((row.get("core_id") or "").strip(), (row.get("list_name") or "").strip())
                detected = detect_map.get(key) or {}
                core_id = (row.get("core_id") or "").strip()
                current_interface = (row.get("traffic_interface") or "").strip()
                options = list(interface_map.get(core_id) or [])
                if current_interface and not any((item.get("name") or "").strip() == current_interface for item in options):
                    options.insert(
                        0,
                        {
                            "name": current_interface,
                            "comment": "Configured value is not currently detected on this router",
                            "type": "",
                            "default_name": "",
                            "disabled": False,
                            "running": False,
                        },
                    )
                row["traffic_interface_options"] = options
                detected_local_ip = (detected.get("local_ip") or "").strip()
                detected_netwatch = (detected.get("netwatch_host") or "").strip()
                row["detected_local_ip"] = detected_local_ip
                row["detected_netwatch_host"] = detected_netwatch
                row["detected_interface"] = (detected.get("interface") or "").strip()
                row["detected_routing_mark"] = (detected.get("routing_mark") or "").strip()
                mode = (row.get("mode") or "routed").strip().lower()
                local_ip = (row.get("local_ip") or "").strip()
                netwatch_host = (row.get("netwatch_host") or "").strip()
                if mode == "routed":
                    local_ip = detected_local_ip
                    netwatch_host = detected_netwatch
                else:
                    if not netwatch_host:
                        netwatch_host = local_ip
                row["local_ip"] = local_ip
                row["netwatch_host"] = netwatch_host
                row["enabled"] = bool(row.get("enabled")) and bool(local_ip)
        except Exception:
            wan_rows = []
            wan_autodetect_warnings = []

    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {
                "message": message,
                "active_tab": active_tab,
                "routers_tab": routers_tab,
                "access_tab": access_tab,
                "settings": pulse_settings,
                "wan_settings": wan_settings_data,
                "wan_rows": wan_rows,
                "wan_rows_loaded": wan_rows_loaded,
                "wan_autodetect_warnings": wan_autodetect_warnings,
                "telegram_state": telegram_state,
                "system_settings": system_settings,
                "auth_settings": auth_settings,
                "auth_permissions": auth_permissions,
                "auth_permission_groups": auth_permission_groups,
                "role_permission_groups": role_permission_groups,
                "auth_roles": auth_roles,
                "auth_users": auth_users,
                "can_run_danger_actions": can_run_danger_actions,
                "danger_groups": danger_groups,
                "danger_bulk_actions": danger_bulk_actions,
                "danger_system_actions": danger_system_actions,
                "danger_requires_password": _system_danger_requires_password(request),
                "system_update_status": system_update_status,
                "system_update_requires_password": _system_danger_requires_password(request),
                **caps,
            },
        ),
    )


def _parse_wan_pppoe_routers_from_form(form, count: int):
    routers = []
    removed_ids = set()
    for idx in range(count):
        router_id = (form.get(f"router_{idx}_id") or "").strip()
        if not router_id:
            continue
        if parse_bool(form, f"router_{idx}_remove"):
            removed_ids.add(router_id)
            continue
        routers.append(
            {
                "id": router_id,
                "name": (form.get(f"router_{idx}_name") or "").strip(),
                "host": (form.get(f"router_{idx}_host") or "").strip(),
                "port": parse_int(form, f"router_{idx}_port", 8728),
                "username": (form.get(f"router_{idx}_username") or "").strip(),
                "password": (form.get(f"router_{idx}_password") or "").strip(),
                "use_tls": parse_bool(form, f"router_{idx}_use_tls"),
            }
        )
    return routers, removed_ids


def _parse_wan_list_from_form(form, count: int, existing_wans=None):
    existing_map = {}
    if isinstance(existing_wans, list):
        existing_map = {
            ((item.get("core_id") or "").strip(), (item.get("list_name") or "").strip()): item
            for item in existing_wans
            if isinstance(item, dict) and (item.get("core_id") or "").strip() and (item.get("list_name") or "").strip()
        }
    wans = []
    for idx in range(count):
        core_id = (form.get(f"wan_{idx}_core_id") or "").strip()
        list_name = (form.get(f"wan_{idx}_list") or "").strip()
        if not core_id or not list_name:
            continue
        existing = existing_map.get((core_id, list_name), {}) or {}
        raw_traffic_interface = form.get(f"wan_{idx}_traffic_interface")
        mode = (form.get(f"wan_{idx}_mode") or "routed").strip().lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"
        local_ip = (form.get(f"wan_{idx}_local_ip") or "").strip()
        netwatch_host = (form.get(f"wan_{idx}_netwatch_host") or "").strip()
        if not netwatch_host:
            netwatch_host = local_ip
        enabled = parse_bool(form, f"wan_{idx}_enabled")
        if not local_ip:
            enabled = False
        wans.append(
            {
                "id": wan_row_id(core_id, list_name),
                "core_id": core_id,
                "list_name": list_name,
                "identifier": (form.get(f"wan_{idx}_identifier") or "").strip(),
                "color": _sanitize_hex_color(form.get(f"wan_{idx}_color") or ""),
                "enabled": enabled,
                "mode": mode,
                "local_ip": local_ip,
                "gateway_ip": "",
                "netwatch_host": netwatch_host,
                "pppoe_router_id": (form.get(f"wan_{idx}_pppoe_router_id") or "").strip(),
                "traffic_interface": (
                    raw_traffic_interface.strip()
                    if raw_traffic_interface is not None
                    else (existing.get("traffic_interface") or "").strip()
                ),
            }
        )
    return wans


@app.post("/settings/system/mikrotik", response_class=HTMLResponse)
async def system_mikrotik_save(request: Request):
    form = await request.form()
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    pulsewatch = settings.get("pulsewatch", {})
    core_ids = parse_lines(form.get("core_ids", ""))
    cores = []
    for core_id in core_ids:
        if not core_id:
            continue
        cores.append(
            {
                "id": core_id,
                "label": form.get(f"{core_id}_label", core_id.upper()),
                "host": form.get(f"{core_id}_host", ""),
                "port": parse_int(form, f"{core_id}_port", 8728),
                "username": form.get(f"{core_id}_username", ""),
                "password": form.get(f"{core_id}_password", ""),
            }
        )
    pulsewatch["mikrotik"] = {"cores": cores}
    settings["pulsewatch"] = pulsewatch
    save_settings("isp_ping", settings)
    return render_system_settings_response(request, "MikroTik settings saved.", active_tab="routers", routers_tab="cores")


@app.post("/settings/system/telegram", response_class=HTMLResponse)
async def system_telegram_save(request: Request):
    form = await request.form()
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    telegram = dict(settings.get("telegram", ISP_PING_DEFAULTS.get("telegram", {})))
    telegram["command_bot_token"] = form.get("telegram_command_bot_token", "")
    telegram["command_chat_id"] = form.get("telegram_command_chat_id", "")
    telegram["allowed_user_ids"] = parse_int_list(form.get("telegram_allowed_user_ids", ""))
    telegram["command_feedback_seconds"] = parse_int(form, "telegram_command_feedback_seconds", 10)
    settings["telegram"] = telegram
    save_settings("isp_ping", settings)
    message = "Telegram command settings saved."
    return render_system_settings_response(request, message, active_tab="telegram", routers_tab="cores")


@app.post("/settings/system/ai", response_class=HTMLResponse)
async def system_ai_save(request: Request):
    return render_system_settings_response(
        request,
        "AI settings were removed from System Settings.",
        active_tab="general",
        routers_tab="cores",
    )


@app.post("/settings/system/ai/test/{provider}", response_class=HTMLResponse)
async def system_ai_test(request: Request, provider: str):
    return render_system_settings_response(
        request,
        "AI settings were removed from System Settings.",
        active_tab="general",
        routers_tab="cores",
    )


def _auth_parse_permission_codes(form, field_name="permission_codes"):
    values = []
    try:
        values = list(form.getlist(field_name))
    except Exception:
        single = form.get(field_name)
        if isinstance(single, str):
            values = [single]
    out = []
    seen = set()
    for value in values or []:
        code = (value or "").strip()
        if not code or code in seen:
            continue
        seen.add(code)
        out.append(code)
    return out


@app.post("/settings/system/auth/settings", response_class=HTMLResponse)
async def system_auth_settings_save(request: Request):
    form = await request.form()
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    auth_cfg = system_settings.get("auth") if isinstance(system_settings.get("auth"), dict) else {}
    smtp_cfg = auth_cfg.get("smtp") if isinstance(auth_cfg.get("smtp"), dict) else {}

    smtp_password = (form.get("auth_smtp_password") or "").strip()
    if parse_bool(form, "auth_smtp_clear_password"):
        smtp_password = ""
    elif not smtp_password:
        smtp_password = (smtp_cfg.get("password") or "").strip()

    auth_cfg["enabled"] = parse_bool(form, "auth_enabled")
    auth_cfg["session_idle_hours"] = parse_int(form, "auth_session_idle_hours", int(auth_cfg.get("session_idle_hours", 8) or 8))
    auth_cfg["audit_retention_days"] = parse_int(
        form,
        "auth_audit_retention_days",
        int(auth_cfg.get("audit_retention_days", 180) or 180),
    )
    auth_cfg["smtp"] = {
        "host": (form.get("auth_smtp_host") or "").strip(),
        "port": parse_int(form, "auth_smtp_port", int(smtp_cfg.get("port", 587) or 587)),
        "username": (form.get("auth_smtp_username") or "").strip(),
        "password": smtp_password,
        "from_email": (form.get("auth_smtp_from_email") or "").strip(),
        "from_name": (form.get("auth_smtp_from_name") or _system_app_name(system_settings)).strip() or _system_app_name(system_settings),
        "use_tls": parse_bool(form, "auth_smtp_use_tls"),
        "use_ssl": parse_bool(form, "auth_smtp_use_ssl"),
    }
    system_settings["auth"] = auth_cfg
    normalized = normalize_system_settings(system_settings)
    save_settings("system", normalized)
    _auth_log_event(request, "auth.settings_saved", resource="/settings/system/auth/settings", details="access settings updated")
    return render_system_settings_response(request, "Access settings saved.", active_tab="access", routers_tab="cores", access_tab="auth")


@app.post("/settings/system/auth/test-email", response_class=HTMLResponse)
async def system_auth_test_email(request: Request):
    form = await request.form()
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    auth_cfg = system_settings.get("auth") if isinstance(system_settings.get("auth"), dict) else {}
    smtp_cfg = auth_cfg.get("smtp") if isinstance(auth_cfg.get("smtp"), dict) else {}

    smtp_password = (form.get("auth_smtp_password") or "").strip()
    if parse_bool(form, "auth_smtp_clear_password"):
        smtp_password = ""
    elif not smtp_password:
        smtp_password = (smtp_cfg.get("password") or "").strip()

    auth_cfg["smtp"] = {
        "host": (form.get("auth_smtp_host") or "").strip() or (smtp_cfg.get("host") or "").strip(),
        "port": parse_int(form, "auth_smtp_port", int(smtp_cfg.get("port", 587) or 587)),
        "username": (form.get("auth_smtp_username") or "").strip() or (smtp_cfg.get("username") or "").strip(),
        "password": smtp_password,
        "from_email": (form.get("auth_smtp_from_email") or "").strip() or (smtp_cfg.get("from_email") or "").strip(),
        "from_name": (form.get("auth_smtp_from_name") or "").strip() or (smtp_cfg.get("from_name") or _system_app_name(system_settings)),
        "use_tls": parse_bool(form, "auth_smtp_use_tls"),
        "use_ssl": parse_bool(form, "auth_smtp_use_ssl"),
    }
    system_settings["auth"] = auth_cfg
    system_settings = normalize_system_settings(system_settings)
    app_name = _system_app_name(system_settings)

    to_email = (form.get("auth_smtp_test_email") or "").strip()
    if not to_email:
        current_user = getattr(request.state, "current_user", None)
        if isinstance(current_user, dict):
            to_email = (current_user.get("email") or "").strip()
    if not to_email:
        return render_system_settings_response(
            request,
            "Test email failed: recipient email is required.",
            active_tab="access",
            routers_tab="cores",
            access_tab="auth",
        )
    try:
        _auth_send_email(
            system_settings,
            to_email=to_email,
            subject=f"{app_name} SMTP test",
            body_text=f"SMTP test successful. This email was sent from {app_name} access settings.",
        )
    except Exception as exc:
        return render_system_settings_response(
            request,
            f"SMTP test failed: {exc}",
            active_tab="access",
            routers_tab="cores",
            access_tab="auth",
        )
    _auth_log_event(request, "auth.smtp_test", resource="/settings/system/auth/test-email", details=f"sent to {to_email}")
    return render_system_settings_response(
        request,
        f"SMTP test successful. Email sent to {to_email}.",
        active_tab="access",
        routers_tab="cores",
        access_tab="auth",
    )


@app.post("/settings/system/auth/permission/add", response_class=HTMLResponse)
async def system_auth_permission_add(request: Request):
    return render_system_settings_response(
        request,
        "Permission catalog is system-managed. Assign permissions from the Roles tab.",
        active_tab="access",
        routers_tab="cores",
        access_tab="permissions",
    )


@app.post("/settings/system/auth/role/add", response_class=HTMLResponse)
async def system_auth_role_add(request: Request):
    form = await request.form()
    name = (form.get("role_name") or "").strip().lower()
    description = (form.get("role_description") or "").strip()
    permission_codes_raw = _auth_parse_permission_codes(form, field_name="permission_codes")
    permission_codes, auto_added = _auth_expand_permission_dependencies(permission_codes_raw)
    try:
        create_auth_role(name=name, description=description, permission_codes=permission_codes)
    except Exception as exc:
        return render_system_settings_response(request, f"Failed to add role: {exc}", active_tab="access", routers_tab="cores", access_tab="roles")
    _auth_log_event(request, "auth.role_added", resource=name, details=f"permissions={len(permission_codes)}")
    message = f"Role `{name}` added."
    if auto_added:
        preview = ", ".join(auto_added[:3])
        extra = len(auto_added) - 3
        if extra > 0:
            preview = f"{preview}, +{extra} more"
        message += f" Required dependencies auto-added: {preview}."
    return render_system_settings_response(request, message, active_tab="access", routers_tab="cores", access_tab="roles")


@app.post("/settings/system/auth/role/save/{role_id}", response_class=HTMLResponse)
async def system_auth_role_save(request: Request, role_id: int):
    form = await request.form()
    name = (form.get("role_name") or "").strip().lower()
    description = (form.get("role_description") or "").strip()
    role = get_auth_role_by_id(role_id) or {}
    if (role.get("name") or "").strip().lower() == "owner":
        return render_system_settings_response(
            request,
            "Owner role is locked and cannot be edited.",
            active_tab="access",
            routers_tab="cores",
            access_tab="roles",
        )
    permission_codes_raw = _auth_parse_permission_codes(form, field_name="permission_codes")
    permission_codes, auto_added = _auth_expand_permission_dependencies(permission_codes_raw)
    try:
        update_auth_role(role_id, name=name, description=description)
        set_auth_role_permissions(role_id, permission_codes)
    except Exception as exc:
        return render_system_settings_response(request, f"Failed to update role: {exc}", active_tab="access", routers_tab="cores", access_tab="roles")
    _auth_log_event(request, "auth.role_updated", resource=f"role_id={role_id}", details=f"permissions={len(permission_codes)}")
    message = f"Role `{name}` updated."
    if auto_added:
        preview = ", ".join(auto_added[:3])
        extra = len(auto_added) - 3
        if extra > 0:
            preview = f"{preview}, +{extra} more"
        message += f" Required dependencies auto-added: {preview}."
    return render_system_settings_response(request, message, active_tab="access", routers_tab="cores", access_tab="roles")


@app.post("/settings/system/auth/role/delete/{role_id}", response_class=HTMLResponse)
async def system_auth_role_delete(request: Request, role_id: int):
    role = get_auth_role_by_id(role_id) or {}
    role_name = (role.get("name") or "").strip() or f"id={role_id}"
    if role_name.lower() == "owner":
        return render_system_settings_response(
            request,
            "Owner role cannot be deleted.",
            active_tab="access",
            routers_tab="cores",
            access_tab="roles",
        )
    try:
        delete_auth_role(role_id)
    except Exception as exc:
        return render_system_settings_response(request, f"Failed to delete role: {exc}", active_tab="access", routers_tab="cores", access_tab="roles")
    _auth_log_event(request, "auth.role_deleted", resource=role_name, details="role removed")
    return render_system_settings_response(request, f"Role `{role_name}` deleted.", active_tab="access", routers_tab="cores", access_tab="roles")


@app.post("/settings/system/auth/user/add", response_class=HTMLResponse)
async def system_auth_user_add(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    email = (form.get("email") or "").strip().lower()
    full_name = (form.get("full_name") or "").strip()
    role_id = parse_int(form, "role_id", 0)
    password = (form.get("password") or "").strip()
    is_active = parse_bool(form, "is_active")
    must_change_password = parse_bool(form, "must_change_password")

    if len(password) < AUTH_PASSWORD_MIN_LENGTH:
        return render_system_settings_response(
            request,
            f"New user password must be at least {AUTH_PASSWORD_MIN_LENGTH} characters.",
            active_tab="access",
            routers_tab="cores",
            access_tab="users",
        )
    if not email:
        return render_system_settings_response(
            request,
            "Email is required so the system can send login link and credentials.",
            active_tab="access",
            routers_tab="cores",
            access_tab="users",
        )
    try:
        password_hash, password_salt = _auth_hash_password(password)
        create_auth_user(
            username=username,
            email=email,
            full_name=full_name,
            role_id=role_id,
            password_hash=password_hash,
            password_salt=password_salt,
            must_change_password=must_change_password,
            is_active=is_active,
        )
    except Exception as exc:
        return render_system_settings_response(request, f"Failed to add user: {exc}", active_tab="access", routers_tab="cores", access_tab="users")
    _auth_log_event(request, "auth.user_added", resource=username, details=f"role_id={role_id}")
    login_link = f"{str(request.base_url).rstrip('/')}/login"
    email_error = ""
    try:
        system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
        app_name = _system_app_name(system_settings)
        _auth_send_email(
            system_settings,
            to_email=email,
            subject=f"{app_name} account created",
            body_text=(
                f"Your {app_name} account has been created.\n\n"
                f"Login URL: {login_link}\n"
                f"Username: {username}\n"
                f"Password: {password}\n\n"
                "Please sign in and change your password as soon as possible."
            ),
        )
        _auth_log_event(request, "auth.user_welcome_email_sent", resource=username, details=f"to={email}")
    except Exception as exc:
        email_error = str(exc)
        _auth_log_event(request, "auth.user_welcome_email_failed", resource=username, details=f"to={email};error={email_error[:180]}")
    if email_error:
        return render_system_settings_response(
            request,
            f"User `{username}` added, but welcome email failed: {email_error}",
            active_tab="access",
            routers_tab="cores",
            access_tab="users",
        )
    return render_system_settings_response(
        request,
        f"User `{username}` added and welcome email sent to {email}.",
        active_tab="access",
        routers_tab="cores",
        access_tab="users",
    )


@app.post("/settings/system/auth/user/save/{user_id}", response_class=HTMLResponse)
async def system_auth_user_save(request: Request, user_id: int):
    form = await request.form()
    email = (form.get("email") or "").strip().lower()
    full_name = (form.get("full_name") or "").strip()
    role_id = parse_int(form, "role_id", 0)
    is_active = parse_bool(form, "is_active")
    new_password = (form.get("new_password") or "").strip()
    must_change_password = parse_bool(form, "must_change_password")
    existing_user = get_auth_user_by_id(user_id) or {}
    if int(role_id or 0) <= 0:
        try:
            role_id = int(existing_user.get("role_id") or 0)
        except Exception:
            role_id = 0
    existing_role_name = (existing_user.get("role_name") or "").strip().lower()
    if existing_role_name == "owner":
        owner_role_id = _get_owner_role_id()
        if int(role_id or 0) != int(owner_role_id or 0):
            return render_system_settings_response(
                request,
                "Owner account role cannot be changed.",
                active_tab="access",
                routers_tab="cores",
                access_tab="users",
            )
        if not is_active:
            return render_system_settings_response(
                request,
                "Owner account cannot be disabled.",
                active_tab="access",
                routers_tab="cores",
                access_tab="users",
            )

    try:
        update_auth_user(user_id=user_id, email=email, full_name=full_name, role_id=role_id, is_active=is_active)
        if new_password:
            if len(new_password) < AUTH_PASSWORD_MIN_LENGTH:
                raise ValueError(f"New password must be at least {AUTH_PASSWORD_MIN_LENGTH} characters.")
            password_hash, password_salt = _auth_hash_password(new_password)
            set_auth_user_password(user_id, password_hash, password_salt, must_change_password=must_change_password)
            revoke_auth_sessions_for_user(user_id)
    except Exception as exc:
        return render_system_settings_response(request, f"Failed to update user: {exc}", active_tab="access", routers_tab="cores", access_tab="users")
    _auth_log_event(request, "auth.user_updated", resource=f"user_id={user_id}", details=f"role_id={role_id}")
    return render_system_settings_response(request, "User updated.", active_tab="access", routers_tab="cores", access_tab="users")


@app.post("/settings/system/auth/user/delete/{user_id}", response_class=HTMLResponse)
async def system_auth_user_delete(request: Request, user_id: int):
    current_user = getattr(request.state, "current_user", None)
    if isinstance(current_user, dict) and int(current_user.get("id") or 0) == int(user_id or 0):
        return render_system_settings_response(
            request,
            "You cannot delete your own account.",
            active_tab="access",
            routers_tab="cores",
            access_tab="users",
        )
    user = get_auth_user_by_id(user_id) or {}
    if (user.get("role_name") or "").strip().lower() == "owner":
        return render_system_settings_response(
            request,
            "Owner account cannot be deleted.",
            active_tab="access",
            routers_tab="cores",
            access_tab="users",
        )
    username = (user.get("username") or "").strip() or f"id={user_id}"
    try:
        delete_auth_user(user_id)
    except Exception as exc:
        return render_system_settings_response(request, f"Failed to delete user: {exc}", active_tab="access", routers_tab="cores", access_tab="users")
    _auth_log_event(request, "auth.user_deleted", resource=username, details="user removed")
    return render_system_settings_response(request, f"User `{username}` deleted.", active_tab="access", routers_tab="cores", access_tab="users")


@app.post("/settings/system/auth/user/reset/{user_id}", response_class=HTMLResponse)
async def system_auth_user_reset_password(request: Request, user_id: int):
    user = get_auth_user_by_id(user_id)
    if not user:
        return render_system_settings_response(request, "User not found.", active_tab="access", routers_tab="cores", access_tab="users")
    email = (user.get("email") or "").strip()
    if not email:
        return render_system_settings_response(request, "User has no email configured.", active_tab="access", routers_tab="cores", access_tab="users")
    temp_password = _auth_generate_temporary_password()
    password_hash, password_salt = _auth_hash_password(temp_password)
    try:
        set_auth_user_password(user_id, password_hash, password_salt, must_change_password=True)
        revoke_auth_sessions_for_user(user_id)
        system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
        app_name = _system_app_name(system_settings)
        _auth_send_email(
            system_settings,
            to_email=email,
            subject=f"{app_name} temporary password",
            body_text=(
                f"A temporary password was generated for your {app_name} account.\n\n"
                f"Username: {(user.get('username') or '').strip()}\n"
                f"Temporary password: {temp_password}\n\n"
                "Sign in and change your password immediately."
            ),
        )
    except Exception as exc:
        return render_system_settings_response(request, f"Password reset failed: {exc}", active_tab="access", routers_tab="cores", access_tab="users")
    _auth_log_event(request, "auth.user_reset_password", resource=(user.get("username") or "").strip(), details="temporary password emailed")
    return render_system_settings_response(
        request,
        f"Temporary password sent to {(user.get('email') or '').strip()}.",
        active_tab="access",
        routers_tab="cores",
        access_tab="users",
    )


@app.post("/settings/system/mikrotik/add", response_class=HTMLResponse)
async def system_mikrotik_add(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    pulsewatch = settings.get("pulsewatch", {})
    mikrotik = pulsewatch.get("mikrotik", {})
    cores = mikrotik.get("cores", [])
    existing_ids = {core.get("id") for core in cores if core.get("id")}
    next_idx = 1
    while f"core{next_idx}" in existing_ids:
        next_idx += 1
    core_id = f"core{next_idx}"
    cores.append(
        {
            "id": core_id,
            "label": f"Core {next_idx}",
            "host": "",
            "port": 8728,
            "username": "",
            "password": "",
        }
    )
    mikrotik["cores"] = cores
    pulsewatch["mikrotik"] = mikrotik
    settings["pulsewatch"] = pulsewatch
    save_settings("isp_ping", settings)
    return render_system_settings_response(request, "MikroTik core added.", active_tab="routers", routers_tab="cores")


@app.post("/settings/system/mikrotik/remove/{core_id}", response_class=HTMLResponse)
async def system_mikrotik_remove(request: Request, core_id: str):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    pulsewatch = settings.get("pulsewatch", {})
    mikrotik = pulsewatch.get("mikrotik", {})
    mikrotik["cores"] = [core for core in mikrotik.get("cores", []) if core.get("id") != core_id]
    for isp in pulsewatch.get("isps", []):
        sources = isp.get("sources", {})
        if isinstance(sources, dict) and core_id in sources:
            sources.pop(core_id, None)
        if isp.get("ping_core_id") == core_id:
            isp["ping_core_id"] = "auto"
            isp["ping_router"] = "auto"
    pulsewatch["mikrotik"] = mikrotik
    settings["pulsewatch"] = pulsewatch
    save_settings("isp_ping", settings)
    return render_system_settings_response(request, f"{core_id} removed.", active_tab="routers", routers_tab="cores")


@app.post("/settings/system/routers/pppoe", response_class=HTMLResponse)
async def system_save_pppoe_routers(request: Request):
    form = await request.form()
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "router_count", 0)
    routers, removed_ids = _parse_wan_pppoe_routers_from_form(form, count)
    wan_settings_data["pppoe_routers"] = routers
    if removed_ids:
        for wan in wan_settings_data.get("wans", []):
            if wan.get("pppoe_router_id") in removed_ids:
                wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(
        request,
        "MikroTik routers saved.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/pppoe/add", response_class=HTMLResponse)
async def system_add_pppoe_router(request: Request):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = wan_settings_data.get("pppoe_routers", [])
    existing_ids = {router.get("id") for router in routers if router.get("id")}
    next_idx = 1
    while f"router{next_idx}" in existing_ids:
        next_idx += 1
    routers.append(
        {
            "id": f"router{next_idx}",
            "name": f"Router {next_idx}",
            "host": "",
            "port": 8728,
            "username": "",
            "password": "",
            "use_tls": False,
        }
    )
    wan_settings_data["pppoe_routers"] = routers
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(
        request,
        "MikroTik router added.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/pppoe/remove/{router_id}", response_class=HTMLResponse)
async def system_remove_pppoe_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = [router for router in wan_settings_data.get("pppoe_routers", []) if router.get("id") != router_id]
    wan_settings_data["pppoe_routers"] = routers
    for wan in wan_settings_data.get("wans", []):
        if wan.get("pppoe_router_id") == router_id:
            wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(
        request,
        "MikroTik router removed.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/pppoe/test/{router_id}", response_class=HTMLResponse)
async def system_test_pppoe_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router = next((item for item in wan_settings_data.get("pppoe_routers", []) if item.get("id") == router_id), None)
    if not router:
        return render_system_settings_response(
            request,
            "Router not found.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    if router.get("use_tls"):
        return render_system_settings_response(
            request,
            "TLS test not supported yet. Disable TLS or use port 8728.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    host = (router.get("host") or "").strip()
    if not host:
        return render_system_settings_response(
            request,
            "Router host is required.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    client = RouterOSClient(
        host,
        int(router.get("port", 8728)),
        router.get("username", ""),
        router.get("password", ""),
    )
    try:
        client.connect()
        message = f"Router {router.get('name') or router_id} connected successfully."
    except Exception as exc:
        message = f"Router test failed: {exc}"
    finally:
        client.close()
    return render_system_settings_response(
        request,
        message,
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/isps", response_class=HTMLResponse)
async def system_save_isps(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "wan_count", 0)
    parsed_wans = _parse_wan_list_from_form(form, count, wan_settings_data.get("wans") or [])
    routed_detect_map, routed_detect_warnings = detect_routed_wan_autofill(pulse_settings, parsed_wans, probe_public=True)
    local_warnings = []
    for wan in parsed_wans:
        mode = (wan.get("mode") or "routed").strip().lower()
        local_ip = ""
        netwatch_host = ""
        if mode == "routed":
            key = ((wan.get("core_id") or "").strip(), (wan.get("list_name") or "").strip())
            detected = routed_detect_map.get(key) or {}
            detected_local = (detected.get("local_ip") or "").strip()
            detected_netwatch = (detected.get("netwatch_host") or "").strip()
            local_ip = detected_local
            netwatch_host = detected_netwatch
            if not local_ip:
                local_warnings.append(f"{wan.get('core_id')} {wan.get('list_name')}: no auto-detected local IP")
            if not netwatch_host:
                local_warnings.append(f"{wan.get('core_id')} {wan.get('list_name')}: no auto-detected WAN/public IP")
        else:
            local_ip = (wan.get("local_ip") or "").strip()
            netwatch_host = (wan.get("netwatch_host") or "").strip()
            if not netwatch_host:
                netwatch_host = local_ip
        wan["local_ip"] = local_ip
        wan["netwatch_host"] = netwatch_host
        if not local_ip:
            wan["enabled"] = False
    wan_settings_data["wans"] = parsed_wans
    save_settings("wan_ping", wan_settings_data)
    sync_errors = wan_ping_notifier.sync_netwatch(wan_settings_data, pulse_settings)
    save_settings("wan_ping", wan_settings_data)
    warn_parts = []
    if routed_detect_warnings:
        warn_parts.append("Auto-detect: " + "; ".join(routed_detect_warnings[:6]))
    if local_warnings:
        warn_parts.append("Routed IP checks: " + "; ".join(local_warnings[:6]))
    if sync_errors:
        warn_parts.append("Netwatch: " + "; ".join(sync_errors[:6]))
    if warn_parts:
        message = "ISP list saved with warnings: " + " | ".join(warn_parts)
    else:
        message = "ISP list saved and Netwatch synced."
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="isps")


@app.post("/settings/system/routers/isp-port-tags", response_class=HTMLResponse)
async def system_save_isp_port_tags(request: Request):
    form = await request.form()
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "wan_count", 0)
    tag_map = {}
    for idx in range(count):
        core_id = (form.get(f"wan_{idx}_core_id") or "").strip()
        list_name = (form.get(f"wan_{idx}_list") or "").strip()
        if not core_id or not list_name:
            continue
        tag_map[(core_id, list_name)] = (form.get(f"wan_{idx}_traffic_interface") or "").strip()

    updated = 0
    for wan in wan_settings_data.get("wans") or []:
        if not isinstance(wan, dict):
            continue
        key = ((wan.get("core_id") or "").strip(), (wan.get("list_name") or "").strip())
        if key not in tag_map:
            continue
        if (wan.get("traffic_interface") or "").strip() != tag_map[key]:
            updated += 1
        wan["traffic_interface"] = tag_map[key]

    existing_keys = {
        ((wan.get("core_id") or "").strip(), (wan.get("list_name") or "").strip())
        for wan in wan_settings_data.get("wans") or []
        if isinstance(wan, dict)
    }
    for (core_id, list_name), traffic_interface in tag_map.items():
        if (core_id, list_name) in existing_keys:
            continue
        if traffic_interface:
            updated += 1
        wan_settings_data.setdefault("wans", []).append(
            {
                "id": wan_row_id(core_id, list_name),
                "core_id": core_id,
                "list_name": list_name,
                "identifier": "",
                "color": "",
                "enabled": False,
                "mode": "routed",
                "local_ip": "",
                "gateway_ip": "",
                "netwatch_host": "",
                "pppoe_router_id": "",
                "traffic_interface": traffic_interface,
            }
        )

    save_settings("wan_ping", wan_settings_data)
    label = "tag" if updated == 1 else "tags"
    return render_system_settings_response(
        request,
        f"ISP port {label} saved. Updated {updated} {label}.",
        active_tab="routers",
        routers_tab="isp-port-tagging",
    )


@app.post("/settings/system/uninstall", response_class=HTMLResponse)
async def system_uninstall(request: Request):
    form = await request.form()
    return _handle_system_danger_submission(request, form, default_action="uninstall")


@app.post("/settings/system/danger/run", response_class=HTMLResponse)
async def system_danger_run(request: Request):
    form = await request.form()
    return _handle_system_danger_submission(request, form)


@app.post("/settings/system/branding", response_class=HTMLResponse)
async def system_branding_save(request: Request):
    form = await request.form()
    app_name = (form.get("branding_app_name") or "").strip()
    if not app_name:
        return render_system_settings_response(
            request,
            "Display name is required.",
            active_tab="general",
            routers_tab="cores",
        )
    if len(app_name) > 80:
        app_name = app_name[:80].strip()
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    branding = system_settings.get("branding") if isinstance(system_settings.get("branding"), dict) else {}
    branding["app_name"] = app_name
    system_settings["branding"] = branding
    save_settings("system", system_settings)
    return render_system_settings_response(
        request,
        "Branding display name updated.",
        active_tab="general",
        routers_tab="cores",
    )


@app.post("/settings/system/logo", response_class=HTMLResponse)
async def system_logo_upload(request: Request, company_logo: UploadFile = File(...)):
    message = ""

    if not company_logo or not (company_logo.filename or "").strip():
        message = "Please select an image file to upload."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    content_type = (company_logo.content_type or "").lower().strip()
    if not content_type.startswith("image/"):
        message = "Invalid file type. Please upload an image only."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    header = await company_logo.read(512)
    await company_logo.seek(0)
    kind = imghdr.what(None, header)
    allowed_kinds = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
    if kind not in allowed_kinds:
        message = "Invalid image. Please upload a PNG, JPG, WebP, or GIF."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    max_bytes = 5 * 1024 * 1024
    public_dir = DATA_DIR / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    for old in public_dir.glob("company_logo.*"):
        try:
            old.unlink()
        except OSError:
            pass
    ext = "jpg" if kind == "jpeg" else kind
    dest = public_dir / f"company_logo.{ext}"
    written = 0
    try:
        with open(dest, "wb") as handle:
            while True:
                chunk = await company_logo.read(1024 * 256)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError("File too large")
                handle.write(chunk)
    except ValueError:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = "Image too large. Max size is 5MB."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = f"Upload failed: {exc}"
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    branding = dict(system_settings.get("branding") or {})
    branding["company_logo"] = {
        "path": str(dest),
        "content_type": allowed_kinds.get(kind) or content_type,
        "updated_at": utc_now_iso(),
    }
    system_settings["branding"] = branding
    save_settings("system", system_settings)

    message = "Company logo updated."
    return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")


@app.post("/settings/system/browser-logo", response_class=HTMLResponse)
async def system_browser_logo_upload(request: Request, browser_logo: UploadFile = File(...)):
    message = ""

    if not browser_logo or not (browser_logo.filename or "").strip():
        message = "Please select an image file to upload."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    content_type = (browser_logo.content_type or "").lower().strip()
    if not content_type.startswith("image/") and content_type not in {"application/octet-stream"}:
        message = "Invalid file type. Please upload an image only."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    header = await browser_logo.read(512)
    await browser_logo.seek(0)
    kind = imghdr.what(None, header)
    is_ico = header[:4] == b"\x00\x00\x01\x00"
    allowed_kinds = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
    if kind not in allowed_kinds and not is_ico:
        message = "Invalid image. Please upload a PNG, JPG, WebP, GIF, or ICO."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    max_bytes = 2 * 1024 * 1024
    public_dir = DATA_DIR / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    for old in public_dir.glob("browser_logo.*"):
        try:
            old.unlink()
        except OSError:
            pass
    if is_ico:
        ext = "ico"
        media = "image/x-icon"
    else:
        ext = "jpg" if kind == "jpeg" else kind
        media = allowed_kinds.get(kind) or content_type or "image/png"
    dest = public_dir / f"browser_logo.{ext}"
    written = 0
    try:
        with open(dest, "wb") as handle:
            while True:
                chunk = await browser_logo.read(1024 * 256)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError("File too large")
                handle.write(chunk)
    except ValueError:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = "Image too large. Max size is 2MB."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = f"Upload failed: {exc}"
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    branding = dict(system_settings.get("branding") or {})
    branding["browser_logo"] = {
        "path": str(dest),
        "content_type": media,
        "updated_at": utc_now_iso(),
    }
    system_settings["branding"] = branding
    save_settings("system", system_settings)

    message = "Browser logo updated."
    return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")
