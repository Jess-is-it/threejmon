import threading
import time as time_module
from datetime import datetime, time, timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout, as_completed
import os
import queue
import re
import subprocess
import select
import socket

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from .db import (
    delete_optical_results_older_than,
    delete_offline_history_older_than,
    delete_pppoe_usage_samples_older_than,
    delete_usage_modem_reboot_history_older_than,
    delete_mikrotik_logs_older_than,
    get_pppoe_usage_window_stats_since,
    insert_mikrotik_logs,
    insert_pppoe_usage_sample,
    insert_isp_status_sample,
    insert_usage_modem_reboot_history,
    insert_offline_history_event,
    list_usage_modem_reboot_account_stats,
    update_job_status,
    update_usage_modem_reboot_history,
    utc_now_iso,
    get_accounts_ping_checker_stats_map,
    get_accounts_ping_down_events_map,
    get_latest_accounts_ping_map,
    get_latest_optical_by_pppoe,
    ensure_surveillance_session,
    touch_surveillance_session,
    end_surveillance_session,
    insert_auth_audit_log,
)
from .db import delete_accounts_ping_raw_older_than, delete_accounts_ping_rollups_older_than, insert_accounts_ping_result
from .accounts_ping_sources import (
    ACCOUNTS_PING_SOURCE_MIKROTIK,
    build_accounts_ping_account_id,
    build_accounts_ping_account_ids_by_pppoe,
    build_accounts_ping_source_devices,
    normalize_accounts_ping_source_mode,
)
from .accounts_missing_support import (
    auto_delete_accounts_missing_entries,
    normalize_accounts_missing_settings,
    reconcile_accounts_missing_state,
)
from .notifiers import optical as optical_notifier
from .notifiers import wan_ping as wan_ping_notifier
from .notifiers import offline as offline_notifier
from .notifiers import usage as usage_notifier
from .notifiers.telegram import TelegramError, get_updates, send_telegram
from .offline_rules import enabled_offline_tracking_rules
from .settings_defaults import (
    ACCOUNTS_MISSING_DEFAULTS,
    ACCOUNTS_PING_DEFAULTS,
    OFFLINE_DEFAULTS,
    OPTICAL_DEFAULTS,
    SURVEILLANCE_DEFAULTS,
    USAGE_DEFAULTS,
    WAN_PING_DEFAULTS,
    ISP_STATUS_DEFAULTS,
    MIKROTIK_LOGS_DEFAULTS,
)
from .settings_store import get_settings, get_state, save_settings, save_state
from .telegram_commands import handle_telegram_command
from .usage_logic import (
    build_usage_summary_data,
    format_ts_ph,
    normalize_usage_modem_reboot_settings,
    normalize_usage_modem_reboot_state,
    usage_issue_key,
)
from .mikrotik import RouterOSClient
from .mikrotik_logs_setup import auto_configure_mikrotik_logs
from .feature_usage import add_feature_cpu, register_feature


def _safe_update_job_status(job_name, **fields):
    try:
        update_job_status(job_name, **fields)
    except Exception:
        pass


def _safe_insert_system_audit(action, resource="", details=""):
    try:
        insert_auth_audit_log(
            timestamp=utc_now_iso(),
            user_id=None,
            username="system",
            action=(action or "").strip()[:120],
            resource=(resource or "").strip()[:255],
            details=(details or "").strip()[:2000],
            ip_address="",
        )
    except Exception:
        pass


_SYSLOG_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<body>.*)$", re.DOTALL)
_SYSLOG_RFC3164_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$",
    re.DOTALL,
)
_SYSLOG_SEVERITIES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}
_SYSLOG_SEVERITY_RANK = {
    "debug": 0,
    "info": 1,
    "notice": 2,
    "warning": 3,
    "error": 4,
    "critical": 5,
    "alert": 6,
    "emergency": 7,
}


def _normalize_mikrotik_logs_settings(settings):
    cfg = MIKROTIK_LOGS_DEFAULTS.copy()
    cfg = {
        "enabled": bool(cfg.get("enabled", False)),
        "receiver": dict(MIKROTIK_LOGS_DEFAULTS.get("receiver") or {}),
        "storage": dict(MIKROTIK_LOGS_DEFAULTS.get("storage") or {}),
        "filters": dict(MIKROTIK_LOGS_DEFAULTS.get("filters") or {}),
        "auto_setup": dict(MIKROTIK_LOGS_DEFAULTS.get("auto_setup") or {}),
    }
    if isinstance(settings, dict):
        cfg["enabled"] = bool(settings.get("enabled", cfg["enabled"]))
        for section in ("receiver", "storage", "filters", "auto_setup"):
            if isinstance(settings.get(section), dict):
                cfg[section].update(settings.get(section) or {})
    receiver = cfg["receiver"]
    receiver["host"] = (receiver.get("host") or "0.0.0.0").strip() or "0.0.0.0"
    try:
        receiver["port"] = max(1, min(int(receiver.get("port") or 5514), 65535))
    except Exception:
        receiver["port"] = 5514
    storage = cfg["storage"]
    for key, default, low, high in (
        ("retention_days", 30, 1, 3650),
        ("batch_size", 100, 1, 1000),
        ("flush_interval_seconds", 2, 1, 30),
    ):
        try:
            storage[key] = max(low, min(int(storage.get(key) or default), high))
        except Exception:
            storage[key] = default
    filters = cfg["filters"]
    filters["allow_unknown_sources"] = bool(filters.get("allow_unknown_sources", True))
    min_severity = (filters.get("min_severity") or "debug").strip().lower()
    if min_severity not in _SYSLOG_SEVERITY_RANK:
        min_severity = "debug"
    filters["min_severity"] = min_severity
    if isinstance(filters.get("drop_topics"), list):
        filters["drop_topics"] = [str(item or "").strip().lower() for item in filters["drop_topics"] if str(item or "").strip()]
    else:
        filters["drop_topics"] = []
    auto_setup = cfg["auto_setup"]
    auto_setup["enabled"] = bool(auto_setup.get("enabled", False))
    auto_setup["server_host"] = (auto_setup.get("server_host") or "").strip()
    for key, default, low, high in (
        ("check_interval_hours", 24, 1, 720),
        ("timeout_seconds", 8, 1, 60),
    ):
        try:
            auto_setup[key] = max(low, min(int(auto_setup.get(key) or default), high))
        except Exception:
            auto_setup[key] = default
    return cfg


def _mikrotik_logs_router_map():
    out = {}
    def add_aliases(router_info, aliases):
        for alias in aliases or []:
            alias = str(alias or "").strip()
            if alias:
                out[alias] = dict(router_info)

    try:
        pulse = get_settings("isp_ping", {})
        cores = (((pulse.get("pulsewatch") or {}).get("mikrotik") or {}).get("cores") or [])
        for core in cores:
            if not isinstance(core, dict):
                continue
            host = (core.get("host") or "").strip()
            if not host:
                continue
            out[host] = {
                "router_id": (core.get("id") or "").strip(),
                "router_name": (core.get("label") or core.get("id") or host).strip(),
                "router_kind": "core",
            }
    except Exception:
        pass
    try:
        wan = get_settings("wan_ping", WAN_PING_DEFAULTS)
        for router in (wan.get("pppoe_routers") or []):
            if not isinstance(router, dict):
                continue
            host = (router.get("host") or "").strip()
            if not host:
                continue
            out[host] = {
                "router_id": (router.get("id") or "").strip(),
                "router_name": (router.get("name") or router.get("id") or host).strip(),
                "router_kind": "pppoe",
            }
    except Exception:
        pass
    try:
        state = get_state("mikrotik_logs_state", {})
        setup = state.get("setup") if isinstance(state, dict) and isinstance(state.get("setup"), dict) else {}
        for item in setup.get("results") or []:
            if not isinstance(item, dict):
                continue
            router_id = (item.get("router_id") or "").strip()
            router_name = (item.get("router_name") or router_id).strip()
            if not router_id and not router_name:
                continue
            info = {
                "router_id": router_id or router_name,
                "router_name": router_name or router_id,
                "router_kind": (item.get("router_kind") or "").strip() or "mikrotik",
            }
            add_aliases(info, item.get("source_aliases") or [])
    except Exception:
        pass
    return out


def _parse_mikrotik_syslog(raw_message, source_ip, source_port, router_info):
    received_at = utc_now_iso()
    text = (raw_message or "").replace("\x00", "").strip()
    priority = None
    facility = None
    severity = "info"
    body = text
    pri_match = _SYSLOG_PRI_RE.match(text)
    if pri_match:
        try:
            priority = int(pri_match.group("pri"))
            facility = priority // 8
            severity = _SYSLOG_SEVERITIES.get(priority % 8, "info")
        except Exception:
            priority = None
            facility = None
        body = (pri_match.group("body") or "").strip()

    timestamp = received_at
    host = ""
    msg = body
    rfc_match = _SYSLOG_RFC3164_RE.match(body)
    if rfc_match:
        host = (rfc_match.group("host") or "").strip()
        msg = (rfc_match.group("msg") or "").strip()
        try:
            year = datetime.utcnow().year
            dt = datetime.strptime(
                f"{year} {rfc_match.group('month')} {rfc_match.group('day')} {rfc_match.group('time')}",
                "%Y %b %d %H:%M:%S",
            )
            timestamp = dt.replace(microsecond=0).isoformat() + "Z"
        except Exception:
            timestamp = received_at

    topics = ""
    topic_match = re.match(r"^(?P<topics>[A-Za-z0-9_,.!-]+):\s+(?P<message>.*)$", msg, flags=re.DOTALL)
    if topic_match:
        topics = (topic_match.group("topics") or "").strip()
        msg = (topic_match.group("message") or "").strip()
    else:
        first_token = msg.split(" ", 1)[0].strip().rstrip(":")
        if "," in first_token and re.match(r"^[A-Za-z0-9_,.!-]+$", first_token):
            topics = first_token
            msg = msg[len(first_token):].strip(" :")
        lower_msg = msg.lower()
        for candidate in ("critical", "error", "warning", "info", "debug"):
            if not topics and lower_msg.startswith(candidate + ","):
                topics = msg.split(" ", 1)[0].strip().rstrip(":")
                msg = msg[len(topics):].strip(" :")
                break

    if severity == "info":
        topic_lower = topics.lower()
        if "critical" in topic_lower:
            severity = "critical"
        elif "error" in topic_lower:
            severity = "error"
        elif "warning" in topic_lower:
            severity = "warning"
        elif "debug" in topic_lower:
            severity = "debug"

    info = router_info if isinstance(router_info, dict) else {}
    return {
        "timestamp": timestamp,
        "received_at": received_at,
        "source_ip": source_ip,
        "source_port": int(source_port or 0),
        "router_id": info.get("router_id") or host or source_ip,
        "router_name": info.get("router_name") or host or source_ip,
        "router_kind": info.get("router_kind") or ("unknown" if not info else ""),
        "severity": severity,
        "facility": facility,
        "priority": priority,
        "topics": topics,
        "message": msg or body or text,
        "raw_message": text,
    }


def _parse_iso_utc(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1]
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _iso_utc(dt):
    if not isinstance(dt, datetime):
        return ""
    return dt.replace(microsecond=0).isoformat() + "Z"


def _normalize_accounts_ping_classification(raw):
    defaults = ACCOUNTS_PING_DEFAULTS.get("classification", {}) or {}
    source = raw if isinstance(raw, dict) else {}
    return {
        "issue_loss_pct": float(source.get("issue_loss_pct", defaults.get("issue_loss_pct", 20.0)) or 20.0),
        "issue_latency_ms": float(source.get("issue_latency_ms", defaults.get("issue_latency_ms", 200.0)) or 200.0),
        "down_loss_pct": float(source.get("down_loss_pct", defaults.get("down_loss_pct", 100.0)) or 100.0),
        "stable_rto_pct": float(source.get("stable_rto_pct", defaults.get("stable_rto_pct", 2.0)) or 2.0),
        "issue_rto_pct": float(source.get("issue_rto_pct", defaults.get("issue_rto_pct", 5.0)) or 5.0),
        "issue_streak": int(source.get("issue_streak", defaults.get("issue_streak", 2)) or 2),
    }


def _normalize_isp_status_job_settings(raw):
    cfg = raw if isinstance(raw, dict) else {}
    defaults = ISP_STATUS_DEFAULTS
    general = cfg.get("general") if isinstance(cfg.get("general"), dict) else {}
    capacity = cfg.get("capacity") if isinstance(cfg.get("capacity"), dict) else {}
    default_general = defaults.get("general", {})
    default_capacity = defaults.get("capacity", {})
    try:
        poll_interval = max(int(general.get("poll_interval_seconds") or default_general.get("poll_interval_seconds", 30)), 5)
    except Exception:
        poll_interval = int(default_general.get("poll_interval_seconds", 30))
    try:
        retention_days = max(int(general.get("history_retention_days") or default_general.get("history_retention_days", 400)), 1)
    except Exception:
        retention_days = int(default_general.get("history_retention_days", 400))
    try:
        low = max(float(capacity.get("hundred_mbps_min") or default_capacity.get("hundred_mbps_min", 90)), 1.0)
    except Exception:
        low = float(default_capacity.get("hundred_mbps_min", 90))
    try:
        high = max(float(capacity.get("hundred_mbps_max") or default_capacity.get("hundred_mbps_max", 105)), low)
    except Exception:
        high = float(default_capacity.get("hundred_mbps_max", 105))
    try:
        window_minutes = max(int(capacity.get("window_minutes") or default_capacity.get("window_minutes", 10)), 1)
    except Exception:
        window_minutes = int(default_capacity.get("window_minutes", 10))
    average_enabled = bool(capacity.get("average_detection_enabled", default_capacity.get("average_detection_enabled", True)))
    try:
        average_window_hours = max(
            int(capacity.get("average_window_hours") or default_capacity.get("average_window_hours", 4)),
            1,
        )
    except Exception:
        average_window_hours = int(default_capacity.get("average_window_hours", 4))
    telegram = cfg.get("telegram") if isinstance(cfg.get("telegram"), dict) else {}
    default_telegram = defaults.get("telegram", {})
    try:
        recovery_confirm_minutes = max(
            int(telegram.get("recovery_confirm_minutes") or default_telegram.get("recovery_confirm_minutes", 2)),
            1,
        )
    except Exception:
        recovery_confirm_minutes = int(default_telegram.get("recovery_confirm_minutes", 2))
    return {
        "enabled": bool(cfg.get("enabled")),
        "poll_interval_seconds": poll_interval,
        "history_retention_days": retention_days,
        "hundred_mbps_min": low,
        "hundred_mbps_max": high,
        "window_minutes": window_minutes,
        "average_detection_enabled": average_enabled,
        "average_window_hours": average_window_hours,
        "telegram": {
            "daily_enabled": bool(telegram.get("daily_enabled", default_telegram.get("daily_enabled", False))),
            "daily_time": (telegram.get("daily_time") or default_telegram.get("daily_time", "07:00")).strip() or "07:00",
            "immediate_100m_enabled": bool(
                telegram.get("immediate_100m_enabled", default_telegram.get("immediate_100m_enabled", True))
            ),
            "recovery_confirm_minutes": recovery_confirm_minutes,
        },
    }


def _parse_routeros_bps(value):
    raw = str(value if value is not None else "").strip().lower()
    if not raw:
        return None
    raw = raw.replace(" ", "")
    try:
        return float(raw)
    except Exception:
        pass
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)([kmgt]?)(?:bps|b/s)?$", raw)
    if not match:
        return None
    value_num = float(match.group(1))
    unit = match.group(2)
    multiplier = {"": 1, "k": 1_000, "m": 1_000_000, "g": 1_000_000_000, "t": 1_000_000_000_000}.get(unit, 1)
    return value_num * multiplier


def _classify_isp_capacity(samples, cfg):
    cleaned = [
        item
        for item in (samples or [])
        if isinstance(item, dict) and item.get("ts") and item.get("peak_mbps") is not None
    ]
    cleaned.sort(key=lambda item: str(item.get("ts") or ""))
    if not cleaned:
        return "observing", "Waiting for traffic samples."
    low = float(cfg.get("hundred_mbps_min") or 90)
    high = float(cfg.get("hundred_mbps_max") or 105)
    window_minutes = int(cfg.get("window_minutes") or 10)
    average_enabled = bool(cfg.get("average_detection_enabled", True))
    average_window_hours = max(int(cfg.get("average_window_hours") or 4), 1)
    latest = cleaned[-1]
    latest_peak = float(latest.get("peak_mbps") or 0.0)
    last_dt = _parse_iso_utc(cleaned[-1].get("ts"))
    short_cutoff = last_dt - timedelta(minutes=window_minutes) if last_dt else None
    short_window = [
        item
        for item in cleaned
        if not short_cutoff or (_parse_iso_utc(item.get("ts")) or datetime.min) >= short_cutoff
    ] or cleaned
    first_dt = _parse_iso_utc(short_window[0].get("ts"))
    short_last_dt = _parse_iso_utc(short_window[-1].get("ts"))
    span_seconds = max((short_last_dt - first_dt).total_seconds(), 0.0) if first_dt and short_last_dt else 0.0
    required_seconds = max(window_minutes * 60, 1)
    short_max_peak = max(float(item.get("peak_mbps") or 0.0) for item in short_window)
    if short_max_peak > high:
        return "1g", f"Recent peak reached {short_max_peak:.1f} Mbps, above the {high:.1f} Mbps 100M ceiling."
    if low <= short_max_peak <= high and span_seconds >= required_seconds * 0.7:
        return "100m", f"Peak stayed within {low:.1f}-{high:.1f} Mbps over the {window_minutes}m observation window."
    if average_enabled and last_dt:
        average_cutoff = last_dt - timedelta(hours=average_window_hours)
        average_window = [
            item
            for item in cleaned
            if (_parse_iso_utc(item.get("ts")) or datetime.min) >= average_cutoff
        ]
        if average_window:
            avg_first_dt = _parse_iso_utc(average_window[0].get("ts"))
            avg_last_dt = _parse_iso_utc(average_window[-1].get("ts"))
            avg_span_seconds = max((avg_last_dt - avg_first_dt).total_seconds(), 0.0) if avg_first_dt and avg_last_dt else 0.0
            avg_required_seconds = max(average_window_hours * 3600, 1)
            avg_peak = sum(float(item.get("peak_mbps") or 0.0) for item in average_window) / max(len(average_window), 1)
            avg_max_peak = max(float(item.get("peak_mbps") or 0.0) for item in average_window)
            if avg_max_peak > high and avg_span_seconds >= avg_required_seconds * 0.7:
                return "1g", f"Average window still observed {avg_max_peak:.1f} Mbps, above the {high:.1f} Mbps 100M ceiling."
            if avg_span_seconds >= avg_required_seconds * 0.7 and low <= avg_peak <= high:
                return (
                    "100m",
                    f"Average peak is {avg_peak:.1f} Mbps over {average_window_hours}h, inside the {low:.1f}-{high:.1f} Mbps 100M window.",
                )
    if low <= latest_peak <= high:
        return "observing", f"Latest peak is {latest_peak:.1f} Mbps; waiting for a full {window_minutes}m window."
    return "observing", f"Latest peak is {latest_peak:.1f} Mbps; no capacity ceiling detected yet."


def _isp_status_local_now():
    if ZoneInfo is not None:
        return datetime.now(ZoneInfo("Asia/Manila"))
    return datetime.now()


def _fmt_mbps(value):
    try:
        return f"{float(value or 0.0):.2f}"
    except Exception:
        return "0.00"


def _isp_status_wan_label(wan, wan_id):
    return (wan.get("identifier") or wan.get("list_name") or wan_id or "ISP").strip()


def _send_isp_status_telegram(wan_cfg, message):
    telegram = wan_cfg.get("telegram") if isinstance(wan_cfg.get("telegram"), dict) else {}
    token = (telegram.get("bot_token") or "").strip()
    chat_id = (telegram.get("chat_id") or "").strip()
    if not token or not chat_id or not (message or "").strip():
        return False
    send_telegram(token, chat_id, message)
    return True


def _send_isp_status_100m_alert(cfg, wan_cfg, wan, wan_id, latest_row):
    telegram_cfg = cfg.get("telegram") if isinstance(cfg.get("telegram"), dict) else {}
    if not telegram_cfg.get("immediate_100m_enabled", True):
        return False
    identifier = (wan.get("identifier") or "").strip()
    list_name = (wan.get("list_name") or latest_row.get("label") or "").strip()
    label = identifier or list_name or _isp_status_wan_label(wan, wan_id)
    core_id = (wan.get("core_id") or latest_row.get("core_id") or "").strip()
    interface_name = (latest_row.get("interface_name") or wan.get("traffic_interface") or "").strip()
    message = "\n".join(
        [
            "⚠️ ISP Port Status detected possible 100M capacity",
            f"Identifier: {label}",
            f"TO-ISP: {list_name or 'n/a'}",
            f"Core: {core_id or 'n/a'}",
            f"Interface: {interface_name or 'n/a'}",
            f"RX: {_fmt_mbps((latest_row.get('rx_bps') or 0.0) / 1_000_000.0)} Mbps",
            f"TX: {_fmt_mbps((latest_row.get('tx_bps') or 0.0) / 1_000_000.0)} Mbps",
            f"Total: {_fmt_mbps((latest_row.get('total_bps') or 0.0) / 1_000_000.0)} Mbps",
            f"Peak: {_fmt_mbps(latest_row.get('peak_mbps'))} Mbps",
            f"Reason: {latest_row.get('capacity_reason') or '100M rule matched.'}",
            f"Detected: {_isp_status_local_now().strftime('%Y-%m-%d %I:%M %p')}",
        ]
    )
    return _send_isp_status_telegram(wan_cfg, message)


def _send_isp_status_recovered_alert(cfg, wan_cfg, wan, wan_id, latest_row, recovery_started_at=""):
    telegram_cfg = cfg.get("telegram") if isinstance(cfg.get("telegram"), dict) else {}
    if not telegram_cfg.get("immediate_100m_enabled", True):
        return False
    identifier = (wan.get("identifier") or "").strip()
    list_name = (wan.get("list_name") or latest_row.get("label") or "").strip()
    label = identifier or list_name or _isp_status_wan_label(wan, wan_id)
    core_id = (wan.get("core_id") or latest_row.get("core_id") or "").strip()
    interface_name = (latest_row.get("interface_name") or wan.get("traffic_interface") or "").strip()
    confirm_minutes = max(int(telegram_cfg.get("recovery_confirm_minutes") or 2), 1)
    message = "\n".join(
        [
            "✅ ISP Port Status recovered from 100M",
            f"Identifier: {label}",
            f"TO-ISP: {list_name or 'n/a'}",
            f"Core: {core_id or 'n/a'}",
            f"Interface: {interface_name or 'n/a'}",
            f"Current Status: 1G",
            f"RX: {_fmt_mbps((latest_row.get('rx_bps') or 0.0) / 1_000_000.0)} Mbps",
            f"TX: {_fmt_mbps((latest_row.get('tx_bps') or 0.0) / 1_000_000.0)} Mbps",
            f"Total: {_fmt_mbps((latest_row.get('total_bps') or 0.0) / 1_000_000.0)} Mbps",
            f"Peak: {_fmt_mbps(latest_row.get('peak_mbps'))} Mbps",
            f"Confirmed: stayed 1G for at least {confirm_minutes} minute(s)",
            f"Recovery Started: {format_ts_ph(recovery_started_at) if recovery_started_at else 'n/a'}",
            f"Detected: {_isp_status_local_now().strftime('%Y-%m-%d %I:%M %p')}",
        ]
    )
    return _send_isp_status_telegram(wan_cfg, message)


def _send_isp_status_daily_report(cfg, wan_cfg, latest):
    telegram_cfg = cfg.get("telegram") if isinstance(cfg.get("telegram"), dict) else {}
    if not telegram_cfg.get("daily_enabled"):
        return False
    rows = []
    counts = {"1g": 0, "100m": 0, "observing": 0, "not_configured": 0, "error": 0}
    latest = latest if isinstance(latest, dict) else {}
    for wan in wan_cfg.get("wans") or []:
        if not isinstance(wan, dict) or not bool(wan.get("enabled", True)):
            continue
        wan_id = (wan.get("id") or f"{wan.get('core_id')}:{wan.get('list_name')}").strip()
        if not wan_id:
            continue
        row = latest.get(wan_id) if isinstance(latest.get(wan_id), dict) else {}
        status = (row.get("capacity_status") or "observing").strip().lower()
        if status not in counts:
            status = "observing"
        counts[status] += 1
        rows.append((wan, wan_id, row, status))
    if not rows:
        return False
    now_local = _isp_status_local_now()
    review_count = counts["observing"] + counts["not_configured"] + counts["error"]
    if counts["100m"] > 0:
        summary_status = "🔴 100M detected"
    elif review_count > 0:
        summary_status = "🟡 Some ISPs need review"
    else:
        summary_status = "🟢 All ISPs are 1G"
    lines = [
        "ISP Port Status Daily Report",
        f"🕖 {now_local.strftime('%Y-%m-%d %I:%M %p')}",
        f"(1G/100M): {counts['1g']}/{counts['100m']} - {summary_status}",
        "",
    ]
    for wan, wan_id, row, status in rows:
        label = _isp_status_wan_label(wan, wan_id)
        label_status = "1G" if status == "1g" else "100M" if status == "100m" else "Needs Check" if status in ("not_configured", "error") else "Observing"
        lines.append(f"{label}: {label_status}")
    return _send_isp_status_telegram(wan_cfg, "\n".join(lines[:80]))


def _accounts_ping_applied_classification(settings=None, state=None):
    settings = settings if isinstance(settings, dict) else get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    saved = _normalize_accounts_ping_classification(settings.get("classification"))
    state = state if isinstance(state, dict) else get_state("accounts_ping_state", {})
    applied = state.get("classification_applied") if isinstance(state.get("classification_applied"), dict) else {}
    if not applied:
        return saved
    return _normalize_accounts_ping_classification(applied)


def _surveillance_entries_map_from_settings(raw_settings):
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    entries = settings.get("entries") if isinstance(settings.get("entries"), list) else []
    entry_map = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            continue
        pppoe = (raw_entry.get("pppoe") or raw_entry.get("name") or "").strip()
        if not pppoe:
            continue
        entry = dict(raw_entry)
        entry["pppoe"] = pppoe
        entry_map[pppoe] = entry
    return entry_map


def _merge_surveillance_job_updates(ip_updates=None, added_entries=None):
    latest_cfg = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    latest_map = _surveillance_entries_map_from_settings(latest_cfg)
    changed = False

    for raw_pppoe, raw_update in (ip_updates or {}).items():
        pppoe = str(raw_pppoe or "").strip()
        if not pppoe:
            continue
        entry = latest_map.get(pppoe)
        if not isinstance(entry, dict):
            continue
        update = raw_update if isinstance(raw_update, dict) else {}
        next_ip = (update.get("ip") or "").strip()
        next_updated_at = (update.get("updated_at") or "").strip()
        next_source = (update.get("source") or "").strip()
        if next_ip and next_ip != (entry.get("ip") or "").strip():
            entry["ip"] = next_ip
            changed = True
        if next_updated_at and next_updated_at != (entry.get("updated_at") or "").strip():
            entry["updated_at"] = next_updated_at
            changed = True
        if next_source and not (entry.get("source") or "").strip():
            entry["source"] = next_source
            changed = True

    for raw_pppoe, raw_entry in (added_entries or {}).items():
        pppoe = str(raw_pppoe or "").strip()
        if not pppoe or pppoe in latest_map or not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        entry["pppoe"] = pppoe
        latest_map[pppoe] = entry
        changed = True

    if changed:
        latest_cfg["entries"] = list(latest_map.values())
        save_settings("surveillance", latest_cfg)
    return changed


def _usage_live_issue_still_present(cfg, row, now_dt=None):
    cfg = cfg if isinstance(cfg, dict) else {}
    row = row if isinstance(row, dict) else {}
    now_dt = now_dt or datetime.utcnow()
    detect = cfg.get("detection") if isinstance(cfg.get("detection"), dict) else {}

    peak_enabled = bool(detect.get("peak_enabled", True))
    peak_window_min = max(int(detect.get("peak_no_usage_minutes", 120) or 120), 5)
    peak_min_devices = max(int(detect.get("min_connected_devices", 2) or 2), 1)
    peak_from = detect.get("total_kbps_from")
    peak_to = detect.get("total_kbps_to")
    if peak_from is None:
        peak_from = 0
    if peak_to is None:
        peak_to = detect.get("min_total_kbps", 8)
    peak_from = max(float(peak_from or 0.0), 0.0) * 1000.0
    peak_to = max(float(peak_to or 0.0), 0.0) * 1000.0
    if peak_to < peak_from:
        peak_from, peak_to = peak_to, peak_from

    anytime_enabled = bool(detect.get("anytime_enabled", False))
    anytime_window_min = max(int(detect.get("anytime_no_usage_minutes", 120) or 120), 5)
    anytime_min_devices = max(int(detect.get("anytime_min_connected_devices", 2) or 2), 1)
    anytime_from = max(float(detect.get("anytime_total_kbps_from", 0) or 0.0), 0.0) * 1000.0
    anytime_to = max(float(detect.get("anytime_total_kbps_to", 8) or 8.0), 0.0) * 1000.0
    if anytime_to < anytime_from:
        anytime_from, anytime_to = anytime_to, anytime_from

    total_bps = max(float(row.get("dl_bps") or 0.0), 0.0) + max(float(row.get("ul_bps") or 0.0), 0.0)
    host_count = max(int(row.get("host_count") or 0), 0)
    sample_interval = max(int(((cfg.get("storage") or {}).get("sample_interval_seconds", 60) or 60)), 10)
    router_id = str(row.get("router_id") or "").strip()
    pppoe = str(row.get("pppoe") or "").strip()
    stat_cache = {}

    def _window_issue(window_min, from_bps, to_bps, required_devices):
        if required_devices <= 0 or host_count < required_devices or not pppoe:
            return False
        cache_key = int(window_min)
        stat_map = stat_cache.get(cache_key)
        if stat_map is None:
            since_iso = (now_dt - timedelta(minutes=max(cache_key, 1))).replace(microsecond=0).isoformat() + "Z"
            stat_map = get_pppoe_usage_window_stats_since(since_iso)
            stat_cache[cache_key] = stat_map
        stat = stat_map.get(usage_issue_key(router_id, pppoe))
        if not stat:
            return False
        expected = int((max(window_min, 1) * 60) / sample_interval)
        min_samples = max(3, int(expected * 0.25), 10)
        if int(stat.get("samples") or 0) < min_samples:
            return False
        max_total_bps = float(stat.get("max_total_bps") or 0.0)
        return bool(from_bps <= max_total_bps <= to_bps)

    try:
        usage_tz = ZoneInfo("Asia/Manila") if ZoneInfo else None
    except Exception:
        usage_tz = None
    now_ph = now_dt.astimezone(usage_tz) if usage_tz else now_dt
    start_ph = (detect.get("peak_start_ph") or "17:30").strip()
    end_ph = (detect.get("peak_end_ph") or "21:00").strip()
    peak_now = False
    if peak_enabled:
        try:
            sh, sm = [int(part) for part in start_ph.split(":", 1)] if ":" in start_ph else (17, 30)
        except Exception:
            sh, sm = (17, 30)
        try:
            eh, em = [int(part) for part in end_ph.split(":", 1)] if ":" in end_ph else (21, 0)
        except Exception:
            eh, em = (21, 0)
        start_t = time(hour=max(min(sh, 23), 0), minute=max(min(sm, 59), 0))
        end_t = time(hour=max(min(eh, 23), 0), minute=max(min(em, 59), 0))
        current_t = now_ph.time()
        if start_t <= end_t:
            peak_now = start_t <= current_t <= end_t
        else:
            peak_now = current_t >= start_t or current_t <= end_t

    peak_issue = bool(peak_enabled and peak_now and _window_issue(peak_window_min, peak_from, peak_to, peak_min_devices))
    anytime_live_low = bool(anytime_enabled and _window_issue(anytime_window_min, anytime_from, anytime_to, anytime_min_devices))
    return bool(peak_issue or anytime_live_low)


def _usage_modem_reboot_bad_detail(result):
    if not isinstance(result, dict):
        return ""
    detail = str(result.get("detail") or result.get("error") or "").strip()
    http_status = int(result.get("http_status", 0) or 0)
    if http_status > 0 and detail:
        return f"HTTP {http_status}: {detail}"
    if http_status > 0:
        return f"HTTP {http_status}"
    return detail


def _process_usage_modem_reboots(cfg, state, summary, now, now_iso):
    reboot_cfg = normalize_usage_modem_reboot_settings(cfg)
    reboot_state = normalize_usage_modem_reboot_state((state or {}).get("modem_reboot"))
    current = reboot_state.get("current") if isinstance(reboot_state.get("current"), dict) else {}
    last_success_at = (
        reboot_state.get("last_success_at") if isinstance(reboot_state.get("last_success_at"), dict) else {}
    )
    suppression = (
        reboot_state.get("issue_suppression") if isinstance(reboot_state.get("issue_suppression"), dict) else {}
    )
    max_attempts = max(int(reboot_cfg.get("max_attempts", 50) or 50), 1)
    checker_days = max(int(reboot_cfg.get("unrebootable_check_interval_days", 14) or 14), 1)
    reboot_stats_map = {}
    try:
        for stat in list_usage_modem_reboot_account_stats():
            stat_key = usage_issue_key(stat.get("router_id"), stat.get("pppoe"))
            if stat_key:
                reboot_stats_map[stat_key] = stat
    except Exception:
        reboot_stats_map = {}

    for key in list(suppression.keys()):
        until_dt = _parse_iso_utc((suppression.get(key) or {}).get("until"))
        if not until_dt or until_dt <= now:
            suppression.pop(key, None)

    success_keep_cutoff = now - timedelta(days=max(int(reboot_cfg.get("history_retention_days", 180) or 180), 30))
    for key in list(last_success_at.keys()):
        ts_dt = _parse_iso_utc(last_success_at.get(key))
        if not ts_dt or ts_dt < success_keep_cutoff:
            last_success_at.pop(key, None)

    all_rows = []
    all_rows.extend(summary.get("issues") or [])
    all_rows.extend(summary.get("stable") or [])
    rows_by_key = {}
    issue_keys = set()
    for row in all_rows:
        key = usage_issue_key(row.get("router_id"), row.get("pppoe"))
        if not key:
            continue
        rows_by_key[key] = row
    for row in summary.get("issues") or []:
        key = usage_issue_key(row.get("router_id"), row.get("pppoe"))
        if key:
            issue_keys.add(key)

    def _save_cycle(key, row, cycle=None):
        cycle = cycle if isinstance(cycle, dict) else {}
        if isinstance(row, dict):
            cycle["pppoe"] = str(row.get("pppoe") or cycle.get("pppoe") or "").strip()
            cycle["router_id"] = str(row.get("router_id") or cycle.get("router_id") or "").strip()
            cycle["router_name"] = str(row.get("router_name") or cycle.get("router_name") or "").strip()
            cycle["address"] = str(row.get("address") or cycle.get("address") or "").strip()
            cycle["device_id"] = str(row.get("device_id") or cycle.get("device_id") or "").strip()
        current[key] = cycle
        return cycle

    def _schedule_retry(cycle, detail):
        retry_limit = max(int(reboot_cfg.get("retry_count", 5) or 5), 0)
        delay_minutes = max(int(reboot_cfg.get("retry_delay_minutes", 5) or 5), 1)
        attempt_count = max(int(cycle.get("attempt_count", 0) or 0), 0)
        cycle["last_error"] = str(detail or "").strip()
        if attempt_count < retry_limit:
            cycle["next_retry_at"] = _iso_utc(now + timedelta(minutes=delay_minutes))
        else:
            cycle["next_retry_at"] = ""

    def _attempt_reboot(key, row, cycle):
        retry_limit = max(int(reboot_cfg.get("retry_count", 5) or 5), 0)
        buffer_hours = max(int(reboot_cfg.get("buffer_hours", 32) or 32), 1)
        verify_after_minutes = max(int(reboot_cfg.get("verify_after_minutes", 5) or 5), 1)

        cycle["attempt_count"] = max(int(cycle.get("attempt_count", 0) or 0), 0) + 1
        cycle["last_attempt_at"] = now_iso
        cycle["verify_status"] = ""
        cycle["verify_due_at"] = ""
        cycle["verify_checked_at"] = ""
        cycle["task_id"] = ""
        cycle["http_status"] = 0

        device_id = str(row.get("device_id") or "").strip()
        if not device_id:
            detail = "No TR-069 / GenieACS device ID is mapped to this account."
            history_id = insert_usage_modem_reboot_history(
                attempted_at=now_iso,
                pppoe=row.get("pppoe") or "",
                router_id=row.get("router_id") or "",
                router_name=row.get("router_name") or "",
                address=row.get("address") or "",
                device_id="",
                issue_opened_at=cycle.get("opened_at") or now_iso,
                retry_index=cycle.get("attempt_count") or 0,
                retry_limit=retry_limit,
                status="no_tr069",
                error_message=detail,
                detail=detail,
            )
            cycle["latest_history_id"] = history_id
            cycle["last_status"] = "no_tr069"
            _schedule_retry(cycle, detail)
            return

        result = usage_notifier.send_genieacs_reboot_task(cfg, device_id, connection_request=True)
        detail = _usage_modem_reboot_bad_detail(result)
        http_status = int(result.get("http_status", 0) or 0)
        if result.get("ok"):
            buffer_until = _iso_utc(now + timedelta(hours=buffer_hours))
            history_id = insert_usage_modem_reboot_history(
                attempted_at=now_iso,
                pppoe=row.get("pppoe") or "",
                router_id=row.get("router_id") or "",
                router_name=row.get("router_name") or "",
                address=row.get("address") or "",
                device_id=device_id,
                issue_opened_at=cycle.get("opened_at") or now_iso,
                retry_index=cycle.get("attempt_count") or 0,
                retry_limit=retry_limit,
                status="success",
                task_id=result.get("task_id") or "",
                http_status=http_status,
                buffer_until=buffer_until,
                detail=detail or "GenieACS reboot task accepted.",
            )
            cycle["latest_history_id"] = history_id
            cycle["last_status"] = "success"
            cycle["last_error"] = ""
            cycle["next_retry_at"] = ""
            cycle["success_at"] = now_iso
            cycle["buffer_until"] = buffer_until
            cycle["verify_due_at"] = _iso_utc(now + timedelta(minutes=verify_after_minutes))
            cycle["verify_status"] = "pending"
            cycle["task_id"] = str(result.get("task_id") or "").strip()
            cycle["http_status"] = http_status
            last_success_at[key] = now_iso
            return

        history_id = insert_usage_modem_reboot_history(
            attempted_at=now_iso,
            pppoe=row.get("pppoe") or "",
            router_id=row.get("router_id") or "",
            router_name=row.get("router_name") or "",
            address=row.get("address") or "",
            device_id=device_id,
            issue_opened_at=cycle.get("opened_at") or now_iso,
            retry_index=cycle.get("attempt_count") or 0,
            retry_limit=retry_limit,
            status="failed",
            task_id=result.get("task_id") or "",
            http_status=http_status,
            error_message=detail or "GenieACS reboot task failed.",
            detail=detail or "GenieACS reboot task failed.",
        )
        cycle["latest_history_id"] = history_id
        cycle["last_status"] = "failed"
        cycle["task_id"] = str(result.get("task_id") or "").strip()
        cycle["http_status"] = http_status
        _schedule_retry(cycle, detail or "GenieACS reboot task failed.")

    def _unrebootable_block_active(key, cycle):
        stat = reboot_stats_map.get(key) if isinstance(reboot_stats_map, dict) else {}
        if not isinstance(stat, dict):
            return False
        failed_count = int(stat.get("failed_count") or 0)
        verification_failed_count = int(stat.get("verification_failed_count") or 0)
        counted_attempts = failed_count + verification_failed_count
        if counted_attempts < max_attempts:
            return False
        latest_dt = _parse_iso_utc(stat.get("latest_attempted_at"))
        if not latest_dt:
            latest_dt = _parse_iso_utc(cycle.get("last_attempt_at"))
        next_check_dt = (latest_dt + timedelta(days=checker_days)) if latest_dt else (now + timedelta(days=checker_days))
        if next_check_dt <= now:
            return False
        cycle["last_status"] = "unrebootable"
        cycle["last_error"] = (
            f"Reboot Blocked: {counted_attempts} failed reboot attempts reached the "
            f"configured maximum of {max_attempts}. Next checker attempt: {format_ts_ph(_iso_utc(next_check_dt))}."
        )
        cycle["next_retry_at"] = _iso_utc(next_check_dt)
        cycle["verify_status"] = ""
        cycle["verify_due_at"] = ""
        cycle["verify_checked_at"] = ""
        return True

    def _finalize_verification(key, cycle, row):
        history_id = int(cycle.get("latest_history_id", 0) or 0)
        if row and not _usage_live_issue_still_present(cfg, row, now_dt=now):
            suppress_minutes = max(
                int(((cfg.get("detection") or {}).get("anytime_no_usage_minutes", 120) or 120))
                if bool(((cfg.get("detection") or {}).get("anytime_enabled", False)))
                else 15,
                5,
            )
            suppression[key] = {
                "until": _iso_utc(now + timedelta(minutes=suppress_minutes)),
                "verified_at": now_iso,
                "reason": "reboot_verified",
            }
            cycle["verify_status"] = "passed"
            cycle["verify_checked_at"] = now_iso
            cycle["last_status"] = "verify_passed"
            cycle["last_error"] = ""
            if history_id > 0:
                update_usage_modem_reboot_history(
                    history_id,
                    verified_at=now_iso,
                    verification_status="passed",
                    detail="Traffic returned after modem reboot verification.",
                )
            return

        detail = "Usage issue was still present after the reboot verification window."
        if not row:
            detail = "No active PPPoE session was found when the reboot verification window elapsed."
        cycle["verify_status"] = "failed"
        cycle["verify_checked_at"] = now_iso
        cycle["last_status"] = "verify_failed"
        cycle["last_error"] = detail
        if history_id > 0:
            update_usage_modem_reboot_history(
                history_id,
                verified_at=now_iso,
                verification_status="failed",
                detail=detail,
                error_message=detail,
            )

    for key in list(current.keys()):
        cycle = current.get(key) if isinstance(current.get(key), dict) else {}
        row = rows_by_key.get(key)
        cycle = _save_cycle(key, row, cycle)
        verify_due_dt = _parse_iso_utc(cycle.get("verify_due_at"))
        verify_status = str(cycle.get("verify_status") or "").strip().lower()
        if cycle.get("success_at") and verify_due_dt and verify_due_dt <= now and verify_status in ("", "pending"):
            _finalize_verification(key, cycle, row)
        if key not in issue_keys:
            pending_success_verify = bool(cycle.get("success_at")) and str(cycle.get("verify_status") or "").strip().lower() in ("", "pending")
            if pending_success_verify:
                current[key] = cycle
                continue
            current.pop(key, None)

    for row in summary.get("issues") or []:
        key = usage_issue_key(row.get("router_id"), row.get("pppoe"))
        if not key:
            continue
        cycle = current.get(key) if isinstance(current.get(key), dict) else {}
        cycle = _save_cycle(key, row, cycle)
        if not str(cycle.get("opened_at") or "").strip():
            cycle["opened_at"] = now_iso

        verify_status = str(cycle.get("verify_status") or "").strip().lower()
        if cycle.get("success_at"):
            if verify_status in ("", "pending"):
                current[key] = cycle
                continue
            buffer_until_dt = _parse_iso_utc(cycle.get("buffer_until"))
            if buffer_until_dt and buffer_until_dt > now:
                current[key] = cycle
                continue
            cycle["success_at"] = ""
            cycle["buffer_until"] = ""
            cycle["verify_status"] = ""
            cycle["verify_due_at"] = ""
            cycle["verify_checked_at"] = ""

        last_success_dt = _parse_iso_utc(last_success_at.get(key))
        if last_success_dt:
            buffer_until_dt = last_success_dt + timedelta(hours=max(int(reboot_cfg.get("buffer_hours", 32) or 32), 1))
            if buffer_until_dt > now and not cycle.get("success_at"):
                cycle["last_status"] = "buffered"
                cycle["buffer_until"] = _iso_utc(buffer_until_dt)
                cycle["next_retry_at"] = ""
                current[key] = cycle
                continue

        if _unrebootable_block_active(key, cycle):
            current[key] = cycle
            continue

        next_retry_dt = _parse_iso_utc(cycle.get("next_retry_at"))
        if next_retry_dt and next_retry_dt > now:
            current[key] = cycle
            continue

        _attempt_reboot(key, row, cycle)
        current[key] = cycle

    reboot_state["current"] = current
    reboot_state["last_success_at"] = last_success_at
    reboot_state["issue_suppression"] = suppression
    return reboot_state


_RE_PING_TIME = re.compile(r"time=([0-9.]+)\s*ms")


def _start_surveillance_ai_report(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return False
    try:
        from . import main as main_module

        starter = getattr(main_module, "_start_surveillance_ai_report", None)
        if callable(starter):
            return bool(starter(pppoe))
    except Exception:
        return False
    return False


def _ping_with_source(ip, source_ip, timeout_seconds, count):
    cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds)]
    if source_ip:
        cmd.extend(["-I", source_ip])
    cmd.append(ip)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output = result.stdout or ""
    replies = 0
    times = []
    for line in output.splitlines():
        if "bytes from" in line:
            replies += 1
        time_match = _RE_PING_TIME.search(line)
        if time_match:
            try:
                times.append(float(time_match.group(1)))
            except Exception:
                pass
    loss = 100.0
    if count > 0:
        loss = round(100.0 * (count - replies) / count, 1)
    min_ms = min(times) if times else None
    max_ms = max(times) if times else None
    avg_ms = round(sum(times) / len(times), 1) if times else None
    return {
        "loss": loss,
        "min_ms": min_ms,
        "avg_ms": avg_ms,
        "max_ms": max_ms,
        "raw_output": output,
        "replies": replies,
    }


def _router_ping_with_client(client, ip, timeout_seconds, count):
    timeout_seconds = max(int(timeout_seconds or 1), 1)
    count = max(int(count or 1), 1)
    times = client.ping_times(ip, count=count, timeout=f"{timeout_seconds * 1000}ms")
    replies = len(times)
    loss = 100.0
    if count > 0:
        loss = round(100.0 * (count - replies) / count, 1)
    min_ms = min(times) if times else None
    max_ms = max(times) if times else None
    avg_ms = round(sum(times) / len(times), 1) if times else None
    return {
        "loss": loss,
        "min_ms": min_ms,
        "avg_ms": avg_ms,
        "max_ms": max_ms,
        "raw_output": "",
        "replies": replies,
    }


class JobsManager:
    def __init__(self):
        self.stop_event = threading.Event()
        self.threads = []
        for name in (
            "Optical Monitoring",
            "Telegram",
            "WAN Ping",
            "ISP Port Status",
            "MikroTik Routers",
            "MikroTik Logs",
            "Accounts Ping",
            "Missing Secrets",
            "Under Surveillance",
            "Usage",
            "Offline",
        ):
            register_feature(name)

    def start(self):
        self.threads = [
            threading.Thread(target=self._optical_loop, daemon=True),
            threading.Thread(target=self._telegram_loop, daemon=True),
            threading.Thread(target=self._wan_ping_loop, daemon=True),
            threading.Thread(target=self._isp_status_loop, daemon=True),
            threading.Thread(target=self._mikrotik_router_health_loop, daemon=True),
            threading.Thread(target=self._mikrotik_logs_loop, daemon=True),
            threading.Thread(target=self._accounts_ping_loop, daemon=True),
            threading.Thread(target=self._accounts_missing_loop, daemon=True),
            threading.Thread(target=self._usage_loop, daemon=True),
            threading.Thread(target=self._offline_loop, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def stop(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=2)

    def _optical_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("optical", OPTICAL_DEFAULTS)
            if not cfg.get("enabled"):
                time_module.sleep(5)
                continue

            loop_cpu_start = time_module.thread_time()
            try:
                state = get_state("optical_state", {"last_run_date": None, "last_run_at": None})
                pause_until = state.get("pause_until")
                if pause_until:
                    pause_dt = datetime.fromisoformat(pause_until.replace("Z", ""))
                    if datetime.utcnow() < pause_dt:
                        time_module.sleep(5)
                        continue
                retention_days = int(cfg.get("storage", {}).get("raw_retention_days", 0) or 0)
                if retention_days > 0:
                    last_prune = state.get("last_prune_at")
                    if not last_prune:
                        last_prune_dt = None
                    else:
                        last_prune_dt = datetime.fromisoformat(last_prune.replace("Z", ""))
                    if not last_prune_dt or last_prune_dt + timedelta(hours=24) < datetime.utcnow():
                        cutoff = datetime.utcnow() - timedelta(days=retention_days)
                        delete_optical_results_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                        state["last_prune_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
                        save_state("optical_state", state)
                interval_minutes = int(cfg.get("general", {}).get("check_interval_minutes", 0) or 0)
                now = datetime.utcnow()
                last_run_at = state.get("last_run_at")
                last_run_dt = datetime.fromisoformat(last_run_at.replace("Z", "")) if last_run_at else None
                due_interval = interval_minutes > 0 and (not last_run_dt or now - last_run_dt >= timedelta(minutes=interval_minutes))
                daily_cfg = dict(cfg.get("general", {}))
                daily_cfg["timezone"] = "Asia/Manila"
                due_daily = should_run_daily_on_minute(daily_cfg, state)
                if due_daily:
                    _safe_update_job_status("optical", last_run_at=utc_now_iso())
                    optical_notifier.run(cfg, send_alerts=True)
                    state = get_state("optical_state", state)
                    state["last_run_date"] = current_date(daily_cfg).isoformat()
                    state["last_run_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    save_state("optical_state", state)
                    _safe_update_job_status("optical", last_success_at=utc_now_iso(), last_error="", last_error_at="")
                elif due_interval:
                    _safe_update_job_status("optical", last_run_at=utc_now_iso())
                    optical_notifier.run(cfg, send_alerts=False)
                    state = get_state("optical_state", state)
                    state["last_run_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    save_state("optical_state", state)
                    _safe_update_job_status("optical", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                _safe_update_job_status("optical", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                _safe_update_job_status("optical", last_error=str(exc), last_error_at=utc_now_iso())
            finally:
                add_feature_cpu("Optical Monitoring", max(time_module.thread_time() - loop_cpu_start, 0.0))

            time_module.sleep(20)

    def _accounts_ping_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
            surv_cfg = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
            surv_enabled = bool(surv_cfg.get("enabled", True))
            auto_add_cfg = surv_cfg.get("auto_add", {}) or {}
            auto_add_sources = auto_add_cfg.get("sources", {}) or {}
            auto_add_enabled = bool(
                surv_enabled
                and auto_add_cfg.get("enabled", False)
                and auto_add_sources.get("accounts_ping", True)
            )
            raw_entries = surv_cfg.get("entries") if isinstance(surv_cfg.get("entries"), list) else []
            surv_entries = []
            for entry in raw_entries:
                if not isinstance(entry, dict):
                    continue
                pppoe = (entry.get("pppoe") or entry.get("name") or "").strip()
                if not pppoe:
                    continue
                status = (entry.get("status") or "under").strip().lower()
                if status not in ("under", "level2"):
                    status = "under"
                surv_entries.append({**entry, "pppoe": pppoe, "status": status})
            surv_map = {entry["pppoe"]: entry for entry in surv_entries}
            surveillance_ip_updates = {}
            surveillance_added_entries = {}
            has_surveillance_targets = bool(surv_enabled and surv_map)

            should_run = bool(cfg.get("enabled") or has_surveillance_targets or auto_add_enabled)
            if not should_run:
                time_module.sleep(5)
                continue

            loop_cpu_start = time_module.thread_time()
            surveillance_cpu_seconds = 0.0
            try:
                now = datetime.utcnow()
                state = get_state("accounts_ping_state", {"accounts": {}, "last_prune_at": None})
                accounts_state = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}
                devices = state.get("devices") if isinstance(state.get("devices"), list) else []
                wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
                routers = wan_cfg.get("pppoe_routers") if isinstance(wan_cfg.get("pppoe_routers"), list) else []
                router_catalog = {
                    (router.get("id") or "").strip(): router
                    for router in routers
                    if isinstance(router, dict) and (router.get("id") or "").strip()
                }
                refreshed_at = state.get("devices_refreshed_at")
                refreshed_dt = datetime.fromisoformat(refreshed_at.replace("Z", "")) if refreshed_at else None
                refresh_minutes = int((cfg.get("source", {}) or {}).get("refresh_minutes", 15) or 15)
                if refresh_minutes < 1:
                    refresh_minutes = 1
                source_cfg = cfg.get("source") if isinstance(cfg.get("source"), dict) else {}
                mikrotik_source_cfg = (
                    source_cfg.get("mikrotik") if isinstance(source_cfg.get("mikrotik"), dict) else {}
                )
                mikrotik_timeout_seconds = max(int(mikrotik_source_cfg.get("timeout_seconds", 5) or 5), 1)
                source_mode = source_cfg.get("mode")

                def account_id_for_target(pppoe, router_id=""):
                    return build_accounts_ping_account_id(
                        pppoe,
                        source_mode=source_mode,
                        router_id=router_id,
                    )

                # Refresh tracked devices from the configured source.
                should_refresh = (not refreshed_dt) or (refreshed_dt + timedelta(minutes=refresh_minutes) < now) or not devices
                if should_refresh:
                    try:
                        source_mode, devices, router_status = build_accounts_ping_source_devices(
                            cfg,
                            routers=routers,
                            previous_devices=devices,
                            now=now,
                        )
                        state["devices"] = devices
                        state["router_status"] = router_status
                        state["devices_refreshed_at"] = now.replace(microsecond=0).isoformat() + "Z"
                        save_state("accounts_ping_state", state)
                    except Exception:
                        if cfg.get("enabled"):
                            raise

                storage = cfg.get("storage", {}) or {}
                raw_retention_days = int(storage.get("raw_retention_days", 0) or 0)
                rollup_retention_days = int(storage.get("rollup_retention_days", 0) or 0)
                bucket_seconds = int(storage.get("bucket_seconds", 60) or 60)
                last_prune = state.get("last_prune_at")
                last_prune_dt = datetime.fromisoformat(last_prune.replace("Z", "")) if last_prune else None
                if (raw_retention_days > 0 or rollup_retention_days > 0) and (
                    not last_prune_dt or last_prune_dt + timedelta(hours=24) < now
                ):
                    if raw_retention_days > 0:
                        cutoff = now - timedelta(days=raw_retention_days)
                        delete_accounts_ping_raw_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                    if rollup_retention_days > 0:
                        cutoff = now - timedelta(days=rollup_retention_days)
                        delete_accounts_ping_rollups_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                    state["last_prune_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    save_state("accounts_ping_state", state)

                pppoe_ip_map = {}
                for device in devices:
                    pppoe = (device.get("pppoe") or device.get("name") or "").strip()
                    ip = (device.get("ip") or "").strip()
                    if not pppoe or not ip:
                        continue
                    pppoe_ip_map[pppoe] = ip

                target_map = {}
                if cfg.get("enabled"):
                    for device in devices:
                        pppoe = (device.get("pppoe") or device.get("name") or "").strip()
                        ip = (device.get("ip") or "").strip()
                        account_id = (device.get("account_id") or "").strip() or account_id_for_target(
                            pppoe,
                            router_id=(device.get("router_id") or "").strip(),
                        )
                        if not pppoe or not ip or not account_id:
                            continue
                        target_map[account_id] = {
                            "id": account_id,
                            "pppoe": pppoe,
                            "name": pppoe,
                            "ip": ip,
                            "router_id": (device.get("router_id") or "").strip(),
                            "router_name": (device.get("router_name") or "").strip(),
                            "source_mode": normalize_accounts_ping_source_mode(device.get("source_mode") or source_mode),
                            "source_missing": bool(device.get("source_missing")),
                            "source_missing_since": (device.get("source_missing_since") or "").strip(),
                        }

                surv_changed = False
                if has_surveillance_targets:
                    for pppoe, entry in surv_map.items():
                        ip = (entry.get("ip") or "").strip() or pppoe_ip_map.get(pppoe, "")
                        if ip and ip != (entry.get("ip") or "").strip():
                            entry["ip"] = ip
                            entry["updated_at"] = now.replace(microsecond=0).isoformat() + "Z"
                            surveillance_ip_updates[pppoe] = {
                                "ip": ip,
                                "updated_at": entry["updated_at"],
                                "source": (entry.get("source") or "").strip(),
                            }
                            surv_changed = True
                            try:
                                touch_surveillance_session(
                                    pppoe,
                                    source=(entry.get("source") or "").strip(),
                                    ip=ip,
                                    state=(entry.get("status") or "under"),
                                )
                            except Exception:
                                pass
                        account_id = account_id_for_target(pppoe)
                        if not account_id or not ip:
                            continue
                        target_map.setdefault(account_id, {"id": account_id, "pppoe": pppoe, "name": pppoe, "ip": ip})

                targets = list(target_map.values())
                account_ids_by_pppoe = build_accounts_ping_account_ids_by_pppoe(devices)
                for target in targets:
                    pppoe = (target.get("pppoe") or "").strip().lower()
                    aid = (target.get("id") or "").strip()
                    if not pppoe or not aid:
                        continue
                    account_ids_by_pppoe.setdefault(pppoe, [])
                    if aid not in account_ids_by_pppoe[pppoe]:
                        account_ids_by_pppoe[pppoe].append(aid)

                if not targets:
                    time_module.sleep(2)
                    continue

                # Seed history sessions for current surveillance entries (once per PPPoE).
                seeded = state.get("surveillance_sessions_seeded")
                if not isinstance(seeded, list):
                    seeded = []
                seeded_set = {str(x).strip() for x in seeded if str(x).strip()}
                seeded_changed = False
                if has_surveillance_targets:
                    for pppoe, entry in surv_map.items():
                        if pppoe in seeded_set:
                            continue
                        try:
                            ensure_surveillance_session(
                                pppoe,
                                started_at=(entry.get("added_at") or "").strip(),
                                source=(entry.get("source") or "").strip(),
                                ip=(entry.get("ip") or "").strip(),
                                state=(entry.get("status") or "under"),
                            )
                        except Exception:
                            pass
                        seeded_set.add(pppoe)
                        seeded_changed = True
                if seeded_changed:
                    state["surveillance_sessions_seeded"] = sorted(seeded_set, key=lambda x: x.lower())

                base_interval = max(int((cfg.get("general", {}) or {}).get("base_interval_seconds", 30) or 30), 1)
                configured_parallel = max(int((cfg.get("general", {}) or {}).get("max_parallel", 64) or 64), 1)
                max_parallel = configured_parallel
                ping_cfg = cfg.get("ping", {}) or {}
                count = max(int(ping_cfg.get("count", 3) or 3), 1)
                timeout_seconds = max(int(ping_cfg.get("timeout_seconds", 1) or 1), 1)
                surv_ping_cfg = surv_cfg.get("ping", {}) or {}
                surv_interval = max(int(surv_ping_cfg.get("interval_seconds", 1) or 1), 1)
                burst_count = max(int(surv_ping_cfg.get("burst_count", 1) or 1), 1)
                burst_timeout_seconds = max(int(surv_ping_cfg.get("burst_timeout_seconds", 1) or 1), 1)

                cls = _accounts_ping_applied_classification(cfg, state)
                issue_loss_pct = float(cls.get("issue_loss_pct", 20.0) or 20.0)
                issue_latency_ms = float(cls.get("issue_latency_ms", 200.0) or 200.0)
                down_loss_pct = float(cls.get("down_loss_pct", 100.0) or 100.0)

                burst_cfg = surv_cfg.get("burst", {}) or {}
                burst_enabled = bool(burst_cfg.get("enabled", True))
                burst_interval = max(int(burst_cfg.get("burst_interval_seconds", 1) or 1), 1)
                burst_duration = max(int(burst_cfg.get("burst_duration_seconds", 120) or 120), 5)
                trigger_on_issue = bool(burst_cfg.get("trigger_on_issue", True))

                backoff_cfg = surv_cfg.get("backoff", {}) or {}
                long_down_seconds = max(int(backoff_cfg.get("long_down_seconds", 7200) or 7200), 60)
                long_down_interval = max(int(backoff_cfg.get("long_down_interval_seconds", 300) or 300), 5)

                def parse_dt(value):
                    if not value:
                        return None
                    try:
                        return datetime.fromisoformat(str(value).replace("Z", ""))
                    except Exception:
                        return None

                def stage_seconds(entry):
                    entry = entry or {}
                    end_dt = now
                    added_at = parse_dt(entry.get("added_at"))
                    level2_at = parse_dt(entry.get("level2_at"))
                    fixed_at = parse_dt(entry.get("last_fixed_at"))
                    status = (entry.get("status") or "under").strip().lower()
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
                    if fixed_at and fixed_at >= added_at:
                        observe_seconds = max(int((end_dt - fixed_at).total_seconds()), 0)
                    else:
                        under_seconds = max(int((end_dt - added_at).total_seconds()), 0)
                    return under_seconds, level2_seconds, observe_seconds

                due_targets = []
                for target in targets:
                    entry = accounts_state.get(target["id"], {}) if isinstance(accounts_state.get(target["id"]), dict) else {}
                    last_check_dt = parse_dt(entry.get("last_check_at"))
                    down_since_dt = parse_dt(entry.get("down_since"))
                    burst_until_dt = parse_dt(entry.get("burst_until"))

                    is_long_down = bool(down_since_dt and (now - down_since_dt).total_seconds() >= long_down_seconds)
                    if is_long_down:
                        burst_until_dt = None

                    in_burst = bool(burst_enabled and (burst_until_dt and now < burst_until_dt))
                    is_surveillance_target = target.get("pppoe") in surv_map

                    effective_interval = base_interval
                    mode = "normal"
                    if is_surveillance_target:
                        if is_long_down:
                            effective_interval = long_down_interval
                            mode = "backoff"
                        else:
                            effective_interval = surv_interval
                            mode = "surveillance"
                    elif is_long_down:
                        effective_interval = long_down_interval
                        mode = "backoff"
                    elif in_burst:
                        effective_interval = burst_interval
                        mode = "burst"

                    due = (not last_check_dt) or ((now - last_check_dt).total_seconds() >= effective_interval)
                    if due:
                        due_targets.append({**target, "_mode": mode})

                if not due_targets:
                    time_module.sleep(1)
                    continue

                _safe_update_job_status("accounts_ping", last_run_at=utc_now_iso())

                router_client_pools = {}
                router_pool_wait_seconds = {}
                router_clients_to_close = []
                mikrotik_due_counts = {}
                for target in due_targets:
                    if normalize_accounts_ping_source_mode(target.get("source_mode") or source_mode) != ACCOUNTS_PING_SOURCE_MIKROTIK:
                        continue
                    router_id = (target.get("router_id") or "").strip()
                    if not router_id:
                        continue
                    mikrotik_due_counts[router_id] = mikrotik_due_counts.get(router_id, 0) + 1
                for router_id, router_target_count in mikrotik_due_counts.items():
                    router = router_catalog.get(router_id) or {}
                    host = (router.get("host") or "").strip()
                    if not host or bool(router.get("use_tls")):
                        continue
                    pool_size = min(
                        max(router_target_count, 1),
                        max(1, min(max_parallel, 4)),
                    )
                    ping_budget_seconds = max(
                        timeout_seconds * count,
                        burst_timeout_seconds * burst_count,
                        1,
                    )
                    router_pool_wait_seconds[router_id] = max(
                        int(((router_target_count + pool_size - 1) // pool_size) * ping_budget_seconds) + 2,
                        2,
                    )
                    pool = queue.LifoQueue()
                    for _ in range(pool_size):
                        try:
                            client = RouterOSClient(
                                host,
                                int(router.get("port", 8728) or 8728),
                                router.get("username", ""),
                                router.get("password", ""),
                                timeout=mikrotik_timeout_seconds,
                            )
                            client.connect()
                            pool.put(client)
                            router_clients_to_close.append(client)
                        except Exception:
                            break
                    if not pool.empty():
                        router_client_pools[router_id] = pool

                def _ping_via_router(router_id, ip, mode, client=None):
                    router = router_catalog.get(router_id) or {}
                    host = (router.get("host") or "").strip()
                    if not host:
                        raise RuntimeError(f"Accounts Ping router '{router_id}' has no host configured.")
                    if bool(router.get("use_tls")):
                        raise RuntimeError(
                            f"Accounts Ping router '{router_id}' uses TLS API, which is not supported by router-side ping."
                        )
                    owns_client = client is None
                    active_client = client
                    if active_client is None:
                        active_client = RouterOSClient(
                            host,
                            int(router.get("port", 8728) or 8728),
                            router.get("username", ""),
                            router.get("password", ""),
                            timeout=mikrotik_timeout_seconds,
                        )
                        active_client.connect()
                    try:
                        if mode in ("burst", "surveillance"):
                            return _router_ping_with_client(active_client, ip, burst_timeout_seconds, burst_count)
                        return _router_ping_with_client(active_client, ip, timeout_seconds, count)
                    finally:
                        if owns_client:
                            try:
                                active_client.close()
                            except Exception:
                                pass

                def do_ping(target_row):
                    ip = target_row["ip"]
                    mode = target_row.get("_mode") or "normal"
                    if target_row.get("source_missing"):
                        return target_row, {
                            "loss": 100.0,
                            "min_ms": None,
                            "avg_ms": None,
                            "max_ms": None,
                            "replies": 0,
                            "source_missing": True,
                        }
                    target_source_mode = normalize_accounts_ping_source_mode(target_row.get("source_mode") or source_mode)
                    router_id = (target_row.get("router_id") or "").strip()
                    if target_source_mode == ACCOUNTS_PING_SOURCE_MIKROTIK and router_id:
                        pool = router_client_pools.get(router_id)
                        wait_timeout = router_pool_wait_seconds.get(
                            router_id,
                            max(timeout_seconds * count, burst_timeout_seconds * burst_count, 1) + 2,
                        )
                        if pool is not None:
                            client = None
                            try:
                                client = pool.get(timeout=wait_timeout)
                                return target_row, _ping_via_router(router_id, ip, mode, client=client)
                            except queue.Empty:
                                client = None
                            except Exception:
                                if client is not None:
                                    try:
                                        client.close()
                                    except Exception:
                                        pass
                                    client = None
                            finally:
                                if client is not None:
                                    try:
                                        pool.put(client)
                                    except Exception:
                                        pass
                        try:
                            return target_row, _ping_via_router(router_id, ip, mode)
                        except Exception as exc:
                            return target_row, {
                                "loss": None,
                                "min_ms": None,
                                "avg_ms": None,
                                "max_ms": None,
                                "raw_output": "",
                                "replies": 0,
                                "probe_error": str(exc),
                            }
                    if mode in ("burst", "surveillance"):
                        res = _ping_with_source(ip, "", burst_timeout_seconds, burst_count)
                    else:
                        res = _ping_with_source(ip, "", timeout_seconds, count)
                    return target_row, res

                results = []
                with ThreadPoolExecutor(max_workers=min(max_parallel, max(len(due_targets), 1))) as executor:
                    future_map = {executor.submit(do_ping, target): target for target in due_targets}
                    for future in as_completed(future_map):
                        try:
                            results.append(future.result())
                        except Exception:
                            target = future_map[future]
                            results.append((target, {"loss": 100.0, "min_ms": None, "avg_ms": None, "max_ms": None, "replies": 0}))

                changed = False
                try:
                    for target, res in results:
                        account_id = target["id"]
                        name = target.get("name") or ""
                        ip = target["ip"]
                        mode = target.get("_mode") or "normal"
                        loss = res.get("loss")
                        min_ms = res.get("min_ms")
                        avg_ms = res.get("avg_ms")
                        max_ms = res.get("max_ms")
                        probe_error = (res.get("probe_error") or "").strip()
                        source_missing = bool(target.get("source_missing") or res.get("source_missing"))
                        entry = accounts_state.get(account_id, {}) if isinstance(accounts_state.get(account_id), dict) else {}
                        if probe_error and loss is None:
                            entry["last_probe_error"] = probe_error[:500]
                            entry["last_probe_error_at"] = now.replace(microsecond=0).isoformat() + "Z"
                            accounts_state[account_id] = entry
                            changed = True
                            continue
                        ok = bool(loss is not None and float(loss) < down_loss_pct and int(res.get("replies") or 0) > 0)

                        is_issue = (not ok) or (loss is not None and float(loss) >= issue_loss_pct) or (
                            avg_ms is not None and float(avg_ms) >= issue_latency_ms
                        )

                        # clear expired windows
                        burst_until_dt = parse_dt(entry.get("burst_until"))
                        if burst_until_dt and now >= burst_until_dt:
                            entry["burst_until"] = ""
                            burst_until_dt = None
                        down_since_dt = parse_dt(entry.get("down_since"))
                        if ok:
                            entry["streak"] = 0
                            entry["down_since"] = ""
                            entry["last_up_at"] = now.replace(microsecond=0).isoformat() + "Z"
                            if is_issue:
                                if not entry.get("issue_since"):
                                    entry["issue_since"] = now.replace(microsecond=0).isoformat() + "Z"
                            else:
                                entry["issue_since"] = ""
                        else:
                            entry["streak"] = int(entry.get("streak", 0) or 0) + 1
                            if not down_since_dt:
                                entry["down_since"] = now.replace(microsecond=0).isoformat() + "Z"
                            entry["issue_since"] = ""

                        entry["last_check_at"] = now.replace(microsecond=0).isoformat() + "Z"
                        entry["last_status"] = "up" if ok and not is_issue else ("issue" if ok else "down")
                        entry["last_ip"] = ip
                        entry["last_ok"] = bool(ok)
                        entry["last_loss"] = loss
                        entry["last_avg_ms"] = avg_ms
                        entry["last_probe_error"] = ""
                        entry["last_probe_error_at"] = ""
                        entry["router_id"] = (target.get("router_id") or "").strip()
                        entry["router_name"] = (target.get("router_name") or "").strip()
                        entry["source_missing"] = source_missing
                        if source_missing:
                            entry["source_missing_since"] = (
                                (target.get("source_missing_since") or "").strip()
                                or (entry.get("source_missing_since") or "")
                                or now.replace(microsecond=0).isoformat() + "Z"
                            )
                        else:
                            entry["source_missing_since"] = ""

                        is_long_down = False
                        down_since_dt2 = parse_dt(entry.get("down_since"))
                        if down_since_dt2 and (now - down_since_dt2).total_seconds() >= long_down_seconds:
                            is_long_down = True
                        if is_long_down:
                            entry["burst_until"] = ""
                        else:
                            if mode not in ("surveillance",) and burst_enabled and ((is_issue and trigger_on_issue) or (not ok)) and not burst_until_dt:
                                entry["burst_until"] = (now + timedelta(seconds=burst_duration)).replace(microsecond=0).isoformat() + "Z"

                        accounts_state[account_id] = entry
                        changed = True

                        insert_accounts_ping_result(
                            account_id=account_id,
                            name=name,
                            ip=ip,
                            loss=loss,
                            min_ms=min_ms,
                            avg_ms=avg_ms,
                            max_ms=max_ms,
                            ok=ok,
                            mode=mode,
                            timestamp=now.replace(microsecond=0).isoformat() + "Z",
                            bucket_seconds=bucket_seconds,
                        )

                    if changed:
                        state["accounts"] = accounts_state
                        save_state("accounts_ping_state", state)
                finally:
                    for client in router_clients_to_close:
                        try:
                            client.close()
                        except Exception:
                            pass

                # auto-transition surveillance entries (every ~5 seconds)
                if surv_enabled and (has_surveillance_targets or auto_add_enabled):
                    surveillance_cpu_start = time_module.thread_time()
                    last_eval = state.get("surveillance_last_eval_at")
                    last_eval_dt = parse_dt(last_eval) if last_eval else None
                    if not last_eval_dt or (now - last_eval_dt).total_seconds() >= 5:
                        now_iso = now.replace(microsecond=0).isoformat() + "Z"
                        entries_changed = False

                        # Auto-add accounts into surveillance on a schedule (minutes).
                        scan_due = False
                        if auto_add_enabled:
                            scan_interval_minutes = max(int(auto_add_cfg.get("scan_interval_minutes", 5) or 5), 1)
                            last_scan = state.get("surveillance_autoadd_last_scan_at")
                            last_scan_dt = parse_dt(last_scan) if last_scan else None
                            scan_due = (not last_scan_dt) or (now - last_scan_dt) >= timedelta(minutes=scan_interval_minutes)

                        if auto_add_enabled and scan_due:
                            sources = auto_add_cfg.get("sources") if isinstance(auto_add_cfg.get("sources"), dict) else {}
                            if not bool(sources.get("accounts_ping", True)):
                                state["surveillance_autoadd_last_scan_at"] = now_iso
                            else:
                                try:
                                    window_days = float(auto_add_cfg.get("window_days", 3) or 3)
                                except Exception:
                                    window_days = 3.0
                                if window_days <= 0:
                                    window_days = 3.0
                                min_down_events = max(int(auto_add_cfg.get("min_down_events", 5) or 5), 1)
                                try:
                                    max_add = int(auto_add_cfg.get("max_add_per_eval", 3))
                                except Exception:
                                    max_add = 3
                                if max_add < 0:
                                    max_add = 0

                                candidates = []
                                for target in targets:
                                    pppoe = (target.get("pppoe") or "").strip()
                                    if not pppoe or pppoe in surv_map:
                                        continue
                                    candidates.append(target)

                                since_iso2 = (now - timedelta(days=window_days)).replace(microsecond=0).isoformat() + "Z"
                                until_iso2 = now.replace(microsecond=0).isoformat() + "Z"
                                down_events_map = get_accounts_ping_down_events_map(
                                    [t["id"] for t in candidates], since_iso2, until_iso2
                                )

                                added = 0
                                for target in candidates:
                                    if max_add and added >= max_add:
                                        break
                                    pppoe = (target.get("pppoe") or "").strip()
                                    if not pppoe or pppoe in surv_map:
                                        continue

                                    down_events = int(down_events_map.get(target["id"]) or 0)
                                    if down_events < min_down_events:
                                        continue
                                    reason = f"Intermittent: {down_events} down events / {window_days:g}d"

                                    ip = (target.get("ip") or "").strip()
                                    entry = {
                                        "pppoe": pppoe,
                                        "name": (target.get("name") or pppoe).strip(),
                                        "ip": ip,
                                        "source": "accounts_ping",
                                        "status": "under",
                                        "added_at": now_iso,
                                        "first_added_at": now_iso,
                                        "updated_at": now_iso,
                                        "level2_at": "",
                                        "level2_reason": "",
                                        "last_fixed_at": "",
                                        "last_fixed_reason": "",
                                        "last_fixed_mode": "",
                                        "added_mode": "auto",
                                        "added_by": "system",
                                        "auto_source": "accounts_ping",
                                        "auto_reason": reason,
                                        "stage_history": [
                                            {
                                                "ts": now_iso,
                                                "from": "",
                                                "to": "under",
                                                "reason": f"Auto-added from accounts_ping: {reason}",
                                                "action": "add_auto",
                                                "actor": "system",
                                            }
                                        ],
                                        "ai_reports": {
                                            "under": {
                                                "status": "",
                                                "error": "",
                                                "generated_at": "",
                                                "provider": "",
                                                "model": "",
                                                "text": "",
                                                "recommend_needs_manual_fix": "unknown",
                                                "recommendation_reason": "",
                                                "potential_problems": [],
                                                "provider_override": "",
                                                "model_override": "",
                                            },
                                            "level2": {
                                                "status": "",
                                                "error": "",
                                                "generated_at": "",
                                                "provider": "",
                                                "model": "",
                                                "text": "",
                                                "recommend_needs_manual_fix": "unknown",
                                                "recommendation_reason": "",
                                                "potential_problems": [],
                                                "provider_override": "",
                                                "model_override": "",
                                            },
                                            "observe": {
                                                "status": "",
                                                "error": "",
                                                "generated_at": "",
                                                "provider": "",
                                                "model": "",
                                                "text": "",
                                                "recommend_needs_manual_fix": "unknown",
                                                "recommendation_reason": "",
                                                "potential_problems": [],
                                                "provider_override": "",
                                                "model_override": "",
                                            },
                                        },
                                        "ai_report_history": [],
                                        "ai_report_pending_stage": "",
                                    }
                                    surv_map[pppoe] = entry
                                    surveillance_added_entries[pppoe] = dict(entry)
                                    entries_changed = True
                                    added += 1
                                    try:
                                        ensure_surveillance_session(
                                            pppoe,
                                            started_at=now_iso,
                                            source="accounts_ping",
                                            ip=ip,
                                            state="under",
                                        )
                                    except Exception:
                                        pass
                                    _safe_insert_system_audit(
                                        action="surveillance.add_auto",
                                        resource=pppoe,
                                        details=(
                                            f"source=accounts_ping;"
                                            f"down_events={down_events};"
                                            f"window_days={window_days:g};"
                                            f"ip={(ip or 'n/a')[:80]};"
                                            f"reason={reason}"
                                        ),
                                    )

                                state.pop("surveillance_autoadd_seen", None)
                                state["surveillance_autoadd_last_scan_at"] = now_iso

                        stab_cfg = surv_cfg.get("stability", {}) or {}
                        stable_window_minutes = max(int(stab_cfg.get("stable_window_minutes", 10) or 10), 1)
                        uptime_threshold_pct = float(stab_cfg.get("uptime_threshold_pct", 95.0) or 95.0)
                        latency_max_ms = float(stab_cfg.get("latency_max_ms", 15.0) or 15.0)
                        try:
                            loss_max_minutes = float(stab_cfg.get("loss_max_minutes", 10.0) or 10.0)
                        except Exception:
                            loss_max_minutes = 10.0
                        if loss_max_minutes < 0:
                            loss_max_minutes = 0.0
                        try:
                            loss_event_max_count = int(stab_cfg.get("loss_event_max_count", 5) or 5)
                        except Exception:
                            loss_event_max_count = 5
                        if loss_event_max_count < 0:
                            loss_event_max_count = 0
                        optical_rx_min_dbm = float(stab_cfg.get("optical_rx_min_dbm", -24.0) or -24.0)
                        require_optical = bool(stab_cfg.get("require_optical", False))

                        if surv_map:
                            def account_ids_for_pppoe(pppoe):
                                ids = list(account_ids_by_pppoe.get((pppoe or "").strip().lower()) or [])
                                fallback = build_accounts_ping_account_id(pppoe)
                                if not ids and fallback:
                                    ids = [fallback]
                                return ids

                            def aggregate_checker_rows(rows_in):
                                rows_in = [row for row in (rows_in or []) if isinstance(row, dict)]
                                if not rows_in:
                                    return {}
                                out = {
                                    "total": 0,
                                    "failures": 0,
                                    "downtime_seconds": 0,
                                    "loss_events": 0,
                                }
                                avg_sum = 0.0
                                avg_weight = 0.0
                                for row in rows_in:
                                    total = int(row.get("total") or 0)
                                    failures = int(row.get("failures") or 0)
                                    out["total"] += total
                                    out["failures"] += failures
                                    out["downtime_seconds"] += int(row.get("downtime_seconds") or 0)
                                    out["loss_events"] += int(row.get("loss_events") or 0)
                                    avg_ms_avg = row.get("avg_ms_avg")
                                    if avg_ms_avg is None:
                                        continue
                                    try:
                                        avg_sum += float(avg_ms_avg) * max(total, 1)
                                        avg_weight += max(total, 1)
                                    except Exception:
                                        pass
                                out["avg_ms_avg"] = (avg_sum / avg_weight) if avg_weight > 0 else None
                                return out

                            def latest_row(rows_in):
                                rows_in = [row for row in (rows_in or []) if isinstance(row, dict)]
                                if not rows_in:
                                    return {}
                                return max(rows_in, key=lambda row: (row.get("timestamp") or "", row.get("account_id") or ""))

                            surveilled_pppoes = list(surv_map.keys())
                            checker_since_by_account = {}
                            surveilled_ids = []
                            seen_surveilled_ids = set()
                            for pppoe in surveilled_pppoes:
                                entry = surv_map.get(pppoe) or {}
                                added_at = parse_dt(entry.get("added_at")) or now
                                fixed_at = parse_dt(entry.get("last_fixed_at"))
                                anchor_dt = fixed_at if (fixed_at and fixed_at <= now) else added_at
                                anchor_iso = anchor_dt.replace(microsecond=0).isoformat() + "Z"
                                for aid in account_ids_for_pppoe(pppoe):
                                    if not aid:
                                        continue
                                    current_iso = checker_since_by_account.get(aid)
                                    if not current_iso:
                                        checker_since_by_account[aid] = anchor_iso
                                    else:
                                        current_dt = parse_dt(current_iso)
                                        if current_dt is None or anchor_dt > current_dt:
                                            checker_since_by_account[aid] = anchor_iso
                                    if aid not in seen_surveilled_ids:
                                        seen_surveilled_ids.add(aid)
                                        surveilled_ids.append(aid)

                            checker_stats_map = get_accounts_ping_checker_stats_map(
                                checker_since_by_account,
                                now.replace(microsecond=0).isoformat() + "Z",
                            )
                            latest_map = get_latest_accounts_ping_map(surveilled_ids)
                            optical_map = get_latest_optical_by_pppoe(surveilled_pppoes)

                            for pppoe, entry in list(surv_map.items()):
                                    status = (entry.get("status") or "under").strip().lower()
                                    account_ids = account_ids_for_pppoe(pppoe)
                                    stats = aggregate_checker_rows([checker_stats_map.get(aid) for aid in account_ids])
                                    latest = latest_row([latest_map.get(aid) for aid in account_ids])

                                    total = int(stats.get("total") or 0)
                                    failures = int(stats.get("failures") or 0)
                                    uptime_pct = (100.0 - (failures / total) * 100.0) if total else 0.0
                                    avg_ms_avg = stats.get("avg_ms_avg")
                                    if avg_ms_avg is None:
                                        avg_ms_avg = latest.get("avg_ms")
                                    downtime_seconds = int(stats.get("downtime_seconds") or 0)
                                    loss_events = int(stats.get("loss_events") or 0)

                                    stable = bool(
                                        total > 0
                                        and uptime_pct >= uptime_threshold_pct
                                        and avg_ms_avg is not None
                                        and float(avg_ms_avg) <= latency_max_ms
                                        and downtime_seconds <= int(round(loss_max_minutes * 60.0))
                                        and loss_events <= loss_event_max_count
                                    )
                                    if stable and require_optical:
                                        opt = optical_map.get(pppoe) or {}
                                        rx = opt.get("rx")
                                        stable = bool(rx is not None and float(rx) >= optical_rx_min_dbm)

                                    if status == "under":
                                        fixed_at = parse_dt(entry.get("last_fixed_at"))
                                        if fixed_at:
                                            continue
                                    elif status == "level2":
                                        continue

                        if surv_changed or entries_changed:
                            _merge_surveillance_job_updates(
                                ip_updates=surveillance_ip_updates,
                                added_entries=surveillance_added_entries,
                            )

                        state["surveillance_last_eval_at"] = now_iso
                        save_state("accounts_ping_state", state)
                    surveillance_cpu_seconds += max(time_module.thread_time() - surveillance_cpu_start, 0.0)

                _safe_update_job_status("accounts_ping", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                _safe_update_job_status("accounts_ping", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                _safe_update_job_status("accounts_ping", last_error=str(exc), last_error_at=utc_now_iso())
            finally:
                total_cpu = max(time_module.thread_time() - loop_cpu_start, 0.0)
                accounts_cpu = max(total_cpu - surveillance_cpu_seconds, 0.0)
                add_feature_cpu("Accounts Ping", accounts_cpu)
                if surveillance_cpu_seconds > 0:
                    add_feature_cpu("Under Surveillance", surveillance_cpu_seconds)

            time_module.sleep(1)

    def _accounts_missing_loop(self):
        while not self.stop_event.is_set():
            cfg = normalize_accounts_missing_settings(get_settings("accounts_missing", ACCOUNTS_MISSING_DEFAULTS))
            auto_delete_cfg = cfg.get("auto_delete") if isinstance(cfg.get("auto_delete"), dict) else {}
            if not cfg.get("enabled") and not bool(auto_delete_cfg.get("enabled")):
                time_module.sleep(10)
                continue

            loop_cpu_start = time_module.thread_time()
            try:
                state = get_state("accounts_missing_state", {})
                try:
                    refresh_minutes = max(int((cfg.get("source") or {}).get("refresh_minutes", 15) or 15), 1)
                except Exception:
                    refresh_minutes = 15
                now = datetime.utcnow()
                last_check_at = str((state or {}).get("last_check_at") or "").strip()
                last_check_dt = datetime.fromisoformat(last_check_at.replace("Z", "")) if last_check_at else None
                due = not last_check_dt or (last_check_dt + timedelta(minutes=refresh_minutes) <= now)
                if not due:
                    time_module.sleep(5)
                    continue

                _safe_update_job_status("accounts_missing", last_run_at=utc_now_iso())
                wan_settings = get_settings("wan_ping", WAN_PING_DEFAULTS)
                next_state = reconcile_accounts_missing_state(
                    cfg,
                    previous_state=state,
                    wan_settings=wan_settings,
                    now=now,
                )
                deleted_pppoes = []
                if bool(next_state.get("validation_active")):
                    next_state, deleted_pppoes = auto_delete_accounts_missing_entries(next_state, cfg, now=now)
                    if deleted_pppoes:
                        next_state["last_auto_delete_at"] = utc_now_iso()
                        for pppoe in deleted_pppoes:
                            _safe_insert_system_audit(
                                "accounts_missing.auto_deleted",
                                resource=pppoe,
                                details=f"Deleted after missing threshold of {int(auto_delete_cfg.get('days', 30) or 30)} day(s).",
                            )
                save_state("accounts_missing_state", next_state)
                paused_reason = str(next_state.get("validation_paused_reason") or "").strip()
                _safe_update_job_status(
                    "accounts_missing",
                    last_success_at=utc_now_iso(),
                    last_error=paused_reason,
                    last_error_at=utc_now_iso() if paused_reason else "",
                )
            except Exception as exc:
                _safe_update_job_status("accounts_missing", last_error=str(exc), last_error_at=utc_now_iso())
            finally:
                add_feature_cpu("Missing Secrets", max(time_module.thread_time() - loop_cpu_start, 0.0))

            time_module.sleep(5)

    def _telegram_loop(self):
        executor = ThreadPoolExecutor(max_workers=2)
        while not self.stop_event.is_set():
            cfg = get_settings("isp_ping", {})
            telegram = cfg.get("telegram", {})
            token = telegram.get("command_bot_token") or telegram.get("bot_token", "")
            command_chat_id = (telegram.get("command_chat_id") or "").strip()
            allowed_user_ids = telegram.get("allowed_user_ids", [])
            feedback_seconds = int(telegram.get("command_feedback_seconds", 10) or 0)

            if not token:
                time_module.sleep(5)
                continue

            loop_cpu_start = time_module.thread_time()
            try:
                state = get_state("telegram_state", {"last_update_id": 0})
                if state.get("token") != token:
                    state["last_update_id"] = 0
                state["token"] = token
                last_seen = int(state.get("last_update_id") or 0)
                offset = last_seen + 1
                updates = get_updates(token, offset=offset, timeout=15)
                state["last_poll_at"] = utc_now_iso()
                for update in updates:
                    update_id = update.get("update_id")
                    if update_id is None:
                        continue
                    update_id = int(update_id)
                    if update_id <= last_seen:
                        continue
                    state["last_update_id"] = max(int(state.get("last_update_id") or 0), update_id)
                    message = update.get("message") or update.get("edited_message")
                    if not message or "text" not in message:
                        continue
                    sender = message.get("from", {})
                    if sender.get("is_bot"):
                        continue
                    chat = message.get("chat", {})
                    chat_id = chat.get("id")
                    if command_chat_id and str(chat_id) != str(command_chat_id):
                        continue
                    sender_id = sender.get("id")
                    if allowed_user_ids and sender_id not in allowed_user_ids:
                        continue
                    text = message.get("text", "")
                    state["last_command"] = text
                    state["last_command_from"] = sender_id
                    future = executor.submit(handle_telegram_command, cfg, text)
                    last_feedback = time_module.time()
                    next_feedback = feedback_seconds
                    sent_feedback = False
                    while True:
                        try:
                            reply = future.result(timeout=1)
                            break
                        except FutureTimeout:
                            if next_feedback > 0 and time_module.time() - last_feedback >= next_feedback:
                                send_telegram(token, chat_id, "Working on it, please wait...")
                                last_feedback = time_module.time()
                                next_feedback = min(next_feedback * 2, 3600)
                                sent_feedback = True
                            continue
                    if reply:
                        send_telegram(token, chat_id, reply)
                        state["last_reply"] = reply[:500]
                        state["last_error"] = ""
                    elif sent_feedback:
                        state["last_reply"] = "Working on it, please wait..."
                save_state("telegram_state", state)
            except TelegramError as exc:
                state = get_state("telegram_state", {"last_update_id": 0})
                state["last_error"] = str(exc)
                state["last_poll_at"] = utc_now_iso()
                save_state("telegram_state", state)
            except Exception as exc:
                state = get_state("telegram_state", {"last_update_id": 0})
                state["last_error"] = f"{type(exc).__name__}: {exc}"
                state["last_poll_at"] = utc_now_iso()
                save_state("telegram_state", state)
            finally:
                add_feature_cpu("Telegram", max(time_module.thread_time() - loop_cpu_start, 0.0))

            time_module.sleep(2)

    def _isp_status_loop(self):
        while not self.stop_event.is_set():
            cfg = _normalize_isp_status_job_settings(get_settings("isp_status", ISP_STATUS_DEFAULTS))
            if not cfg.get("enabled"):
                time_module.sleep(10)
                continue
            loop_cpu_start = time_module.thread_time()
            try:
                now_iso = utc_now_iso()
                _safe_update_job_status("isp_status", last_run_at=now_iso)
                wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
                pulse_cfg = get_settings("isp_ping", {})
                cores = ((pulse_cfg.get("pulsewatch") or {}).get("mikrotik") or {}).get("cores") or []
                core_map = {
                    (core.get("id") or "").strip(): core
                    for core in cores
                    if isinstance(core, dict) and (core.get("id") or "").strip()
                }
                state = get_state("isp_status_state", {})
                if not isinstance(state, dict):
                    state = {}
                latest = state.setdefault("latest", {})
                windows = state.setdefault("capacity_windows", {})
                capacity_alerts = state.setdefault("capacity_alerts", {})
                if not isinstance(latest, dict):
                    latest = {}
                    state["latest"] = latest
                if not isinstance(windows, dict):
                    windows = {}
                    state["capacity_windows"] = windows
                if not isinstance(capacity_alerts, dict):
                    capacity_alerts = {}
                    state["capacity_alerts"] = capacity_alerts

                groups = {}
                for wan in wan_cfg.get("wans") or []:
                    if not isinstance(wan, dict) or not bool(wan.get("enabled", True)):
                        continue
                    wan_id = (wan.get("id") or f"{wan.get('core_id')}:{wan.get('list_name')}").strip()
                    if not wan_id:
                        continue
                    core_id = (wan.get("core_id") or "").strip()
                    label = (wan.get("identifier") or wan.get("list_name") or wan_id).strip()
                    interface_name = (wan.get("traffic_interface") or "").strip()
                    if not interface_name:
                        latest[wan_id] = {
                            "wan_id": wan_id,
                            "core_id": core_id,
                            "label": label,
                            "interface_name": "",
                            "status": "not_configured",
                            "capacity_status": "not_configured",
                            "capacity_reason": "Traffic Interface is not set in System Settings -> Routers -> ISP Port Tagging.",
                            "last_sample_at": now_iso,
                        }
                        continue
                    core = core_map.get(core_id)
                    if not isinstance(core, dict) or not (core.get("host") or "").strip():
                        latest[wan_id] = {
                            "wan_id": wan_id,
                            "core_id": core_id,
                            "label": label,
                            "interface_name": interface_name,
                            "status": "error",
                            "capacity_status": "error",
                            "capacity_reason": "Core MikroTik is not configured.",
                            "last_sample_at": now_iso,
                        }
                        continue
                    group_key = f"{core.get('host')}|{core.get('port', 8728)}|{core.get('username', '')}"
                    groups.setdefault(group_key, {"core": core, "items": []})["items"].append((wan_id, wan, label, interface_name))

                cutoff_minutes = int(cfg.get("window_minutes") or 10)
                if cfg.get("average_detection_enabled", True):
                    cutoff_minutes = max(cutoff_minutes, int(cfg.get("average_window_hours") or 4) * 60)
                cutoff_dt = datetime.utcnow() - timedelta(minutes=max(cutoff_minutes, 1))
                max_window_samples = max(
                    int((max(cutoff_minutes, 1) * 60) / max(int(cfg.get("poll_interval_seconds") or 30), 1)) + 20,
                    500,
                )
                for group in groups.values():
                    core = group.get("core") or {}
                    client = RouterOSClient(
                        core.get("host", ""),
                        int(core.get("port", 8728)),
                        core.get("username", ""),
                        core.get("password", ""),
                    )
                    try:
                        client.connect()
                    except Exception as exc:
                        error_text = str(exc)
                        for wan_id, wan, label, interface_name in group.get("items", []):
                            core_id = (wan.get("core_id") or "").strip()
                            latest[wan_id] = {
                                "wan_id": wan_id,
                                "core_id": core_id,
                                "label": label,
                                "interface_name": interface_name,
                                "status": "error",
                                "capacity_status": "error",
                                "capacity_reason": error_text,
                                "last_sample_at": now_iso,
                                "last_error": error_text,
                            }
                            insert_isp_status_sample(
                                wan_id,
                                core_id=core_id,
                                label=label,
                                interface_name=interface_name,
                                rx_bps=None,
                                tx_bps=None,
                                timestamp=now_iso,
                                capacity_status="error",
                                capacity_reason=error_text,
                                retention_days=cfg.get("history_retention_days", 400),
                            )
                        client.close()
                        continue
                    try:
                        for wan_id, wan, label, interface_name in group.get("items", []):
                            core_id = (wan.get("core_id") or "").strip()
                            try:
                                traffic = client.monitor_interface_traffic(interface_name)
                                rx_bps = _parse_routeros_bps(traffic.get("rx-bits-per-second"))
                                tx_bps = _parse_routeros_bps(traffic.get("tx-bits-per-second"))
                                peak_mbps = max((rx_bps or 0.0), (tx_bps or 0.0)) / 1_000_000.0
                                window = [
                                    item
                                    for item in (windows.get(wan_id) or [])
                                    if isinstance(item, dict)
                                    and (_parse_iso_utc(item.get("ts")) or datetime.min) >= cutoff_dt
                                ]
                                window.append({"ts": now_iso, "peak_mbps": peak_mbps})
                                windows[wan_id] = window[-max_window_samples:]
                                capacity_status, capacity_reason = _classify_isp_capacity(windows[wan_id], cfg)
                                insert_isp_status_sample(
                                    wan_id,
                                    core_id=core_id,
                                    label=label,
                                    interface_name=interface_name,
                                    rx_bps=rx_bps,
                                    tx_bps=tx_bps,
                                    timestamp=now_iso,
                                    capacity_status=capacity_status,
                                    capacity_reason=capacity_reason,
                                    retention_days=cfg.get("history_retention_days", 400),
                                )
                                latest_row = {
                                    "wan_id": wan_id,
                                    "core_id": core_id,
                                    "label": label,
                                    "interface_name": interface_name,
                                    "status": "ok",
                                    "rx_bps": rx_bps,
                                    "tx_bps": tx_bps,
                                    "total_bps": (rx_bps or 0.0) + (tx_bps or 0.0),
                                    "peak_mbps": peak_mbps,
                                    "capacity_status": capacity_status,
                                    "capacity_reason": capacity_reason,
                                    "last_sample_at": now_iso,
                                    "last_error": "",
                                }
                                latest[wan_id] = latest_row
                                alert_row = capacity_alerts.setdefault(wan_id, {})
                                previous_capacity_status = (alert_row.get("last_status") or "").strip().lower()
                                if capacity_status == "100m" and previous_capacity_status != "100m":
                                    alert_sent = False
                                    alert_row["recovery_started_at"] = ""
                                    alert_row["last_recovered_sent_at"] = ""
                                    try:
                                        if _send_isp_status_100m_alert(cfg, wan_cfg, wan, wan_id, latest_row):
                                            alert_row["last_100m_sent_at"] = now_iso
                                            alert_row["last_alert_error"] = ""
                                            alert_sent = True
                                    except TelegramError:
                                        alert_row["last_alert_error"] = "Telegram send failed."
                                    except Exception as exc:
                                        alert_row["last_alert_error"] = str(exc)
                                    if alert_sent:
                                        alert_row["last_status"] = capacity_status
                                elif capacity_status == "100m":
                                    alert_row["last_status"] = capacity_status
                                    alert_row["recovery_started_at"] = ""
                                else:
                                    if previous_capacity_status == "100m" and capacity_status == "1g":
                                        recovery_started_at = (alert_row.get("recovery_started_at") or "").strip()
                                        if not recovery_started_at:
                                            recovery_started_at = now_iso
                                            alert_row["recovery_started_at"] = recovery_started_at
                                        started_dt = _parse_iso_utc(recovery_started_at)
                                        recovery_minutes = max(int((cfg.get("telegram") or {}).get("recovery_confirm_minutes") or 2), 1)
                                        elapsed_seconds = (
                                            max((datetime.utcnow() - started_dt).total_seconds(), 0.0)
                                            if started_dt
                                            else 0.0
                                        )
                                        if elapsed_seconds >= recovery_minutes * 60:
                                            recovered_sent = False
                                            try:
                                                if _send_isp_status_recovered_alert(cfg, wan_cfg, wan, wan_id, latest_row, recovery_started_at):
                                                    alert_row["last_recovered_sent_at"] = now_iso
                                                    alert_row["last_alert_error"] = ""
                                                    recovered_sent = True
                                            except TelegramError:
                                                alert_row["last_alert_error"] = "Telegram recovery send failed."
                                            except Exception as exc:
                                                alert_row["last_alert_error"] = str(exc)
                                            if recovered_sent:
                                                alert_row["last_status"] = capacity_status
                                                alert_row["recovery_started_at"] = ""
                                    elif previous_capacity_status == "100m":
                                        alert_row["recovery_started_at"] = ""
                                    else:
                                        alert_row["last_status"] = capacity_status
                                alert_row["last_seen_at"] = now_iso
                            except Exception as exc:
                                latest[wan_id] = {
                                    "wan_id": wan_id,
                                    "core_id": core_id,
                                    "label": label,
                                    "interface_name": interface_name,
                                    "status": "error",
                                    "capacity_status": "error",
                                    "capacity_reason": str(exc),
                                    "last_sample_at": now_iso,
                                    "last_error": str(exc),
                                }
                                insert_isp_status_sample(
                                    wan_id,
                                    core_id=core_id,
                                    label=label,
                                    interface_name=interface_name,
                                    rx_bps=None,
                                    tx_bps=None,
                                    timestamp=now_iso,
                                    capacity_status="error",
                                    capacity_reason=str(exc),
                                    retention_days=cfg.get("history_retention_days", 400),
                                )
                    finally:
                        client.close()

                state["last_check_at"] = now_iso
                telegram_cfg = cfg.get("telegram") if isinstance(cfg.get("telegram"), dict) else {}
                if telegram_cfg.get("daily_enabled"):
                    summary_state = {"last_run_date": state.get("telegram_daily_last_run_date")}
                    general_cfg = {
                        "schedule_time_ph": telegram_cfg.get("daily_time", "07:00"),
                        "timezone": "Asia/Manila",
                    }
                    if should_run_daily(general_cfg, summary_state):
                        try:
                            _send_isp_status_daily_report(cfg, wan_cfg, latest)
                        except TelegramError:
                            pass
                        except Exception:
                            pass
                        state["telegram_daily_last_run_date"] = current_date(general_cfg).isoformat()
                save_state("isp_status_state", state)
                _safe_update_job_status("isp_status", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except Exception as exc:
                _safe_update_job_status("isp_status", last_error=str(exc), last_error_at=utc_now_iso())
            finally:
                add_feature_cpu("ISP Port Status", max(time_module.thread_time() - loop_cpu_start, 0.0))
            time_module.sleep(max(int(cfg.get("poll_interval_seconds") or 30), 5))

    def _mikrotik_router_health_loop(self):
        def _router_key(kind, router_id):
            return f"{kind}:{str(router_id or '').strip()}"

        def _configured_routers():
            pulse_cfg = get_settings("isp_ping", {})
            wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
            rows = []
            seen = set()
            for core in ((((pulse_cfg.get("pulsewatch") or {}).get("mikrotik") or {}).get("cores")) or []):
                if not isinstance(core, dict):
                    continue
                core_id = (core.get("id") or "").strip()
                if not core_id:
                    continue
                key = _router_key("core", core_id)
                seen.add(key)
                rows.append(
                    {
                        "key": key,
                        "kind": "core",
                        "id": core_id,
                        "label": (core.get("label") or core_id).strip(),
                        "host": (core.get("host") or "").strip(),
                        "port": int(core.get("port", 8728) or 8728),
                        "username": core.get("username", ""),
                        "password": core.get("password", ""),
                        "use_tls": False,
                    }
                )
            for router in (wan_cfg.get("pppoe_routers") or []):
                if not isinstance(router, dict):
                    continue
                router_id = (router.get("id") or "").strip()
                if not router_id:
                    continue
                key = _router_key("pppoe", router_id)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "key": key,
                        "kind": "pppoe",
                        "id": router_id,
                        "label": (router.get("name") or router_id).strip(),
                        "host": (router.get("host") or "").strip(),
                        "port": int(router.get("port", 8728) or 8728),
                        "username": router.get("username", ""),
                        "password": router.get("password", ""),
                        "use_tls": bool(router.get("use_tls")),
                    }
                )
            return rows

        def _check_router(row):
            now_iso = utc_now_iso()
            base = {
                "key": row.get("key") or _router_key(row.get("kind"), row.get("id")),
                "kind": row.get("kind") or "",
                "id": row.get("id") or "",
                "label": row.get("label") or row.get("id") or "Router",
                "host": row.get("host") or "",
                "port": int(row.get("port", 8728) or 8728),
                "status": "down",
                "connected": False,
                "error": "",
                "last_check_at": now_iso,
                "response_ms": None,
            }
            if not base["host"]:
                base["error"] = "Router host is not configured."
                return base
            if row.get("use_tls"):
                base["error"] = "TLS/API-SSL is not supported by the current RouterOS API client. Disable TLS or use port 8728."
                return base
            client = RouterOSClient(
                base["host"],
                base["port"],
                row.get("username", ""),
                row.get("password", ""),
                timeout=3,
            )
            started = time_module.monotonic()
            try:
                client.connect()
                base["status"] = "up"
                base["connected"] = True
                base["response_ms"] = round((time_module.monotonic() - started) * 1000.0, 1)
            except Exception as exc:
                base["error"] = str(exc)
            finally:
                client.close()
            return base

        while not self.stop_event.is_set():
            loop_cpu_start = time_module.thread_time()
            try:
                now_iso = utc_now_iso()
                _safe_update_job_status("mikrotik_router_health", last_run_at=now_iso)
                configured = _configured_routers()
                rows = []
                if configured:
                    workers = min(max(len(configured), 1), 16)
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        futures = [executor.submit(_check_router, row) for row in configured]
                        for future in as_completed(futures):
                            try:
                                rows.append(future.result())
                            except Exception as exc:
                                rows.append(
                                    {
                                        "key": "",
                                        "kind": "",
                                        "id": "",
                                        "label": "Router",
                                        "host": "",
                                        "port": 8728,
                                        "status": "down",
                                        "connected": False,
                                        "error": str(exc),
                                        "last_check_at": now_iso,
                                        "response_ms": None,
                                    }
                                )
                rows = sorted(rows, key=lambda item: (item.get("kind") or "", item.get("label") or ""))
                up = sum(1 for item in rows if (item.get("status") or "").lower() == "up")
                down = sum(1 for item in rows if (item.get("status") or "").lower() == "down")
                state = {
                    "last_check_at": now_iso,
                    "total": len(rows),
                    "up": up,
                    "down": down,
                    "unknown": 0,
                    "rows": rows,
                }
                save_state("mikrotik_router_health_state", state)
                _safe_update_job_status("mikrotik_router_health", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except Exception as exc:
                _safe_update_job_status("mikrotik_router_health", last_error=str(exc), last_error_at=utc_now_iso())
            finally:
                add_feature_cpu("MikroTik Routers", max(time_module.thread_time() - loop_cpu_start, 0.0))
            time_module.sleep(30)

    def _mikrotik_logs_loop(self):
        sock = None
        bound_addr = None
        pending = []
        last_flush = time_module.monotonic()
        last_settings_check = 0.0
        last_prune = 0.0
        last_setup_check = 0.0
        cfg = _normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
        router_map = _mikrotik_logs_router_map()

        def _close_socket():
            nonlocal sock, bound_addr
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            sock = None
            bound_addr = None

        def _flush():
            nonlocal pending, last_flush
            if not pending:
                last_flush = time_module.monotonic()
                return
            count = len(pending)
            insert_mikrotik_logs(pending)
            state = get_state("mikrotik_logs_state", {})
            if not isinstance(state, dict):
                state = {}
            state["last_received_at"] = pending[-1].get("received_at") or utc_now_iso()
            state["last_source_ip"] = pending[-1].get("source_ip") or ""
            state["inserted_total"] = int(state.get("inserted_total") or 0) + count
            state["last_batch_count"] = count
            save_state("mikrotik_logs_state", state)
            pending = []
            last_flush = time_module.monotonic()

        while not self.stop_event.is_set():
            loop_cpu_start = time_module.thread_time()
            try:
                now_mono = time_module.monotonic()
                if now_mono - last_settings_check >= 5:
                    cfg = _normalize_mikrotik_logs_settings(get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS))
                    router_map = _mikrotik_logs_router_map()
                    last_settings_check = now_mono

                if not cfg.get("enabled"):
                    _flush()
                    _close_socket()
                    _safe_update_job_status("mikrotik_logs", last_run_at=utc_now_iso(), last_error="", last_error_at="")
                    time_module.sleep(2)
                    continue

                auto_setup = cfg.get("auto_setup") if isinstance(cfg.get("auto_setup"), dict) else {}
                setup_interval = max(int(auto_setup.get("check_interval_hours") or 24), 1) * 3600
                if bool(auto_setup.get("enabled")) and (time_module.monotonic() - last_setup_check >= setup_interval):
                    try:
                        auto_configure_mikrotik_logs(cfg)
                    finally:
                        last_setup_check = time_module.monotonic()

                receiver = cfg.get("receiver") or {}
                desired_addr = ((receiver.get("host") or "0.0.0.0").strip(), int(receiver.get("port") or 5514))
                if sock is None or bound_addr != desired_addr:
                    _flush()
                    _close_socket()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(desired_addr)
                    sock.setblocking(False)
                    bound_addr = desired_addr
                    state = get_state("mikrotik_logs_state", {})
                    if not isinstance(state, dict):
                        state = {}
                    state["listen_host"] = desired_addr[0]
                    state["listen_port"] = desired_addr[1]
                    state["started_at"] = utc_now_iso()
                    state["last_error"] = ""
                    save_state("mikrotik_logs_state", state)

                _safe_update_job_status("mikrotik_logs", last_run_at=utc_now_iso())
                readable, _, _ = select.select([sock], [], [], 1.0)
                if readable:
                    data, addr = sock.recvfrom(65535)
                    source_ip = addr[0] if addr else ""
                    source_port = int(addr[1]) if addr and len(addr) > 1 else 0
                    raw = data.decode("utf-8", errors="replace")
                    router_info = router_map.get(source_ip) or {}
                    filters = cfg.get("filters") or {}
                    if router_info or bool(filters.get("allow_unknown_sources", True)):
                        row = _parse_mikrotik_syslog(raw, source_ip, source_port, router_info)
                        min_sev = (filters.get("min_severity") or "debug").strip().lower()
                        row_sev = (row.get("severity") or "info").strip().lower()
                        drop_topics = filters.get("drop_topics") if isinstance(filters.get("drop_topics"), list) else []
                        router_blob = (row.get("router_id") or row.get("source_ip") or "").lower()
                        topic_blob = (row.get("topics") or "").lower()
                        message_blob = (row.get("message") or "").lower()
                        dropped_exact = False
                        for raw_rule in drop_topics:
                            rule = str(raw_rule or "").strip().lower()
                            if rule.count("\t") < 2:
                                continue
                            rule_router, rule_topic, rule_message = rule.split("\t", 2)
                            if router_blob == rule_router.strip() and topic_blob == rule_topic.strip() and message_blob == rule_message.strip():
                                dropped_exact = True
                                break
                        if (
                            _SYSLOG_SEVERITY_RANK.get(row_sev, 1) >= _SYSLOG_SEVERITY_RANK.get(min_sev, 0)
                            and not dropped_exact
                        ):
                            pending.append(row)

                storage = cfg.get("storage") or {}
                batch_size = int(storage.get("batch_size") or 100)
                flush_interval = int(storage.get("flush_interval_seconds") or 2)
                if pending and (len(pending) >= batch_size or time_module.monotonic() - last_flush >= flush_interval):
                    _flush()
                    _safe_update_job_status("mikrotik_logs", last_success_at=utc_now_iso(), last_error="", last_error_at="")

                if time_module.monotonic() - last_prune >= 3600:
                    retention_days = max(int(storage.get("retention_days") or 30), 1)
                    cutoff = (datetime.utcnow() - timedelta(days=retention_days)).replace(microsecond=0).isoformat() + "Z"
                    delete_mikrotik_logs_older_than(cutoff)
                    last_prune = time_module.monotonic()
            except Exception as exc:
                _close_socket()
                state = get_state("mikrotik_logs_state", {})
                if not isinstance(state, dict):
                    state = {}
                state["last_error"] = str(exc)
                state["last_error_at"] = utc_now_iso()
                save_state("mikrotik_logs_state", state)
                _safe_update_job_status("mikrotik_logs", last_error=str(exc), last_error_at=utc_now_iso())
                time_module.sleep(3)
            finally:
                add_feature_cpu("MikroTik Logs", max(time_module.thread_time() - loop_cpu_start, 0.0))

        try:
            _flush()
        except Exception:
            pass
        _close_socket()

    def _wan_ping_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
            if not cfg.get("wans"):
                time_module.sleep(10)
                continue
            router_catalog = get_settings("isp_ping", {})
            loop_cpu_start = time_module.thread_time()
            try:
                _safe_update_job_status("wan_ping", last_run_at=utc_now_iso())
                state = get_state("wan_ping_state", {})
                reset_at = state.get("reset_at")
                state = wan_ping_notifier.run_check(cfg, router_catalog, state)
                latest = get_state("wan_ping_state", {})
                if latest.get("reset_at") and latest.get("reset_at") != reset_at:
                    state = wan_ping_notifier.run_check(cfg, router_catalog, latest)
                summary_cfg = cfg.get("summary", {})
                if summary_cfg.get("enabled"):
                    summary_state = {"last_run_date": state.get("summary_last_run_date")}
                    general_cfg = {
                        "schedule_time_ph": summary_cfg.get("daily_time", "07:00"),
                        "timezone": summary_cfg.get("timezone", "Asia/Manila"),
                    }
                    if should_run_daily(general_cfg, summary_state):
                        wan_ping_notifier.send_daily_summary(cfg, router_catalog, state)
                        state["summary_last_run_date"] = current_date(general_cfg).isoformat()
                save_state("wan_ping_state", state)
                _safe_update_job_status("wan_ping", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                _safe_update_job_status("wan_ping", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                _safe_update_job_status("wan_ping", last_error=str(exc), last_error_at=utc_now_iso())
            finally:
                add_feature_cpu("WAN Ping", max(time_module.thread_time() - loop_cpu_start, 0.0))
            general = cfg.get("general") if isinstance(cfg.get("general"), dict) else {}
            status_interval = int(general.get("interval_seconds", 30) or 30)
            status_interval = max(status_interval, 1)
            target_interval = int(general.get("target_latency_interval_seconds") or status_interval or 30)
            target_interval = max(target_interval, 1)
            rotation_raw = general.get("target_rotation_enabled", False)
            if isinstance(rotation_raw, str):
                rotation_enabled = rotation_raw.strip().lower() in ("1", "true", "yes", "on")
            else:
                rotation_enabled = bool(rotation_raw)
            targets_per_wan_raw = general.get("targets_per_wan_per_run", 1)
            if targets_per_wan_raw in (None, ""):
                targets_per_wan_raw = 1
            try:
                targets_per_wan = max(int(targets_per_wan_raw), 0)
            except Exception:
                targets_per_wan = 1
            enabled_targets = [
                item
                for item in (general.get("targets") or [])
                if isinstance(item, dict)
                and (item.get("id") or "").strip()
                and (item.get("host") or "").strip()
                and bool(item.get("enabled", True))
            ]
            sleep_s = status_interval
            target_sampling_enabled = bool(enabled_targets) and ((not rotation_enabled) or targets_per_wan > 0)
            if target_sampling_enabled:
                sleep_s = min(status_interval, target_interval)
            time_module.sleep(max(int(sleep_s or 1), 1))

    def _usage_loop(self):
        clients = {}
        client_sigs = {}
        genieacs_parser_version = "3"
        usage_tz = None
        try:
            if ZoneInfo:
                usage_tz = ZoneInfo("Asia/Manila")
        except Exception:
            usage_tz = None

        def _parse_hhmm(value, default=(0, 0)):
            parts = (value or "").strip().split(":")
            if len(parts) != 2:
                return default
            try:
                return int(parts[0]), int(parts[1])
            except Exception:
                return default

        def _in_time_window(now_dt, start_hhmm, end_hhmm, start_default=(0, 0), end_default=(23, 59)):
            sh, sm = _parse_hhmm(start_hhmm, default=start_default)
            eh, em = _parse_hhmm(end_hhmm, default=end_default)
            start_t = time(hour=max(min(sh, 23), 0), minute=max(min(sm, 59), 0))
            end_t = time(hour=max(min(eh, 23), 0), minute=max(min(em, 59), 0))
            current_t = now_dt.time()
            if start_t <= end_t:
                return start_t <= current_t <= end_t
            return current_t >= start_t or current_t <= end_t

        try:
            while not self.stop_event.is_set():
                cfg = get_settings("usage", USAGE_DEFAULTS)
                if not cfg.get("enabled"):
                    time_module.sleep(5)
                    continue

                now = datetime.utcnow().replace(microsecond=0)
                now_iso = now.isoformat() + "Z"
                state = get_state(
                    "usage_state",
                    {
                        "last_check_at": None,
                        "last_prune_at": None,
                        "last_genieacs_refresh_at": None,
                        "last_db_write_at": None,
                        "secrets_refreshed_at": {},
                        "secrets_cache": {},
                        "prev_bytes": {},
                        "pppoe_hosts": {},
                        "peak_issues": {},
                        "peak_eval_at": None,
                        "anytime_issues": {},
                        "anytime_eval_at": None,
                        "ppp_active_stats_supported": {},
                    },
                )

                loop_cpu_start = time_module.thread_time()
                try:
                    retention_days = int((cfg.get("storage") or {}).get("raw_retention_days", 0) or 0)
                    reboot_cfg = normalize_usage_modem_reboot_settings(cfg)
                    reboot_retention_days = max(int(reboot_cfg.get("history_retention_days", 180) or 180), 1)
                    if retention_days > 0 or reboot_retention_days > 0:
                        last_prune = state.get("last_prune_at")
                        last_prune_dt = datetime.fromisoformat(last_prune.replace("Z", "")) if last_prune else None
                        if not last_prune_dt or last_prune_dt + timedelta(hours=24) < now:
                            if retention_days > 0:
                                cutoff = now - timedelta(days=retention_days)
                                delete_pppoe_usage_samples_older_than(cutoff.isoformat() + "Z")
                            reboot_cutoff = now - timedelta(days=reboot_retention_days)
                            delete_usage_modem_reboot_history_older_than(reboot_cutoff.isoformat() + "Z")
                            state["last_prune_at"] = now_iso

                    refresh_minutes = int((cfg.get("source") or {}).get("refresh_minutes", 15) or 15)
                    last_genie = state.get("last_genieacs_refresh_at")
                    last_genie_dt = datetime.fromisoformat(last_genie.replace("Z", "")) if last_genie else None
                    if refresh_minutes < 1:
                        refresh_minutes = 1
                    dev_cfg = cfg.get("device") if isinstance(cfg.get("device"), dict) else {}
                    genie_cfg = cfg.get("genieacs") if isinstance(cfg.get("genieacs"), dict) else {}
                    genie_sig = {
                        "v": genieacs_parser_version,
                        "base_url": (genie_cfg.get("base_url") or "").strip().rstrip("/"),
                        "page_size": int(genie_cfg.get("page_size", 100) or 100),
                        "pppoe_paths": list(dev_cfg.get("pppoe_paths") or []),
                        "host_count_paths": list(dev_cfg.get("host_count_paths") or []),
                        "host_name_paths": list(dev_cfg.get("host_name_paths") or []),
                        "host_ip_paths": list(dev_cfg.get("host_ip_paths") or []),
                        "host_active_paths": list(dev_cfg.get("host_active_paths") or []),
                    }
                    force_refresh = state.get("genieacs_sig") != genie_sig
                    if force_refresh:
                        last_genie_dt = None
                    if not last_genie_dt or last_genie_dt + timedelta(minutes=refresh_minutes) < now:
                        try:
                            state["pppoe_hosts"] = usage_notifier.build_pppoe_host_map(cfg)
                            state["last_genieacs_refresh_at"] = now_iso
                            state["genieacs_error"] = ""
                            state["genieacs_sig"] = genie_sig
                        except Exception as exc:
                            state["genieacs_error"] = str(exc)

                    poll_seconds = int((cfg.get("mikrotik") or {}).get("poll_interval_seconds", 10) or 10)
                    poll_seconds = max(poll_seconds, 3)
                    secrets_refresh_minutes = int((cfg.get("mikrotik") or {}).get("secrets_refresh_minutes", 15) or 15)
                    if secrets_refresh_minutes < 1:
                        secrets_refresh_minutes = 1
                    timeout_seconds = int((cfg.get("mikrotik") or {}).get("timeout_seconds", 5) or 5)

                    # Shared MikroTik routers are now managed in System Settings (wan_ping.pppoe_routers).
                    # Back-compat: migrate legacy routers from Usage settings if System Settings is empty.
                    wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
                    routers = wan_cfg.get("pppoe_routers") if isinstance(wan_cfg.get("pppoe_routers"), list) else []
                    if not routers:
                        legacy = (cfg.get("mikrotik") or {}).get("routers") or []
                        migrated = []
                        for item in legacy:
                            if not isinstance(item, dict):
                                continue
                            rid = (item.get("id") or "").strip()
                            host = (item.get("host") or "").strip()
                            if not rid or not host:
                                continue
                            migrated.append(
                                {
                                    "id": rid,
                                    "name": (item.get("name") or "").strip(),
                                    "host": host,
                                    "port": int(item.get("port", 8728) or 8728),
                                    "username": item.get("username", ""),
                                    "password": item.get("password", ""),
                                    "use_tls": False,
                                }
                            )
                        if migrated:
                            wan_cfg.setdefault("pppoe_routers", [])
                            wan_cfg["pppoe_routers"] = migrated
                            save_settings("wan_ping", wan_cfg)
                            routers = migrated
                    usage_router_enabled = (
                        (cfg.get("mikrotik") or {}).get("router_enabled")
                        if isinstance((cfg.get("mikrotik") or {}).get("router_enabled"), dict)
                        else {}
                    )
                    enabled_router_ids = set()
                    active_rows = []
                    offline_rows = []
                    router_status = []

                    prev_bytes = state.get("prev_bytes") if isinstance(state.get("prev_bytes"), dict) else {}
                    secrets_cache = state.get("secrets_cache") if isinstance(state.get("secrets_cache"), dict) else {}
                    secrets_refreshed_at = (
                        state.get("secrets_refreshed_at") if isinstance(state.get("secrets_refreshed_at"), dict) else {}
                    )
                    stats_cap = (
                        state.get("ppp_active_stats_supported")
                        if isinstance(state.get("ppp_active_stats_supported"), dict)
                        else {}
                    )

                    _safe_update_job_status("usage", last_run_at=utc_now_iso())
                    for router in routers:
                        if not isinstance(router, dict):
                            continue
                        router_id = (router.get("id") or "").strip()
                        router_name = (router.get("name") or router_id or "router").strip()
                        host = (router.get("host") or "").strip()
                        if not router_id or not host:
                            continue
                        if not bool(usage_router_enabled.get(router_id, True)):
                            continue
                        enabled_router_ids.add(router_id)
                        if router.get("use_tls"):
                            router_status.append(
                                {
                                    "router_id": router_id,
                                    "router_name": router_name,
                                    "active_count": 0,
                                    "queue_count": 0,
                                    "queue_match_count": 0,
                                    "queue_bytes_ok": False,
                                    "queue_rate_ok": False,
                                    "iface_count": 0,
                                    "iface_match_count": 0,
                                    "iface_bytes_ok": False,
                                    "offline_count": 0,
                                    "error": "TLS/API-SSL is not supported by the current RouterOS API client. Disable TLS or use port 8728.",
                                    "connected": False,
                                }
                            )
                            continue

                        last_secret = secrets_refreshed_at.get(router_id)
                        last_secret_dt = datetime.fromisoformat(last_secret.replace("Z", "")) if last_secret else None
                        secrets_due = not last_secret_dt or last_secret_dt + timedelta(minutes=secrets_refresh_minutes) < now

                        port = int(router.get("port", 8728) or 8728)
                        username = router.get("username", "")
                        password = router.get("password", "")
                        sig = (host, port, username, password, timeout_seconds)

                        client = clients.get(router_id)
                        if client is None or client_sigs.get(router_id) != sig:
                            try:
                                if client is not None:
                                    client.close()
                            except Exception:
                                pass
                            client = RouterOSClient(host, port, username, password, timeout=timeout_seconds)
                            clients[router_id] = client
                            client_sigs[router_id] = sig

                        router_error = ""
                        router_active = []
                        router_active_counters = []
                        router_queues = []
                        router_ifaces = []
                        connected = False
                        try:
                            # Keep a persistent API connection; reconnect on failure.
                            if client.sock is None:
                                client.connect()
                            connected = True
                            router_active = usage_notifier.fetch_pppoe_active(client)
                            router_queues = usage_notifier.fetch_simple_queues(client)
                            router_ifaces = usage_notifier.fetch_ppp_interfaces(client)
                            if stats_cap.get(router_id) is not False:
                                try:
                                    router_active_counters = usage_notifier.fetch_pppoe_active_counters(client)
                                    if router_active_counters:
                                        stats_cap[router_id] = True
                                except Exception:
                                    stats_cap[router_id] = False
                            if secrets_due:
                                secrets_cache[router_id] = usage_notifier.fetch_pppoe_secrets(client)
                                secrets_refreshed_at[router_id] = now_iso
                        except Exception as exc:
                            router_error = str(exc)
                            try:
                                client.close()
                            except Exception:
                                pass
                            clients[router_id] = RouterOSClient(host, port, username, password, timeout=timeout_seconds)
                            client_sigs[router_id] = sig
                            # One reconnect attempt immediately (covers session expiry / dropped sockets).
                            try:
                                clients[router_id].connect()
                                connected = True
                                router_active = usage_notifier.fetch_pppoe_active(clients[router_id])
                                router_queues = usage_notifier.fetch_simple_queues(clients[router_id])
                                router_ifaces = usage_notifier.fetch_ppp_interfaces(clients[router_id])
                                if stats_cap.get(router_id) is not False:
                                    try:
                                        router_active_counters = usage_notifier.fetch_pppoe_active_counters(clients[router_id])
                                        if router_active_counters:
                                            stats_cap[router_id] = True
                                    except Exception:
                                        stats_cap[router_id] = False
                                if secrets_due:
                                    secrets_cache[router_id] = usage_notifier.fetch_pppoe_secrets(clients[router_id])
                                    secrets_refreshed_at[router_id] = now_iso
                                router_error = ""
                            except Exception as exc2:
                                router_error = str(exc2)
                                try:
                                    clients[router_id].close()
                                except Exception:
                                    pass
                                connected = False

                        computed = []
                        active_set = set()
                        queue_rows = router_queues if isinstance(router_queues, list) else []
                        queue_match_count = 0
                        queue_bytes_ok = 0
                        queue_rate_ok = 0
                        iface_rows = router_ifaces if isinstance(router_ifaces, list) else []
                        iface_match_count = 0
                        iface_bytes_ok = 0
                        active_counter_rows = (
                            router_active_counters if isinstance(router_active_counters, list) else []
                        )
                        active_counter_by_id = {r.get(".id"): r for r in active_counter_rows if isinstance(r, dict) and r.get(".id")}
                        active_counter_by_name = {r.get("name"): r for r in active_counter_rows if isinstance(r, dict) and r.get("name")}

                        def match_queue_for_row(pppoe, address):
                            pppoe = (pppoe or "").strip()
                            address = (address or "").strip()
                            if not queue_rows or (not pppoe and not address):
                                return None

                            def target_matches(q):
                                tgt = (q.get("target") or "").strip()
                                if not tgt or not address:
                                    return False
                                targets = [t.strip() for t in tgt.split(",") if t.strip()]
                                for t in targets:
                                    if t == address or t.startswith(address + "/"):
                                        return True
                                return False

                            candidates = []
                            for q in queue_rows:
                                name = (q.get("name") or "").strip()
                                if pppoe and (pppoe == name or pppoe in name):
                                    candidates.append(q)
                                    continue
                                low = pppoe.lower()
                                if low and low in name.lower():
                                    candidates.append(q)
                                    continue
                                if target_matches(q):
                                    candidates.append(q)

                            if not candidates:
                                return None

                            def score(q):
                                name = (q.get("name") or "").strip()
                                # Prefer exact name match, then target match, then substring match.
                                exact = 0 if pppoe and name == pppoe else 1
                                tgt = 0 if target_matches(q) else 1
                                sub = 0 if pppoe and (pppoe in name or pppoe.lower() in name.lower()) else 1
                                return (exact, tgt, sub, len(name), name)

                            return min(candidates, key=score)

                        def match_iface_for_row(pppoe, iface_hint):
                            pppoe = (pppoe or "").strip()
                            iface_hint = (iface_hint or "").strip()
                            if not iface_rows:
                                return None
                            if iface_hint:
                                for i in iface_rows:
                                    if (i.get("name") or "").strip().lower() == iface_hint.lower():
                                        return i
                            if not pppoe:
                                return None
                            # Prefer exact interface name match (common for PPPoE client interfaces named after the account).
                            low = pppoe.lower()
                            for i in iface_rows:
                                name = (i.get("name") or "").strip()
                                if name and name.strip().lower() == low:
                                    return i
                            candidates = [i for i in iface_rows if pppoe in ((i.get("name") or "").strip())]
                            if not candidates:
                                candidates = [
                                    i for i in iface_rows if low and low in ((i.get("name") or "").strip().lower())
                                ]
                            if not candidates:
                                return None
                            return min(
                                candidates,
                                key=lambda i: (len((i.get("name") or "").strip()), (i.get("name") or "").strip()),
                            )

                        for row in router_active:
                            pppoe = (row.get("name") or "").strip()
                            if not pppoe:
                                continue
                            counter_row = active_counter_by_id.get(row.get(".id")) or active_counter_by_name.get(pppoe)
                            addr = (row.get("address") or "").strip()
                            iface_hint = (row.get("interface") or "").strip()
                            active_set.add(pppoe)
                            key = f"{router_id}|{pppoe}"
                            prev = prev_bytes.get(key) or {}
                            prev_ts = prev.get("ts")
                            prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "")) if prev_ts else None
                            prev_in = prev.get("bytes_in")
                            prev_out = prev.get("bytes_out")
                            # Prefer per-subscriber traffic via simple queues when available; otherwise
                            # fall back to dynamic PPP interface counters (rx-byte/tx-byte).
                            q = match_queue_for_row(pppoe, addr)
                            if q:
                                queue_match_count += 1
                            q_bytes = usage_notifier.parse_duplex_int((q or {}).get("bytes")) if q else None
                            q_rate = usage_notifier.parse_duplex_float((q or {}).get("rate")) if q else None
                            if q_bytes:
                                queue_bytes_ok += 1
                            if q_rate:
                                queue_rate_ok += 1

                            # Convention (UI): DL = router->client, UL = client->router.
                            # MikroTik queue "bytes" and "rate" are commonly formatted as "download/upload".
                            now_out = q_bytes[0] if q_bytes else None  # DL total bytes
                            now_in = q_bytes[1] if q_bytes else None  # UL total bytes

                            # Dynamic PPP interface counters: rx-byte (UL), tx-byte (DL)
                            iface = None
                            if now_in is None or now_out is None:
                                iface = match_iface_for_row(pppoe, iface_hint)
                                if iface:
                                    iface_match_count += 1
                                    rx_b = usage_notifier._parse_int((iface or {}).get("rx-byte"))
                                    tx_b = usage_notifier._parse_int((iface or {}).get("tx-byte"))
                                    if rx_b is not None and tx_b is not None:
                                        iface_bytes_ok += 1
                                    if now_in is None:
                                        now_in = rx_b
                                    if now_out is None:
                                        now_out = tx_b

                            # Fallback: PPP active counters (when supported).
                            if (now_in is None or now_out is None) and counter_row:
                                c_in = usage_notifier._parse_int(counter_row.get("bytes-in"))
                                c_out = usage_notifier._parse_int(counter_row.get("bytes-out"))
                                if now_in is None:
                                    now_in = c_in
                                if now_out is None:
                                    now_out = c_out

                            rate_dl_bps = q_rate[0] if q_rate else None
                            rate_ul_bps = q_rate[1] if q_rate else None
                            computed_rx_bps = None
                            computed_tx_bps = None
                            # Prefer queue-reported rate; fall back to delta computation if missing.
                            if rate_ul_bps is not None:
                                computed_rx_bps = float(rate_ul_bps)
                            if rate_dl_bps is not None:
                                computed_tx_bps = float(rate_dl_bps)
                            if (computed_rx_bps is None or computed_tx_bps is None) and counter_row:
                                # PPP active rates are rx/tx relative to the router.
                                c_rx = usage_notifier._parse_float(counter_row.get("rx-rate"))
                                c_tx = usage_notifier._parse_float(counter_row.get("tx-rate"))
                                if c_rx is None or c_tx is None:
                                    duplex = (counter_row.get("rate") or "").strip()
                                    parsed = usage_notifier.parse_duplex_float(duplex)
                                    if parsed:
                                        c_rx = c_rx if c_rx is not None else parsed[0]
                                        c_tx = c_tx if c_tx is not None else parsed[1]
                                if computed_rx_bps is None and c_rx is not None:
                                    computed_rx_bps = float(c_rx)
                                if computed_tx_bps is None and c_tx is not None:
                                    computed_tx_bps = float(c_tx)

                            if (computed_rx_bps is None or computed_tx_bps is None) and prev_dt and now_in is not None and now_out is not None and prev_in is not None and prev_out is not None:
                                dt = (now - prev_dt).total_seconds()
                                if dt and dt > 0:
                                    d_in = now_in - int(prev_in)
                                    d_out = now_out - int(prev_out)
                                    if computed_rx_bps is None and d_in >= 0:
                                        computed_rx_bps = (d_in * 8.0) / dt
                                    if computed_tx_bps is None and d_out >= 0:
                                        computed_tx_bps = (d_out * 8.0) / dt
                            if computed_rx_bps is None and now_in is not None and prev_in is None:
                                computed_rx_bps = 0.0
                            if computed_tx_bps is None and now_out is not None and prev_out is None:
                                computed_tx_bps = 0.0

                            if now_in is not None or now_out is not None:
                                prev_bytes[key] = {"ts": now_iso, "bytes_in": now_in, "bytes_out": now_out}

                            norm = usage_notifier.normalize_active_row(
                                {**row, **(counter_row or {})},
                                timestamp=now_iso,
                                router_id=router_id,
                                router_name=router_name,
                                computed_rx_bps=computed_rx_bps,
                                computed_tx_bps=computed_tx_bps,
                            )
                            if norm:
                                if now_in is not None:
                                    norm["bytes_in"] = now_in
                                if now_out is not None:
                                    norm["bytes_out"] = now_out
                                computed.append(norm)

                        # Offline rows from cached secrets
                        secrets = secrets_cache.get(router_id) if isinstance(secrets_cache.get(router_id), list) else []
                        for secret in secrets:
                            name = (secret.get("name") or "").strip()
                            if not name or name in active_set:
                                continue
                            offline_rows.append(
                                {
                                    "router_id": router_id,
                                    "router_name": router_name,
                                    "pppoe": name,
                                    "disabled": str(secret.get("disabled") or "").strip().lower() in ("yes", "true", "1"),
                                    "profile": (secret.get("profile") or "").strip(),
                                    "last_logged_out": (secret.get("last-logged-out") or "").strip(),
                                }
                            )

                        active_rows.extend(computed)
                        router_status.append(
                            {
                                "router_id": router_id,
                                "router_name": router_name,
                                "active_count": len(active_set),
                                "queue_count": len(queue_rows),
                                "queue_match_count": queue_match_count,
                                "queue_bytes_ok": queue_bytes_ok,
                                "queue_rate_ok": queue_rate_ok,
                                "iface_count": len(iface_rows),
                                "iface_match_count": iface_match_count,
                                "iface_bytes_ok": iface_bytes_ok,
                                "offline_count": len(
                                    [
                                        1
                                        for s in (secrets or [])
                                        if (s.get("name") or "").strip() and (s.get("name") or "").strip() not in active_set
                                    ]
                                ),
                                "error": router_error,
                                "connected": bool(connected),
                            }
                        )

                    # Close connections for routers that were removed/disabled.
                    for rid in list(clients.keys()):
                        if rid not in enabled_router_ids:
                            try:
                                clients[rid].close()
                            except Exception:
                                pass
                            clients.pop(rid, None)
                            client_sigs.pop(rid, None)

                    # Persist raw samples at a lower cadence than the live polling.
                    sample_interval = int((cfg.get("storage") or {}).get("sample_interval_seconds", 60) or 60)
                    sample_interval = max(sample_interval, 10)
                    last_db = state.get("last_db_write_at")
                    last_db_dt = datetime.fromisoformat(last_db.replace("Z", "")) if last_db else None
                    should_write = (not last_db_dt) or (now - last_db_dt >= timedelta(seconds=sample_interval))
                    if should_write and active_rows:
                        hosts = state.get("pppoe_hosts") if isinstance(state.get("pppoe_hosts"), dict) else {}
                        for row in active_rows:
                            pppoe = (row.get("pppoe") or "").strip()
                            host_info = hosts.get(pppoe) or hosts.get(pppoe.lower()) or {}
                            host_count = int(host_info.get("host_count") or 0)
                            insert_pppoe_usage_sample(
                                row.get("timestamp"),
                                row.get("router_id"),
                                row.get("router_name"),
                                row.get("pppoe"),
                                address=row.get("address"),
                                session_id=row.get("session_id"),
                                uptime=row.get("uptime"),
                                bytes_in=row.get("bytes_in"),
                                bytes_out=row.get("bytes_out"),
                                host_count=host_count,
                                rx_bps=row.get("rx_bps"),
                                tx_bps=row.get("tx_bps"),
                            )
                        state["last_db_write_at"] = now_iso

                    # Window-based no-usage detection for Peak Hours and Anytime rules.
                    detect = cfg.get("detection") if isinstance(cfg.get("detection"), dict) else {}
                    peak_enabled = bool(detect.get("peak_enabled", True))
                    peak_window_min = int(detect.get("peak_no_usage_minutes", 120) or 120)
                    peak_window_min = max(peak_window_min, 5)
                    peak_min_devices = max(int(detect.get("min_connected_devices", 2) or 2), 1)
                    peak_from_bps = detect.get("total_kbps_from")
                    peak_to_bps = detect.get("total_kbps_to")
                    if peak_from_bps is None:
                        peak_from_bps = 0
                    if peak_to_bps is None:
                        peak_to_bps = detect.get("min_total_kbps", 8)
                    peak_from_bps = max(float(peak_from_bps or 0.0) * 1000.0, 0.0)
                    peak_to_bps = max(float(peak_to_bps or 0.0) * 1000.0, 0.0)
                    if peak_to_bps < peak_from_bps:
                        peak_from_bps, peak_to_bps = peak_to_bps, peak_from_bps
                    peak_start = (detect.get("peak_start_ph") or "17:30").strip()
                    peak_end = (detect.get("peak_end_ph") or "21:00").strip()

                    anytime_enabled = bool(detect.get("anytime_enabled", False))
                    anytime_window_min = int(detect.get("anytime_no_usage_minutes", 120) or 120)
                    anytime_window_min = max(anytime_window_min, 5)
                    anytime_min_devices = max(int(detect.get("anytime_min_connected_devices", 2) or 2), 1)
                    anytime_from_bps = max(float(detect.get("anytime_total_kbps_from", 0) or 0.0) * 1000.0, 0.0)
                    anytime_to_bps = max(float(detect.get("anytime_total_kbps_to", 8) or 8.0) * 1000.0, 0.0)
                    if anytime_to_bps < anytime_from_bps:
                        anytime_from_bps, anytime_to_bps = anytime_to_bps, anytime_from_bps
                    work_start = (detect.get("anytime_work_start_ph") or "00:00").strip()
                    work_end = (detect.get("anytime_work_end_ph") or "23:59").strip()

                    def _calc_min_samples(window_minutes):
                        expected = int((window_minutes * 60) / max(sample_interval, 10))
                        return max(3, int(expected * 0.25), 10)

                    stats_cache = {}

                    def _load_window_stats(window_minutes):
                        cache_key = int(window_minutes)
                        stats = stats_cache.get(cache_key)
                        if stats is None:
                            since_iso = (now - timedelta(minutes=cache_key)).isoformat() + "Z"
                            stats = get_pppoe_usage_window_stats_since(since_iso)
                            stats_cache[cache_key] = stats
                        return stats

                    hosts = state.get("pppoe_hosts") if isinstance(state.get("pppoe_hosts"), dict) else {}
                    now_ph = datetime.now(usage_tz) if usage_tz else datetime.utcnow()

                    peak_last_eval = state.get("peak_eval_at")
                    peak_last_eval_dt = datetime.fromisoformat(peak_last_eval.replace("Z", "")) if peak_last_eval else None
                    peak_eval_due = (not peak_last_eval_dt) or (now - peak_last_eval_dt >= timedelta(seconds=60))
                    if not peak_enabled:
                        state["peak_issues"] = {}
                    elif peak_eval_due:
                        if not _in_time_window(now_ph, peak_start, peak_end):
                            state["peak_issues"] = {}
                            state["peak_eval_at"] = now_iso
                        else:
                            stats_map = _load_window_stats(peak_window_min)
                            min_samples = _calc_min_samples(peak_window_min)
                            issues_map = {}
                            for row in active_rows:
                                pppoe = (row.get("pppoe") or "").strip()
                                if not pppoe:
                                    continue
                                router_id = (row.get("router_id") or "").strip()
                                host_info = hosts.get(pppoe) or hosts.get(pppoe.lower()) or {}
                                host_count = int(host_info.get("host_count") or 0)
                                if host_count < peak_min_devices:
                                    continue
                                key = usage_issue_key(router_id, pppoe)
                                stat = stats_map.get(key)
                                if not stat:
                                    continue
                                if int(stat.get("samples") or 0) < min_samples:
                                    continue
                                max_total_bps = float(stat.get("max_total_bps") or 0.0)
                                if peak_from_bps <= max_total_bps <= peak_to_bps:
                                    issues_map[key] = {
                                        "samples": int(stat.get("samples") or 0),
                                        "max_total_bps": max_total_bps,
                                        "window_minutes": peak_window_min,
                                        "min_samples": min_samples,
                                    }
                            state["peak_issues"] = issues_map
                            state["peak_eval_at"] = now_iso

                    anytime_last_eval = state.get("anytime_eval_at")
                    anytime_last_eval_dt = datetime.fromisoformat(anytime_last_eval.replace("Z", "")) if anytime_last_eval else None
                    anytime_eval_due = (not anytime_last_eval_dt) or (now - anytime_last_eval_dt >= timedelta(seconds=60))
                    if not anytime_enabled:
                        state["anytime_issues"] = {}
                    elif anytime_eval_due:
                        if not _in_time_window(now_ph, work_start, work_end):
                            state["anytime_issues"] = {}
                            state["anytime_eval_at"] = now_iso
                        else:
                            stats_map = _load_window_stats(anytime_window_min)
                            min_samples = _calc_min_samples(anytime_window_min)
                            issues_map = {}
                            for row in active_rows:
                                pppoe = (row.get("pppoe") or "").strip()
                                if not pppoe:
                                    continue
                                router_id = (row.get("router_id") or "").strip()
                                host_info = hosts.get(pppoe) or hosts.get(pppoe.lower()) or {}
                                host_count = int(host_info.get("host_count") or 0)
                                if host_count < anytime_min_devices:
                                    continue
                                key = usage_issue_key(router_id, pppoe)
                                stat = stats_map.get(key)
                                if not stat:
                                    continue
                                if int(stat.get("samples") or 0) < min_samples:
                                    continue
                                max_total_bps = float(stat.get("max_total_bps") or 0.0)
                                if anytime_from_bps <= max_total_bps <= anytime_to_bps:
                                    issues_map[key] = {
                                        "samples": int(stat.get("samples") or 0),
                                        "max_total_bps": max_total_bps,
                                        "window_minutes": anytime_window_min,
                                        "min_samples": min_samples,
                                    }
                            state["anytime_issues"] = issues_map
                            state["anytime_eval_at"] = now_iso

                    state["active_rows"] = active_rows
                    state["offline_rows"] = offline_rows
                    if reboot_cfg.get("enabled"):
                        summary = build_usage_summary_data(cfg, state)
                        state["modem_reboot"] = _process_usage_modem_reboots(cfg, state, summary, now, now_iso)
                    elif isinstance(state.get("modem_reboot"), dict):
                        reboot_state = normalize_usage_modem_reboot_state(state.get("modem_reboot"))
                        reboot_state["current"] = {}
                        state["modem_reboot"] = reboot_state

                    state["routers"] = router_status
                    state["enabled_router_ids"] = sorted(list(enabled_router_ids))
                    state["prev_bytes"] = prev_bytes
                    state["secrets_cache"] = secrets_cache
                    state["secrets_refreshed_at"] = secrets_refreshed_at
                    state["ppp_active_stats_supported"] = stats_cap
                    state["last_check_at"] = now_iso
                    save_state("usage_state", state)
                    _safe_update_job_status("usage", last_success_at=utc_now_iso(), last_error="", last_error_at="")
                except Exception as exc:
                    _safe_update_job_status("usage", last_error=str(exc), last_error_at=utc_now_iso())
                finally:
                    add_feature_cpu("Usage", max(time_module.thread_time() - loop_cpu_start, 0.0))

                # Sleep based on configured poll interval.
                poll_seconds = int((cfg.get("mikrotik") or {}).get("poll_interval_seconds", 10) or 10)
                time_module.sleep(max(poll_seconds, 3))
        finally:
            for client in list(clients.values()):
                try:
                    client.close()
                except Exception:
                    pass

    def _offline_loop(self):
        """
        Offline accounts collector.
        - Mode secrets: MikroTik secrets minus /ppp/active
        - Mode radius: Radius list minus /ppp/active
        Routers are shared from System Settings (wan_ping.pppoe_routers).
        """
        clients = {}
        client_sigs = {}
        while not self.stop_event.is_set():
            cfg = get_settings("offline", OFFLINE_DEFAULTS)
            if not cfg.get("enabled"):
                time_module.sleep(5)
                continue

            poll_seconds = int((cfg.get("general") or {}).get("poll_interval_seconds", 15) or 15)
            poll_seconds = max(poll_seconds, 5)
            timeout_seconds = 5
            general_cfg = cfg.get("general") if isinstance(cfg.get("general"), dict) else {}
            tracking_rules = enabled_offline_tracking_rules(
                general_cfg.get("tracking_rules"),
                fallback_value=general_cfg.get("min_offline_value", 1),
                fallback_unit=general_cfg.get("min_offline_unit", "day"),
            )
            min_offline_minutes = min(int(rule.get("minutes", 0) or 0) for rule in tracking_rules) if tracking_rules else 0
            history_retention_days = int(general_cfg.get("history_retention_days", 365) or 365)
            history_retention_days = max(history_retention_days, 1)

            mode = (cfg.get("mode") or "secrets").strip().lower()
            if mode not in ("secrets", "radius"):
                mode = "secrets"
            mikrotik_cfg = cfg.get("mikrotik") if isinstance(cfg.get("mikrotik"), dict) else {}
            offline_router_enabled = (
                mikrotik_cfg.get("router_enabled") if isinstance(mikrotik_cfg.get("router_enabled"), dict) else {}
            )

            wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
            routers = wan_cfg.get("pppoe_routers") if isinstance(wan_cfg.get("pppoe_routers"), list) else []
            if not routers:
                usage_cfg = get_settings("usage", USAGE_DEFAULTS)
                legacy = (usage_cfg.get("mikrotik") or {}).get("routers") or []
                migrated = []
                for item in legacy:
                    if not isinstance(item, dict):
                        continue
                    rid = (item.get("id") or "").strip()
                    host = (item.get("host") or "").strip()
                    if not rid or not host:
                        continue
                    migrated.append(
                        {
                            "id": rid,
                            "name": (item.get("name") or "").strip(),
                            "host": host,
                            "port": int(item.get("port", 8728) or 8728),
                            "username": item.get("username", ""),
                            "password": item.get("password", ""),
                            "use_tls": False,
                        }
                    )
                if migrated:
                    wan_cfg.setdefault("pppoe_routers", [])
                    wan_cfg["pppoe_routers"] = migrated
                    save_settings("wan_ping", wan_cfg)
                    routers = migrated

            enabled_router_ids = set()
            monitored_routers = []
            for router in routers:
                if not isinstance(router, dict):
                    continue
                router_id = (router.get("id") or "").strip()
                host = (router.get("host") or "").strip()
                if not router_id or not host:
                    continue
                if not bool(offline_router_enabled.get(router_id, True)):
                    continue
                monitored_routers.append(router)
                enabled_router_ids.add(router_id)

            now_iso = utc_now_iso()
            _safe_update_job_status("offline", last_run_at=now_iso)
            state = get_state("offline_state", {})
            tracker = state.get("tracker") if isinstance(state.get("tracker"), dict) else {}
            offline_rows = []
            source_accounts_map = {}
            router_status = []
            router_errors = []
            active_users_all = set()
            active_users_by_router = {}

            # Prefer Usage collector cache when available (avoids extra RouterOS logins).
            usage_state = get_state("usage_state", {})
            use_cache = False
            try:
                last = usage_state.get("last_check_at")
                if last:
                    last_dt = datetime.fromisoformat(str(last).replace("Z", ""))
                    if datetime.utcnow() - last_dt <= timedelta(seconds=poll_seconds * 3):
                        use_cache = True
            except Exception:
                use_cache = False
            if use_cache:
                try:
                    cached_router_ids = set(usage_state.get("enabled_router_ids") or [])
                    if not enabled_router_ids or not enabled_router_ids.issubset(cached_router_ids):
                        use_cache = False
                except Exception:
                    use_cache = False

            loop_cpu_start = time_module.thread_time()
            try:
                def _source_account_key(row, fallback_mode=""):
                    if not isinstance(row, dict):
                        return ""
                    pppoe = str(row.get("pppoe") or row.get("name") or row.get("username") or "").strip()
                    if not pppoe:
                        return ""
                    router_id = str(row.get("router_id") or "").strip()
                    mode_key = str(row.get("mode") or fallback_mode or mode or "offline").strip().lower() or "offline"
                    return f"{router_id or mode_key}|{pppoe.lower()}"

                def _register_source_account(row, *, source_status="", fallback_mode=""):
                    if not isinstance(row, dict):
                        return
                    pppoe = str(row.get("pppoe") or row.get("name") or row.get("username") or "").strip()
                    if not pppoe:
                        return
                    item = {
                        "pppoe": pppoe,
                        "router_id": str(row.get("router_id") or "").strip(),
                        "router_name": str(row.get("router_name") or row.get("router_id") or "").strip(),
                        "mode": str(row.get("mode") or fallback_mode or mode or "offline").strip().lower() or "offline",
                        "profile": str(row.get("profile") or row.get("groups") or "").strip(),
                        "disabled": bool(row.get("disabled")) if row.get("disabled") is not None else None,
                        "last_logged_out": str(row.get("last_logged_out") or row.get("last_stop") or "").strip(),
                        "radius_status": str(row.get("radius_status") or row.get("status") or "").strip(),
                        "source_status": str(source_status or row.get("source_status") or "").strip().lower(),
                        "online_since": str(row.get("online_since") or "").strip(),
                        "ip": str(row.get("ip") or row.get("address") or "").strip(),
                    }
                    key = _source_account_key(item, fallback_mode=fallback_mode)
                    if not key:
                        return
                    existing = source_accounts_map.get(key)
                    if not existing:
                        source_accounts_map[key] = item
                        return
                    existing_rank = 1 if str(existing.get("source_status") or "").strip().lower() == "active" else 0
                    item_rank = 1 if item["source_status"] == "active" else 0
                    if item_rank > existing_rank:
                        source_accounts_map[key] = item
                        return
                    for field in ("router_name", "profile", "last_logged_out", "radius_status", "online_since", "ip"):
                        if item.get(field) and not existing.get(field):
                            existing[field] = item.get(field)
                    if existing.get("disabled") is None and item.get("disabled") is not None:
                        existing["disabled"] = item.get("disabled")

                # Retention for history (once per day).
                try:
                    last_prune = state.get("last_prune_at")
                    last_prune_dt = datetime.fromisoformat(last_prune.replace("Z", "")) if last_prune else None
                    if not last_prune_dt or last_prune_dt + timedelta(hours=24) < datetime.utcnow():
                        cutoff = datetime.utcnow() - timedelta(days=history_retention_days)
                        delete_offline_history_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                        state["last_prune_at"] = now_iso
                except Exception:
                    pass

                if use_cache:
                    active_rows = usage_state.get("active_rows") if isinstance(usage_state.get("active_rows"), list) else []
                    for row in active_rows:
                        rid = (row.get("router_id") or "").strip()
                        if rid not in enabled_router_ids:
                            continue
                        user = (row.get("pppoe") or row.get("name") or "").strip()
                        if not user:
                            continue
                        _register_source_account(
                            {
                                "pppoe": user,
                                "router_id": rid,
                                "router_name": (row.get("router_name") or rid or "").strip(),
                                "mode": "secrets",
                                "profile": (row.get("profile") or "").strip(),
                                "last_logged_out": (row.get("last_logged_out") or "").strip(),
                                "radius_status": (row.get("status") or "").strip(),
                                "ip": (row.get("ip") or row.get("address") or "").strip(),
                            },
                            source_status="active",
                            fallback_mode="secrets",
                        )
                        active_users_all.add(user)
                        active_users_by_router.setdefault(rid, set()).add(user)
                    router_status = [
                        row
                        for row in (usage_state.get("routers") if isinstance(usage_state.get("routers"), list) else [])
                        if isinstance(row, dict) and (row.get("router_id") or "").strip() in enabled_router_ids
                    ]

                    if mode == "secrets":
                        offline_rows = [
                            row
                            for row in (usage_state.get("offline_rows") if isinstance(usage_state.get("offline_rows"), list) else [])
                            if isinstance(row, dict) and (row.get("router_id") or "").strip() in enabled_router_ids
                        ]
                        for row in offline_rows:
                            _register_source_account({**row, "mode": "secrets"}, source_status="inactive", fallback_mode="secrets")
                else:
                    for router in monitored_routers:
                        router_id = (router.get("id") or "").strip()
                        router_name = (router.get("name") or router_id or "router").strip()
                        host = (router.get("host") or "").strip()
                        if not router_id or not host:
                            continue
                        if router.get("use_tls"):
                            router_error = "TLS/API-SSL is not supported by the current RouterOS API client. Disable TLS or use port 8728."
                            router_status.append(
                                {
                                    "router_id": router_id,
                                    "router_name": router_name,
                                    "active_count": 0,
                                    "connected": False,
                                    "error": router_error,
                                }
                            )
                            router_errors.append(f"{router_name}: {router_error}")
                            continue

                        port = int(router.get("port", 8728) or 8728)
                        username = router.get("username", "")
                        password = router.get("password", "")
                        sig = (host, port, username, password, timeout_seconds)

                        client = clients.get(router_id)
                        if client is None or client_sigs.get(router_id) != sig:
                            try:
                                if client is not None:
                                    client.close()
                            except Exception:
                                pass
                            client = RouterOSClient(host, port, username, password, timeout=timeout_seconds)
                            clients[router_id] = client
                            client_sigs[router_id] = sig

                        router_error = ""
                        router_active = []
                        router_secrets = []
                        connected = False
                        try:
                            if client.sock is None:
                                client.connect()
                            connected = True
                            router_active = usage_notifier.fetch_pppoe_active(client)
                            if mode == "secrets":
                                router_secrets = usage_notifier.fetch_pppoe_secrets(client)
                        except Exception as exc:
                            router_error = str(exc)
                            try:
                                client.close()
                            except Exception:
                                pass
                            clients[router_id] = RouterOSClient(host, port, username, password, timeout=timeout_seconds)
                            client_sigs[router_id] = sig
                            try:
                                clients[router_id].connect()
                                connected = True
                                router_active = usage_notifier.fetch_pppoe_active(clients[router_id])
                                if mode == "secrets":
                                    router_secrets = usage_notifier.fetch_pppoe_secrets(clients[router_id])
                                router_error = ""
                            except Exception as exc2:
                                router_error = str(exc2)
                                try:
                                    clients[router_id].close()
                                except Exception:
                                    pass
                                connected = False

                        active_set = set()
                        for row in router_active:
                            user = (row.get("name") or "").strip()
                            if not user:
                                continue
                            _register_source_account(
                                {
                                    "pppoe": user,
                                    "router_id": router_id,
                                    "router_name": router_name,
                                    "mode": "secrets",
                                    "ip": (row.get("address") or "").strip(),
                                },
                                source_status="active",
                                fallback_mode="secrets",
                            )
                            active_set.add(user)
                            active_users_all.add(user)
                            active_users_by_router.setdefault(router_id, set()).add(user)

                        if mode == "secrets":
                            for secret in router_secrets:
                                name = (secret.get("name") or "").strip()
                                _register_source_account(
                                    {
                                        "pppoe": name,
                                        "router_id": router_id,
                                        "router_name": router_name,
                                        "mode": "secrets",
                                        "disabled": str(secret.get("disabled") or "").strip().lower() in ("yes", "true", "1"),
                                        "profile": (secret.get("profile") or "").strip(),
                                        "last_logged_out": (secret.get("last-logged-out") or "").strip(),
                                    },
                                    source_status="active" if name in active_set else "inactive",
                                    fallback_mode="secrets",
                                )
                                if not name or name in active_set:
                                    continue
                                offline_rows.append(
                                    {
                                        "router_id": router_id,
                                        "router_name": router_name,
                                        "pppoe": name,
                                        "disabled": str(secret.get("disabled") or "").strip().lower() in ("yes", "true", "1"),
                                        "profile": (secret.get("profile") or "").strip(),
                                        "last_logged_out": (secret.get("last-logged-out") or "").strip(),
                                    }
                                )

                        router_status.append(
                            {
                                "router_id": router_id,
                                "router_name": router_name,
                                "active_count": len(active_set),
                                "connected": bool(connected),
                                "error": router_error,
                            }
                        )
                        if router_error:
                            router_errors.append(f"{router_name}: {router_error}")

                    # Close connections for routers that were removed/disabled.
                    for rid in list(clients.keys()):
                        if rid not in enabled_router_ids:
                            try:
                                clients[rid].close()
                            except Exception:
                                pass
                            clients.pop(rid, None)
                            client_sigs.pop(rid, None)

                radius_error = ""
                radius_accounts = {}
                if mode == "radius":
                    offline_rows = []
                    if enabled_router_ids:
                        radius_cfg = cfg.get("radius") if isinstance(cfg.get("radius"), dict) else {}
                        if not radius_cfg.get("enabled"):
                            radius_error = "Radius mode is selected but Radius settings are disabled."
                        else:
                            try:
                                radius_accounts = offline_notifier.fetch_radius_accounts(radius_cfg)
                            except Exception as exc:
                                radius_error = str(exc)
                                radius_accounts = {}

                        for user, status in (radius_accounts or {}).items():
                            _register_source_account(
                                {
                                    "pppoe": user,
                                    "router_id": "",
                                    "router_name": "Radius",
                                    "mode": "radius",
                                    "radius_status": status or "",
                                },
                                source_status="active" if user in active_users_all else "inactive",
                                fallback_mode="radius",
                            )
                            if user in active_users_all:
                                continue
                            offline_rows.append(
                                {
                                    "router_id": "",
                                    "router_name": "Radius",
                                    "pppoe": user,
                                    "radius_status": status or "",
                                }
                            )
                else:
                    radius_error = ""

                # Offline threshold + history tracking.
                now_dt = datetime.utcnow()

                def _parse_dt(iso):
                    if not iso:
                        return None
                    raw = str(iso).strip()
                    if raw.endswith("Z"):
                        raw = raw[:-1]
                    try:
                        return datetime.fromisoformat(raw)
                    except Exception:
                        return None

                def _minutes_since(iso):
                    dt = _parse_dt(iso)
                    if not dt:
                        return 0
                    return int((now_dt - dt).total_seconds() / 60)

                candidates = {}
                active_keys = set()
                if mode == "secrets":
                    for rid, users in active_users_by_router.items():
                        for user in users:
                            active_keys.add(f"{rid}|{user.strip().lower()}")
                    for row in offline_rows:
                        rid = (row.get("router_id") or "").strip()
                        user = (row.get("pppoe") or "").strip()
                        if not rid or not user:
                            continue
                        key = f"{rid}|{user.lower()}"
                        candidates[key] = row
                else:
                    for user in active_users_all:
                        active_keys.add(f"radius|{user.strip().lower()}")
                    for row in offline_rows:
                        user = (row.get("pppoe") or "").strip()
                        if not user:
                            continue
                        key = f"radius|{user.lower()}"
                        candidates[key] = row

                # Update tracker for current offline candidates.
                for key, row in candidates.items():
                    item = tracker.get(key) if isinstance(tracker.get(key), dict) else {}
                    if not item.get("first_offline_at"):
                        item["first_offline_at"] = now_iso
                    item["last_offline_at"] = now_iso
                    item["mode"] = mode
                    # Keep latest meta for rendering / history.
                    item["meta"] = row
                    minutes = _minutes_since(item.get("first_offline_at"))
                    if minutes >= min_offline_minutes:
                        item["listed"] = True
                    tracker[key] = item

                # Resolve tracker entries that are no longer offline; write history if they were listed and became active.
                for key in list(tracker.keys()):
                    if key in candidates:
                        continue
                    item = tracker.get(key) if isinstance(tracker.get(key), dict) else {}
                    if not item:
                        tracker.pop(key, None)
                        continue
                    was_listed = bool(item.get("listed"))
                    became_active = key in active_keys
                    if was_listed and became_active:
                        started = item.get("first_offline_at") or now_iso
                        started_dt = _parse_dt(started) or now_dt
                        duration_sec = int(max(0, (now_dt - started_dt).total_seconds()))
                        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
                        insert_offline_history_event(
                            pppoe=(meta.get("pppoe") or "").strip(),
                            router_id=(meta.get("router_id") or "").strip(),
                            router_name=(meta.get("router_name") or meta.get("router_id") or "").strip(),
                            mode=mode,
                            offline_started_at=started,
                            offline_ended_at=now_iso,
                            duration_seconds=duration_sec,
                            radius_status=meta.get("radius_status"),
                            disabled=meta.get("disabled"),
                            profile=meta.get("profile"),
                            last_logged_out=meta.get("last_logged_out"),
                        )
                    tracker.pop(key, None)

                # Build displayed offline rows (only after threshold).
                displayed = []
                for key, row in candidates.items():
                    item = tracker.get(key) if isinstance(tracker.get(key), dict) else {}
                    if not item.get("listed"):
                        continue
                    started = item.get("first_offline_at") or now_iso
                    displayed.append({**row, "offline_since": started})
                offline_rows = displayed

                state.update(
                    {
                        "mode": mode,
                        "rows": offline_rows,
                        "source_accounts": sorted(
                            source_accounts_map.values(),
                            key=lambda item: (
                                str(item.get("router_name") or item.get("router_id") or "").lower(),
                                str(item.get("pppoe") or "").lower(),
                            ),
                        ),
                        "active_accounts": len(active_users_all),
                        "tracking_rules": tracking_rules,
                        "routers": router_status,
                        "router_errors": router_errors,
                        "radius_error": radius_error,
                        "tracker": tracker,
                        "enabled_router_ids": sorted(list(enabled_router_ids)),
                        "min_offline_minutes": int(min_offline_minutes),
                        "last_check_at": now_iso,
                    }
                )
                save_state("offline_state", state)
                _safe_update_job_status("offline", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except Exception as exc:
                _safe_update_job_status("offline", last_error=str(exc), last_error_at=utc_now_iso())
            finally:
                add_feature_cpu("Offline", max(time_module.thread_time() - loop_cpu_start, 0.0))

            time_module.sleep(poll_seconds)


def parse_time(value):
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        return time(hour=7, minute=0)
    try:
        return time(hour=int(parts[0]), minute=int(parts[1]))
    except (TypeError, ValueError):
        return time(hour=7, minute=0)


def current_date(general_cfg):
    timezone = general_cfg.get("timezone", "Asia/Manila")
    if ZoneInfo is not None:
        return datetime.now(ZoneInfo(timezone)).date()
    return datetime.now().date()


def should_run_daily(general_cfg, state):
    schedule_time = parse_time(general_cfg.get("schedule_time_ph", "07:00"))
    timezone = general_cfg.get("timezone", "Asia/Manila")
    if ZoneInfo is not None:
        now = datetime.now(ZoneInfo(timezone))
    else:
        now = datetime.now()
    if state.get("last_run_date") == now.date().isoformat():
        return False
    return now.time() >= schedule_time


def should_run_daily_on_minute(general_cfg, state):
    schedule_time = parse_time(general_cfg.get("schedule_time_ph", "07:00"))
    timezone = general_cfg.get("timezone", "Asia/Manila")
    if ZoneInfo is not None:
        now = datetime.now(ZoneInfo(timezone))
    else:
        now = datetime.now()
    if state.get("last_run_date") == now.date().isoformat():
        return False
    return now.hour == schedule_time.hour and now.minute == schedule_time.minute
