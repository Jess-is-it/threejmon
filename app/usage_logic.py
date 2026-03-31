import copy
from datetime import datetime, timedelta, time as dt_time, timezone

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from .settings_defaults import USAGE_DEFAULTS


try:
    PH_TZ = ZoneInfo("Asia/Manila") if ZoneInfo else None
except Exception:
    PH_TZ = None


def _parse_hhmm(value, default=(0, 0)):
    parts = str(value or "").strip().split(":")
    if len(parts) != 2:
        return default
    try:
        return int(parts[0]), int(parts[1])
    except Exception:
        return default


def is_time_window_ph(now_dt, start_hhmm, end_hhmm):
    sh, sm = _parse_hhmm(start_hhmm, default=(0, 0))
    eh, em = _parse_hhmm(end_hhmm, default=(23, 59))
    start_t = dt_time(hour=max(min(sh, 23), 0), minute=max(min(sm, 59), 0))
    end_t = dt_time(hour=max(min(eh, 23), 0), minute=max(min(em, 59), 0))
    current_t = now_dt.time()
    if start_t <= end_t:
        return start_t <= current_t <= end_t
    return current_t >= start_t or current_t <= end_t


def usage_issue_key(router_id, pppoe):
    router_id = str(router_id or "").strip()
    pppoe = str(pppoe or "").strip().lower()
    if not pppoe:
        return ""
    return f"{router_id}|{pppoe}"


def usage_nav_entry_id(row):
    if not isinstance(row, dict):
        return ""
    return usage_issue_key(row.get("router_id"), row.get("pppoe")) or ""


def _utc_now():
    return datetime.utcnow().replace(microsecond=0)


def _iso_utc(dt):
    if not isinstance(dt, datetime):
        return ""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0).isoformat() + "Z"


def format_ts_ph(value):
    dt = _parse_iso(value)
    if not dt:
        return "n/a"
    if PH_TZ:
        try:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(PH_TZ)
        except Exception:
            pass
    return dt.strftime("%Y-%m-%d %I:%M %p")


def _parse_iso(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1]
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def normalize_usage_modem_reboot_settings(raw_settings):
    settings = copy.deepcopy(USAGE_DEFAULTS.get("modem_reboot") or {})
    if isinstance(raw_settings, dict):
        modem = raw_settings.get("modem_reboot")
        if isinstance(modem, dict):
            settings.update(modem)
    settings["enabled"] = bool(settings.get("enabled"))
    try:
        settings["buffer_hours"] = max(int(settings.get("buffer_hours", 32) or 32), 1)
    except Exception:
        settings["buffer_hours"] = 32
    try:
        settings["retry_count"] = max(int(settings.get("retry_count", 5) or 5), 0)
    except Exception:
        settings["retry_count"] = 5
    try:
        settings["retry_delay_minutes"] = max(int(settings.get("retry_delay_minutes", 5) or 5), 1)
    except Exception:
        settings["retry_delay_minutes"] = 5
    try:
        settings["verify_after_minutes"] = max(int(settings.get("verify_after_minutes", 5) or 5), 1)
    except Exception:
        settings["verify_after_minutes"] = 5
    try:
        settings["history_retention_days"] = max(int(settings.get("history_retention_days", 180) or 180), 1)
    except Exception:
        settings["history_retention_days"] = 180
    return settings


def _normalize_cycle(raw):
    data = raw if isinstance(raw, dict) else {}
    return {
        "pppoe": str(data.get("pppoe") or "").strip(),
        "router_id": str(data.get("router_id") or "").strip(),
        "router_name": str(data.get("router_name") or "").strip(),
        "address": str(data.get("address") or "").strip(),
        "device_id": str(data.get("device_id") or "").strip(),
        "opened_at": str(data.get("opened_at") or "").strip(),
        "last_attempt_at": str(data.get("last_attempt_at") or "").strip(),
        "attempt_count": max(int(data.get("attempt_count", 0) or 0), 0),
        "last_status": str(data.get("last_status") or "").strip(),
        "last_error": str(data.get("last_error") or "").strip(),
        "next_retry_at": str(data.get("next_retry_at") or "").strip(),
        "success_at": str(data.get("success_at") or "").strip(),
        "buffer_until": str(data.get("buffer_until") or "").strip(),
        "verify_due_at": str(data.get("verify_due_at") or "").strip(),
        "verify_status": str(data.get("verify_status") or "").strip(),
        "verify_checked_at": str(data.get("verify_checked_at") or "").strip(),
        "latest_history_id": int(data.get("latest_history_id", 0) or 0),
        "task_id": str(data.get("task_id") or "").strip(),
        "http_status": int(data.get("http_status", 0) or 0),
    }


def normalize_usage_modem_reboot_state(raw_state):
    raw_state = raw_state if isinstance(raw_state, dict) else {}
    current = {}
    for raw_key, raw_cycle in (raw_state.get("current") or {}).items():
        key = str(raw_key or "").strip()
        if not key:
            continue
        current[key] = _normalize_cycle(raw_cycle)

    last_success_at = {}
    for raw_key, raw_ts in (raw_state.get("last_success_at") or {}).items():
        key = str(raw_key or "").strip()
        ts = str(raw_ts or "").strip()
        if key and ts:
            last_success_at[key] = ts

    issue_suppression = {}
    for raw_key, raw_item in (raw_state.get("issue_suppression") or {}).items():
        key = str(raw_key or "").strip()
        item = raw_item if isinstance(raw_item, dict) else {}
        until = str(item.get("until") or "").strip()
        if key and until:
            issue_suppression[key] = {
                "until": until,
                "verified_at": str(item.get("verified_at") or "").strip(),
                "reason": str(item.get("reason") or "").strip(),
            }

    return {
        "current": current,
        "last_success_at": last_success_at,
        "issue_suppression": issue_suppression,
        "history_last_prune_at": str(raw_state.get("history_last_prune_at") or "").strip(),
    }


def _suppression_active(item, now_dt):
    if not isinstance(item, dict):
        return False
    until_dt = _parse_iso(item.get("until"))
    if not until_dt:
        return False
    return until_dt > now_dt


def _reboot_badge_for_cycle(cycle, now_dt=None):
    cycle = cycle if isinstance(cycle, dict) else {}
    now_dt = now_dt or _utc_now()
    next_retry_dt = _parse_iso(cycle.get("next_retry_at"))
    buffer_until_dt = _parse_iso(cycle.get("buffer_until"))
    last_status = str(cycle.get("last_status") or "").strip().lower()
    verify_status = str(cycle.get("verify_status") or "").strip().lower()
    success_at = str(cycle.get("success_at") or "").strip()
    last_error = str(cycle.get("last_error") or "").strip()
    attempt_count = int(cycle.get("attempt_count", 0) or 0)

    if next_retry_dt and next_retry_dt > now_dt and not success_at:
        retry_label = format_ts_ph(_iso_utc(next_retry_dt))
        title = f"Last reboot attempt failed. Retry #{attempt_count + 1} is scheduled at {retry_label}."
        if last_error:
            title = f"{title} {last_error}"
        return {
            "label": "Retrying",
            "class": "bg-yellow-lt text-yellow",
            "icon": "ti ti-rotate-clockwise-2",
            "title": title,
        }

    if success_at:
        title_parts = [f"Reboot command accepted at {format_ts_ph(success_at)}."]
        if verify_status == "pending":
            verify_due_at = str(cycle.get("verify_due_at") or "").strip()
            if verify_due_at:
                title_parts.append(f"Verification runs at {format_ts_ph(verify_due_at)}.")
        elif verify_status == "passed":
            verify_checked_at = str(cycle.get("verify_checked_at") or "").strip()
            if verify_checked_at:
                title_parts.append(f"Usage recovered at {format_ts_ph(verify_checked_at)}.")
        elif verify_status == "failed":
            verify_checked_at = str(cycle.get("verify_checked_at") or "").strip()
            if verify_checked_at:
                title_parts.append(f"Usage issue was still present at {format_ts_ph(verify_checked_at)}.")
        if buffer_until_dt and buffer_until_dt > now_dt:
            title_parts.append(f"Reboot buffer active until {format_ts_ph(cycle.get('buffer_until'))}.")
        if last_error:
            title_parts.append(last_error)
        return {
            "label": "Rebooted",
            "class": "bg-azure-lt text-azure",
            "icon": "ti ti-power",
            "title": " ".join(part for part in title_parts if part),
        }

    if buffer_until_dt and buffer_until_dt > now_dt:
        return {
            "label": "Buffered",
            "class": "bg-secondary-lt text-secondary",
            "icon": "ti ti-hourglass-low",
            "title": f"Successful reboot buffer is active until {format_ts_ph(cycle.get('buffer_until'))}.",
        }

    if last_status == "no_tr069":
        return {
            "label": "No TR-069",
            "class": "bg-red-lt text-red",
            "icon": "ti ti-plug-x",
            "title": last_error or "No GenieACS / TR-069 device mapping was found for this account.",
        }

    if last_status in ("failed", "verify_failed"):
        return {
            "label": "Reboot Failed",
            "class": "bg-red-lt text-red",
            "icon": "ti ti-alert-circle",
            "title": last_error or "The modem reboot action did not complete successfully.",
        }

    return None


def build_usage_summary_data(settings, state):
    settings = settings if isinstance(settings, dict) else {}
    state = state if isinstance(state, dict) else {}
    active_rows = state.get("active_rows") if isinstance(state.get("active_rows"), list) else []
    offline_rows = state.get("offline_rows") if isinstance(state.get("offline_rows"), list) else []
    hosts = state.get("pppoe_hosts") if isinstance(state.get("pppoe_hosts"), dict) else {}
    reboot_state = normalize_usage_modem_reboot_state(state.get("modem_reboot"))

    detect = settings.get("detection") if isinstance(settings.get("detection"), dict) else {}
    peak_enabled = bool(detect.get("peak_enabled", True))
    min_devices = max(int(detect.get("min_connected_devices", 2) or 2), 1)
    peak_window_minutes = max(int(detect.get("peak_no_usage_minutes", 120) or 120), 5)
    kbps_from = detect.get("total_kbps_from")
    kbps_to = detect.get("total_kbps_to")
    if kbps_from is None:
        kbps_from = 0
    if kbps_to is None:
        kbps_to = detect.get("min_total_kbps", 8)
    kbps_from = max(float(kbps_from or 0.0), 0.0)
    kbps_to = max(float(kbps_to or 0.0), 0.0)
    if kbps_to < kbps_from:
        kbps_from, kbps_to = kbps_to, kbps_from
    range_from_bps = kbps_from * 1000.0
    range_to_bps = kbps_to * 1000.0
    start_ph = (detect.get("peak_start_ph") or "17:30").strip()
    end_ph = (detect.get("peak_end_ph") or "21:00").strip()

    now_dt = _utc_now()
    now_ph = datetime.now(PH_TZ) if PH_TZ else datetime.utcnow()
    in_peak = is_time_window_ph(now_ph, start_ph, end_ph)
    peak_issues = state.get("peak_issues") if isinstance(state.get("peak_issues"), dict) else {}
    anytime_issues = state.get("anytime_issues") if isinstance(state.get("anytime_issues"), dict) else {}

    issues = []
    stable = []
    for row in active_rows:
        pppoe = (row.get("pppoe") or "").strip()
        if not pppoe:
            continue
        host_info = hosts.get(pppoe) or hosts.get(pppoe.lower()) or {}
        host_count = int(host_info.get("host_count") or 0)
        hostnames = host_info.get("hostnames") if isinstance(host_info.get("hostnames"), list) else []
        device_id = str(host_info.get("device_id") or "").strip()
        ul_bps = row.get("rx_bps")
        dl_bps = row.get("tx_bps")
        total_bps = float(ul_bps or 0.0) + float(dl_bps or 0.0)
        key = usage_issue_key(row.get("router_id"), pppoe)
        peak_issue = bool(peak_issues.get(key))
        anytime_issue = bool(anytime_issues.get(key))
        suppression = reboot_state["issue_suppression"].get(key)
        anytime_suppressed = False
        peak_suppressed = False
        if (peak_issue or anytime_issue) and _suppression_active(suppression, now_dt):
            peak_suppressed = bool(peak_issue)
            anytime_issue = False
            peak_issue = False
            anytime_suppressed = True

        is_issue = bool(peak_issue or anytime_issue)
        cycle = reboot_state["current"].get(key)
        reboot_badge = _reboot_badge_for_cycle(cycle, now_dt=now_dt)
        target = issues if is_issue else stable
        target.append(
            {
                "entry_id": usage_nav_entry_id(row),
                "pppoe": pppoe,
                "router_id": row.get("router_id") or "",
                "router_name": row.get("router_name") or row.get("router_id") or "",
                "address": row.get("address") or "",
                "uptime": row.get("uptime") or "",
                "session_id": row.get("session_id") or "",
                "device_id": device_id,
                "dl_bps": dl_bps,
                "ul_bps": ul_bps,
                "dl_total_bytes": row.get("bytes_out"),
                "ul_total_bytes": row.get("bytes_in"),
                "host_count": host_count,
                "hostnames": hostnames,
                "last_seen": format_ts_ph(row.get("timestamp")),
                "last_seen_ts": row.get("timestamp") or "",
                "issue": is_issue,
                "issue_peak": peak_issue,
                "issue_peak_suppressed": peak_suppressed,
                "issue_anytime": anytime_issue,
                "issue_anytime_suppressed": anytime_suppressed,
                "is_new": False,
                "reboot": reboot_badge,
                "reboot_status": dict(cycle) if isinstance(cycle, dict) else None,
            }
        )

    return {
        "issues": issues,
        "stable": stable,
        "offline_rows": offline_rows,
        "peak": {
            "in_peak": bool(in_peak),
            "start": start_ph,
            "end": end_ph,
            "min_devices": min_devices,
            "no_usage_minutes": peak_window_minutes,
            "total_kbps_from": kbps_from,
            "total_kbps_to": kbps_to,
            "enabled": bool(peak_enabled),
        },
        "anytime": {
            "enabled": bool(detect.get("anytime_enabled", False)),
            "no_usage_minutes": int(detect.get("anytime_no_usage_minutes", 120) or 120),
            "min_devices": int(detect.get("anytime_min_connected_devices", 2) or 2),
            "total_kbps_from": float(detect.get("anytime_total_kbps_from", 0) or 0),
            "total_kbps_to": float(detect.get("anytime_total_kbps_to", 8) or 8),
            "work_start": (detect.get("anytime_work_start_ph") or "00:00").strip(),
            "work_end": (detect.get("anytime_work_end_ph") or "23:59").strip(),
            "last_eval": format_ts_ph(state.get("anytime_eval_at")),
        },
        "modem_reboot": {
            "settings": normalize_usage_modem_reboot_settings(settings),
        },
    }
