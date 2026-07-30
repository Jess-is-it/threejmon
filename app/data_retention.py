import copy
import os
import shutil
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import (
    data_retention_dataset_catalog,
    delete_data_retention_dataset_oldest,
    delete_data_retention_history_older_than,
    get_data_retention_dataset_stats,
    record_data_retention_event,
    utc_now_iso,
    vacuum_data_retention_datasets,
)
from .settings_defaults import (
    ACCOUNTS_PING_DEFAULTS,
    ISP_STATUS_DEFAULTS,
    MIKROTIK_LOGS_DEFAULTS,
    OFFLINE_DEFAULTS,
    OPTICAL_DEFAULTS,
    USAGE_DEFAULTS,
    WAN_PING_DEFAULTS,
)
from .settings_store import get_settings, get_state, save_settings, save_state


DATA_RETENTION_FEATURES = (
    {"key": "accounts_ping", "label": "Accounts Ping", "datasets": ("accounts_ping_raw", "accounts_ping_rollups")},
    {"key": "usage", "label": "Usage", "datasets": ("usage_samples", "usage_reboots")},
    {"key": "optical", "label": "Optical Monitoring", "datasets": ("optical_results",)},
    {"key": "wan", "label": "WAN Ping", "datasets": ("wan_status", "wan_targets")},
    {"key": "isp_status", "label": "ISP Port Status", "datasets": ("isp_status",)},
    {"key": "offline", "label": "Offline", "datasets": ("offline_history",)},
    {"key": "mikrotik_logs", "label": "MikroTik Logs", "datasets": ("mikrotik_logs",)},
    {"key": "auth_audit", "label": "Access Audit", "datasets": ("auth_audit",)},
)


DATA_RETENTION_DEFAULTS = {
    "guardian": {
        "trigger_percent": 85,
        "recovery_percent": 80,
        "check_interval_minutes": 5,
        "cooldown_hours": 6,
        "max_rows_per_dataset": 100000,
        "vacuum_after_cleanup": True,
        "history_retention_days": 365,
    },
    "features": {
        "accounts_ping": {"delete_percent": 10, "min_keep_days": 7, "scheduled_cleanup_interval_days": 30},
        "usage": {"delete_percent": 10, "min_keep_days": 7, "scheduled_cleanup_interval_days": 30},
        "optical": {"delete_percent": 10, "min_keep_days": 7, "scheduled_cleanup_interval_days": 30},
        "wan": {"delete_percent": 10, "min_keep_days": 7, "scheduled_cleanup_interval_days": 30},
        "isp_status": {"delete_percent": 10, "min_keep_days": 7, "scheduled_cleanup_interval_days": 30},
        "offline": {"delete_percent": 10, "min_keep_days": 7, "scheduled_cleanup_interval_days": 30},
        "mikrotik_logs": {"delete_percent": 10, "min_keep_days": 7, "scheduled_cleanup_interval_days": 30},
        # Audit history is important and comparatively small, so it is excluded by default.
        "auth_audit": {"delete_percent": 0, "min_keep_days": 30, "scheduled_cleanup_interval_days": 30},
    },
}


DATA_RETENTION_NORMAL_FIELDS = {
    "accounts_ping": (
        ("accounts_ping_raw_days", "Raw samples"),
        ("accounts_ping_rollup_days", "Minute rollups"),
    ),
    "usage": (
        ("usage_raw_days", "Usage samples"),
        ("usage_reboot_days", "Reboot history"),
    ),
    "optical": (("optical_days", "Optical readings"),),
    "wan": (("wan_days", "Status and target samples"),),
    "isp_status": (("isp_status_days", "Bandwidth samples"),),
    "offline": (("offline_days", "Offline history"),),
    "mikrotik_logs": (("mikrotik_logs_days", "Log messages"),),
    "auth_audit": (("auth_audit_days", "Audit events"),),
}


_guardian_lock = threading.Lock()
_STATE_KEY = "data_retention_guardian_state"


def _int_value(value, fallback, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(fallback)
    return max(min(parsed, maximum), minimum)


def normalize_data_retention_settings(settings):
    source = settings if isinstance(settings, dict) else {}
    normalized = copy.deepcopy(DATA_RETENTION_DEFAULTS)
    source_guardian = source.get("guardian") if isinstance(source.get("guardian"), dict) else {}
    guardian = normalized["guardian"]
    guardian["trigger_percent"] = _int_value(source_guardian.get("trigger_percent"), 85, 70, 98)
    guardian["recovery_percent"] = _int_value(
        source_guardian.get("recovery_percent"),
        min(80, guardian["trigger_percent"] - 1),
        50,
        guardian["trigger_percent"] - 1,
    )
    guardian["check_interval_minutes"] = _int_value(source_guardian.get("check_interval_minutes"), 5, 1, 60)
    guardian["cooldown_hours"] = _int_value(source_guardian.get("cooldown_hours"), 6, 1, 168)
    guardian["max_rows_per_dataset"] = _int_value(
        source_guardian.get("max_rows_per_dataset"), 100000, 1000, 1000000
    )
    guardian["vacuum_after_cleanup"] = bool(source_guardian.get("vacuum_after_cleanup", True))
    guardian["history_retention_days"] = _int_value(
        source_guardian.get("history_retention_days"), 365, 30, 3650
    )

    source_features = source.get("features") if isinstance(source.get("features"), dict) else {}
    for feature in DATA_RETENTION_FEATURES:
        key = feature["key"]
        source_feature = source_features.get(key) if isinstance(source_features.get(key), dict) else {}
        defaults = DATA_RETENTION_DEFAULTS["features"][key]
        normalized["features"][key] = {
            "delete_percent": _int_value(source_feature.get("delete_percent"), defaults["delete_percent"], 0, 50),
            "min_keep_days": _int_value(source_feature.get("min_keep_days"), defaults["min_keep_days"], 1, 3650),
            "scheduled_cleanup_interval_days": _int_value(
                source_feature.get("scheduled_cleanup_interval_days"),
                defaults["scheduled_cleanup_interval_days"],
                1,
                365,
            ),
        }
    return normalized


def get_data_retention_settings():
    return normalize_data_retention_settings(get_settings("data_retention", DATA_RETENTION_DEFAULTS))


def save_data_retention_settings(settings):
    normalized = normalize_data_retention_settings(settings)
    save_settings("data_retention", normalized)
    return normalized


def scheduled_cleanup_interval_days_for_feature(feature_key, settings=None):
    key = str(feature_key or "").strip().lower()
    feature_keys = {item["key"] for item in DATA_RETENTION_FEATURES}
    if key not in feature_keys:
        raise ValueError(f"Unsupported data-retention feature: {key}")
    current = normalize_data_retention_settings(settings or get_data_retention_settings())
    return int(current["features"][key]["scheduled_cleanup_interval_days"])


def storage_health(settings=None):
    settings = normalize_data_retention_settings(settings or get_data_retention_settings())
    configured_path = Path(os.environ.get("THREEJ_STORAGE_PATH", "/data"))
    storage_path = configured_path if configured_path.exists() else Path("/")
    usage = shutil.disk_usage(str(storage_path))
    used_percent = round((usage.used / usage.total * 100.0) if usage.total else 0.0, 1)
    guardian = settings["guardian"]
    if used_percent >= guardian["trigger_percent"]:
        status = "critical"
    elif used_percent >= guardian["recovery_percent"]:
        status = "warning"
    else:
        status = "healthy"
    return {
        "path": str(storage_path),
        "configured_path": str(configured_path),
        "total_bytes": int(usage.total),
        "used_bytes": int(usage.used),
        "free_bytes": int(usage.free),
        "used_percent": used_percent,
        "status": status,
        "trigger_percent": guardian["trigger_percent"],
        "recovery_percent": guardian["recovery_percent"],
    }


def format_bytes(value):
    size = float(value or 0)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    unit = units[0]
    for candidate in units:
        unit = candidate
        if abs(size) < 1024.0 or candidate == units[-1]:
            break
        size /= 1024.0
    precision = 0 if unit == "B" else 1
    return f"{size:.{precision}f} {unit}"


def normal_retention_values():
    accounts = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    usage = get_settings("usage", USAGE_DEFAULTS)
    optical = get_settings("optical", OPTICAL_DEFAULTS)
    offline = get_settings("offline", OFFLINE_DEFAULTS)
    wan = get_settings("wan_ping", WAN_PING_DEFAULTS)
    isp = get_settings("isp_status", ISP_STATUS_DEFAULTS)
    logs = get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS)
    system = get_settings("system", {"auth": {"audit_retention_days": 180}})
    return {
        "accounts_ping_raw_days": int((accounts.get("storage") or {}).get("raw_retention_days", 365) or 365),
        "accounts_ping_rollup_days": int((accounts.get("storage") or {}).get("rollup_retention_days", 365) or 365),
        "usage_raw_days": int((usage.get("storage") or {}).get("raw_retention_days", 365) or 365),
        "usage_reboot_days": int((usage.get("modem_reboot") or {}).get("history_retention_days", 180) or 180),
        "optical_days": int((optical.get("storage") or {}).get("raw_retention_days", 365) or 365),
        "offline_days": int((offline.get("general") or {}).get("history_retention_days", 365) or 365),
        "wan_days": int((wan.get("general") or {}).get("history_retention_days", 400) or 400),
        "isp_status_days": int((isp.get("general") or {}).get("history_retention_days", 400) or 400),
        "mikrotik_logs_days": int((logs.get("storage") or {}).get("retention_days", 30) or 30),
        "auth_audit_days": int((system.get("auth") or {}).get("audit_retention_days", 180) or 180),
    }


def save_normal_retention_values(values):
    values = values if isinstance(values, dict) else {}

    def days(key, fallback):
        return _int_value(values.get(key), fallback, 1, 3650)

    accounts = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    accounts.setdefault("storage", {})["raw_retention_days"] = days("accounts_ping_raw_days", 365)
    accounts["storage"]["rollup_retention_days"] = days("accounts_ping_rollup_days", 365)
    save_settings("accounts_ping", accounts)

    usage = get_settings("usage", USAGE_DEFAULTS)
    usage.setdefault("storage", {})["raw_retention_days"] = days("usage_raw_days", 365)
    usage.setdefault("modem_reboot", {})["history_retention_days"] = days("usage_reboot_days", 180)
    save_settings("usage", usage)

    optical = get_settings("optical", OPTICAL_DEFAULTS)
    optical.setdefault("storage", {})["raw_retention_days"] = days("optical_days", 365)
    save_settings("optical", optical)

    offline = get_settings("offline", OFFLINE_DEFAULTS)
    offline.setdefault("general", {})["history_retention_days"] = days("offline_days", 365)
    save_settings("offline", offline)

    wan = get_settings("wan_ping", WAN_PING_DEFAULTS)
    wan.setdefault("general", {})["history_retention_days"] = days("wan_days", 400)
    save_settings("wan_ping", wan)

    isp = get_settings("isp_status", ISP_STATUS_DEFAULTS)
    isp.setdefault("general", {})["history_retention_days"] = days("isp_status_days", 400)
    save_settings("isp_status", isp)

    logs = get_settings("mikrotik_logs", MIKROTIK_LOGS_DEFAULTS)
    logs.setdefault("storage", {})["retention_days"] = days("mikrotik_logs_days", 30)
    save_settings("mikrotik_logs", logs)

    system = get_settings("system", {"auth": {"audit_retention_days": 180}})
    system.setdefault("auth", {})["audit_retention_days"] = days("auth_audit_days", 180)
    save_settings("system", system)
    return normal_retention_values()


def data_retention_normal_fields_for_feature(feature_key, values=None):
    key = str(feature_key or "").strip().lower()
    field_specs = DATA_RETENTION_NORMAL_FIELDS.get(key)
    if not field_specs:
        raise ValueError(f"Unsupported data-retention feature: {key}")
    current = values if isinstance(values, dict) else normal_retention_values()
    return [
        {"name": field_name, "label": label, "value": int(current.get(field_name) or 1)}
        for field_name, label in field_specs
    ]


def data_retention_feature_rows(settings=None, include_stats=True):
    settings = normalize_data_retention_settings(settings or get_data_retention_settings())
    normal = normal_retention_values()
    stats_by_dataset = {}
    if include_stats:
        try:
            stats_by_dataset = {row["dataset_key"]: row for row in get_data_retention_dataset_stats()}
        except Exception:
            stats_by_dataset = {}
    normal_labels = {
        "accounts_ping": f"Raw {normal['accounts_ping_raw_days']}d · rollups {normal['accounts_ping_rollup_days']}d",
        "usage": f"Samples {normal['usage_raw_days']}d · reboot history {normal['usage_reboot_days']}d",
        "optical": f"Readings {normal['optical_days']}d",
        "wan": f"Status and targets {normal['wan_days']}d",
        "isp_status": f"Samples {normal['isp_status_days']}d",
        "offline": f"History {normal['offline_days']}d",
        "mikrotik_logs": f"Messages {normal['mikrotik_logs_days']}d",
        "auth_audit": f"Audit events {normal['auth_audit_days']}d",
    }
    catalog = data_retention_dataset_catalog()
    rows = []
    for feature in DATA_RETENTION_FEATURES:
        feature_settings = settings["features"][feature["key"]]
        dataset_rows = []
        total_bytes = 0
        estimated_rows = 0
        for dataset_key in feature["datasets"]:
            stat = stats_by_dataset.get(dataset_key, {})
            spec = catalog[dataset_key]
            total_bytes += int(stat.get("total_bytes") or 0)
            estimated_rows += int(stat.get("estimated_rows") or 0)
            dataset_rows.append(
                {
                    "key": dataset_key,
                    "label": spec["dataset_label"],
                    "table_name": spec["table"],
                    "total_bytes": int(stat.get("total_bytes") or 0),
                    "total_bytes_label": format_bytes(stat.get("total_bytes") or 0),
                    "estimated_rows": int(stat.get("estimated_rows") or 0),
                }
            )
        rows.append(
            {
                **feature,
                **feature_settings,
                "normal_policy": normal_labels[feature["key"]],
                "normal_fields": data_retention_normal_fields_for_feature(feature["key"], normal),
                "datasets_detail": dataset_rows,
                "total_bytes": total_bytes,
                "total_bytes_label": format_bytes(total_bytes),
                "estimated_rows": estimated_rows,
            }
        )
    return rows


def _parse_utc(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def get_data_retention_guardian_state():
    state = get_state(_STATE_KEY, {})
    return state if isinstance(state, dict) else {}


def run_data_retention_guardian_cycle():
    """Check storage and, at most once per cooldown, run one bounded cleanup cycle."""
    if not _guardian_lock.acquire(blocking=False):
        return {"status": "already_running", "rows_deleted": 0}
    try:
        settings = get_data_retention_settings()
        guardian = settings["guardian"]
        health_before = storage_health(settings)
        now = datetime.now(timezone.utc)
        now_iso = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        state = get_data_retention_guardian_state()
        state.update(
            {
                "last_checked_at": now_iso,
                "last_disk_percent": health_before["used_percent"],
                "last_storage_status": health_before["status"],
            }
        )
        if health_before["used_percent"] < guardian["trigger_percent"]:
            state["last_check_result"] = "below_threshold"
            save_state(_STATE_KEY, state)
            return {"status": "below_threshold", "rows_deleted": 0, "storage": health_before}

        last_triggered = _parse_utc(state.get("last_triggered_at"))
        cooldown_until = last_triggered + timedelta(hours=guardian["cooldown_hours"]) if last_triggered else None
        if cooldown_until and now < cooldown_until:
            state["last_check_result"] = "cooldown"
            state["cooldown_until"] = cooldown_until.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            save_state(_STATE_KEY, state)
            return {"status": "cooldown", "rows_deleted": 0, "storage": health_before}

        run_id = f"emergency-{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        # Persist the cooldown before deletion so a process crash cannot immediately retrigger a loop.
        state.update(
            {
                "last_triggered_at": now_iso,
                "last_run_id": run_id,
                "last_check_result": "running",
                "cooldown_until": (now + timedelta(hours=guardian["cooldown_hours"]))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
        save_state(_STATE_KEY, state)

        try:
            stats = {row["dataset_key"]: row for row in get_data_retention_dataset_stats()}
        except Exception:
            stats = {}
        feature_order = sorted(
            DATA_RETENTION_FEATURES,
            key=lambda item: -sum(int((stats.get(key) or {}).get("total_bytes") or 0) for key in item["datasets"]),
        )
        total_deleted = 0
        attempted = 0
        failures = []
        vacuum_candidates = []
        for feature in feature_order:
            feature_settings = settings["features"][feature["key"]]
            delete_percent = int(feature_settings["delete_percent"])
            if delete_percent <= 0:
                continue
            min_keep_days = int(feature_settings["min_keep_days"])
            cutoff = (now - timedelta(days=min_keep_days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            for dataset_key in feature["datasets"]:
                attempted += 1
                started_at = utc_now_iso()
                started_monotonic = time.monotonic()
                estimate = max(int((stats.get(dataset_key) or {}).get("estimated_rows") or 0), 0)
                target_rows = max(int(estimate * delete_percent / 100.0), 1)
                target_rows = min(target_rows, int(guardian["max_rows_per_dataset"]))
                details = (
                    f"Bounded guardian target {target_rows} rows from an estimated {estimate}; "
                    f"oldest eligible data only. Collector enabled state is intentionally ignored."
                )
                try:
                    deleted = delete_data_retention_dataset_oldest(dataset_key, cutoff, target_rows)
                    total_deleted += deleted
                    if deleted > 0:
                        vacuum_candidates.append(dataset_key)
                    health_after_dataset = storage_health(settings)
                    record_data_retention_event(
                        run_id=run_id,
                        started_at=started_at,
                        completed_at=utc_now_iso(),
                        trigger_type="emergency",
                        dataset_key=dataset_key,
                        status="completed",
                        rows_deleted=deleted,
                        cutoff_at=cutoff,
                        delete_percent=delete_percent,
                        min_keep_days=min_keep_days,
                        disk_percent_before=health_before["used_percent"],
                        disk_percent_after=health_after_dataset["used_percent"],
                        duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                        actor_username="system",
                        details=details,
                    )
                except Exception as exc:
                    error = str(exc)[:500]
                    failures.append(f"{dataset_key}: {error}")
                    record_data_retention_event(
                        run_id=run_id,
                        started_at=started_at,
                        completed_at=utc_now_iso(),
                        trigger_type="emergency",
                        dataset_key=dataset_key,
                        status="failed",
                        rows_deleted=0,
                        cutoff_at=cutoff,
                        delete_percent=delete_percent,
                        min_keep_days=min_keep_days,
                        disk_percent_before=health_before["used_percent"],
                        disk_percent_after=storage_health(settings)["used_percent"],
                        duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                        actor_username="system",
                        details=details,
                        error_message=error,
                    )

        vacuum_result = {"vacuumed": [], "errors": {}}
        if guardian["vacuum_after_cleanup"] and vacuum_candidates:
            vacuum_result = vacuum_data_retention_datasets(vacuum_candidates)
            for key, error in (vacuum_result.get("errors") or {}).items():
                failures.append(f"vacuum {key}: {error}")

        history_cutoff = (now - timedelta(days=guardian["history_retention_days"])).replace(microsecond=0)
        deleted_history_rows = delete_data_retention_history_older_than(
            history_cutoff.isoformat().replace("+00:00", "Z")
        )
        health_after = storage_health(settings)
        state.update(
            {
                "last_completed_at": utc_now_iso(),
                "last_check_result": "completed_with_errors" if failures else "completed",
                "last_rows_deleted": total_deleted,
                "last_datasets_attempted": attempted,
                "last_disk_percent_after": health_after["used_percent"],
                "last_error": "; ".join(failures)[:2000],
                "last_vacuumed_datasets": vacuum_result.get("vacuumed") or [],
                "last_history_rows_deleted": deleted_history_rows,
            }
        )
        save_state(_STATE_KEY, state)
        return {
            "status": state["last_check_result"],
            "run_id": run_id,
            "rows_deleted": total_deleted,
            "datasets_attempted": attempted,
            "storage_before": health_before,
            "storage_after": health_after,
            "errors": failures,
        }
    except Exception as exc:
        state = get_data_retention_guardian_state()
        state.update({"last_check_result": "failed", "last_error": str(exc)[:2000], "last_completed_at": utc_now_iso()})
        save_state(_STATE_KEY, state)
        raise
    finally:
        _guardian_lock.release()
