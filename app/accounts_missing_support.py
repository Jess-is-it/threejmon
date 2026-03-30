import copy
from datetime import datetime, timedelta

from .accounts_ping_sources import (
    ACCOUNTS_PING_SOURCE_MIKROTIK,
    build_accounts_ping_account_id,
    normalize_accounts_ping_device,
)
from .db import (
    delete_accounts_ping_results_for_pppoe,
    delete_accounts_ping_rollups_for_account_ids,
    delete_auth_audit_logs_for_pppoe,
    delete_offline_history_for_pppoe,
    delete_optical_results_for_pppoe,
    delete_pppoe_usage_samples_for_pppoe,
    delete_surveillance_sessions_for_pppoe,
)
from .mikrotik import RouterOSClient
from .notifiers import usage as usage_notifier
from .settings_defaults import ACCOUNTS_MISSING_DEFAULTS, SURVEILLANCE_DEFAULTS, WAN_PING_DEFAULTS
from .settings_store import get_settings, get_state, save_settings, save_state


def _iso_now(now=None):
    now = now or datetime.utcnow()
    return now.replace(microsecond=0).isoformat() + "Z"


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


def _pppoe_key(value):
    return str(value or "").strip().lower()


def _unique_sorted(values):
    return sorted({str(item or "").strip() for item in (values or []) if str(item or "").strip()})


def normalize_accounts_missing_settings(raw):
    settings = copy.deepcopy(ACCOUNTS_MISSING_DEFAULTS)
    if isinstance(raw, dict):
        if isinstance(raw.get("source"), dict):
            settings["source"].update(raw.get("source") or {})
            if isinstance((raw.get("source") or {}).get("mikrotik"), dict):
                settings["source"]["mikrotik"].update((raw.get("source") or {}).get("mikrotik") or {})
        if isinstance(raw.get("auto_delete"), dict):
            settings["auto_delete"].update(raw.get("auto_delete") or {})
        if "enabled" in raw:
            settings["enabled"] = bool(raw.get("enabled"))

    source = settings.setdefault("source", {})
    try:
        source["refresh_minutes"] = max(int(source.get("refresh_minutes", ACCOUNTS_MISSING_DEFAULTS["source"]["refresh_minutes"]) or 1), 1)
    except Exception:
        source["refresh_minutes"] = ACCOUNTS_MISSING_DEFAULTS["source"]["refresh_minutes"]

    mikrotik = source.setdefault("mikrotik", {})
    router_enabled = mikrotik.get("router_enabled")
    mikrotik["router_enabled"] = {
        str(key).strip(): bool(value)
        for key, value in (router_enabled or {}).items()
        if str(key).strip()
    }
    try:
        mikrotik["timeout_seconds"] = max(int(mikrotik.get("timeout_seconds", ACCOUNTS_MISSING_DEFAULTS["source"]["mikrotik"]["timeout_seconds"]) or 1), 1)
    except Exception:
        mikrotik["timeout_seconds"] = ACCOUNTS_MISSING_DEFAULTS["source"]["mikrotik"]["timeout_seconds"]

    auto_delete = settings.setdefault("auto_delete", {})
    auto_delete["enabled"] = bool(auto_delete.get("enabled"))
    try:
        auto_delete["days"] = max(int(auto_delete.get("days", ACCOUNTS_MISSING_DEFAULTS["auto_delete"]["days"]) or 1), 1)
    except Exception:
        auto_delete["days"] = ACCOUNTS_MISSING_DEFAULTS["auto_delete"]["days"]

    settings["enabled"] = bool(settings.get("enabled"))
    return settings


def selected_accounts_missing_routers(settings, wan_settings=None):
    settings = normalize_accounts_missing_settings(settings)
    if not isinstance(wan_settings, dict):
        wan_settings = get_settings("wan_ping", WAN_PING_DEFAULTS)
    routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
    enabled_map = (settings.get("source") or {}).get("mikrotik", {}).get("router_enabled") or {}
    selected = []
    for router in routers:
        if not isinstance(router, dict):
            continue
        router_id = str(router.get("id") or "").strip()
        host = str(router.get("host") or "").strip()
        if not router_id or not host:
            continue
        if not bool(enabled_map.get(router_id, True)):
            continue
        selected.append(router)
    return selected


def build_accounts_missing_secret_snapshot(settings, routers=None, now=None):
    settings = normalize_accounts_missing_settings(settings)
    now_iso = _iso_now(now)
    routers = list(routers or selected_accounts_missing_routers(settings))
    timeout_seconds = int(((settings.get("source") or {}).get("mikrotik") or {}).get("timeout_seconds", 5) or 5)

    secret_map = {}
    router_status = []
    selected_router_ids = []
    connected_router_ids = []
    secret_total = 0

    for router in routers:
        if not isinstance(router, dict):
            continue
        router_id = str(router.get("id") or "").strip()
        router_name = str(router.get("name") or router_id or "router").strip()
        host = str(router.get("host") or "").strip()
        if not router_id or not host:
            continue
        selected_router_ids.append(router_id)

        if router.get("use_tls"):
            router_status.append(
                {
                    "router_id": router_id,
                    "router_name": router_name,
                    "secret_count": 0,
                    "connected": False,
                    "error": "TLS/API-SSL is not supported by the current RouterOS API client. Disable TLS or use port 8728.",
                }
            )
            continue

        client = RouterOSClient(
            host,
            int(router.get("port", 8728) or 8728),
            router.get("username", ""),
            router.get("password", ""),
            timeout=timeout_seconds,
        )
        secret_rows = []
        connected = False
        error = ""
        try:
            client.connect()
            connected = True
            connected_router_ids.append(router_id)
            secret_rows = usage_notifier.fetch_pppoe_secrets(client) or []
        except Exception as exc:
            error = str(exc)
        finally:
            client.close()

        secret_count = 0
        for row in secret_rows:
            pppoe = str(row.get("name") or "").strip()
            if not pppoe:
                continue
            key = _pppoe_key(pppoe)
            item = secret_map.setdefault(
                key,
                {
                    "pppoe": pppoe,
                    "router_ids": [],
                    "router_names": [],
                    "last_seen_at": now_iso,
                },
            )
            if router_id not in item["router_ids"]:
                item["router_ids"].append(router_id)
            if router_name and router_name not in item["router_names"]:
                item["router_names"].append(router_name)
            item["last_seen_at"] = now_iso
            secret_count += 1
            secret_total += 1

        router_status.append(
            {
                "router_id": router_id,
                "router_name": router_name,
                "secret_count": secret_count,
                "connected": bool(connected),
                "error": error,
            }
        )

    validation_active = bool(selected_router_ids) and len(connected_router_ids) == len(selected_router_ids)
    paused_reason = ""
    if not selected_router_ids:
        paused_reason = "No routers are enabled for Accounts Missing."
    elif not validation_active:
        paused_reason = (
            f"{len(selected_router_ids) - len(connected_router_ids)} of {len(selected_router_ids)} selected router(s) are unavailable. "
            "Missing detection is paused until all selected routers respond."
        )

    return {
        "checked_at": now_iso,
        "secret_map": secret_map,
        "router_status": router_status,
        "selected_router_ids": selected_router_ids,
        "connected_router_ids": connected_router_ids,
        "selected_router_count": len(selected_router_ids),
        "connected_router_count": len(connected_router_ids),
        "secret_total": secret_total,
        "validation_active": validation_active,
        "paused_reason": paused_reason,
    }


def _merge_known_account(
    known_map,
    pppoe,
    *,
    now_iso="",
    ip="",
    router_id="",
    router_name="",
    router_ids=None,
    router_names=None,
    source="",
    eligible=False,
    ever_seen_in_secret=False,
    first_seen_at="",
    last_secret_seen_at="",
):
    pppoe_value = str(pppoe or "").strip()
    key = _pppoe_key(pppoe_value)
    if not key:
        return
    item = known_map.get(key) if isinstance(known_map.get(key), dict) else {}
    if not item:
        item = {
            "pppoe": pppoe_value,
            "first_seen_at": first_seen_at or now_iso,
            "last_seen_at": now_iso,
            "last_ip": str(ip or "").strip(),
            "router_ids": [],
            "router_names": [],
            "last_router_id": str(router_id or "").strip(),
            "last_router_name": str(router_name or "").strip(),
            "sources": [],
            "eligible": False,
            "ever_seen_in_secret": False,
            "last_secret_seen_at": str(last_secret_seen_at or "").strip(),
            "first_missing_at": "",
            "last_missing_at": "",
            "last_present_at": "",
        }
        known_map[key] = item

    if not item.get("pppoe"):
        item["pppoe"] = pppoe_value
    if first_seen_at and (not item.get("first_seen_at") or str(first_seen_at) < str(item.get("first_seen_at"))):
        item["first_seen_at"] = str(first_seen_at)
    if now_iso:
        item["last_seen_at"] = str(now_iso)
    if ip:
        item["last_ip"] = str(ip).strip()

    merged_router_ids = list(item.get("router_ids") or [])
    merged_router_names = list(item.get("router_names") or [])
    router_id_value = str(router_id or "").strip()
    router_name_value = str(router_name or "").strip()
    if router_id_value and router_id_value not in merged_router_ids:
        merged_router_ids.append(router_id_value)
    if router_name_value and router_name_value not in merged_router_names:
        merged_router_names.append(router_name_value)
    for value in router_ids or []:
        normalized = str(value or "").strip()
        if normalized and normalized not in merged_router_ids:
            merged_router_ids.append(normalized)
    for value in router_names or []:
        normalized = str(value or "").strip()
        if normalized and normalized not in merged_router_names:
            merged_router_names.append(normalized)
    item["router_ids"] = _unique_sorted(merged_router_ids)
    item["router_names"] = _unique_sorted(merged_router_names)

    if router_id_value:
        item["last_router_id"] = router_id_value
    if router_name_value:
        item["last_router_name"] = router_name_value
    elif router_id_value and not item.get("last_router_name"):
        item["last_router_name"] = router_id_value

    sources = list(item.get("sources") or [])
    if source:
        source_value = str(source).strip()
        if source_value and source_value not in sources:
            sources.append(source_value)
    item["sources"] = _unique_sorted(sources)

    item["eligible"] = bool(item.get("eligible") or eligible or router_id_value or item.get("router_ids"))
    item["ever_seen_in_secret"] = bool(item.get("ever_seen_in_secret") or ever_seen_in_secret)
    if last_secret_seen_at:
        item["last_secret_seen_at"] = str(last_secret_seen_at)
    return item


def collect_accounts_missing_known_map(previous_state=None, now=None):
    now_iso = _iso_now(now)
    previous_state = previous_state if isinstance(previous_state, dict) else {}
    known_map = {}

    for raw in previous_state.get("known_accounts") or []:
        if not isinstance(raw, dict):
            continue
        key = _pppoe_key(raw.get("pppoe"))
        if not key:
            continue
        item = dict(raw)
        item["router_ids"] = _unique_sorted(item.get("router_ids") or [])
        item["router_names"] = _unique_sorted(item.get("router_names") or [])
        item["sources"] = _unique_sorted(item.get("sources") or [])
        item["eligible"] = bool(item.get("eligible") or item.get("ever_seen_in_secret") or item["router_ids"])
        item["ever_seen_in_secret"] = bool(item.get("ever_seen_in_secret"))
        known_map[key] = item

    accounts_ping_state = get_state("accounts_ping_state", {})
    for raw in accounts_ping_state.get("devices") or []:
        device = normalize_accounts_ping_device(raw)
        if not device:
            continue
        _merge_known_account(
            known_map,
            device.get("pppoe"),
            now_iso=now_iso,
            ip=device.get("ip"),
            router_id=device.get("router_id"),
            router_name=device.get("router_name"),
            source="accounts_ping",
            eligible=bool((device.get("router_id") or "").strip()),
        )

    usage_state = get_state("usage_state", {})
    for row in usage_state.get("active_rows") or []:
        if not isinstance(row, dict):
            continue
        _merge_known_account(
            known_map,
            row.get("pppoe") or row.get("name"),
            now_iso=now_iso,
            ip=row.get("address"),
            router_id=row.get("router_id"),
            router_name=row.get("router_name"),
            source="usage",
            eligible=bool((row.get("router_id") or "").strip()),
        )
    for row in usage_state.get("offline_rows") or []:
        if not isinstance(row, dict):
            continue
        _merge_known_account(
            known_map,
            row.get("pppoe"),
            now_iso=now_iso,
            router_id=row.get("router_id"),
            router_name=row.get("router_name"),
            source="usage_offline",
            eligible=bool((row.get("router_id") or "").strip()),
        )

    offline_state = get_state("offline_state", {})
    for row in offline_state.get("rows") or []:
        if not isinstance(row, dict):
            continue
        _merge_known_account(
            known_map,
            row.get("pppoe"),
            now_iso=now_iso,
            router_id=row.get("router_id"),
            router_name=row.get("router_name"),
            source="offline",
            eligible=bool((row.get("router_id") or "").strip()),
        )
    tracker = offline_state.get("tracker") if isinstance(offline_state.get("tracker"), dict) else {}
    for item in tracker.values():
        if not isinstance(item, dict):
            continue
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        _merge_known_account(
            known_map,
            meta.get("pppoe"),
            now_iso=now_iso,
            router_id=meta.get("router_id"),
            router_name=meta.get("router_name"),
            source="offline_tracker",
            eligible=bool((meta.get("router_id") or "").strip()),
        )

    optical_state = get_state("optical_state", {})
    for item in optical_state.get("current_devices") or []:
        if not isinstance(item, dict):
            continue
        _merge_known_account(
            known_map,
            item.get("pppoe"),
            now_iso=now_iso,
            ip=item.get("ip"),
            router_ids=item.get("router_ids") or [],
            router_names=item.get("router_names") or [],
            source="optical",
            eligible=bool(item.get("router_ids")),
        )
    for item in optical_state.get("known_accounts") or []:
        if not isinstance(item, dict):
            continue
        _merge_known_account(
            known_map,
            item.get("pppoe"),
            now_iso=now_iso,
            ip=item.get("ip"),
            router_id=item.get("router_id"),
            router_name=item.get("router_name"),
            source="optical_truth",
            eligible=bool((item.get("router_id") or "").strip()),
        )

    surveillance_settings = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    for entry in surveillance_settings.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        _merge_known_account(
            known_map,
            entry.get("pppoe"),
            now_iso=now_iso,
            ip=entry.get("ip"),
            source="surveillance",
            first_seen_at=entry.get("added_at") or "",
        )

    return known_map


def _missing_entry_from_known(item, now=None):
    now = now or datetime.utcnow()
    started_at = str(item.get("first_missing_at") or "").strip()
    started_dt = _parse_iso(started_at)
    missing_for_seconds = int(max((now - started_dt).total_seconds(), 0)) if started_dt else 0
    return {
        "pppoe": str(item.get("pppoe") or "").strip(),
        "last_ip": str(item.get("last_ip") or "").strip(),
        "last_router_id": str(item.get("last_router_id") or "").strip(),
        "last_router_name": str(item.get("last_router_name") or "").strip(),
        "router_ids": _unique_sorted(item.get("router_ids") or []),
        "router_names": _unique_sorted(item.get("router_names") or []),
        "sources": _unique_sorted(item.get("sources") or []),
        "source_count": len(_unique_sorted(item.get("sources") or [])),
        "first_seen_at": str(item.get("first_seen_at") or "").strip(),
        "last_seen_at": str(item.get("last_seen_at") or "").strip(),
        "last_secret_seen_at": str(item.get("last_secret_seen_at") or "").strip(),
        "first_missing_at": started_at,
        "last_missing_at": str(item.get("last_missing_at") or "").strip(),
        "missing_for_seconds": missing_for_seconds,
        "eligible": bool(item.get("eligible")),
        "ever_seen_in_secret": bool(item.get("ever_seen_in_secret")),
    }


def reconcile_accounts_missing_state(settings, previous_state=None, wan_settings=None, now=None):
    now = now or datetime.utcnow()
    now_iso = _iso_now(now)
    settings = normalize_accounts_missing_settings(settings)
    previous_state = previous_state if isinstance(previous_state, dict) else {}

    routers = selected_accounts_missing_routers(settings, wan_settings=wan_settings)
    secret_snapshot = build_accounts_missing_secret_snapshot(settings, routers=routers, now=now)
    secret_map = secret_snapshot.get("secret_map") if isinstance(secret_snapshot.get("secret_map"), dict) else {}
    validation_active = bool(secret_snapshot.get("validation_active"))

    known_map = collect_accounts_missing_known_map(previous_state=previous_state, now=now)
    if validation_active:
        for key, secret in secret_map.items():
            _merge_known_account(
                known_map,
                secret.get("pppoe"),
                now_iso=now_iso,
                router_ids=secret.get("router_ids") or [],
                router_names=secret.get("router_names") or [],
                source="mikrotik_secret",
                eligible=True,
                ever_seen_in_secret=True,
                last_secret_seen_at=now_iso,
            )
            item = known_map.get(key) if isinstance(known_map.get(key), dict) else {}
            if not item:
                continue
            item["current_in_secret"] = True
            item["first_missing_at"] = ""
            item["last_missing_at"] = ""
            item["last_present_at"] = now_iso
            if secret.get("router_ids"):
                item["last_router_id"] = str((secret.get("router_ids") or [""])[-1] or "").strip()
            if secret.get("router_names"):
                item["last_router_name"] = str((secret.get("router_names") or [""])[-1] or "").strip()

        for key, item in known_map.items():
            if key in secret_map:
                continue
            item["current_in_secret"] = False
            eligible = bool(item.get("eligible") or item.get("ever_seen_in_secret"))
            if eligible:
                item["first_missing_at"] = str(item.get("first_missing_at") or now_iso).strip()
                item["last_missing_at"] = now_iso
            else:
                item["first_missing_at"] = ""
                item["last_missing_at"] = ""
    else:
        for item in known_map.values():
            if item.get("first_missing_at"):
                item["current_in_secret"] = False
            else:
                item["current_in_secret"] = None

    known_accounts = []
    missing_entries = []
    present_total = 0
    for key in sorted(known_map.keys()):
        item = dict(known_map.get(key) or {})
        item["router_ids"] = _unique_sorted(item.get("router_ids") or [])
        item["router_names"] = _unique_sorted(item.get("router_names") or [])
        item["sources"] = _unique_sorted(item.get("sources") or [])
        item["eligible"] = bool(item.get("eligible") or item.get("ever_seen_in_secret") or item["router_ids"])
        if bool(item.get("current_in_secret")):
            present_total += 1
        known_accounts.append(item)
        if str(item.get("first_missing_at") or "").strip():
            missing_entries.append(_missing_entry_from_known(item, now=now))

    return {
        "last_check_at": now_iso,
        "last_success_at": now_iso if validation_active else str(previous_state.get("last_success_at") or "").strip(),
        "router_status": secret_snapshot.get("router_status") or [],
        "selected_router_ids": secret_snapshot.get("selected_router_ids") or [],
        "connected_router_ids": secret_snapshot.get("connected_router_ids") or [],
        "selected_router_count": int(secret_snapshot.get("selected_router_count") or 0),
        "connected_router_count": int(secret_snapshot.get("connected_router_count") or 0),
        "validation_active": validation_active,
        "validation_paused_reason": str(secret_snapshot.get("paused_reason") or "").strip(),
        "known_accounts": known_accounts,
        "missing_entries": missing_entries,
        "source_stats": {
            "known_total": len(known_accounts),
            "present_total": present_total,
            "missing_total": len(missing_entries),
            "secret_total": int(secret_snapshot.get("secret_total") or 0),
        },
    }


def auto_delete_accounts_missing_entries(state, settings, now=None):
    now = now or datetime.utcnow()
    settings = normalize_accounts_missing_settings(settings)
    auto_delete = settings.get("auto_delete") if isinstance(settings.get("auto_delete"), dict) else {}
    if not bool(auto_delete.get("enabled")):
        return state, []
    cutoff = now - timedelta(days=max(int(auto_delete.get("days", 30) or 30), 1))
    deleted = []
    for entry in list((state or {}).get("missing_entries") or []):
        if not isinstance(entry, dict):
            continue
        pppoe = str(entry.get("pppoe") or "").strip()
        first_missing_dt = _parse_iso(entry.get("first_missing_at"))
        if not pppoe or not first_missing_dt or first_missing_dt > cutoff:
            continue
        purge_pppoe_account_data(pppoe)
        deleted.append(pppoe)
    if not deleted:
        return state, []
    deleted_keys = {_pppoe_key(item) for item in deleted}
    next_state = copy.deepcopy(state if isinstance(state, dict) else {})
    next_state["known_accounts"] = [
        item
        for item in (next_state.get("known_accounts") or [])
        if not isinstance(item, dict) or _pppoe_key(item.get("pppoe")) not in deleted_keys
    ]
    next_state["missing_entries"] = [
        item
        for item in (next_state.get("missing_entries") or [])
        if not isinstance(item, dict) or _pppoe_key(item.get("pppoe")) not in deleted_keys
    ]
    stats = next_state.get("source_stats") if isinstance(next_state.get("source_stats"), dict) else {}
    stats["known_total"] = len(next_state.get("known_accounts") or [])
    stats["missing_total"] = len(next_state.get("missing_entries") or [])
    next_state["source_stats"] = stats
    return next_state, deleted


def purge_pppoe_account_data(pppoe):
    pppoe = str(pppoe or "").strip()
    if not pppoe:
        return {"ok": False, "pppoe": "", "account_ids": []}

    pppoe_key = _pppoe_key(pppoe)
    accounts_ping_state = get_state("accounts_ping_state", {})
    account_ids = {build_accounts_ping_account_id(pppoe)}
    for raw in accounts_ping_state.get("devices") or []:
        device = normalize_accounts_ping_device(raw)
        if not device:
            continue
        if _pppoe_key(device.get("pppoe")) != pppoe_key:
            continue
        account_id = str(device.get("account_id") or "").strip()
        if account_id:
            account_ids.add(account_id)

    wan_settings = get_settings("wan_ping", WAN_PING_DEFAULTS)
    for router in wan_settings.get("pppoe_routers") or []:
        if not isinstance(router, dict):
            continue
        router_id = str(router.get("id") or "").strip()
        if not router_id:
            continue
        account_ids.add(
            build_accounts_ping_account_id(
                pppoe,
                source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
                router_id=router_id,
            )
        )
    account_ids = {item for item in account_ids if item}

    delete_accounts_ping_results_for_pppoe(pppoe, sorted(account_ids))
    delete_accounts_ping_rollups_for_account_ids(sorted(account_ids))
    delete_optical_results_for_pppoe(pppoe)
    delete_pppoe_usage_samples_for_pppoe(pppoe)
    delete_offline_history_for_pppoe(pppoe)
    delete_surveillance_sessions_for_pppoe(pppoe)
    delete_auth_audit_logs_for_pppoe(pppoe)

    surveillance_settings = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    entries = surveillance_settings.get("entries") if isinstance(surveillance_settings.get("entries"), list) else []
    filtered_entries = [
        entry
        for entry in entries
        if not isinstance(entry, dict) or _pppoe_key(entry.get("pppoe")) != pppoe_key
    ]
    if len(filtered_entries) != len(entries):
        surveillance_settings["entries"] = filtered_entries
        save_settings("surveillance", surveillance_settings)

    if isinstance(accounts_ping_state, dict):
        devices = accounts_ping_state.get("devices") if isinstance(accounts_ping_state.get("devices"), list) else []
        accounts = accounts_ping_state.get("accounts") if isinstance(accounts_ping_state.get("accounts"), dict) else {}
        accounts_ping_state["devices"] = [
            device
            for device in devices
            if not isinstance(device, dict) or _pppoe_key(device.get("pppoe") or device.get("name")) != pppoe_key
        ]
        for account_id in list(accounts.keys()):
            if account_id in account_ids:
                accounts.pop(account_id, None)
        seeded = accounts_ping_state.get("surveillance_sessions_seeded")
        if isinstance(seeded, list):
            accounts_ping_state["surveillance_sessions_seeded"] = [
                item for item in seeded if _pppoe_key(item) != pppoe_key
            ]
        accounts_ping_state["accounts"] = accounts
        save_state("accounts_ping_state", accounts_ping_state)

    usage_state = get_state("usage_state", {})
    if isinstance(usage_state, dict):
        usage_state["active_rows"] = [
            row
            for row in (usage_state.get("active_rows") or [])
            if not isinstance(row, dict) or _pppoe_key(row.get("pppoe") or row.get("name")) != pppoe_key
        ]
        usage_state["offline_rows"] = [
            row
            for row in (usage_state.get("offline_rows") or [])
            if not isinstance(row, dict) or _pppoe_key(row.get("pppoe")) != pppoe_key
        ]
        anytime = usage_state.get("anytime_issues") if isinstance(usage_state.get("anytime_issues"), dict) else {}
        usage_state["anytime_issues"] = {
            key: value
            for key, value in anytime.items()
            if _pppoe_key(str(key).split("|", 1)[-1]) != pppoe_key
        }
        prev_bytes = usage_state.get("prev_bytes") if isinstance(usage_state.get("prev_bytes"), dict) else {}
        usage_state["prev_bytes"] = {
            key: value
            for key, value in prev_bytes.items()
            if _pppoe_key(str(key).split("|", 1)[-1]) != pppoe_key
        }
        pppoe_hosts = usage_state.get("pppoe_hosts") if isinstance(usage_state.get("pppoe_hosts"), dict) else {}
        usage_state["pppoe_hosts"] = {
            key: value
            for key, value in pppoe_hosts.items()
            if _pppoe_key(key) != pppoe_key
        }
        secrets_cache = usage_state.get("secrets_cache") if isinstance(usage_state.get("secrets_cache"), dict) else {}
        next_secrets_cache = {}
        for router_id, rows in secrets_cache.items():
            if not isinstance(rows, list):
                next_secrets_cache[router_id] = rows
                continue
            next_secrets_cache[router_id] = [
                row
                for row in rows
                if not isinstance(row, dict) or _pppoe_key(row.get("name")) != pppoe_key
            ]
        usage_state["secrets_cache"] = next_secrets_cache
        save_state("usage_state", usage_state)

    offline_state = get_state("offline_state", {})
    if isinstance(offline_state, dict):
        offline_state["rows"] = [
            row
            for row in (offline_state.get("rows") or [])
            if not isinstance(row, dict) or _pppoe_key(row.get("pppoe")) != pppoe_key
        ]
        tracker = offline_state.get("tracker") if isinstance(offline_state.get("tracker"), dict) else {}
        offline_state["tracker"] = {
            key: value
            for key, value in tracker.items()
            if _pppoe_key((value.get("meta") or {}).get("pppoe") if isinstance(value, dict) else "") != pppoe_key
        }
        save_state("offline_state", offline_state)

    optical_state = get_state("optical_state", {})
    if isinstance(optical_state, dict):
        current_devices = [
            item
            for item in (optical_state.get("current_devices") or [])
            if not isinstance(item, dict) or _pppoe_key(item.get("pppoe")) != pppoe_key
        ]
        known_accounts = [
            item
            for item in (optical_state.get("known_accounts") or [])
            if not isinstance(item, dict) or _pppoe_key(item.get("pppoe")) != pppoe_key
        ]
        optical_state["current_devices"] = current_devices
        optical_state["known_accounts"] = known_accounts
        optical_state["current_device_ids"] = [
            str(item.get("device_id") or "").strip()
            for item in current_devices
            if isinstance(item, dict) and str(item.get("device_id") or "").strip()
        ]
        optical_state["current_pppoe_keys"] = _unique_sorted(
            _pppoe_key(item.get("pppoe"))
            for item in current_devices
            if isinstance(item, dict) and _pppoe_key(item.get("pppoe"))
        )
        optical_state["current_ip_keys"] = _unique_sorted(
            str(item.get("ip") or "").strip()
            for item in current_devices
            if isinstance(item, dict) and str(item.get("ip") or "").strip()
        )
        save_state("optical_state", optical_state)

    accounts_missing_state = get_state("accounts_missing_state", {})
    if isinstance(accounts_missing_state, dict):
        accounts_missing_state["known_accounts"] = [
            item
            for item in (accounts_missing_state.get("known_accounts") or [])
            if not isinstance(item, dict) or _pppoe_key(item.get("pppoe")) != pppoe_key
        ]
        accounts_missing_state["missing_entries"] = [
            item
            for item in (accounts_missing_state.get("missing_entries") or [])
            if not isinstance(item, dict) or _pppoe_key(item.get("pppoe")) != pppoe_key
        ]
        stats = accounts_missing_state.get("source_stats") if isinstance(accounts_missing_state.get("source_stats"), dict) else {}
        stats["known_total"] = len(accounts_missing_state.get("known_accounts") or [])
        stats["missing_total"] = len(accounts_missing_state.get("missing_entries") or [])
        accounts_missing_state["source_stats"] = stats
        save_state("accounts_missing_state", accounts_missing_state)

    return {"ok": True, "pppoe": pppoe, "account_ids": sorted(account_ids)}
