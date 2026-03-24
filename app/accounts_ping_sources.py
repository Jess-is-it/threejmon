import base64
from datetime import datetime

from .mikrotik import RouterOSClient
from .notifiers import rto as rto_notifier
from .notifiers import usage as usage_notifier

ACCOUNTS_PING_SOURCE_SSH_CSV = "ssh_csv"
ACCOUNTS_PING_SOURCE_MIKROTIK = "mikrotik_routers"


def normalize_accounts_ping_source_mode(value):
    raw = str(value or "").strip().lower()
    if raw in {
        ACCOUNTS_PING_SOURCE_MIKROTIK,
        "mikrotik",
        "mikrotik_router",
        "mikrotik_routers",
        "router",
        "routers",
    }:
        return ACCOUNTS_PING_SOURCE_MIKROTIK
    return ACCOUNTS_PING_SOURCE_SSH_CSV


def build_accounts_ping_account_id(pppoe, source_mode=ACCOUNTS_PING_SOURCE_SSH_CSV, router_id=""):
    pppoe_value = (pppoe or "").strip()
    if not pppoe_value:
        return ""
    source_mode = normalize_accounts_ping_source_mode(source_mode)
    router_value = (router_id or "").strip()
    if source_mode == ACCOUNTS_PING_SOURCE_MIKROTIK and router_value:
        raw = f"mikrotik:{router_value}:{pppoe_value}".encode("utf-8")
    else:
        raw = pppoe_value.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def normalize_accounts_ping_device(device, default_source_mode=ACCOUNTS_PING_SOURCE_SSH_CSV):
    if not isinstance(device, dict):
        return None
    pppoe = (device.get("pppoe") or device.get("name") or "").strip()
    ip = (device.get("ip") or "").strip()
    router_id = (device.get("router_id") or "").strip()
    router_name = (device.get("router_name") or "").strip()
    source_mode = normalize_accounts_ping_source_mode(device.get("source_mode") or default_source_mode)
    account_id = (
        (device.get("account_id") or "").strip()
        or build_accounts_ping_account_id(pppoe, source_mode=source_mode, router_id=router_id)
    )
    if not pppoe or not account_id:
        return None
    return {
        "account_id": account_id,
        "pppoe": pppoe,
        "name": pppoe,
        "ip": ip,
        "router_id": router_id,
        "router_name": router_name,
        "source_mode": source_mode,
        "source_missing": bool(device.get("source_missing")),
        "source_missing_since": (device.get("source_missing_since") or "").strip(),
        "last_source_seen_at": (device.get("last_source_seen_at") or "").strip(),
    }


def build_accounts_ping_account_ids_by_pppoe(devices):
    mapping = {}
    for raw_device in devices or []:
        device = normalize_accounts_ping_device(raw_device)
        if not device:
            continue
        key = device["pppoe"].strip().lower()
        if not key:
            continue
        mapping.setdefault(key, [])
        if device["account_id"] not in mapping[key]:
            mapping[key].append(device["account_id"])
    return mapping


def build_accounts_ping_csv_devices(cfg):
    csv_text = rto_notifier.fetch_csv_text(cfg)
    parsed = rto_notifier.parse_devices(csv_text)
    devices = []
    for item in parsed or []:
        device = normalize_accounts_ping_device(
            {
                "pppoe": (item.get("pppoe") or item.get("name") or item.get("ip") or "").strip(),
                "name": (item.get("pppoe") or item.get("name") or item.get("ip") or "").strip(),
                "ip": (item.get("ip") or "").strip(),
                "source_mode": ACCOUNTS_PING_SOURCE_SSH_CSV,
                "source_missing": False,
                "source_missing_since": "",
                "last_source_seen_at": "",
            },
            default_source_mode=ACCOUNTS_PING_SOURCE_SSH_CSV,
        )
        if not device or not device.get("ip"):
            continue
        devices.append(device)
    return devices


def build_accounts_ping_mikrotik_devices(cfg, routers, previous_devices=None, now=None):
    now = now or datetime.utcnow()
    now_iso = now.replace(microsecond=0).isoformat() + "Z"
    source_cfg = cfg.get("source") if isinstance(cfg.get("source"), dict) else {}
    mikrotik_cfg = source_cfg.get("mikrotik") if isinstance(source_cfg.get("mikrotik"), dict) else {}
    router_enabled = mikrotik_cfg.get("router_enabled") if isinstance(mikrotik_cfg.get("router_enabled"), dict) else {}

    previous_by_router = {}
    for raw_device in previous_devices or []:
        device = normalize_accounts_ping_device(raw_device, default_source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK)
        if not device or device.get("source_mode") != ACCOUNTS_PING_SOURCE_MIKROTIK:
            continue
        router_id = device.get("router_id") or ""
        if not router_id:
            continue
        previous_by_router.setdefault(router_id, {})
        previous_by_router[router_id][device["pppoe"].strip().lower()] = device

    device_map = {}
    router_status = []

    for router in routers or []:
        if not isinstance(router, dict):
            continue
        router_id = (router.get("id") or "").strip()
        router_name = (router.get("name") or router_id or "router").strip()
        host = (router.get("host") or "").strip()
        if not router_id or not host:
            continue
        if not bool(router_enabled.get(router_id, True)):
            continue

        previous_for_router = previous_by_router.get(router_id, {})
        if router.get("use_tls"):
            router_status.append(
                {
                    "router_id": router_id,
                    "router_name": router_name,
                    "active_count": 0,
                    "error": "TLS/API-SSL is not supported by the current RouterOS API client. Disable TLS or use port 8728.",
                    "connected": False,
                }
            )
            for device in previous_for_router.values():
                device_map[device["account_id"]] = dict(device)
            continue

        active_keys = set()
        active_count = 0
        connected = False
        error = ""
        client = RouterOSClient(
            host,
            int(router.get("port", 8728) or 8728),
            router.get("username", ""),
            router.get("password", ""),
            timeout=max(int(mikrotik_cfg.get("timeout_seconds", 5) or 5), 1),
        )
        try:
            client.connect()
            connected = True
            for row in usage_notifier.fetch_pppoe_active(client) or []:
                pppoe = (row.get("name") or "").strip()
                if not pppoe:
                    continue
                ip = (row.get("address") or "").strip()
                key = pppoe.lower()
                active_keys.add(key)
                previous = previous_for_router.get(key) or {}
                device = normalize_accounts_ping_device(
                    {
                        **previous,
                        "account_id": build_accounts_ping_account_id(
                            pppoe,
                            source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
                            router_id=router_id,
                        ),
                        "pppoe": pppoe,
                        "name": pppoe,
                        "ip": ip or (previous.get("ip") or ""),
                        "router_id": router_id,
                        "router_name": router_name,
                        "source_mode": ACCOUNTS_PING_SOURCE_MIKROTIK,
                        "source_missing": not bool(ip),
                        "source_missing_since": "" if ip else (previous.get("source_missing_since") or now_iso),
                        "last_source_seen_at": now_iso,
                    },
                    default_source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
                )
                if not device:
                    continue
                device_map[device["account_id"]] = device
                active_count += 1
        except Exception as exc:
            error = str(exc)
            for device in previous_for_router.values():
                device_map[device["account_id"]] = dict(device)
        finally:
            client.close()

        if connected:
            for key, previous in previous_for_router.items():
                if key in active_keys:
                    continue
                device = normalize_accounts_ping_device(
                    {
                        **previous,
                        "source_mode": ACCOUNTS_PING_SOURCE_MIKROTIK,
                        "source_missing": True,
                        "source_missing_since": previous.get("source_missing_since") or now_iso,
                        "last_source_seen_at": previous.get("last_source_seen_at") or "",
                    },
                    default_source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
                )
                if not device:
                    continue
                device_map[device["account_id"]] = device

        router_status.append(
            {
                "router_id": router_id,
                "router_name": router_name,
                "active_count": active_count,
                "error": error,
                "connected": bool(connected),
            }
        )

    devices = sorted(
        device_map.values(),
        key=lambda item: (
            (item.get("pppoe") or "").strip().lower(),
            (item.get("router_name") or item.get("router_id") or "").strip().lower(),
            (item.get("account_id") or "").strip(),
        ),
    )
    return devices, router_status


def build_accounts_ping_source_devices(cfg, routers=None, previous_devices=None, now=None):
    source_cfg = cfg.get("source") if isinstance(cfg.get("source"), dict) else {}
    source_mode = normalize_accounts_ping_source_mode(source_cfg.get("mode"))
    if source_mode == ACCOUNTS_PING_SOURCE_MIKROTIK:
        return source_mode, *build_accounts_ping_mikrotik_devices(
            cfg,
            routers or [],
            previous_devices=previous_devices,
            now=now,
        )
    return source_mode, build_accounts_ping_csv_devices(cfg), []
