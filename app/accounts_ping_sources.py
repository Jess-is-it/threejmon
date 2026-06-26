import base64
from datetime import datetime

from .mikrotik import borrow_routeros_client
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
        "profile": (device.get("profile") or "").strip(),
        "source_mode": source_mode,
        "source_missing": bool(device.get("source_missing")),
        "source_missing_since": (device.get("source_missing_since") or "").strip(),
        "last_source_seen_at": (device.get("last_source_seen_at") or "").strip(),
        "secret_seen_at": (device.get("secret_seen_at") or "").strip(),
        "profile_disabled": bool(device.get("profile_disabled")),
        "profile_disabled_since": (device.get("profile_disabled_since") or "").strip(),
        "last_profile_seen_at": (device.get("last_profile_seen_at") or "").strip(),
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


def accounts_ping_profile_enabled_map(settings):
    source_cfg = settings.get("source") if isinstance(settings, dict) and isinstance(settings.get("source"), dict) else {}
    mikrotik_cfg = source_cfg.get("mikrotik") if isinstance(source_cfg.get("mikrotik"), dict) else {}
    raw_map = mikrotik_cfg.get("profile_enabled") if isinstance(mikrotik_cfg.get("profile_enabled"), dict) else {}
    out = {}
    for router_id, profiles in raw_map.items():
        router_key = str(router_id or "").strip()
        if not router_key or not isinstance(profiles, dict):
            continue
        out[router_key] = {
            str(profile or "").strip(): bool(enabled)
            for profile, enabled in profiles.items()
            if str(profile or "").strip()
        }
    return out


def accounts_ping_profile_is_enabled(profile_enabled, router_id, profile):
    profile_value = (profile or "").strip()
    if not profile_value:
        return True
    router_key = (router_id or "").strip()
    per_router = profile_enabled.get(router_key) if isinstance(profile_enabled, dict) else {}
    if not isinstance(per_router, dict):
        per_router = {}
    return bool(per_router.get(profile_value, True))


def build_accounts_ping_disabled_account_lookup(devices):
    router_pppoe = set()
    pppoe = set()
    for raw_device in devices or []:
        device = normalize_accounts_ping_device(raw_device, default_source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK)
        if not device or not bool(device.get("profile_disabled")):
            continue
        pppoe_key = (device.get("pppoe") or "").strip().lower()
        router_key = (device.get("router_id") or "").strip()
        if not pppoe_key:
            continue
        pppoe.add(pppoe_key)
        if router_key:
            router_pppoe.add((router_key, pppoe_key))
    return {"router_pppoe": router_pppoe, "pppoe": pppoe}


def is_accounts_ping_disabled_account(router_id, pppoe, profile="", profile_enabled=None, disabled_lookup=None):
    pppoe_key = (pppoe or "").strip().lower()
    if not pppoe_key:
        return False
    router_key = (router_id or "").strip()
    lookup = disabled_lookup if isinstance(disabled_lookup, dict) else {}
    router_pppoe = lookup.get("router_pppoe") if isinstance(lookup.get("router_pppoe"), set) else set()
    disabled_pppoe = lookup.get("pppoe") if isinstance(lookup.get("pppoe"), set) else set()
    if router_key and (router_key, pppoe_key) in router_pppoe:
        return True
    if not router_key and pppoe_key in disabled_pppoe:
        return True
    if profile_enabled is not None and profile and not accounts_ping_profile_is_enabled(
        profile_enabled,
        router_key,
        profile,
    ):
        return True
    return False


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
    profile_enabled = mikrotik_cfg.get("profile_enabled") if isinstance(mikrotik_cfg.get("profile_enabled"), dict) else {}

    def is_profile_enabled(router_id, profile):
        profile_value = (profile or "").strip()
        if not profile_value:
            return True
        per_router = profile_enabled.get(router_id) if isinstance(profile_enabled.get(router_id), dict) else {}
        return bool(per_router.get(profile_value, True))

    def _profile_summary_row(profile, *, active_count=0, secret_count=0, enabled=True):
        profile_value = (profile or "").strip()
        if not profile_value:
            profile_value = "default"
        return {
            "name": profile_value,
            "enabled": bool(enabled),
            "active_count": int(active_count or 0),
            "secret_count": int(secret_count or 0),
        }

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
        tracked_count = 0
        disabled_profile_count = 0
        connected = False
        error = ""
        profile_error = ""
        secrets_error = ""
        profiles = []
        secrets = []
        secrets_by_name = {}
        profile_active_counts = {}
        profile_secret_counts = {}
        try:
            with borrow_routeros_client(
                host,
                int(router.get("port", 8728) or 8728),
                router.get("username", ""),
                router.get("password", ""),
                timeout=max(int(mikrotik_cfg.get("timeout_seconds", 5) or 5), 1),
                max_size=1,
            ) as client:
                connected = True
                try:
                    profiles = usage_notifier.fetch_ppp_profiles(client) or []
                except Exception as exc:
                    profile_error = str(exc)
                    profiles = []
                try:
                    secrets = usage_notifier.fetch_pppoe_secrets(client) or []
                except Exception as exc:
                    secrets_error = str(exc)
                    secrets = []
                secrets_by_name = {
                    (secret.get("name") or "").strip().lower(): secret
                    for secret in secrets
                    if isinstance(secret, dict) and (secret.get("name") or "").strip()
                }
                profile_active_counts = {}
                profile_secret_counts = {}
                for secret in secrets_by_name.values():
                    profile = (secret.get("profile") or "").strip()
                    if profile:
                        profile_secret_counts[profile] = profile_secret_counts.get(profile, 0) + 1
                for row in usage_notifier.fetch_pppoe_active(client) or []:
                    pppoe = (row.get("name") or "").strip()
                    if not pppoe:
                        continue
                    ip = (row.get("address") or "").strip()
                    key = pppoe.lower()
                    active_keys.add(key)
                    previous = previous_for_router.get(key) or {}
                    secret = secrets_by_name.get(key) or {}
                    profile = (secret.get("profile") or previous.get("profile") or "").strip()
                    if profile:
                        profile_active_counts[profile] = profile_active_counts.get(profile, 0) + 1
                    profile_disabled = not is_profile_enabled(router_id, profile)
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
                            "profile": profile,
                            "source_mode": ACCOUNTS_PING_SOURCE_MIKROTIK,
                            "source_missing": not bool(ip),
                            "source_missing_since": "" if ip else (previous.get("source_missing_since") or now_iso),
                            "last_source_seen_at": now_iso,
                            "secret_seen_at": now_iso if secret else (previous.get("secret_seen_at") or ""),
                            "profile_disabled": profile_disabled,
                            "profile_disabled_since": (
                                (previous.get("profile_disabled_since") or now_iso)
                                if profile_disabled
                                else ""
                            ),
                            "last_profile_seen_at": now_iso if profile else (previous.get("last_profile_seen_at") or ""),
                        },
                        default_source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
                    )
                    if not device:
                        continue
                    device_map[device["account_id"]] = device
                    active_count += 1
                    if profile_disabled:
                        disabled_profile_count += 1
                    else:
                        tracked_count += 1
        except Exception as exc:
            error = str(exc)
            for device in previous_for_router.values():
                device_map[device["account_id"]] = dict(device)

        if connected:
            for key, previous in previous_for_router.items():
                if key in active_keys:
                    continue
                secret = {}
                try:
                    secret = secrets_by_name.get(key) or {}
                except Exception:
                    secret = {}
                profile = (secret.get("profile") or previous.get("profile") or "").strip()
                profile_disabled = not is_profile_enabled(router_id, profile)
                device = normalize_accounts_ping_device(
                    {
                        **previous,
                        "profile": profile,
                        "source_mode": ACCOUNTS_PING_SOURCE_MIKROTIK,
                        "source_missing": True,
                        "source_missing_since": previous.get("source_missing_since") or now_iso,
                        "last_source_seen_at": previous.get("last_source_seen_at") or "",
                        "secret_seen_at": now_iso if secret else (previous.get("secret_seen_at") or ""),
                        "profile_disabled": profile_disabled,
                        "profile_disabled_since": (
                            (previous.get("profile_disabled_since") or now_iso)
                            if profile_disabled
                            else ""
                        ),
                        "last_profile_seen_at": now_iso if profile else (previous.get("last_profile_seen_at") or ""),
                    },
                    default_source_mode=ACCOUNTS_PING_SOURCE_MIKROTIK,
                )
                if not device:
                    continue
                device_map[device["account_id"]] = device
                if profile_disabled:
                    disabled_profile_count += 1

        profile_names = set()
        for row in profiles or []:
            if isinstance(row, dict) and (row.get("name") or "").strip():
                profile_names.add((row.get("name") or "").strip())
        profile_names.update(profile_secret_counts.keys())
        profile_names.update(profile_active_counts.keys())
        configured_profiles = profile_enabled.get(router_id) if isinstance(profile_enabled.get(router_id), dict) else {}
        profile_names.update(str(name).strip() for name in configured_profiles.keys() if str(name).strip())
        profile_rows = [
            _profile_summary_row(
                profile,
                active_count=profile_active_counts.get(profile, 0),
                secret_count=profile_secret_counts.get(profile, 0),
                enabled=is_profile_enabled(router_id, profile),
            )
            for profile in sorted(profile_names, key=lambda value: value.lower())
        ]
        disabled_profile_names = [row["name"] for row in profile_rows if not bool(row.get("enabled"))]

        router_status.append(
            {
                "router_id": router_id,
                "router_name": router_name,
                "active_count": active_count,
                "tracked_count": tracked_count,
                "disabled_profile_count": disabled_profile_count,
                "profile_count": len(profile_rows),
                "profiles": profile_rows,
                "disabled_profiles": disabled_profile_names,
                "error": error,
                "profile_error": profile_error,
                "secrets_error": secrets_error,
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
