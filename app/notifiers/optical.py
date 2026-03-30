import base64
import json
import math
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from .telegram import send_telegram
from ..db import get_latest_non_null_optical_tx_for_devices, insert_optical_result, utc_now_iso
from ..mikrotik import RouterOSClient
from ..settings_defaults import USAGE_DEFAULTS, WAN_PING_DEFAULTS
from ..settings_store import get_settings, get_state, save_state
from . import usage as usage_notifier

FLOAT_RE = re.compile(r"-?\d+(?:\.\d+)?")
REALISTIC_RX_MIN = -40.0
REALISTIC_RX_MAX = 5.0
TX_FALLBACK_LOOKBACK_DAYS = 30
TR069_DEFAULT_PERIODIC_SECONDS = 300
TR069_GRACE_SECONDS = 120
TR069_PERIODIC_INTERVAL_PATHS = (
    "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
    "Device.ManagementServer.PeriodicInformInterval",
    "VirtualParameters.PeriodicInformInterval",
)


def parse_list(values):
    if isinstance(values, str):
        values = values.splitlines()
    return [line.strip() for line in values if line and line.strip()]


def build_auth_header(cfg):
    user = cfg["genieacs"]["username"]
    password = cfg["genieacs"]["password"]
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def fetch_devices(cfg):
    base_url = cfg["genieacs"]["base_url"].rstrip("/")
    page_size = int(cfg["genieacs"].get("page_size", 100))
    headers = build_auth_header(cfg)

    devices = []
    skip = 0
    while True:
        params = {
            "query": "{}",
            "limit": str(page_size),
            "skip": str(skip),
        }
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if not payload:
            break
        devices.extend(payload)
        skip += page_size
    return devices


def fetch_device_by_id(cfg, device_id):
    device_id = str(device_id or "").strip()
    if not device_id:
        return None
    base_url = cfg["genieacs"]["base_url"].rstrip("/")
    headers = build_auth_header(cfg)
    params = {
        "query": json.dumps({"_id": device_id}, separators=(",", ":")),
        "limit": "1",
    }
    url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    if isinstance(payload, list) and payload:
        return payload[0]
    return None


def request_parameter_values(cfg, device_id, parameter_names, *, timeout_ms=3000):
    device_id = str(device_id or "").strip()
    names = [str(item).strip() for item in (parameter_names or []) if str(item).strip()]
    if not device_id or not names:
        return False
    base_url = cfg["genieacs"]["base_url"].rstrip("/")
    headers = build_auth_header(cfg)
    headers["Content-Type"] = "application/json"
    query = f"timeout={max(int(timeout_ms or 0), 1000)}&connection_request"
    url = f"{base_url}/devices/{urllib.parse.quote(device_id, safe='')}/tasks?{query}"
    payload = json.dumps(
        {"name": "getParameterValues", "parameterNames": names},
        separators=(",", ":"),
    ).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=max(10, (int(timeout_ms or 0) / 1000.0) + 5)) as resp:
        return int(getattr(resp, "status", 200) or 200) < 300


def refresh_missing_tx(cfg, device_id, tx_paths, tx_min, tx_max):
    if not device_id:
        return None
    try:
        if not request_parameter_values(cfg, device_id, tx_paths):
            return None
    except Exception:
        return None
    for attempt in range(4):
        try:
            refreshed_device = fetch_device_by_id(cfg, device_id)
        except Exception:
            refreshed_device = None
        if refreshed_device is not None:
            tx = pick_param_with_bounds(refreshed_device, tx_paths, tx_min, tx_max, prefer_negative=False)
            if tx is not None:
                return tx
        if attempt < 3:
            time.sleep(0.35)
    return None


def get_nested(node, path):
    current = node
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def extract_value(node):
    if isinstance(node, dict):
        if "_value" in node:
            return node.get("_value")
        if "value" in node:
            return node.get("value")
    return node


def parse_float(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    match = FLOAT_RE.search(str(value))
    if not match:
        return None
    return float(match.group(0))


def parse_int(value):
    parsed = parse_float(value)
    if parsed is None:
        return None
    try:
        return int(parsed)
    except Exception:
        return None


def parse_iso_utc(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _router_match_entry(router_id, router_name, pppoe="", ip=""):
    return {
        "router_id": (router_id or "").strip(),
        "router_name": (router_name or router_id or "").strip(),
        "pppoe": (pppoe or "").strip(),
        "ip": (ip or "").strip(),
    }


def _add_router_match(index, key, entry):
    normalized_key = (key or "").strip().lower()
    if not normalized_key:
        return
    bucket = index.setdefault(normalized_key, [])
    router_id = (entry.get("router_id") or "").strip()
    pppoe = (entry.get("pppoe") or "").strip().lower()
    ip = (entry.get("ip") or "").strip()
    for existing in bucket:
        if (
            (existing.get("router_id") or "").strip() == router_id
            and (existing.get("pppoe") or "").strip().lower() == pppoe
            and (existing.get("ip") or "").strip() == ip
        ):
            return
    bucket.append(entry)


def _load_optical_router_configs():
    usage_cfg = get_settings("usage", USAGE_DEFAULTS)
    wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
    routers = wan_cfg.get("pppoe_routers") if isinstance(wan_cfg.get("pppoe_routers"), list) else []
    if not routers:
        legacy = (usage_cfg.get("mikrotik") or {}).get("routers") or []
        migrated = []
        for item in legacy:
            if not isinstance(item, dict):
                continue
            router_id = (item.get("id") or "").strip()
            host = (item.get("host") or "").strip()
            if not router_id or not host:
                continue
            migrated.append(
                {
                    "id": router_id,
                    "name": (item.get("name") or "").strip(),
                    "host": host,
                    "port": int(item.get("port", 8728) or 8728),
                    "username": item.get("username", ""),
                    "password": item.get("password", ""),
                    "use_tls": False,
                }
            )
        routers = migrated
    router_enabled = (
        (usage_cfg.get("mikrotik") or {}).get("router_enabled")
        if isinstance((usage_cfg.get("mikrotik") or {}).get("router_enabled"), dict)
        else {}
    )
    enabled = []
    for router in routers or []:
        if not isinstance(router, dict):
            continue
        router_id = (router.get("id") or "").strip()
        host = (router.get("host") or "").strip()
        if not router_id or not host:
            continue
        if not bool(router_enabled.get(router_id, True)):
            continue
        enabled.append(router)
    return enabled


def _load_truth_index_from_snapshot(snapshot):
    state = snapshot if isinstance(snapshot, dict) else {}
    known_pppoe_index = {}
    active_ip_index = {}
    for item in state.get("known_accounts") or []:
        if not isinstance(item, dict):
            continue
        entry = _router_match_entry(
            item.get("router_id"),
            item.get("router_name"),
            pppoe=item.get("pppoe"),
            ip=item.get("ip"),
        )
        pppoe_key = (entry.get("pppoe") or "").strip().lower()
        ip_key = (entry.get("ip") or "").strip()
        if pppoe_key:
            _add_router_match(known_pppoe_index, pppoe_key, entry)
        if ip_key:
            _add_router_match(active_ip_index, ip_key, entry)
    return {
        "mode": "state_fallback",
        "validation_active": bool(known_pppoe_index or active_ip_index),
        "known_pppoe_index": known_pppoe_index,
        "active_ip_index": active_ip_index,
        "known_accounts": [
            item
            for item in (state.get("known_accounts") or [])
            if isinstance(item, dict)
        ],
        "router_status": [
            item
            for item in (state.get("router_status") or [])
            if isinstance(item, dict)
        ],
        "router_total": len([item for item in (state.get("router_status") or []) if isinstance(item, dict)]),
        "connected_router_count": len(
            [
                item
                for item in (state.get("router_status") or [])
                if isinstance(item, dict) and bool(item.get("connected"))
            ]
        ),
    }


def _build_mikrotik_truth_index(timeout_seconds=5):
    routers = _load_optical_router_configs()
    if not routers:
        return {
            "mode": "unvalidated",
            "validation_active": False,
            "known_pppoe_index": {},
            "active_ip_index": {},
            "known_accounts": [],
            "router_status": [],
            "router_total": 0,
            "connected_router_count": 0,
        }

    known_pppoe_index = {}
    active_ip_index = {}
    known_accounts = []
    router_status = []
    connected_router_count = 0

    for router in routers:
        router_id = (router.get("id") or "").strip()
        router_name = (router.get("name") or router_id or "router").strip()
        if router.get("use_tls"):
            router_status.append(
                {
                    "router_id": router_id,
                    "router_name": router_name,
                    "connected": False,
                    "active_count": 0,
                    "secret_count": 0,
                    "error": "TLS/API-SSL is not supported by the current RouterOS API client. Disable TLS or use port 8728.",
                }
            )
            continue

        active_rows = []
        secret_rows = []
        connected = False
        error = ""
        client = RouterOSClient(
            (router.get("host") or "").strip(),
            int(router.get("port", 8728) or 8728),
            router.get("username", ""),
            router.get("password", ""),
            timeout=max(int(timeout_seconds or 0), 1),
        )
        try:
            client.connect()
            connected = True
            active_rows = usage_notifier.fetch_pppoe_active(client) or []
            secret_rows = usage_notifier.fetch_pppoe_secrets(client) or []
            connected_router_count += 1
        except Exception as exc:
            error = str(exc)
        finally:
            client.close()

        secret_count = 0
        active_count = 0

        for row in secret_rows:
            pppoe = (row.get("name") or "").strip()
            if not pppoe:
                continue
            entry = _router_match_entry(router_id, router_name, pppoe=pppoe)
            _add_router_match(known_pppoe_index, pppoe, entry)
            known_accounts.append(entry)
            secret_count += 1

        for row in active_rows:
            pppoe = (row.get("name") or "").strip()
            ip = (row.get("address") or "").strip()
            if not pppoe and not ip:
                continue
            entry = _router_match_entry(router_id, router_name, pppoe=pppoe, ip=ip)
            if pppoe:
                _add_router_match(known_pppoe_index, pppoe, entry)
                known_accounts.append(entry)
            if ip:
                _add_router_match(active_ip_index, ip, entry)
            active_count += 1

        router_status.append(
            {
                "router_id": router_id,
                "router_name": router_name,
                "connected": bool(connected),
                "active_count": active_count,
                "secret_count": secret_count,
                "error": error,
            }
        )

    return {
        "mode": "mikrotik_live",
        "validation_active": connected_router_count > 0,
        "known_pppoe_index": known_pppoe_index,
        "active_ip_index": active_ip_index,
        "known_accounts": known_accounts,
        "router_status": router_status,
        "router_total": len(router_status),
        "connected_router_count": connected_router_count,
    }


def _normalize_truth_index(truth_index):
    if isinstance(truth_index, dict):
        return truth_index
    return {
        "mode": "unvalidated",
        "validation_active": False,
        "known_pppoe_index": {},
        "active_ip_index": {},
        "known_accounts": [],
        "router_status": [],
        "router_total": 0,
        "connected_router_count": 0,
    }


def _lookup_truth_match(truth_index, pppoe, ip):
    index = _normalize_truth_index(truth_index)
    if not bool(index.get("validation_active")):
        canonical_pppoe = (pppoe or "").strip()
        ip_value = (ip or "").strip()
        identity_key = f"ppp:{canonical_pppoe.lower()}" if canonical_pppoe else (f"ip:{ip_value}" if ip_value else "")
        return {
            "valid": bool(identity_key),
            "match_mode": "unvalidated",
            "routers": [],
            "canonical_pppoe": canonical_pppoe,
            "identity_key": identity_key,
        }

    pppoe_key = (pppoe or "").strip().lower()
    routers = []
    match_mode = ""
    canonical_pppoe = (pppoe or "").strip()

    if pppoe_key:
        routers = list(index.get("known_pppoe_index", {}).get(pppoe_key) or [])
        if routers:
            match_mode = "pppoe"
            canonical_pppoe = canonical_pppoe or (routers[0].get("pppoe") or "").strip()

    if not routers:
        ip_key = (ip or "").strip()
        if ip_key:
            routers = list(index.get("active_ip_index", {}).get(ip_key) or [])
            if routers:
                match_mode = "ip"
                canonical_pppoe = canonical_pppoe or (routers[0].get("pppoe") or "").strip()

    identity_key = f"ppp:{canonical_pppoe.lower()}" if canonical_pppoe else (f"ip:{(ip or '').strip()}" if (ip or "").strip() else "")
    return {
        "valid": bool(routers and identity_key),
        "match_mode": match_mode,
        "routers": routers,
        "canonical_pppoe": canonical_pppoe,
        "identity_key": identity_key,
    }


def _device_periodic_interval_seconds(device):
    for path in TR069_PERIODIC_INTERVAL_PATHS:
        value = extract_value(get_nested(device, path))
        seconds = parse_int(value)
        if seconds is not None and seconds > 0:
            return seconds
    return TR069_DEFAULT_PERIODIC_SECONDS


def _device_tr069_status(device, now_dt=None):
    now_dt = now_dt or datetime.now(timezone.utc)
    last_inform_dt = parse_iso_utc((device or {}).get("_lastInform"))
    interval_seconds = max(int(_device_periodic_interval_seconds(device) or TR069_DEFAULT_PERIODIC_SECONDS), 60)
    threshold_seconds = interval_seconds + TR069_GRACE_SECONDS
    if last_inform_dt is None:
        return {
            "online": False,
            "last_inform_dt": None,
            "last_inform_at": "",
            "interval_seconds": interval_seconds,
            "threshold_seconds": threshold_seconds,
        }
    age_seconds = max((now_dt - last_inform_dt).total_seconds(), 0.0)
    return {
        "online": age_seconds <= threshold_seconds,
        "last_inform_dt": last_inform_dt,
        "last_inform_at": last_inform_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "interval_seconds": interval_seconds,
        "threshold_seconds": threshold_seconds,
    }


def _candidate_rank(candidate):
    last_inform_dt = candidate.get("last_inform_dt")
    if not isinstance(last_inform_dt, datetime):
        last_inform_dt = datetime.min.replace(tzinfo=timezone.utc)
    return (
        1 if candidate.get("match_mode") == "pppoe" else 0,
        1 if candidate.get("rx") is not None else 0,
        last_inform_dt,
        1 if candidate.get("tx") is not None else 0,
        (candidate.get("device_id") or "").strip().lower(),
    )


def _convert_raw_optical_to_dbm(parsed):
    try:
        value = float(parsed)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    try:
        return 10.0 * math.log10(value / 10000.0)
    except (ValueError, ZeroDivisionError):
        return None


def normalize_optical_power(value, min_value, max_value, *, prefer_negative=False):
    parsed = parse_float(value)
    if parsed is None:
        return None
    raw_text = str(value).strip() if value is not None else ""
    has_decimal = isinstance(value, float) and not float(value).is_integer()
    if not has_decimal and raw_text:
        has_decimal = "." in raw_text
    if min_value <= parsed <= max_value:
        if prefer_negative and parsed >= 0 and not has_decimal:
            converted = _convert_raw_optical_to_dbm(parsed)
            if converted is not None and min_value <= converted <= max_value and converted < parsed:
                return converted
        return parsed
    converted = _convert_raw_optical_to_dbm(parsed)
    if converted is not None and min_value <= converted <= max_value:
        return converted
    return parsed


def pick_param_with_bounds(device, paths, min_value, max_value, *, prefer_negative=False):
    first_value = None
    first_within = None
    for path in paths:
        raw = get_nested(device, path)
        value = extract_value(raw)
        parsed = normalize_optical_power(value, min_value, max_value, prefer_negative=prefer_negative)
        if parsed is None:
            continue
        if first_value is None:
            first_value = parsed
        if min_value <= parsed <= max_value:
            if first_within is None:
                first_within = parsed
            if parsed < 0:
                return parsed
    if first_within is not None:
        return first_within
    return first_value


def pick_text(device, paths):
    for path in paths:
        raw = get_nested(device, path)
        value = extract_value(raw)
        if isinstance(value, list):
            for item in value:
                item_value = extract_value(item)
                if item_value not in (None, ""):
                    return str(item_value)
            continue
        if value not in (None, ""):
            return str(value)
    return None


def device_label(device):
    device_id = device.get("DeviceID", {}) if isinstance(device, dict) else {}
    serial = device_id.get("SerialNumber")
    manufacturer = device_id.get("Manufacturer")
    product = device_id.get("ProductClass")
    if serial and manufacturer:
        return f"{manufacturer}-{serial}"
    if serial:
        return serial
    if manufacturer and product:
        return f"{manufacturer}-{product}"
    if manufacturer:
        return manufacturer
    fallback = device.get("_id") if isinstance(device, dict) else None
    return str(fallback) if fallback else "Unknown"


def format_split(lines, max_chars):
    messages = []
    current = []
    total = 0

    for line in lines:
        line_to_add = line
        if max_chars and len(line_to_add) > max_chars:
            line_to_add = line_to_add[:max_chars]
        add_len = len(line_to_add) + (1 if current else 0)
        if max_chars and current and total + add_len > max_chars:
            messages.append("\n".join(current))
            current = [line_to_add]
            total = len(line_to_add)
        else:
            current.append(line_to_add)
            total += add_len

    if current:
        messages.append("\n".join(current))
    return messages


def build_messages(cfg, rows, total_devices):
    title = cfg["general"].get("message_title", "Optical Power Alert")
    include_header = bool(cfg["general"].get("include_header", True))
    threshold = cfg["optical"].get("rx_threshold_dbm", -26)
    tx_low = cfg["optical"].get("tx_low_threshold_dbm", -1)
    priority_threshold = cfg["optical"].get("priority_rx_threshold_dbm", -29)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        title,
        f"Time: {timestamp}",
        f"Summary: Alerts: {len(rows)} / {total_devices}",
        f"Thresholds: RX <= {threshold} dBm; TX <= {tx_low} dBm; Priority: RX <= {priority_threshold} dBm",
    ]

    if not rows:
        lines.append("No devices below threshold.")
        return ["\n".join(lines)]

    if include_header:
        lines.append("Customer PPPOE name | IP Address | RX | TX")
    for row in rows:
        rx = f"{row['rx']:.2f}" if row["rx"] is not None else "N/A"
        tx = f"{row['tx']:.2f}" if row["tx"] is not None else "N/A"
        prefix = "🔴 " if row.get("priority") else ""
        pppoe = f"{prefix}{row.get('pppoe') or 'Unknown'}"
        ip_address = row.get("ip") or "N/A"
        lines.append(f"{pppoe} | {ip_address} | {rx} | {tx}")

    max_chars = int(cfg["general"].get("max_chars", 3800))
    return format_split(lines, max_chars)


def run(cfg, send_alerts=True):
    rx_paths = parse_list(cfg["optical"].get("rx_paths", []))
    tx_paths = parse_list(cfg["optical"].get("tx_paths", []))
    pppoe_paths = parse_list(cfg["optical"].get("pppoe_paths", []))
    ip_paths = parse_list(cfg["optical"].get("ip_paths", []))

    devices = fetch_devices(cfg)
    threshold = float(cfg["optical"].get("rx_threshold_dbm", -26.0))
    tx_low = float(cfg["optical"].get("tx_low_threshold_dbm", -1.0))
    priority_threshold = float(cfg["optical"].get("priority_rx_threshold_dbm", -29.0))
    timestamp = utc_now_iso()
    now_dt = parse_iso_utc(timestamp) or datetime.now(timezone.utc)
    fallback_since_iso = (datetime.utcnow() - timedelta(days=TX_FALLBACK_LOOKBACK_DAYS)).replace(microsecond=0).isoformat() + "Z"

    realistic_min = float(cfg.get("classification", {}).get("rx_realistic_min_dbm", REALISTIC_RX_MIN))
    realistic_max = float(cfg.get("classification", {}).get("rx_realistic_max_dbm", REALISTIC_RX_MAX))
    tx_min = float(cfg.get("classification", {}).get("tx_realistic_min_dbm", -10.0))
    tx_max = float(cfg.get("classification", {}).get("tx_realistic_max_dbm", 10.0))
    previous_state = get_state("optical_state", {"last_run_date": None, "last_run_at": None})
    truth_index = _build_mikrotik_truth_index()
    if truth_index.get("router_total") and not truth_index.get("connected_router_count"):
        fallback_truth = _load_truth_index_from_snapshot(previous_state)
        if fallback_truth.get("validation_active"):
            truth_index = fallback_truth

    selected_candidates = {}
    stats = {
        "genie_total": len(devices),
        "matched_truth": 0,
        "tr069_online": 0,
        "duplicates_removed": 0,
        "rx_ready": 0,
    }

    for device in devices:
        if not isinstance(device, dict):
            continue
        device_id = str(device.get("_id") or "").strip()
        pppoe = (pick_text(device, pppoe_paths) or "").strip()
        ip_address = (pick_text(device, ip_paths) or "").strip()

        truth = _lookup_truth_match(truth_index, pppoe, ip_address)
        if not truth.get("valid"):
            continue
        stats["matched_truth"] += 1

        tr069 = _device_tr069_status(device, now_dt=now_dt)
        if not tr069.get("online"):
            continue
        stats["tr069_online"] += 1

        canonical_pppoe = (truth.get("canonical_pppoe") or pppoe or device_label(device)).strip()
        identity_key = (truth.get("identity_key") or "").strip()
        if not identity_key:
            continue

        rx = pick_param_with_bounds(device, rx_paths, realistic_min, realistic_max, prefer_negative=True)
        tx = pick_param_with_bounds(device, tx_paths, tx_min, tx_max, prefer_negative=False)
        if rx is not None:
            stats["rx_ready"] += 1

        candidate = {
            "device": device,
            "device_id": device_id or canonical_pppoe,
            "pppoe": canonical_pppoe,
            "ip": ip_address,
            "identity_key": identity_key,
            "match_mode": truth.get("match_mode") or "",
            "routers": list(truth.get("routers") or []),
            "router_ids": sorted(
                {
                    (item.get("router_id") or "").strip()
                    for item in (truth.get("routers") or [])
                    if (item.get("router_id") or "").strip()
                }
            ),
            "router_names": sorted(
                {
                    (item.get("router_name") or item.get("router_id") or "").strip()
                    for item in (truth.get("routers") or [])
                    if (item.get("router_name") or item.get("router_id") or "").strip()
                }
            ),
            "last_inform_at": tr069.get("last_inform_at") or "",
            "last_inform_dt": tr069.get("last_inform_dt"),
            "interval_seconds": int(tr069.get("interval_seconds") or TR069_DEFAULT_PERIODIC_SECONDS),
            "threshold_seconds": int(tr069.get("threshold_seconds") or (TR069_DEFAULT_PERIODIC_SECONDS + TR069_GRACE_SECONDS)),
            "rx": rx,
            "tx": tx,
        }

        existing = selected_candidates.get(identity_key)
        if existing and _candidate_rank(existing) >= _candidate_rank(candidate):
            stats["duplicates_removed"] += 1
            continue
        if existing:
            stats["duplicates_removed"] += 1
        selected_candidates[identity_key] = candidate

    known_tx_map = get_latest_non_null_optical_tx_for_devices(
        [
            candidate.get("device_id")
            for candidate in selected_candidates.values()
            if (candidate.get("device_id") or "").strip()
        ],
        since_iso=fallback_since_iso,
    )

    rows = []
    current_devices = []
    for candidate in sorted(
        selected_candidates.values(),
        key=lambda item: (
            (item.get("pppoe") or "").strip().lower(),
            (item.get("device_id") or "").strip().lower(),
        ),
    ):
        device = candidate.get("device") if isinstance(candidate.get("device"), dict) else {}
        device_id = (candidate.get("device_id") or "").strip()
        rx = candidate.get("rx")
        tx = candidate.get("tx")
        if tx is None and device_id:
            refreshed_device = None
            try:
                refreshed_device = fetch_device_by_id(cfg, device_id)
            except Exception:
                refreshed_device = None
            if refreshed_device is not None:
                tx = pick_param_with_bounds(refreshed_device, tx_paths, tx_min, tx_max, prefer_negative=False)
        if tx is None and device_id:
            tx = refresh_missing_tx(cfg, device_id, tx_paths, tx_min, tx_max)
        if tx is None and device_id:
            fallback_row = known_tx_map.get(device_id) or {}
            fallback_tx = fallback_row.get("tx")
            if fallback_tx is not None:
                tx = fallback_tx
        if rx is None:
            continue
        pppoe = (candidate.get("pppoe") or "").strip() or device_label(device)
        ip_address = (candidate.get("ip") or "").strip()
        if not device_id:
            device_id = pppoe
        if tx is not None:
            known_tx_map[device_id] = {"tx": tx, "timestamp": timestamp}
        priority = rx <= priority_threshold
        insert_optical_result(device_id, pppoe, ip_address, rx, tx, priority, timestamp=timestamp)
        current_devices.append(
            {
                "device_id": device_id,
                "pppoe": pppoe,
                "ip": ip_address,
                "match_mode": candidate.get("match_mode") or "",
                "router_ids": list(candidate.get("router_ids") or []),
                "router_names": list(candidate.get("router_names") or []),
                "last_inform_at": candidate.get("last_inform_at") or "",
                "tr069_interval_seconds": int(candidate.get("interval_seconds") or TR069_DEFAULT_PERIODIC_SECONDS),
                "tr069_threshold_seconds": int(
                    candidate.get("threshold_seconds") or (TR069_DEFAULT_PERIODIC_SECONDS + TR069_GRACE_SECONDS)
                ),
            }
        )
        tx_alert = tx is not None and tx <= tx_low
        if rx <= threshold or tx_alert:
            rows.append(
                {
                    "pppoe": pppoe,
                    "ip": ip_address,
                    "rx": rx,
                    "tx": tx,
                    "priority": priority,
                }
            )

    rows.sort(key=lambda x: x["rx"])
    optical_state = previous_state if isinstance(previous_state, dict) else {}
    optical_state.update(
        {
            "last_source_refresh_at": timestamp,
            "truth_mode": truth_index.get("mode") or "unvalidated",
            "router_status": list(truth_index.get("router_status") or []),
            "known_accounts": list(truth_index.get("known_accounts") or []),
            "current_devices": current_devices,
            "current_device_ids": [item["device_id"] for item in current_devices if item.get("device_id")],
            "current_pppoe_keys": sorted(
                {
                    (item.get("pppoe") or "").strip().lower()
                    for item in current_devices
                    if (item.get("pppoe") or "").strip()
                }
            ),
            "current_ip_keys": sorted(
                {
                    (item.get("ip") or "").strip()
                    for item in current_devices
                    if (item.get("ip") or "").strip()
                }
            ),
            "source_stats": stats,
        }
    )
    save_state("optical_state", optical_state)

    messages = build_messages(cfg, rows, len(current_devices))
    if send_alerts:
        token = cfg["telegram"].get("bot_token", "")
        chat_id = cfg["telegram"].get("chat_id", "")
        for message in messages:
            send_telegram(token, chat_id, message)
    return {
        "current_devices": current_devices,
        "rows": rows,
        "stats": stats,
        "truth_mode": truth_index.get("mode") or "unvalidated",
    }
