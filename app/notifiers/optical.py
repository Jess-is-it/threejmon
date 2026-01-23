import base64
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime

from .telegram import send_telegram
from ..db import insert_optical_result, utc_now_iso

FLOAT_RE = re.compile(r"-?\d+(?:\.\d+)?")
REALISTIC_RX_MIN = -40.0
REALISTIC_RX_MAX = 5.0


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


def pick_param(device, paths):
    for path in paths:
        raw = get_nested(device, path)
        value = extract_value(raw)
        parsed = parse_float(value)
        if parsed is not None:
            return parsed
    return None


def pick_param_with_bounds(device, paths, min_value, max_value):
    first_value = None
    first_within = None
    for path in paths:
        raw = get_nested(device, path)
        value = extract_value(raw)
        parsed = parse_float(value)
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

    realistic_min = float(cfg.get("classification", {}).get("rx_realistic_min_dbm", REALISTIC_RX_MIN))
    realistic_max = float(cfg.get("classification", {}).get("rx_realistic_max_dbm", REALISTIC_RX_MAX))
    tx_min = float(cfg.get("classification", {}).get("tx_realistic_min_dbm", -10.0))
    tx_max = float(cfg.get("classification", {}).get("tx_realistic_max_dbm", 10.0))

    rows = []
    for device in devices:
        rx = pick_param_with_bounds(device, rx_paths, realistic_min, realistic_max)
        tx = pick_param_with_bounds(device, tx_paths, tx_min, tx_max)
        if rx is None:
            continue
        pppoe = pick_text(device, pppoe_paths) or device_label(device)
        ip_address = pick_text(device, ip_paths)
        device_id = device.get("_id") if isinstance(device, dict) else None
        if not device_id:
            device_id = pppoe
        priority = rx <= priority_threshold
        insert_optical_result(device_id, pppoe, ip_address, rx, tx, priority, timestamp=timestamp)
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
    messages = build_messages(cfg, rows, len(devices))
    if send_alerts:
        token = cfg["telegram"].get("bot_token", "")
        chat_id = cfg["telegram"].get("chat_id", "")
        for message in messages:
            send_telegram(token, chat_id, message)
