import base64
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone


# Loosely parse numeric values that may include RouterOS unit suffixes.
_FLOAT_RE = re.compile(r"-?\d+(?:\.\d+)?")
_INT_RE = re.compile(r"-?\d+")

# Matches a TR-069 path like:
#   InternetGatewayDevice.LANDevice.1.Hosts.Host.6.HostName
# Capturing:
#   prefix = InternetGatewayDevice.LANDevice.1.Hosts.Host
#   idx    = 6
#   prop   = HostName
_HOST_INDEX_PATH_RE = re.compile(r"^(?P<prefix>.*\.Hosts\.Host)\.(?P<idx>\d+)\.(?P<prop>[^.]+)$")


def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_list(values):
    if isinstance(values, str):
        values = values.splitlines()
    return [line.strip() for line in values if line and line.strip()]


def _parse_int(value):
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        match = _INT_RE.search(str(value))
        if not match:
            return None
        return int(match.group(0))
    except Exception:
        return None


def _parse_int_strict(value):
    try:
        return int(value)
    except Exception:
        return None


def _parse_bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def _parse_float(value):
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return float(int(value))
        if isinstance(value, (int, float)):
            return float(value)
        match = _FLOAT_RE.search(str(value))
        if not match:
            return None
        return float(match.group(0))
    except Exception:
        return None


def _sentence_to_dict(sentence):
    # sentence is list[str], like: ["!re", "=name=foo", "=bytes-in=123"]
    data = {}
    for word in sentence[1:]:
        if not word:
            continue
        if word.startswith("="):
            word = word[1:]
        if "=" not in word:
            continue
        key, value = word.split("=", 1)
        data[key] = value
    return data


def routeros_print(client, path, proplist=None, stats=False, stats_word="=stats="):
    words = [path]
    if stats and stats_word:
        words.append(stats_word)
    if proplist:
        words.append(f"=.proplist={','.join(proplist)}")
    replies = client.talk(words)
    rows = []
    for sentence in replies:
        if not sentence or sentence[0] != "!re":
            continue
        rows.append(_sentence_to_dict(sentence))
    return rows


def _rows_have_usage(rows):
    if not rows:
        return False
    for row in rows[:20]:
        if _parse_int(row.get("bytes-in")) is not None:
            return True
        if _parse_int(row.get("bytes-out")) is not None:
            return True
        if _parse_int(row.get("rx-bytes")) is not None:
            return True
        if _parse_int(row.get("tx-bytes")) is not None:
            return True
        if _parse_float(row.get("rx-rate")) is not None:
            return True
        if _parse_float(row.get("tx-rate")) is not None:
            return True
        duplex = (row.get("rate") or "").strip()
        if duplex and "/" in duplex:
            left, right = duplex.split("/", 1)
            if _parse_float(left.strip()) is not None or _parse_float(right.strip()) is not None:
                return True
    return False


def fetch_pppoe_active(client):
    # Keep this call conservative: some RouterOS builds close the API connection when unsupported
    # flags (like stats) are used on /ppp/active. We fetch identity fields here and collect
    # usage counters via queues/interfaces instead.
    proplist = [
        ".id",
        "name",
        "service",
        "address",
        "interface",
        "uptime",
        "session-id",
        "caller-id",
        "encoding",
        "radius",
        "limit-bytes-in",
        "limit-bytes-out",
    ]
    rows = routeros_print(client, "/ppp/active/print", proplist=proplist, stats=False)
    if rows:
        return rows
    return routeros_print(client, "/ppp/active/print", proplist=None, stats=False)


def fetch_pppoe_secrets(client):
    proplist = [
        ".id",
        "name",
        "service",
        "profile",
        "disabled",
        "last-logged-out",
        "comment",
    ]
    return routeros_print(client, "/ppp/secret/print", proplist=proplist)


def fetch_simple_queues(client):
    # Simple queues often expose live rate + byte counters per subscriber.
    proplist = [
        ".id",
        "name",
        "target",
        "bytes",
        "rate",
        "packet-rate",
        "total-bytes",
        "total-rate",
    ]
    rows = routeros_print(client, "/queue/simple/print", proplist=proplist, stats=False) or []
    # Some RouterOS builds require `=stats=` to include counters.
    has_counters = False
    for row in rows[:25]:
        duplex_b = (row.get("bytes") or "").strip()
        duplex_r = (row.get("rate") or "").strip()
        if duplex_b and "/" in duplex_b:
            has_counters = True
            break
        if duplex_r and "/" in duplex_r:
            has_counters = True
            break
    if rows and not has_counters:
        try:
            rows2 = routeros_print(client, "/queue/simple/print", proplist=proplist, stats=True) or []
            if rows2:
                return rows2
        except Exception:
            pass
    return rows


def fetch_ppp_interfaces(client):
    # Dynamic PPP interfaces expose rx/tx byte counters even when PPP active does not.
    proplist = [
        ".id",
        "name",
        "type",
        "dynamic",
        "running",
        "rx-byte",
        "tx-byte",
        "fp-rx-byte",
        "fp-tx-byte",
    ]
    rows = routeros_print(client, "/interface/print", proplist=proplist, stats=False) or []
    filtered = []
    for row in rows:
        dyn = (row.get("dynamic") or "").strip().lower()
        typ = (row.get("type") or "").strip().lower()
        if dyn not in ("true", "yes", "1"):
            continue
        if "ppp" not in typ:
            continue
        filtered.append(row)
    return filtered


def parse_duplex_int(value):
    raw = (value or "").strip()
    if not raw or "/" not in raw:
        return None
    left, right = raw.split("/", 1)
    a = _parse_int(left.strip())
    b = _parse_int(right.strip())
    if a is None or b is None:
        return None
    return a, b


def parse_duplex_float(value):
    raw = (value or "").strip()
    if not raw or "/" not in raw:
        return None
    left, right = raw.split("/", 1)
    a = _parse_float(left.strip())
    b = _parse_float(right.strip())
    if a is None or b is None:
        return None
    return a, b


def build_auth_header(cfg):
    user = (cfg.get("genieacs") or {}).get("username") or ""
    password = (cfg.get("genieacs") or {}).get("password") or ""
    if not (user or password):
        return {}
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def fetch_genieacs_devices(cfg):
    genie = cfg.get("genieacs") or {}
    base_url = (genie.get("base_url") or "").rstrip("/")
    if not base_url:
        return []
    page_size = int(genie.get("page_size", 100) or 100)
    headers = build_auth_header(cfg)

    devices = []
    skip = 0
    while True:
        params = {"query": "{}", "limit": str(page_size), "skip": str(skip)}
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if not payload:
            break
        if isinstance(payload, list):
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


def _expand_indexed_paths(device, paths):
    # Support a user-provided example like "...Hosts.Host.1.HostName" and auto-enumerate Hosts.Host.<n>.
    expanded = []
    for path in paths:
        match = _HOST_INDEX_PATH_RE.match(path)
        if not match:
            expanded.append({"mode": "direct", "path": path})
            continue
        prefix = match.group("prefix")
        prop = match.group("prop")
        host_root = get_nested(device, prefix)
        if not isinstance(host_root, dict):
            expanded.append({"mode": "direct", "path": path})
            continue
        indices = [k for k in host_root.keys() if str(k).isdigit()]
        for idx in sorted(indices, key=lambda x: int(str(x))):
            expanded.append({"mode": "direct", "path": f"{prefix}.{idx}.{prop}"})
    return expanded


def _collect_indexed_value_map(device, paths):
    # Returns {idx:int -> value:any} for TR-069 host list entries.
    out = {}
    for path in paths:
        match = _HOST_INDEX_PATH_RE.match(path)
        if not match:
            continue
        prefix = match.group("prefix")
        prop = match.group("prop")
        host_root = get_nested(device, prefix)
        if not isinstance(host_root, dict):
            continue
        indices = [k for k in host_root.keys() if str(k).isdigit()]
        for idx_key in indices:
            idx = int(str(idx_key))
            raw = get_nested(device, f"{prefix}.{idx}.{prop}")
            value = extract_value(raw)
            if value in (None, ""):
                continue
            out[idx] = value
    return out


def _collect_host_indices(device, paths):
    # Returns a set of numeric Host.<n> instance numbers for any template path like "...Hosts.Host.1.<Prop>".
    indices = set()
    for path in paths:
        match = _HOST_INDEX_PATH_RE.match(path)
        if not match:
            continue
        prefix = match.group("prefix")
        host_root = get_nested(device, prefix)
        if not isinstance(host_root, dict):
            continue
        for key in host_root.keys():
            if str(key).isdigit():
                indices.add(int(str(key)))
    return indices


def build_pppoe_host_map(cfg):
    device_cfg = cfg.get("device") or {}
    pppoe_paths = parse_list(device_cfg.get("pppoe_paths", []))
    host_count_paths = parse_list(device_cfg.get("host_count_paths", []))
    host_name_paths = parse_list(device_cfg.get("host_name_paths", []))
    host_ip_paths = parse_list(device_cfg.get("host_ip_paths", []))
    host_active_paths = parse_list(device_cfg.get("host_active_paths", []))

    out = {}
    for device in fetch_genieacs_devices(cfg):
        pppoe = (pick_text(device, pppoe_paths) or "").strip()
        if not pppoe:
            continue
        device_id = device.get("_id") if isinstance(device, dict) else None
        host_count = None
        for path in host_count_paths:
            raw = get_nested(device, path)
            value = extract_value(raw)
            count = _parse_int(value)
            if count is not None:
                host_count = count
                break

        # Enumerate hosts (supports non-contiguous indexes: Host.1, Host.3, Host.6, ...).
        name_map = _collect_indexed_value_map(device, host_name_paths)
        ip_map = _collect_indexed_value_map(device, host_ip_paths)
        active_map = _collect_indexed_value_map(device, host_active_paths)

        # Prefer counting based on the existence of Host.<n> instances rather than HostName/IP values,
        # because some devices leave HostName blank.
        indices = set()
        indices |= _collect_host_indices(device, host_name_paths)
        indices |= _collect_host_indices(device, host_ip_paths)
        indices |= _collect_host_indices(device, host_active_paths)
        if not indices:
            indices = set(name_map.keys()) | set(ip_map.keys()) | set(active_map.keys())

        all_indices = sorted(indices)
        if active_map:
            # If Host.Active is provided, only show hosts where Active=true.
            active_indices = [idx for idx in all_indices if _parse_bool(active_map.get(idx))]
        else:
            active_indices = list(all_indices)

        def build_labels(index_list):
            labels = []
            for idx in index_list:
                name = str(name_map.get(idx) or "").strip()
                ip = str(ip_map.get(idx) or "").strip()
                label = name or ip or f"Host {idx}"
                labels.append(label)
            return labels

        cleaned_hosts = build_labels(active_indices)

        # Count instances based on existence of Host.<n> instances; when Active is provided, count active only.
        computed_total_count = len(all_indices) if all_indices else 0
        computed_active_count = len(active_indices) if active_indices else 0
        reported_count = int(host_count or 0) if host_count is not None else None
        computed_total_count = max(computed_total_count, reported_count or 0)
        host_count = computed_active_count

        out[pppoe] = {
            "device_id": str(device_id) if device_id else "",
            "host_count": int(host_count or 0),
            "hostnames": cleaned_hosts,
            "host_count_total": int(computed_total_count or 0),
        }
        # Also store a case-insensitive key variant for safer joins (GenieACS vs MikroTik may differ by case).
        low = pppoe.lower()
        if low and low not in out:
            out[low] = out[pppoe]
    return out


def normalize_active_row(row, timestamp, router_id, router_name, computed_rx_bps=None, computed_tx_bps=None):
    # RouterOS fields are strings.
    pppoe = (row.get("name") or "").strip()
    if not pppoe:
        return None
    bytes_in = _parse_int(row.get("bytes-in"))
    if bytes_in is None:
        bytes_in = _parse_int(row.get("rx-bytes"))
    bytes_out = _parse_int(row.get("bytes-out"))
    if bytes_out is None:
        bytes_out = _parse_int(row.get("tx-bytes"))

    rx_rate = _parse_float(row.get("rx-rate"))
    tx_rate = _parse_float(row.get("tx-rate"))
    if rx_rate is None or tx_rate is None:
        duplex = (row.get("rate") or "").strip()
        if duplex and "/" in duplex:
            left, right = duplex.split("/", 1)
            left_v = _parse_float(left.strip())
            right_v = _parse_float(right.strip())
            # RouterOS "rate" is commonly formatted as "rx/tx".
            if rx_rate is None:
                rx_rate = left_v
            if tx_rate is None:
                tx_rate = right_v
    rx_bps = rx_rate if rx_rate is not None else computed_rx_bps
    tx_bps = tx_rate if tx_rate is not None else computed_tx_bps
    return {
        "timestamp": timestamp,
        "router_id": router_id,
        "router_name": router_name,
        "pppoe": pppoe,
        "address": (row.get("address") or "").strip(),
        "session_id": (row.get("session-id") or "").strip(),
        "uptime": (row.get("uptime") or "").strip(),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
    }
