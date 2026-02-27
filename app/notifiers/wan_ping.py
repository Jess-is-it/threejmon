from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import ipaddress
import re
import socket
import subprocess
import time as time_module

from ..db import utc_now_iso, insert_wan_history_row, insert_wan_target_ping_result
from ..settings_defaults import WAN_MESSAGE_DEFAULTS, WAN_SUMMARY_DEFAULTS
from ..mikrotik import RouterOSClient
from .telegram import send_telegram, TelegramError


ICON_MAP = {
    ":warning:": "⚠️",
    ":x:": "❌",
    ":check:": "✅",
    ":red_circle:": "🔴",
    ":yellow_circle:": "🟡",
    ":green_circle:": "🟢",
}

RE_TIME = re.compile(r"time=([0-9.]+)\s*ms")
RE_BYTES = re.compile(r"(\d+)\s+bytes from")
RE_TTL = re.compile(r"ttl=(\d+)")

_DNS_CACHE = {}


def _replace_icons(text):
    if not text:
        return ""
    updated = str(text)
    for key, value in ICON_MAP.items():
        updated = updated.replace(key, value)
    return updated


def _parse_ts(value):
    if not value:
        return None
    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = raw[:-1]
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _netwatch_interval(seconds):
    seconds = max(int(seconds), 5)
    minutes, sec = divmod(seconds, 60)
    return f"00:{minutes:02d}:{sec:02d}"


def _parse_netwatch_seconds(value):
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("s"):
        try:
            return int(float(raw[:-1]))
        except ValueError:
            return None
    if ":" in raw:
        parts = raw.split(":")
        if len(parts) != 3:
            return None
        try:
            hours = int(parts[0])
            minutes = int(parts[1])
            seconds = int(parts[2])
        except ValueError:
            return None
        return hours * 3600 + minutes * 60 + seconds
    try:
        return int(float(raw))
    except ValueError:
        return None


def _find_core(pulse_settings, core_id):
    cores = pulse_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    for core in cores:
        if core.get("id") == core_id:
            return core
    return None


def _resolve_target(wan, pulse_settings):
    mode = (wan.get("mode") or "routed").strip().lower()
    netwatch_host = (wan.get("netwatch_host") or "").strip()
    if netwatch_host:
        return netwatch_host
    if mode == "routed":
        return None
    local_ip = (wan.get("local_ip") or "").strip()
    if local_ip:
        return local_ip
    return None


def _ensure_netwatch(client, wan_id, host, interval_seconds):
    comment = f"threejnotif_wan:{wan_id}"
    entries = client.list_netwatch()
    desired_interval = _netwatch_interval(interval_seconds)
    desired_interval_seconds = _parse_netwatch_seconds(desired_interval)
    desired_timeout_seconds = _parse_netwatch_seconds("1s")
    for entry in entries:
        if (entry.get("comment") or "") == comment:
            entry_id = entry.get(".id")
            needs_update = False
            if entry.get("host") != host:
                needs_update = True
            entry_interval_seconds = _parse_netwatch_seconds(entry.get("interval"))
            if desired_interval_seconds is None or entry_interval_seconds is None:
                if entry.get("interval") != desired_interval:
                    needs_update = True
            elif entry_interval_seconds != desired_interval_seconds:
                needs_update = True
            entry_timeout_seconds = _parse_netwatch_seconds(entry.get("timeout"))
            if desired_timeout_seconds is None or entry_timeout_seconds is None:
                if entry.get("timeout") != "1s":
                    needs_update = True
            elif entry_timeout_seconds != desired_timeout_seconds:
                needs_update = True
            if entry_id and needs_update:
                client.set_netwatch(entry_id, host, desired_interval, "1s", comment)
            return entry
    client.add_netwatch(host, _netwatch_interval(interval_seconds), "1s", comment)
    entries = client.list_netwatch()
    for entry in entries:
        if (entry.get("comment") or "") == comment:
            return entry
    return None


def _find_netwatch_entry(client, wan_id):
    comment = f"threejnotif_wan:{wan_id}"
    entries = client.list_netwatch()
    for entry in entries:
        if (entry.get("comment") or "") == comment:
            return entry
    return None


def _remove_netwatch_entry(client, wan_id):
    entry = _find_netwatch_entry(client, wan_id)
    if not entry:
        return False
    entry_id = (entry.get(".id") or "").strip()
    if not entry_id:
        return False
    replies = client.talk(["/tool/netwatch/remove", f"=.id={entry_id}"])
    for sentence in replies:
        if sentence and sentence[0] == "!trap":
            raise RuntimeError(f"RouterOS netwatch remove failed: {sentence}")
    return True


def _is_private_ipv4(value):
    raw = (value or "").strip()
    if not raw:
        return False
    try:
        ip_obj = ipaddress.ip_address(raw)
    except Exception:
        return False
    return bool(ip_obj.version == 4 and (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local))


def _refresh_routed_wan_hosts(settings, pulse_settings):
    wans = settings.get("wans", []) if isinstance(settings, dict) else []
    routed_rows = []
    for wan in wans:
        if not isinstance(wan, dict):
            continue
        mode = (wan.get("mode") or "routed").strip().lower()
        if mode != "routed":
            continue
        core_id = (wan.get("core_id") or "").strip()
        list_name = (wan.get("list_name") or "").strip()
        if not core_id or not list_name:
            continue
        routed_rows.append(
            {
                "core_id": core_id,
                "list_name": list_name,
                "mode": mode,
                "local_ip": (wan.get("local_ip") or "").strip(),
                "netwatch_host": (wan.get("netwatch_host") or "").strip(),
            }
        )
    if not routed_rows:
        return []

    try:
        from .. import main as app_main
    except Exception:
        return []
    detector = getattr(app_main, "detect_routed_wan_autofill", None)
    if not callable(detector):
        return []

    detect_map, detect_warnings = detector(pulse_settings, routed_rows, probe_public=False)
    for wan in wans:
        if not isinstance(wan, dict):
            continue
        mode = (wan.get("mode") or "routed").strip().lower()
        if mode != "routed":
            continue
        key = ((wan.get("core_id") or "").strip(), (wan.get("list_name") or "").strip())
        detected = detect_map.get(key) or {}
        detected_local = (detected.get("local_ip") or "").strip()
        detected_host = (detected.get("netwatch_host") or "").strip()
        if detected_local:
            wan["local_ip"] = detected_local
        if detected_host:
            wan["netwatch_host"] = detected_host
        else:
            current_host = (wan.get("netwatch_host") or "").strip()
            if _is_private_ipv4(current_host):
                wan["netwatch_host"] = ""
        if not (wan.get("local_ip") or "").strip():
            wan["enabled"] = False
    return detect_warnings or []


def _send_message(settings, message):
    token = (settings.get("telegram", {}) or {}).get("bot_token", "")
    chat_id = (settings.get("telegram", {}) or {}).get("chat_id", "")
    if not token or not chat_id or not message:
        return
    send_telegram(token, chat_id, _replace_icons(message))


def _default_messages(label):
    return {
        "down": WAN_MESSAGE_DEFAULTS["down_msg"],
        "up": WAN_MESSAGE_DEFAULTS["up_msg"],
        "still_down": WAN_MESSAGE_DEFAULTS["still_down_msg"],
    }


_STAMP_TZ = timezone(timedelta(hours=8))


def _format_date(dt):
    return dt.astimezone(_STAMP_TZ).strftime("%Y-%m-%d")


def _format_time(dt):
    return dt.astimezone(_STAMP_TZ).strftime("%I:%M %p").lstrip("0")


def _format_datetime(dt):
    return f"{_format_date(dt)} {_format_time(dt)}"


def _format_ping_lines(lines, count):
    count = max(min(int(count), 20), 1)
    output = []
    for idx in range(count):
        if idx < len(lines):
            output.append(lines[idx])
        else:
            output.append("Request timed out.")
    return "\n".join(output)


def _ping_from_server(target, source_ip, count=3, timeout_seconds=1):
    cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds)]
    if source_ip:
        cmd.extend(["-I", source_ip])
    cmd.append(target)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    replies = 0
    times = []
    reply_lines = []
    for line in (result.stdout or "").splitlines():
        if "bytes from" in line:
            replies += 1
            bytes_match = RE_BYTES.search(line)
            ttl_match = RE_TTL.search(line.lower())
            time_match = RE_TIME.search(line)
            bytes_value = bytes_match.group(1) if bytes_match else "64"
            ttl_value = ttl_match.group(1) if ttl_match else "0"
            time_value = f"{float(time_match.group(1)):.0f}ms" if time_match else "0ms"
            reply_lines.append(f"Reply from {target}: bytes={bytes_value} time={time_value} TTL={ttl_value}")
        time_match = RE_TIME.search(line)
        if time_match:
            times.append(float(time_match.group(1)))
    return replies, times, reply_lines


def _resolve_target_host_ipv4(host):
    raw = (host or "").strip()
    if not raw:
        return ""
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    key = raw.lower()
    cached = _DNS_CACHE.get(key)
    now_s = time_module.time()
    if isinstance(cached, dict) and cached.get("expires_at", 0) > now_s:
        return (cached.get("ip") or "").strip()
    ip_value = ""
    try:
        infos = socket.getaddrinfo(raw, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for info in infos:
            addr = info[4][0] if info and len(info) >= 5 else ""
            if addr:
                ip_value = addr
                break
    except Exception:
        ip_value = ""
    if ip_value:
        _DNS_CACHE[key] = {"ip": ip_value, "expires_at": now_s + 900}
    return ip_value or ""


def _apply_tokens(template, context, ping_provider=None):
    if not template:
        return ""
    text = str(template)
    ping_cache = {}

    def _replace_ping(match):
        count = int(match.group(1))
        if count in ping_cache:
            return ping_cache[count]
        if not ping_provider:
            ping_cache[count] = ""
            return ""
        ping_cache[count] = ping_provider(count) or ""
        return ping_cache[count]

    text = re.sub(r"\{\{?ping(\d{1,2})\}\}?", _replace_ping, text, flags=re.IGNORECASE)
    for key, value in context.items():
        placeholder = f"{{{key}}}"
        double = f"{{{{{key}}}}}"
        text = text.replace(placeholder, value).replace(double, value)
    return text


def run_check(settings, pulse_settings, state):
    now = datetime.now(timezone.utc)
    state = state or {}
    wan_state = state.setdefault("wans", {})

    general = settings.get("general") if isinstance(settings.get("general"), dict) else {}
    status_interval_seconds = max(int(general.get("interval_seconds", 30) or 30), 1)
    target_interval_seconds = int(general.get("target_latency_interval_seconds") or status_interval_seconds or 30)
    target_interval_seconds = max(target_interval_seconds, 1)
    enabled_targets = [
        item
        for item in (general.get("targets") or [])
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
    rotation_raw = general.get("target_rotation_enabled", False)
    if isinstance(rotation_raw, str):
        rotation_enabled = rotation_raw.strip().lower() in ("1", "true", "yes", "on")
    else:
        rotation_enabled = bool(rotation_raw)
    configured_targets_per_wan_raw = general.get("targets_per_wan_per_run", 1)
    if configured_targets_per_wan_raw in (None, ""):
        configured_targets_per_wan_raw = 1
    try:
        configured_targets_per_wan = max(int(configured_targets_per_wan_raw), 0)
    except Exception:
        configured_targets_per_wan = 1
    targets_per_wan = configured_targets_per_wan if rotation_enabled else len(enabled_targets)
    target_parallel_workers_raw = general.get("target_parallel_workers", 0)
    if target_parallel_workers_raw in (None, ""):
        target_parallel_workers_raw = 0
    try:
        target_parallel_workers = max(min(int(target_parallel_workers_raw), 64), 0)
    except Exception:
        target_parallel_workers = 0
    target_ping_timeout_ms = int(general.get("target_ping_timeout_ms", 1000) or 1000)
    target_ping_timeout_ms = max(min(target_ping_timeout_ms, 60000), 100)
    target_ping_timeout = f"{target_ping_timeout_ms}ms"
    target_ping_count = int(general.get("target_ping_count", 1) or 1)
    target_ping_count = max(min(target_ping_count, 20), 1)
    history_retention_days = int(general.get("history_retention_days", 400) or 400)

    last_status_poll_at = _parse_ts(state.get("last_status_poll_at"))
    status_due = not last_status_poll_at or now - last_status_poll_at >= timedelta(seconds=status_interval_seconds)
    target_enabled = bool(enabled_targets) and targets_per_wan > 0
    last_target_poll_at = _parse_ts(state.get("last_target_poll_at"))
    target_due = target_enabled and (
        not last_target_poll_at or now - last_target_poll_at >= timedelta(seconds=target_interval_seconds)
    )
    did_status_poll = False
    did_target_poll = False

    if not status_due and not target_due:
        state["last_run_at"] = utc_now_iso()
        return state

    target_cursor = state.get("target_cursor")
    if not isinstance(target_cursor, dict):
        target_cursor = {}
    target_latest = state.get("target_latest")
    if not isinstance(target_latest, dict):
        target_latest = {}

    def _netwatch_map(client):
        out = {}
        try:
            entries = client.list_netwatch()
        except Exception:
            return out
        for entry in entries:
            comment = (entry.get("comment") or "").strip()
            if comment.startswith("threejnotif_wan:"):
                out[comment.split(":", 1)[1]] = entry
        return out

    def _fetch_router_iface_ips(client):
        try:
            replies = client.talk(["/ip/address/print"])
        except Exception:
            return []
        out = []
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
                out.append(ipaddress.ip_interface(addr))
            except Exception:
                continue
        return out

    def _pick_router_src_address(configured_ip, iface_ips):
        raw = (configured_ip or "").strip()
        if not raw or not iface_ips:
            return ""
        try:
            ip_obj = ipaddress.ip_address(raw)
        except Exception:
            return ""
        for iface in iface_ips:
            try:
                if iface.ip == ip_obj:
                    return str(iface.ip)
            except Exception:
                continue
        return ""

    def _router_key(host, port, username, password):
        return f"{host}|{port}|{username}|{password}"

    def _pick_targets_for_wan(wan_id):
        if not enabled_targets or targets_per_wan <= 0:
            return []
        if not rotation_enabled:
            return enabled_targets
        idx = int(target_cursor.get(wan_id) or 0)
        count = min(targets_per_wan, len(enabled_targets))
        picked = [enabled_targets[(idx + offset) % len(enabled_targets)] for offset in range(count)]
        target_cursor[wan_id] = (idx + count) % max(len(enabled_targets), 1)
        return picked

    def _sample_target_with_client(client_obj, target_item, src_address, src_invalid):
        target_id = (target_item.get("id") or "").strip()
        target_host = (target_item.get("host") or "").strip()
        if not target_id or not target_host:
            return None
        ok = 0
        rtt_ms = None
        if not src_invalid:
            try:
                times = client_obj.ping_times(
                    target_host,
                    count=target_ping_count,
                    src_address=src_address,
                    timeout=target_ping_timeout,
                )
                if times:
                    ok = 1
                    rtt_ms = float(sum(times) / len(times))
            except Exception:
                ok = 0
                rtt_ms = None
        return {
            "target_id": target_id,
            "target_host": target_host,
            "ok": ok,
            "rtt_ms": rtt_ms,
        }

    # Group WAN checks per router to minimize RouterOS API logins.
    groups = {}
    for wan in settings.get("wans", []):
        if not wan.get("enabled", True):
            continue
        if not (wan.get("local_ip") or "").strip():
            continue
        wan_id = wan.get("id") or f"{wan.get('core_id')}:{wan.get('list_name')}"
        mode = (wan.get("mode") or "routed").lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"
        router_host = ""
        router_port = 8728
        router_user = ""
        router_pass = ""
        core_label = wan.get("core_id") or ""
        if mode == "bridged":
            router_id = (wan.get("pppoe_router_id") or "").strip()
            router = next((item for item in settings.get("pppoe_routers", []) if item.get("id") == router_id), None)
            if not router:
                prev = wan_state.get(wan_id, {}) or {}
                prev.update({"status": "down", "last_check": utc_now_iso(), "last_error": "PPPoE router not configured."})
                wan_state[wan_id] = prev
                continue
            if router.get("use_tls"):
                prev = wan_state.get(wan_id, {}) or {}
                prev.update({"status": "down", "last_check": utc_now_iso(), "last_error": "TLS RouterOS API is not supported yet."})
                wan_state[wan_id] = prev
                continue
            router_host = (router.get("host") or "").strip()
            router_port = int(router.get("port", 8728))
            router_user = router.get("username", "")
            router_pass = router.get("password", "")
            core = _find_core(pulse_settings, wan.get("core_id"))
            if core and core.get("label"):
                core_label = core.get("label")
        else:
            core = _find_core(pulse_settings, wan.get("core_id"))
            if not core or not core.get("host"):
                prev = wan_state.get(wan_id, {}) or {}
                prev.update({"status": "down", "last_check": utc_now_iso(), "last_error": "Core router not configured."})
                wan_state[wan_id] = prev
                continue
            router_host = (core.get("host") or "").strip()
            router_port = int(core.get("port", 8728))
            router_user = core.get("username", "")
            router_pass = core.get("password", "")
            if core.get("label"):
                core_label = core.get("label")

        if not router_host:
            prev = wan_state.get(wan_id, {}) or {}
            prev.update({"status": "down", "last_check": utc_now_iso(), "last_error": "Router host not configured."})
            wan_state[wan_id] = prev
            continue

        key = _router_key(router_host, router_port, router_user, router_pass)
        groups.setdefault(
            key,
            {
                "host": router_host,
                "port": router_port,
                "username": router_user,
                "password": router_pass,
                "items": [],
            },
        )["items"].append((wan_id, wan, core_label))

    # Process groups.
    for group in groups.values():
        client = RouterOSClient(
            group.get("host", ""),
            int(group.get("port", 8728)),
            group.get("username", ""),
            group.get("password", ""),
        )
        group_clients = [client]
        try:
            client.connect()

            def _ensure_parallel_clients(required_total):
                needed = max(int(required_total or 1), 1)
                while len(group_clients) < needed:
                    extra_client = RouterOSClient(
                        group.get("host", ""),
                        int(group.get("port", 8728)),
                        group.get("username", ""),
                        group.get("password", ""),
                    )
                    extra_client.connect()
                    group_clients.append(extra_client)
                return group_clients

            netwatch_entries = _netwatch_map(client) if status_due else {}
            iface_ips = _fetch_router_iface_ips(client) if target_due else []
            for wan_id, wan, core_label in group.get("items", []):
                mode = (wan.get("mode") or "routed").lower()
                target = _resolve_target(wan, pulse_settings)
                label = wan.get("list_name") or wan_id
                identifier = (wan.get("identifier") or "").strip()
                if identifier:
                    label = identifier
                # Source hint (configured in System Settings → Routers → Add ISP).
                # Must match an exact local IP configured on the router for ISP-scoped ping.
                configured_local_ip = (wan.get("local_ip") or "").strip()
                src_for_router_ping = _pick_router_src_address(configured_local_ip, iface_ips) or None
                has_src_hint = bool(configured_local_ip)
                src_invalid = bool(has_src_hint and not src_for_router_ping)

                # Server-side source IP (legacy, used only for Telegram template tokens like {ping5}).
                server_source_ip = configured_local_ip

                prev = wan_state.get(wan_id, {}) or {}
                prev_status = prev.get("status")
                now_iso = utc_now_iso()
                if status_due:
                    result = {"status": "down", "error": "", "rtt_ms": None}
                    try:
                        if not target:
                            if mode == "routed":
                                raise RuntimeError("No WAN IP configured for routed Netwatch host.")
                            raise RuntimeError("No target available for ping.")
                        entry = netwatch_entries.get(wan_id)
                        status = (entry or {}).get("status", "").lower()
                        if status in ("up", "down"):
                            result["status"] = status
                        else:
                            result["status"] = "down"
                    except Exception as exc:
                        result["status"] = "down"
                        result["error"] = str(exc)

                    now_local = now.astimezone(_STAMP_TZ)
                    down_since_dt = _parse_ts(prev.get("down_since"))
                    if result["status"] == "down" and prev_status != "down":
                        down_since_dt = now
                    if down_since_dt:
                        down_since_local = down_since_dt.astimezone(_STAMP_TZ)
                    else:
                        down_since_local = None
                    msg_cfg = settings.get("messages", {}).get(wan_id, {})
                    defaults = _default_messages(label)
                    token_context = {
                        "label": label,
                        "isp": label,
                        "wan-id": wan_id,
                        "core": core_label,
                        "list": wan.get("list_name") or "",
                        "mode": mode,
                        "status": result["status"],
                        "target": target or "",
                        "local-ip": server_source_ip or "",
                        "date": _format_date(now_local),
                        "time": _format_time(now_local),
                        "datetime": _format_datetime(now_local),
                        "down-sincedatetime": _format_datetime(down_since_local) if down_since_local else "n/a",
                        "down-since": _format_datetime(down_since_local) if down_since_local else "n/a",
                    }

                    def ping_provider(count):
                        if not target:
                            return "ping unavailable"
                        count = max(min(int(count), 20), 1)
                        try:
                            src = server_source_ip or None
                            _, _, lines = _ping_from_server(target, src, count=count, timeout_seconds=1)
                            return _format_ping_lines(lines, count)
                        except Exception:
                            return "ping unavailable"

                    down_tpl = msg_cfg.get("down_msg") or defaults["down"]
                    up_tpl = msg_cfg.get("up_msg") or defaults["up"]
                    still_tpl = msg_cfg.get("still_down_msg") or defaults["still_down"]
                    send_down_once = msg_cfg.get("send_down_once")
                    if send_down_once is None:
                        send_down_once = True
                    repeat_minutes = int(msg_cfg.get("repeat_down_interval_minutes") or 30)
                    still_hours = int(msg_cfg.get("still_down_interval_hours") or 8)

                    if result["status"] == "up":
                        if prev_status != "up":
                            try:
                                _send_message(settings, _apply_tokens(up_tpl, token_context, ping_provider))
                            except TelegramError:
                                pass
                        prev["down_since"] = ""
                        prev["last_down_notified_at"] = ""
                        prev["last_still_notified_at"] = ""
                    else:
                        if prev_status != "down":
                            try:
                                _send_message(settings, _apply_tokens(down_tpl, token_context, ping_provider))
                            except TelegramError:
                                pass
                            prev["down_since"] = now_iso
                            prev["last_down_notified_at"] = now_iso
                            prev["last_still_notified_at"] = ""
                        else:
                            last_down_at = _parse_ts(prev.get("last_down_notified_at"))
                            last_still_at = _parse_ts(prev.get("last_still_notified_at"))
                            down_since_at = _parse_ts(prev.get("down_since"))
                            if not send_down_once:
                                if not last_down_at or now - last_down_at >= timedelta(minutes=repeat_minutes):
                                    try:
                                        _send_message(settings, _apply_tokens(down_tpl, token_context, ping_provider))
                                    except TelegramError:
                                        pass
                                    prev["last_down_notified_at"] = now_iso
                            if still_tpl:
                                if down_since_at and now - down_since_at >= timedelta(hours=still_hours):
                                    if not last_still_at or now - last_still_at >= timedelta(hours=still_hours):
                                        try:
                                            _send_message(settings, _apply_tokens(still_tpl, token_context, ping_provider))
                                        except TelegramError:
                                            pass
                                        prev["last_still_notified_at"] = now_iso

                    prev.update(
                        {
                            "status": result["status"],
                            "last_check": now_iso,
                            "last_error": result.get("error", ""),
                            "last_rtt_ms": result.get("rtt_ms"),
                            "label": label,
                            "target": target,
                        }
                    )
                    history = prev.get("history")
                    if not isinstance(history, list):
                        history = []
                    history.append(
                        {
                            "ts": now_iso,
                            "status": result["status"],
                            "up_pct": 100 if result["status"] == "up" else 0,
                        }
                    )
                    if len(history) > 120:
                        history = history[-120:]
                    prev["history"] = history
                    insert_wan_history_row(
                        wan_id,
                        result["status"],
                        timestamp=now_iso,
                        target=target,
                        core_id=wan.get("core_id"),
                        label=label,
                        up_pct=100 if result["status"] == "up" else 0,
                        retention_days=history_retention_days,
                    )
                    did_status_poll = True

                # Target latency sampling (rotating) via RouterOS /tool/ping.
                if target_due:
                    did_target_poll = True
                    prev["last_target_check"] = now_iso
                    prev["target_src_address"] = (src_for_router_ping or "").strip()
                    selected_targets = _pick_targets_for_wan(wan_id)
                    sampled = {}
                    if selected_targets:
                        desired_workers = target_parallel_workers if target_parallel_workers > 0 else len(selected_targets)
                        desired_workers = max(1, min(desired_workers, len(selected_targets)))
                        active_clients = [client]
                        if desired_workers > 1:
                            try:
                                active_clients = _ensure_parallel_clients(desired_workers)
                            except Exception:
                                active_clients = [client]
                        worker_count = max(1, min(len(active_clients), desired_workers, len(selected_targets)))
                        if worker_count <= 1:
                            for target_item in selected_targets:
                                result_item = _sample_target_with_client(client, target_item, src_for_router_ping, src_invalid)
                                if result_item and result_item.get("target_id"):
                                    sampled[result_item["target_id"]] = result_item
                        else:
                            chunks = [[] for _ in range(worker_count)]
                            for idx, target_item in enumerate(selected_targets):
                                chunks[idx % worker_count].append(target_item)

                            def _run_chunk(worker_client, target_chunk):
                                out = {}
                                for target_item in target_chunk:
                                    result_item = _sample_target_with_client(worker_client, target_item, src_for_router_ping, src_invalid)
                                    if result_item and result_item.get("target_id"):
                                        out[result_item["target_id"]] = result_item
                                return out

                            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                                futures = []
                                for worker_idx in range(worker_count):
                                    futures.append(executor.submit(_run_chunk, active_clients[worker_idx], chunks[worker_idx]))
                                for future in as_completed(futures):
                                    try:
                                        sampled.update(future.result() or {})
                                    except Exception:
                                        continue

                    for t in selected_targets:
                        target_id = (t.get("id") or "").strip()
                        target_host = (t.get("host") or "").strip()
                        if not target_id or not target_host:
                            continue
                        result_item = sampled.get(target_id) or {}
                        ok = int(result_item.get("ok") or 0)
                        rtt_ms = result_item.get("rtt_ms")
                        insert_wan_target_ping_result(
                            wan_id,
                            target_id,
                            target_host,
                            ok,
                            rtt_ms=rtt_ms,
                            timestamp=now_iso,
                            core_id=wan.get("core_id"),
                            label=label,
                            src_address=(src_for_router_ping or "").strip(),
                            retention_days=history_retention_days,
                        )
                        target_latest.setdefault(wan_id, {})[target_id] = {"ts": now_iso, "ok": ok, "rtt_ms": rtt_ms}

                wan_state[wan_id] = prev
        except Exception as exc:
            error_msg = str(exc)
            now_iso = utc_now_iso()
            for wan_id, _, _core_label in group.get("items", []):
                prev = wan_state.get(wan_id, {}) or {}
                prev.update({"status": "down", "last_check": now_iso, "last_error": error_msg})
                wan_state[wan_id] = prev
        finally:
            for extra_client in group_clients[1:]:
                try:
                    extra_client.close()
                except Exception:
                    pass
            client.close()

    state["wans"] = wan_state
    stamp_now = utc_now_iso()
    state["last_run_at"] = stamp_now
    if did_status_poll:
        state["last_status_poll_at"] = stamp_now
    if did_target_poll:
        state["last_target_poll_at"] = stamp_now
    state["target_cursor"] = target_cursor
    state["target_latest"] = target_latest
    return state


def sync_netwatch(settings, pulse_settings):
    interval_seconds = int(settings.get("general", {}).get("interval_seconds", 30) or 30)
    errors = []
    detect_warnings = _refresh_routed_wan_hosts(settings, pulse_settings)
    if detect_warnings:
        for item in detect_warnings[:6]:
            errors.append(f"auto-detect: {item}")
    for wan in settings.get("wans", []):
        if not wan.get("enabled", True):
            continue
        if not (wan.get("local_ip") or "").strip():
            continue
        wan_id = wan.get("id") or f"{wan.get('core_id')}:{wan.get('list_name')}"
        mode = (wan.get("mode") or "routed").lower()
        target = _resolve_target(wan, pulse_settings)
        if not target:
            if mode == "routed":
                core = _find_core(pulse_settings, wan.get("core_id"))
                if core and core.get("host"):
                    client = RouterOSClient(
                        core.get("host", ""),
                        int(core.get("port", 8728)),
                        core.get("username", ""),
                        core.get("password", ""),
                    )
                    try:
                        client.connect()
                        _remove_netwatch_entry(client, wan_id)
                    except Exception as exc:
                        errors.append(f"{wan_id}: failed to remove stale Netwatch entry ({exc})")
                    finally:
                        client.close()
                errors.append(f"{wan_id}: WAN IP is required for routed Netwatch host")
            else:
                errors.append(f"{wan_id}: no target available for ping")
            continue
        try:
            if mode == "bridged":
                router_id = (wan.get("pppoe_router_id") or "").strip()
                router = next((item for item in settings.get("pppoe_routers", []) if item.get("id") == router_id), None)
                if not router:
                    errors.append(f"{wan_id}: PPPoE router not configured")
                    continue
                if router.get("use_tls"):
                    errors.append(f"{wan_id}: TLS RouterOS API is not supported yet")
                    continue
                client = RouterOSClient(
                    router.get("host", ""),
                    int(router.get("port", 8728)),
                    router.get("username", ""),
                    router.get("password", ""),
                )
                try:
                    client.connect()
                    _ensure_netwatch(client, wan_id, target, interval_seconds)
                finally:
                    client.close()
            else:
                core = _find_core(pulse_settings, wan.get("core_id"))
                if not core or not core.get("host"):
                    errors.append(f"{wan_id}: core router not configured")
                    continue
                client = RouterOSClient(
                    core.get("host", ""),
                    int(core.get("port", 8728)),
                    core.get("username", ""),
                    core.get("password", ""),
                )
                try:
                    client.connect()
                    _ensure_netwatch(client, wan_id, target, interval_seconds)
                finally:
                    client.close()
        except Exception as exc:
            errors.append(f"{wan_id}: {exc}")
    return errors


def send_daily_summary(settings, pulse_settings, state):
    summary_cfg = settings.get("summary", {})
    if not summary_cfg.get("enabled"):
        return state
    now = datetime.now(timezone.utc)
    now_local = now.astimezone(_STAMP_TZ)
    wan_state = (state or {}).get("wans", {})
    lines = []
    total = 0
    up_count = 0
    for wan in settings.get("wans", []):
        if not wan.get("enabled", True):
            continue
        local_ip = (wan.get("local_ip") or "").strip()
        if not local_ip:
            continue
        mode = (wan.get("mode") or "routed").lower()
        if mode == "bridged" and not wan.get("pppoe_router_id"):
            continue
        wan_id = wan.get("id") or f"{wan.get('core_id')}:{wan.get('list_name')}"
        label = (wan.get("identifier") or "").strip() or wan.get("list_name") or wan_id
        status = (wan_state.get(wan_id, {}).get("status") or "down").upper()
        total += 1
        if status == "UP":
            up_count += 1
        target = _resolve_target(wan, pulse_settings) or ""
        context = {
            "label": label,
            "status": status,
            "target": target,
            "local-ip": local_ip,
            "date": _format_date(now_local),
            "time": _format_time(now_local),
            "datetime": _format_datetime(now_local),
        }
        line_template = summary_cfg.get("line_template") or WAN_SUMMARY_DEFAULTS["line_template"]
        lines.append(_apply_tokens(line_template, context))

    if total == 0:
        return state
    context = {
        "up": str(up_count),
        "total": str(total),
        "down": str(max(total - up_count, 0)),
        "date": _format_date(now_local),
        "time": _format_time(now_local),
        "datetime": _format_datetime(now_local),
    }
    if up_count == total:
        header = summary_cfg.get("all_up_msg") or WAN_SUMMARY_DEFAULTS["all_up_msg"]
    else:
        header = summary_cfg.get("partial_msg") or WAN_SUMMARY_DEFAULTS["partial_msg"]
    message = _apply_tokens(header, context)
    if lines:
        message = f"{message}\n" + "\n".join(lines)
    try:
        _send_message(settings, message)
    except TelegramError:
        pass
    return state
