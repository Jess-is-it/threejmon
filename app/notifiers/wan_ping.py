from datetime import datetime, timezone, timedelta

from ..db import utc_now_iso
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


def _find_core(pulse_settings, core_id):
    cores = pulse_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    for core in cores:
        if core.get("id") == core_id:
            return core
    return None


def _find_preset(pulse_settings, core_id, list_name):
    for preset in pulse_settings.get("pulsewatch", {}).get("list_presets", []):
        if preset.get("core_id") == core_id and preset.get("list") == list_name:
            return preset
    return None


def _resolve_target(wan, pulse_settings):
    gateway = (wan.get("gateway_ip") or "").strip()
    if gateway:
        return gateway
    preset = _find_preset(pulse_settings, wan.get("core_id"), wan.get("list_name"))
    targets = preset.get("ping_targets", []) if preset else []
    for target in targets:
        cleaned = (target or "").strip()
        if cleaned:
            return cleaned
    return None


def _ensure_netwatch(client, wan_id, host, interval_seconds):
    comment = f"threejnotif_wan:{wan_id}"
    entries = client.list_netwatch()
    desired_interval = _netwatch_interval(interval_seconds)
    for entry in entries:
        if (entry.get("comment") or "") == comment:
            entry_id = entry.get(".id")
            needs_update = False
            if entry.get("host") != host:
                needs_update = True
            if entry.get("interval") != desired_interval:
                needs_update = True
            if entry.get("timeout") != "1s":
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


def _send_message(settings, message):
    token = (settings.get("telegram", {}) or {}).get("bot_token", "")
    chat_id = (settings.get("telegram", {}) or {}).get("chat_id", "")
    if not token or not chat_id or not message:
        return
    send_telegram(token, chat_id, _replace_icons(message))


def _default_messages(label):
    return {
        "down": f"{label} is DOWN",
        "up": f"{label} is UP",
        "still_down": f"{label} is still DOWN",
    }


def _apply_tokens(template, label):
    if not template:
        return ""
    return (
        str(template)
        .replace("{label}", label)
        .replace("{isp}", label)
    )


def run_check(settings, pulse_settings, state):
    now = datetime.now(timezone.utc)
    state = state or {}
    wan_state = state.setdefault("wans", {})
    interval_seconds = int(settings.get("general", {}).get("interval_seconds", 30) or 30)

    for wan in settings.get("wans", []):
        if not wan.get("enabled", True):
            continue
        wan_id = wan.get("id") or f"{wan.get('core_id')}:{wan.get('list_name')}"
        mode = (wan.get("mode") or "routed").lower()
        target = _resolve_target(wan, pulse_settings)
        label = wan.get("list_name") or wan_id
        preset = _find_preset(pulse_settings, wan.get("core_id"), wan.get("list_name"))
        identifier = (preset.get("identifier") if preset else "") or ""
        if identifier:
            label = identifier

        result = {"status": "down", "error": "", "rtt_ms": None}
        try:
            if not target:
                raise RuntimeError("No target available for ping.")
            if mode == "bridged":
                router_id = (wan.get("pppoe_router_id") or "").strip()
                router = next((item for item in settings.get("pppoe_routers", []) if item.get("id") == router_id), None)
                if not router:
                    raise RuntimeError("PPPoE router not configured.")
                if router.get("use_tls"):
                    raise RuntimeError("TLS RouterOS API is not supported yet.")
                client = RouterOSClient(
                    router.get("host", ""),
                    int(router.get("port", 8728)),
                    router.get("username", ""),
                    router.get("password", ""),
                )
                try:
                    client.connect()
                    entry = _ensure_netwatch(client, wan_id, target, interval_seconds)
                    status = (entry or {}).get("status", "").lower()
                    if status in ("up", "down"):
                        result["status"] = status
                    else:
                        result["status"] = "down"
                finally:
                    client.close()
            else:
                core = _find_core(pulse_settings, wan.get("core_id"))
                if not core or not core.get("host"):
                    raise RuntimeError("Core router not configured.")
                client = RouterOSClient(
                    core.get("host", ""),
                    int(core.get("port", 8728)),
                    core.get("username", ""),
                    core.get("password", ""),
                )
                try:
                    client.connect()
                    src = (wan.get("local_ip") or "").strip() or None
                    ok, rtt_ms, _ = client.ping(target, count=3, src_address=src)
                    result["status"] = "up" if ok else "down"
                    result["rtt_ms"] = rtt_ms
                finally:
                    client.close()
        except Exception as exc:
            result["status"] = "down"
            result["error"] = str(exc)

        prev = wan_state.get(wan_id, {})
        prev_status = prev.get("status")
        now_iso = utc_now_iso()
        msg_cfg = settings.get("messages", {}).get(wan_id, {})
        defaults = _default_messages(label)
        down_msg = _apply_tokens(msg_cfg.get("down_msg") or defaults["down"], label)
        up_msg = _apply_tokens(msg_cfg.get("up_msg") or defaults["up"], label)
        still_msg = _apply_tokens(msg_cfg.get("still_down_msg") or defaults["still_down"], label)
        send_down_once = msg_cfg.get("send_down_once")
        if send_down_once is None:
            send_down_once = True
        repeat_minutes = int(msg_cfg.get("repeat_down_interval_minutes") or 30)
        still_hours = int(msg_cfg.get("still_down_interval_hours") or 8)

        if result["status"] == "up":
            if prev_status != "up":
                try:
                    _send_message(settings, up_msg)
                except TelegramError:
                    pass
            prev["down_since"] = ""
            prev["last_down_notified_at"] = ""
            prev["last_still_notified_at"] = ""
        else:
            if prev_status != "down":
                try:
                    _send_message(settings, down_msg)
                except TelegramError:
                    pass
                prev["down_since"] = now_iso
                prev["last_down_notified_at"] = now_iso
                prev["last_still_notified_at"] = ""
            else:
                last_down_at = _parse_ts(prev.get("last_down_notified_at"))
                last_still_at = _parse_ts(prev.get("last_still_notified_at"))
                if not send_down_once:
                    if not last_down_at or now - last_down_at >= timedelta(minutes=repeat_minutes):
                        try:
                            _send_message(settings, down_msg)
                        except TelegramError:
                            pass
                        prev["last_down_notified_at"] = now_iso
                if still_msg:
                    if not last_still_at or now - last_still_at >= timedelta(hours=still_hours):
                        try:
                            _send_message(settings, still_msg)
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
        wan_state[wan_id] = prev

    state["wans"] = wan_state
    state["last_run_at"] = utc_now_iso()
    return state
