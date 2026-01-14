import base64

from .notifiers import isp_ping as isp_ping_notifier
from .settings_store import get_state, save_state
from .db import utc_now_iso


def _preset_id(core_id, list_name):
    raw = f"{core_id}|{list_name}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _build_label_map(settings):
    cores = settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_labels = {core.get("id"): core.get("label") or core.get("id") for core in cores}
    labels = {}
    for preset in settings.get("pulsewatch", {}).get("list_presets", []):
        core_id = preset.get("core_id")
        list_name = preset.get("list")
        if not core_id or not list_name:
            continue
        key = _preset_id(core_id, list_name)
        labels[key] = f"{core_labels.get(core_id, core_id)} {list_name}".strip()
    return labels


def _command_help(settings):
    presets = settings.get("pulsewatch", {}).get("list_presets", [])
    lines = [
        "Pulsewatch commands:",
        "/? or /help - show this list",
        "/list - list available ISP presets",
        "/runpingall - run ping on all presets",
        "/runping <core_id> <list> - run ping on one preset",
        "/runspeedtestall - run speedtest on all presets",
        "/runspeedtest <core_id> <list> - run speedtest on one preset",
        "/status - show last Pulsewatch summary",
    ]
    if not presets:
        lines.append("")
        lines.append("No presets saved yet.")
    return "\n".join(lines)


def _format_ping_results(results_by_isp, label_map, ping_count):
    if not results_by_isp:
        return "No ping results."
    lines = [f"Ping summary ({utc_now_iso()}, count={ping_count})"]
    for isp_id, results in results_by_isp.items():
        label = label_map.get(isp_id, isp_id)
        if not results:
            lines.append(f"{label}: no targets")
            continue
        for item in results:
            target = item.get("target", "target")
            loss = item.get("loss")
            avg = item.get("avg_ms")
            loss_text = "n/a" if loss is None else f"{loss}%"
            avg_text = "n/a" if avg is None else f"{avg}ms"
            lines.append(f"{label} {target} | loss {loss_text}, avg {avg_text}")
    return "\n".join(lines)


def _format_speedtest_results(results, label_map):
    if not results:
        return "No speedtest results."
    lines = []
    for isp_id, item in results.items():
        label = label_map.get(isp_id, isp_id)
        if not isinstance(item, dict):
            lines.append(f"{label}: no result")
            continue
        down = item.get("download_mbps")
        up = item.get("upload_mbps")
        latency = item.get("latency_ms")
        down_text = "n/a" if down is None else f"{down} Mbps"
        up_text = "n/a" if up is None else f"{up} Mbps"
        lat_text = "n/a" if latency is None else f"{latency} ms"
        lines.append(f"{label} | down {down_text}, up {up_text}, latency {lat_text}")
    return "\n".join(lines)


def _status_summary(settings, state):
    pulse_cfg = settings.get("pulsewatch", {})
    enabled = "enabled" if pulse_cfg.get("enabled") else "disabled"
    presets = pulse_cfg.get("list_presets", [])
    lines = [f"Pulsewatch is {enabled}. Presets: {len(presets)}"]
    summaries = state.get("pulsewatch", {})
    label_map = _build_label_map(settings)
    for isp_id, data in summaries.items():
        summary = (data or {}).get("last_summary", {})
        if not summary:
            continue
        label = label_map.get(isp_id, isp_id)
        loss = summary.get("loss_max")
        avg = summary.get("avg_max")
        loss_text = "n/a" if loss is None else f"{loss}%"
        avg_text = "n/a" if avg is None else f"{avg}ms"
        lines.append(f"{label}: last loss {loss_text}, avg {avg_text}")
    return "\n".join(lines)


def handle_telegram_command(settings, text):
    text = (text or "").strip()
    if not text:
        return None
    parts = text.split()
    command = parts[0].split("@", 1)[0].lower()
    args = parts[1:]
    label_map = _build_label_map(settings)

    if command in ("/?", "/help", "/start"):
        return _command_help(settings)

    if command == "/list":
        presets = settings.get("pulsewatch", {}).get("list_presets", [])
        if not presets:
            return "No presets saved yet."
        lines = ["Presets:"]
        for preset in presets:
            core_id = preset.get("core_id")
            list_name = preset.get("list")
            address = preset.get("address")
            if not core_id or not list_name:
                continue
            lines.append(f"{core_id} {list_name} ({address})")
        return "\n".join(lines)

    if command == "/runpingall":
        state = get_state("isp_ping_state", {"pulsewatch": {}})
        state, results = isp_ping_notifier.run_pulsewatch_check(settings, state, force=True)
        save_state("isp_ping_state", state)
        ping_count = int(settings.get("pulsewatch", {}).get("ping", {}).get("count", 5))
        return _format_ping_results(results, label_map, ping_count)

    if command == "/runping":
        if len(args) < 2:
            return "Usage: /runping <core_id> <list>"
        core_id = args[0]
        list_name = " ".join(args[1:])
        isp_id = _preset_id(core_id, list_name)
        state = get_state("isp_ping_state", {"pulsewatch": {}})
        state, results = isp_ping_notifier.run_pulsewatch_check(
            settings, state, only_isps=[isp_id], force=True
        )
        save_state("isp_ping_state", state)
        ping_count = int(settings.get("pulsewatch", {}).get("ping", {}).get("count", 5))
        return _format_ping_results(results, label_map, ping_count)

    if command == "/runspeedtestall":
        state = get_state("isp_ping_state", {"pulsewatch": {}})
        results, messages = isp_ping_notifier.run_speedtests(settings, state, force=True)
        save_state("isp_ping_state", state)
        if messages:
            return "\n".join(messages)
        return _format_speedtest_results(results, label_map)

    if command == "/runspeedtest":
        if len(args) < 2:
            return "Usage: /runspeedtest <core_id> <list>"
        core_id = args[0]
        list_name = " ".join(args[1:])
        isp_id = _preset_id(core_id, list_name)
        state = get_state("isp_ping_state", {"pulsewatch": {}})
        results, messages = isp_ping_notifier.run_speedtests(
            settings, state, only_isps=[isp_id], force=True
        )
        save_state("isp_ping_state", state)
        if messages:
            return "\n".join(messages)
        return _format_speedtest_results(results, label_map)

    if command == "/status":
        state = get_state("isp_ping_state", {"pulsewatch": {}})
        return _status_summary(settings, state)

    return "Unknown command. Send /? for the command list."
