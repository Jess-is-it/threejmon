import base64
import json
import logging
import re
import shlex
import subprocess
import time as time_module
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, time, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from ..db import delete_pulsewatch_older_than, insert_alert_log, insert_ping_result, insert_speedtest_result, utc_now_iso
from ..mikrotik import RouterOSClient, reconcile_address_lists
from .telegram import send_telegram

logger = logging.getLogger(__name__)

RE_BYTES = re.compile(r"(\d+)\s+bytes from")
RE_TTL = re.compile(r"ttl=(\d+)")
RE_TIME = re.compile(r"time=([0-9.]+)\s*ms")

COMMENT_TAG = "threejnotif:pulsewatch"

def _preset_id(core_id, list_name):
    raw = f"{core_id}|{list_name}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _get_router_source_ip(isp, core_id):
    core_id = (core_id or "").lower()
    sources = isp.get("sources") or {}
    if isinstance(sources, dict):
        value = sources.get(core_id)
        if value:
            return str(value).strip()
    if core_id == "core2":
        value = isp.get("core2_source_ip")
    elif core_id == "core3":
        value = isp.get("core3_source_ip")
    else:
        value = None
    if value:
        return str(value).strip()
    legacy = isp.get("source_ip")
    return str(legacy).strip() if legacy else ""


def _get_ping_source_ip(isp):
    preferred = (isp.get("ping_core_id") or isp.get("ping_router") or "auto").lower()
    if preferred and preferred != "auto":
        return _get_router_source_ip(isp, preferred)
    sources = isp.get("sources") or {}
    order = []
    if isinstance(sources, dict):
        if "core2" in sources:
            order.append("core2")
        if "core3" in sources:
            order.append("core3")
        for key in sorted(sources.keys()):
            if key not in order:
                order.append(key)
    for core_id in order:
        value = _get_router_source_ip(isp, core_id)
        if value:
            return value
    return _get_router_source_ip(isp, "core2") or _get_router_source_ip(isp, "core3")


def _isps_from_presets(pulse_cfg):
    presets = pulse_cfg.get("list_presets", [])
    isps = []
    for preset in presets:
        core_id = preset.get("core_id")
        list_name = preset.get("list")
        identifier = (preset.get("identifier") or "").strip()
        if not core_id or not list_name:
            continue
        isp_id = _preset_id(core_id, list_name)
        label_value = identifier or list_name
        isps.append(
            {
                "id": isp_id,
                "label": label_value,
                "sources": {core_id: preset.get("address")},
                "ping_targets": preset.get("ping_targets", []),
                "thresholds": {
                    "latency_ms": preset.get("latency_ms", 120),
                    "loss_pct": preset.get("loss_pct", 20),
                },
                "consecutive_breach_count": preset.get("breach_count", 3),
                "cooldown_minutes": preset.get("cooldown_minutes", 10),
            }
        )
    return isps


def parse_list(values):
    if isinstance(values, str):
        values = values.splitlines()
    return [line.strip() for line in values if line and line.strip()]


def ping_ip(ip, timeout_seconds, count):
    cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds), ip]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    replies = []
    for line in (result.stdout or "").splitlines():
        if "bytes from" not in line:
            continue
        bytes_match = RE_BYTES.search(line)
        ttl_match = RE_TTL.search(line)
        time_match = RE_TIME.search(line)
        bytes_value = bytes_match.group(1) if bytes_match else "32"
        ttl_value = ttl_match.group(1) if ttl_match else "0"
        if time_match:
            time_ms = int(round(float(time_match.group(1))))
            time_value = f"{time_ms}ms"
        else:
            time_value = "0ms"
        replies.append(f"Reply from {ip}: bytes={bytes_value} time={time_value} TTL={ttl_value}")

    while len(replies) < count:
        replies.append("Request timed out.")

    return replies


def ping_with_source(ip, source_ip, timeout_seconds, count):
    cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds)]
    if source_ip:
        cmd.extend(["-I", source_ip])
    cmd.append(ip)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output = result.stdout or ""
    replies = 0
    times = []
    for line in output.splitlines():
        if "bytes from" in line:
            replies += 1
        time_match = RE_TIME.search(line)
        if time_match:
            times.append(float(time_match.group(1)))
    loss = 100.0
    if count > 0:
        loss = round(100.0 * (count - replies) / count, 1)
    min_ms = min(times) if times else None
    max_ms = max(times) if times else None
    avg_ms = round(sum(times) / len(times), 1) if times else None
    return {
        "loss": loss,
        "min_ms": min_ms,
        "avg_ms": avg_ms,
        "max_ms": max_ms,
        "raw_output": output,
        "replies": replies,
    }


def parse_daily_time(value):
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        raise ValueError("daily_time must be HH:MM")
    hour = int(parts[0])
    minute = int(parts[1])
    return time(hour=hour, minute=minute)


def normalize_report_state(cfg, state):
    report_time_value = cfg["report"].get("daily_time", "07:00")
    report_timezone = cfg["report"].get("timezone", "Asia/Manila")
    if state.get("last_report_time") != report_time_value or state.get("last_report_timezone") != report_timezone:
        state["last_report_date"] = None
        state["last_report_time"] = report_time_value
        state["last_report_timezone"] = report_timezone


def should_send_report(cfg, state, now):
    report_time = parse_daily_time(cfg["report"].get("daily_time", "07:00"))
    last_report_date = state.get("last_report_date")
    if last_report_date == now.date().isoformat():
        return False
    if now.time() >= report_time:
        return True
    return False


def build_report_message(now, results):
    lines = [
        "ISP Ping Status Report",
        f"Time: {now.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    for item in results:
        status = "UP" if item["up"] else "DOWN"
        lines.append(f"{item['label']} ({item['ip']}) | {status}")
        lines.extend(item["icmp_lines"])
    return "\n".join(lines)


def _parse_iso(value):
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _utcnow():
    return datetime.now(timezone.utc)


def _format_speedtest_command(cfg, source_ip, isp_id):
    speed_cfg = cfg["pulsewatch"]["speedtest"]
    cmd = [speed_cfg.get("command") or "speedtest"]
    args = speed_cfg.get("args") or ""
    if args:
        cmd.extend(shlex.split(args))

    if speed_cfg.get("use_netns"):
        netns = f"{speed_cfg.get('netns_prefix', 'isp')}{isp_id}"
        cmd = ["ip", "netns", "exec", netns] + cmd
        return cmd

    if source_ip and "--source" not in args and "--interface" not in args:
        cmd.extend(["--source", source_ip])
    return cmd


def _parse_speedtest_json(raw_output):
    data = json.loads(raw_output)
    download_mbps = None
    upload_mbps = None
    latency_ms = None
    server_name = None
    server_id = None
    public_ip = None

    if isinstance(data, dict):
        if "download" in data and isinstance(data["download"], dict):
            bandwidth = data["download"].get("bandwidth")
            if bandwidth is not None:
                download_mbps = round(bandwidth * 8 / 1_000_000, 2)
        elif "download" in data and isinstance(data["download"], (int, float)):
            download_mbps = round(float(data["download"]) / 1_000_000, 2)

        if "upload" in data and isinstance(data["upload"], dict):
            bandwidth = data["upload"].get("bandwidth")
            if bandwidth is not None:
                upload_mbps = round(bandwidth * 8 / 1_000_000, 2)
        elif "upload" in data and isinstance(data["upload"], (int, float)):
            upload_mbps = round(float(data["upload"]) / 1_000_000, 2)

        ping = data.get("ping") or {}
        if isinstance(ping, dict):
            latency_ms = ping.get("latency")

        server = data.get("server") or {}
        if isinstance(server, dict):
            server_name = server.get("name")
            server_id = server.get("id")

        interface = data.get("interface") or {}
        if isinstance(interface, dict):
            public_ip = interface.get("externalIp")

    return {
        "download_mbps": download_mbps,
        "upload_mbps": upload_mbps,
        "latency_ms": latency_ms,
        "server_name": server_name,
        "server_id": server_id,
        "public_ip": public_ip,
    }


def _run_speedtest(cfg, isp):
    source_ip = _get_ping_source_ip(isp)
    cmd = _format_speedtest_command(cfg, source_ip, isp.get("id"))
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout or "Speedtest failed.")
    raw_output = result.stdout.strip()
    if not raw_output:
        raise RuntimeError("Speedtest returned empty output.")
    parsed = _parse_speedtest_json(raw_output)
    if parsed["download_mbps"] is None or parsed["upload_mbps"] is None:
        raise RuntimeError("Speedtest JSON missing bandwidth fields.")
    if not cfg["pulsewatch"].get("store_raw_output"):
        raw_output = None
    insert_speedtest_result(
        isp.get("id"),
        parsed["download_mbps"],
        parsed["upload_mbps"],
        parsed.get("latency_ms"),
        parsed.get("server_name"),
        parsed.get("server_id"),
        parsed.get("public_ip"),
        raw_output=raw_output,
    )
    return parsed


def _select_alert_chat_id(cfg):
    alert_channel = cfg["telegram"].get("alert_channel_id")
    return alert_channel or cfg["telegram"].get("chat_id", "")


def _should_run_reconcile(state, interval_minutes):
    if interval_minutes <= 0:
        return True
    last = _parse_iso(state.get("last_mikrotik_reconcile_at"))
    if not last:
        return True
    return _utcnow() - last >= timedelta(minutes=interval_minutes)


def _reconcile_mikrotik(cfg, state):
    pulse_cfg = cfg.get("pulsewatch", {})
    if not pulse_cfg.get("manage_address_lists"):
        return
    if not _should_run_reconcile(state, int(pulse_cfg.get("reconcile_interval_minutes", 10))):
        return

    isps = pulse_cfg.get("isps", [])
    cores = pulse_cfg.get("mikrotik", {}).get("cores", [])
    presets = pulse_cfg.get("list_presets", [])
    desired = {core.get("id"): [] for core in cores if core.get("id")}
    if presets:
        for preset in presets:
            core_id = preset.get("core_id")
            list_name = preset.get("list")
            address = (preset.get("address") or "").strip()
            if core_id and list_name and address:
                desired.setdefault(core_id, []).append({"list": list_name, "address": address})
    else:
        for idx, isp in enumerate(isps, start=1):
            list_name = f"TO-ISP{idx}"
            for core in cores:
                core_id = core.get("id")
                if not core_id:
                    continue
                source_ip = _get_router_source_ip(isp, core_id)
                if source_ip:
                    desired.setdefault(core_id, []).append({"list": list_name, "address": source_ip})

    for core in cores:
        core_id = core.get("id") or "core"
        host = core.get("host")
        if not host:
            continue
        client = RouterOSClient(
            host,
            int(core.get("port", 8728)),
            core.get("username", ""),
            core.get("password", ""),
        )
        try:
            client.connect()
            actions, warnings = reconcile_address_lists(client, desired.get(core_id, []), COMMENT_TAG)
            for warning in warnings:
                logger.warning("MikroTik %s: %s", core_id, warning)
            logger.info("MikroTik %s reconcile actions: %s", core_id, actions)
        finally:
            client.close()

    state["last_mikrotik_reconcile_at"] = utc_now_iso()


def _pulsewatch_summary(results):
    loss_values = [item["loss"] for item in results if item.get("loss") is not None]
    avg_values = [item["avg_ms"] for item in results if item.get("avg_ms") is not None]
    loss_max = max(loss_values) if loss_values else None
    avg_max = max(avg_values) if avg_values else None
    return loss_max, avg_max


def _purge_pulsewatch_data(cfg, state):
    pulse_cfg = cfg.get("pulsewatch", {})
    retention_days = int(pulse_cfg.get("retention_days", 0) or 0)
    if retention_days <= 0:
        return
    last_run = _parse_iso(state.get("last_pulsewatch_prune_at"))
    if last_run and _utcnow() - last_run < timedelta(hours=24):
        return
    cutoff = _utcnow() - timedelta(days=retention_days)
    delete_pulsewatch_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
    state["last_pulsewatch_prune_at"] = _utcnow().replace(microsecond=0).isoformat() + "Z"


def run_pulsewatch_check(cfg, state, only_isps=None, force=False):
    pulse_cfg = cfg.get("pulsewatch", {})
    _purge_pulsewatch_data(cfg, state)
    _reconcile_mikrotik(cfg, state)
    if not pulse_cfg.get("enabled") and not force:
        return state, {}

    presets = pulse_cfg.get("list_presets", [])
    isps = _isps_from_presets(pulse_cfg) if presets else pulse_cfg.get("isps", [])
    if only_isps is not None:
        isps = [isp for isp in isps if isp.get("id") in only_isps]

    ping_cfg = pulse_cfg.get("ping", {})
    timeout_seconds = int(ping_cfg.get("timeout_seconds", 1))
    ping_count = int(ping_cfg.get("count", 5))
    max_workers = int(ping_cfg.get("max_parallel", 8))

    tasks = {}
    results_by_isp = {isp.get("id"): [] for isp in isps}
    with ThreadPoolExecutor(max_workers=max(max_workers, 1)) as executor:
        for isp in isps:
            isp_id = isp.get("id")
            source_ip = _get_ping_source_ip(isp)
            targets = parse_list(isp.get("ping_targets", []))
            if not source_ip or not targets:
                continue
            for target in targets:
                future = executor.submit(ping_with_source, target, source_ip, timeout_seconds, ping_count)
                tasks[future] = (isp_id, target)

        for future in as_completed(tasks):
            isp_id, target = tasks[future]
            try:
                result = future.result()
            except Exception as exc:
                logger.exception("Pulsewatch ping failed for %s %s", isp_id, target)
                result = {"loss": 100.0, "min_ms": None, "avg_ms": None, "max_ms": None, "raw_output": str(exc)}
            if not cfg["pulsewatch"].get("store_raw_output"):
                result["raw_output"] = None
            insert_ping_result(
                isp_id,
                target,
                result.get("loss"),
                result.get("min_ms"),
                result.get("avg_ms"),
                result.get("max_ms"),
                raw_output=result.get("raw_output"),
            )
            results_by_isp.setdefault(isp_id, []).append({"target": target, **result})

    pulse_state = state.setdefault("pulsewatch", {})
    isp_state = pulse_state.setdefault("isps", {})

    for isp in isps:
        isp_id = isp.get("id")
        if not isp_id:
            continue
        results = results_by_isp.get(isp_id, [])
        loss_max, avg_max = _pulsewatch_summary(results)
        thresholds = isp.get("thresholds", {})
        latency_threshold = float(thresholds.get("latency_ms", 0) or 0)
        loss_threshold = float(thresholds.get("loss_pct", 0) or 0)
        breach = False
        if loss_max is not None and loss_threshold and loss_max >= loss_threshold:
            breach = True
        if avg_max is not None and latency_threshold and avg_max >= latency_threshold:
            breach = True

        current = isp_state.setdefault(
            isp_id,
            {
                "breach_count": 0,
                "cooldown_until": "",
                "last_summary": {},
            },
        )
        if breach:
            current["breach_count"] = int(current.get("breach_count", 0)) + 1
        else:
            current["breach_count"] = 0

        summary = {
            "loss_max": loss_max,
            "avg_max": avg_max,
            "last_check": utc_now_iso(),
        }
        current["last_summary"] = summary

        cooldown_until = _parse_iso(current.get("cooldown_until"))
        if cooldown_until and cooldown_until > _utcnow():
            continue

        required_breaches = int(isp.get("consecutive_breach_count", 3) or 1)
        if breach and current["breach_count"] >= required_breaches:
            cooldown_minutes = int(isp.get("cooldown_minutes", 10) or 0)
            cooldown_until = _utcnow() + timedelta(minutes=cooldown_minutes)
            current["cooldown_until"] = cooldown_until.replace(microsecond=0).isoformat() + "Z"

            label = isp.get("label") or isp_id
            loss_text = "n/a" if loss_max is None else f"{loss_max}%"
            avg_text = "n/a" if avg_max is None else f"{avg_max}ms"
            message = (
                f"Pulsewatch Alert: {label} sustained high latency/loss. "
                f"Loss max {loss_text}, Avg max {avg_text}."
            )
            send_telegram(cfg["telegram"].get("bot_token", ""), _select_alert_chat_id(cfg), message)
            insert_alert_log(isp_id, "pulsewatch_threshold", message, current["cooldown_until"])

    return state, results_by_isp


def run_speedtests(cfg, state, only_isps=None, force=False):
    pulse_cfg = cfg.get("pulsewatch", {})
    if not pulse_cfg.get("enabled") or not pulse_cfg.get("speedtest", {}).get("enabled"):
        return {}, ["Speedtest is disabled."]

    presets = pulse_cfg.get("list_presets", [])
    isps = _isps_from_presets(pulse_cfg) if presets else pulse_cfg.get("isps", [])
    if only_isps:
        isps = [isp for isp in isps if isp.get("id") in only_isps]

    messages = []
    results = {}
    last_runs = state.setdefault("pulsewatch", {}).setdefault("speedtest_last", {})
    min_interval = int(pulse_cfg.get("speedtest", {}).get("min_interval_minutes", 60))

    for isp in isps:
        isp_id = isp.get("id")
        if not isp_id:
            continue
        last = _parse_iso(last_runs.get(isp_id))
        if not force and last and _utcnow() - last < timedelta(minutes=min_interval):
            messages.append(f"{isp_id} speedtest skipped (rate limit).")
            continue
        try:
            result = _run_speedtest(cfg, isp)
            results[isp_id] = result
            last_runs[isp_id] = utc_now_iso()
        except Exception as exc:
            logger.exception("Speedtest failed for %s", isp_id)
            messages.append(f"{isp_id} speedtest failed: {exc}")

    return results, messages


def run_check(cfg, state, force_report=False):
    timeout_seconds = int(cfg["general"].get("ping_timeout_seconds", 1))
    ping_count = int(cfg["general"].get("ping_count", 5))
    timezone = cfg["report"].get("timezone", "Asia/Manila")
    targets = cfg.get("targets", [])

    if ZoneInfo is not None:
        now = datetime.now(ZoneInfo(timezone))
    else:
        now = datetime.now()
    stamp = now.strftime("%Y-%m-%d %H:%M:%S")

    normalize_report_state(cfg, state)

    results = []
    max_workers = min(len(targets), int(cfg["general"].get("max_parallel_pings", 8)))
    with ThreadPoolExecutor(max_workers=max_workers or 1) as executor:
        future_map = {
            executor.submit(ping_ip, target["ip"], timeout_seconds, ping_count): target
            for target in targets
        }
        for future in as_completed(future_map):
            target = future_map[future]
            icmp_lines = future.result()
            up = any(line.startswith("Reply from") for line in icmp_lines)
            results.append(
                {
                    "ip": target["ip"],
                    "label": target.get("label") or target["ip"],
                    "up": up,
                    "icmp_lines": icmp_lines,
                }
            )
            last_status = state.get("last_status", {}).get(target["ip"])
            if not up and last_status != "down":
                base_message = target.get("down_message") or f"{target['ip']} is DOWN"
                send_telegram(
                    cfg["telegram"].get("bot_token", ""),
                    cfg["telegram"].get("chat_id", ""),
                    f"{base_message} | {stamp}",
                )
            if up and last_status == "down":
                base_message = target.get("up_message") or f"{target['ip']} is UP"
                ping_count = int(cfg["general"].get("ping_count", 5))
                include_up_icmp = bool(cfg["general"].get("include_up_icmp", False))
                up_icmp_lines = int(cfg["general"].get("up_icmp_lines", ping_count))
                up_icmp_lines = max(0, min(up_icmp_lines, 20))
                ping_details = "\n".join(icmp_lines[:up_icmp_lines])
                send_telegram(
                    cfg["telegram"].get("bot_token", ""),
                    cfg["telegram"].get("chat_id", ""),
                    (
                        f"{base_message} | {stamp}\n({ping_count} pings) {ping_details}"
                        if include_up_icmp and up_icmp_lines > 0
                        else f"{base_message} | {stamp}"
                    ),
                )
            state.setdefault("last_status", {})[target["ip"]] = "up" if up else "down"

    if targets and (force_report or should_send_report(cfg, state, now)):
        send_telegram(
            cfg["telegram"].get("bot_token", ""),
            cfg["telegram"].get("chat_id", ""),
            build_report_message(now, results),
        )
        state["last_report_date"] = now.date().isoformat()

    state, _ = run_pulsewatch_check(cfg, state)
    return state


def run_loop(cfg_provider, state_provider, save_state, stop_event):
    while not stop_event.is_set():
        cfg = cfg_provider()
        if not cfg.get("enabled"):
            time_module.sleep(5)
            continue

        state = state_provider()
        state = run_check(cfg, state)
        save_state(state)

        interval_seconds = int(cfg["general"].get("daemon_interval_seconds", 15))
        time_module.sleep(max(interval_seconds, 1))
