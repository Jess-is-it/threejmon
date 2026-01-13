import os
import re
import subprocess
import time as time_module
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, time

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from .telegram import send_telegram

RE_BYTES = re.compile(r"(\d+)\s+bytes from")
RE_TTL = re.compile(r"ttl=(\d+)")
RE_TIME = re.compile(r"time=([0-9.]+)\s*ms")


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


def run_check(cfg, state):
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
                send_telegram(
                    cfg["telegram"].get("bot_token", ""),
                    cfg["telegram"].get("chat_id", ""),
                    f"{base_message} | {stamp}",
                )
            state.setdefault("last_status", {})[target["ip"]] = "up" if up else "down"

    if should_send_report(cfg, state, now):
        send_telegram(cfg["telegram"].get("bot_token", ""), cfg["telegram"].get("chat_id", ""), build_report_message(now, results))
        state["last_report_date"] = now.date().isoformat()

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
