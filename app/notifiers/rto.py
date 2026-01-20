import csv
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .telegram import send_telegram


def build_ssh_command(cfg):
    host = cfg["ssh"]["host"]
    port = str(cfg["ssh"].get("port", 22))
    user = cfg["ssh"]["user"]
    remote_path = cfg["ssh"]["remote_csv_path"]
    use_key = bool(cfg["ssh"].get("use_key", False))
    key_path = cfg["ssh"].get("key_path", "").strip()

    base = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=10",
        "-p",
        port,
    ]
    if use_key and key_path:
        base.extend(["-i", key_path, "-o", "IdentitiesOnly=yes"])

    target = f"{user}@{host}"
    command = base + [target, f"cat {remote_path}"]
    return command


def fetch_csv_text(cfg):
    password = cfg["ssh"].get("password", "")
    command = build_ssh_command(cfg)

    env = os.environ.copy()
    askpass_path = None
    try:
        if password:
            fd, askpass_path = tempfile.mkstemp(prefix="askpass_", text=True)
            os.write(fd, b"#!/bin/sh\n")
            os.write(fd, b"echo \"$SSH_PASSWORD\"\n")
            os.close(fd)
            os.chmod(askpass_path, 0o700)
            env["SSH_PASSWORD"] = password
            env["SSH_ASKPASS"] = askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = "dummy"
            command = ["setsid", "-w"] + command

        result = subprocess.run(
            command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            check=False,
        )
    finally:
        if askpass_path and os.path.exists(askpass_path):
            os.remove(askpass_path)

    if result.returncode != 0:
        raise RuntimeError(f"ssh failed: {result.stderr.strip()}")
    return result.stdout


def parse_devices(csv_text):
    reader = csv.DictReader(csv_text.splitlines())
    if not reader.fieldnames:
        raise RuntimeError("CSV has no header")

    ip_field = None
    name_fields = ["Circuit Name", "Device Name", "Circuit ID", "Device ID"]
    for field in reader.fieldnames:
        if field.strip().lower() == "ipv4":
            ip_field = field
            break
    if not ip_field:
        raise RuntimeError("CSV does not contain IPv4 column")

    devices = []
    for row in reader:
        ip = (row.get(ip_field) or "").strip()
        if not ip:
            continue
        name = None
        for nf in name_fields:
            if nf in row and row[nf].strip():
                name = row[nf].strip()
                break
        if not name:
            name = ip
        devices.append({"name": name, "ip": ip})
    return devices


def ping_ip(ip, count, timeout_sec):
    cmd = ["ping", "-c", str(count), "-W", str(timeout_sec), ip]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def ping_all(devices, count, timeout_sec, max_workers):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(ping_ip, d["ip"], count, timeout_sec): d for d in devices}
        for future in as_completed(future_map):
            device = future_map[future]
            ok = False
            try:
                ok = future.result()
            except Exception:
                ok = False
            results[device["ip"]] = ok
    return results


def update_history(history, devices, results, window_size):
    by_ip = {d["ip"]: d for d in devices}
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for ip, ok in results.items():
        entry = history.get(ip, {})
        statuses = entry.get("statuses", [])
        statuses.append(1 if ok else 0)
        if window_size > 0:
            statuses = statuses[-window_size:]
        entry["statuses"] = statuses
        entry["name"] = by_ip.get(ip, {}).get("name", ip)
        entry["last_check"] = timestamp
        entry["last_status"] = 1 if ok else 0
        history[ip] = entry
    return history


def compute_rto_stats(history, results):
    rto_list = []
    for ip, ok in results.items():
        entry = history.get(ip, {})
        statuses = entry.get("statuses", [])
        if not statuses:
            continue
        total = len(statuses)
        failures = total - sum(statuses)
        rto_pct = (failures / total) * 100.0
        streak = 0
        for value in reversed(statuses):
            if value == 0:
                streak += 1
            else:
                break
        if not ok:
            rto_list.append(
                {
                    "name": entry.get("name", ip),
                    "ip": ip,
                    "rto_pct": rto_pct,
                    "streak": streak,
                }
            )
    return rto_list


def summarize_history(history):
    rows = []
    for ip, entry in history.items():
        statuses = entry.get("statuses", [])
        if not statuses:
            continue
        total = len(statuses)
        failures = total - sum(statuses)
        rto_pct = (failures / total) * 100.0
        streak = 0
        for value in reversed(statuses):
            if value == 0:
                streak += 1
            else:
                break
        last_value = statuses[-1]
        rows.append(
            {
                "name": entry.get("name", ip),
                "ip": ip,
                "total": total,
                "failures": failures,
                "rto_pct": rto_pct,
                "uptime_pct": 100.0 - rto_pct,
                "streak": streak,
                "last_status": "down" if last_value == 0 else "up",
                "last_check": entry.get("last_check", ""),
            }
        )
    return rows


def format_truncate(lines, max_lines, max_chars):
    result_lines = []
    total = 0
    truncated = False

    for line in lines:
        if max_lines and len(result_lines) >= max_lines:
            truncated = True
            break
        add_len = len(line) + (1 if result_lines else 0)
        if max_chars and total + add_len > max_chars:
            truncated = True
            break
        result_lines.append(line)
        total += add_len

    if truncated:
        suffix = "...(truncated)"
        add_len = len(suffix) + (1 if result_lines else 0)
        if max_chars and total + add_len > max_chars:
            if max_chars:
                suffix = suffix[:max_chars]
            if not result_lines:
                result_lines = [suffix]
        else:
            result_lines.append(suffix)

    return "\n".join(result_lines)


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


def build_lines(cfg, rto_list, total_devices, output_mode):
    title = cfg["general"].get("message_title", "RTO Customers")
    include_header = bool(cfg["general"].get("include_header", True))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = f"Summary: Total RTO: {len(rto_list)} / {total_devices}"
    if output_mode == "summary_top" and rto_list:
        top_n = int(cfg["general"].get("top_n", 20))
        summary += f" | Showing top {min(top_n, len(rto_list))}"

    if not rto_list:
        return [title, f"Time: {timestamp}", f"Summary: Total RTO: 0 / {total_devices}", "No RTO detected."]

    lines = [title, f"Time: {timestamp}", summary]
    if include_header:
        lines.append("Name | IPv4 | RTO% | Streak")
    for d in rto_list:
        lines.append(f"{d['name']} | {d['ip']} | {d['rto_pct']:.0f}% | {d['streak']}")
    return lines


def format_messages(cfg, lines, output_mode):
    max_chars = int(cfg["general"].get("max_chars", 3800))
    max_lines = int(cfg["general"].get("max_lines", 0))

    if output_mode == "split":
        return format_split(lines, max_chars)
    return [format_truncate(lines, max_lines, max_chars)]


def run(cfg, history_state):
    csv_text = fetch_csv_text(cfg)
    devices = parse_devices(csv_text)

    count = int(cfg["ping"].get("count", 1))
    timeout_sec = int(cfg["ping"].get("per_ping_timeout_sec", 1))
    max_workers = int(cfg["ping"].get("max_workers", 32))
    history_window = int(cfg["history"].get("window_size", 0))

    results = ping_all(devices, count, timeout_sec, max_workers)
    history = update_history(history_state or {}, devices, results, history_window)

    rto_list = compute_rto_stats(history, results)
    output_mode = (cfg["general"].get("output_mode", "truncate").strip().lower())

    if output_mode == "summary_top":
        top_n = int(cfg["general"].get("top_n", 20))
        rto_list = sorted(
            rto_list,
            key=lambda x: (-x["rto_pct"], -x["streak"], x["name"].lower()),
        )[: max(top_n, 0)]
    else:
        rto_list = sorted(rto_list, key=lambda x: x["name"].lower())

    lines = build_lines(cfg, rto_list, len(devices), output_mode)
    messages = format_messages(cfg, lines, output_mode)

    token = cfg["telegram"].get("bot_token", "")
    chat_id = cfg["telegram"].get("chat_id", "")
    for message in messages:
        send_telegram(token, chat_id, message)
    return history
