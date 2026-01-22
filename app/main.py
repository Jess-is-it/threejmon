from pathlib import Path

import copy

import asyncio
import json
import os
import base64
import shlex
import shutil
import time
import subprocess
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import (
    clear_rto_results,
    get_job_status,
    get_latest_speedtest_map,
    get_ping_history_map,
    get_ping_latency_trend_map,
    get_ping_latency_trend_window,
    get_ping_rollup_history_map,
    get_ping_stability_counts,
    get_rto_results_since,
    get_rto_results_for_ip_since,
    init_db,
    clear_pulsewatch_data,
    utc_now_iso,
)
from .forms import parse_bool, parse_float, parse_int, parse_int_list, parse_lines
from .jobs import JobsManager
from .notifiers import isp_ping as isp_ping_notifier
from .mikrotik import RouterOSClient
from .notifiers import optical as optical_notifier
from .notifiers import rto as rto_notifier
from .notifiers import wan_ping as wan_ping_notifier
from .notifiers.telegram import TelegramError, send_telegram
from .settings_defaults import ISP_PING_DEFAULTS, OPTICAL_DEFAULTS, RTO_DEFAULTS, WAN_PING_DEFAULTS, WAN_MESSAGE_DEFAULTS, WAN_SUMMARY_DEFAULTS
from .settings_store import export_settings, get_settings, get_state, import_settings, save_settings, save_state

BASE_DIR = Path(__file__).resolve().parent
PH_TZ = ZoneInfo("Asia/Manila")

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

jobs_manager = JobsManager()
_cpu_sample = {"total": None, "idle": None}


@app.on_event("startup")
async def startup_event():
    init_db()
    jobs_manager.start()


@app.on_event("shutdown")
async def shutdown_event():
    jobs_manager.stop()


def make_context(request, extra=None):
    ctx = {"request": request}
    if extra:
        ctx.update(extra)
    return ctx


def get_interface_options():
    base_dir = "/host_sys_class_net"
    if not os.path.isdir(base_dir):
        base_dir = "/sys/class/net"
    try:
        names = sorted(os.listdir(base_dir))
    except OSError:
        return []
    filtered = []
    for name in names:
        if name == "lo":
            continue
        if name.startswith(("br-", "docker", "veth", "tun", "tap", "ifb")):
            continue
        filtered.append(name)
    return filtered


def compute_pulsewatch_interface_map(settings):
    pulsewatch = settings.get("pulsewatch", {})
    cores = pulsewatch.get("mikrotik", {}).get("cores", [])
    isps = pulsewatch.get("isps", [])
    presets = pulsewatch.get("list_presets", [])
    interface_map = {}
    if presets:
        for preset in presets:
            core_id = preset.get("core_id")
            raw_ip = (preset.get("address") or "").strip()
            if not core_id or not raw_ip:
                continue
            core = next((item for item in cores if item.get("id") == core_id), None)
            if not core:
                continue
            iface = (core.get("interface") or "").strip()
            if not iface:
                continue
            prefix = str(core.get("prefix") or "24").strip()
            addr = raw_ip if "/" in raw_ip else f"{raw_ip}/{prefix}"
            interface_map.setdefault(iface, set()).add(addr)
    else:
        for isp in isps:
            sources = isp.get("sources") or {}
            for core in cores:
                core_id = core.get("id")
                iface = (core.get("interface") or "").strip()
                if not core_id or not iface:
                    continue
                raw_ip = (sources.get(core_id) or "").strip()
                if not raw_ip:
                    continue
                prefix = str(core.get("prefix") or "24").strip()
                addr = raw_ip if "/" in raw_ip else f"{raw_ip}/{prefix}"
                interface_map.setdefault(iface, set()).add(addr)
    return interface_map


def build_pulsewatch_netplan(settings):
    host_dir = "/host_netplan"
    if not os.path.isdir(host_dir):
        return None, "Host netplan directory is not mounted.", {}, []
    interface_map = compute_pulsewatch_interface_map(settings)
    pulsewatch = settings.get("pulsewatch", {})
    cores = pulsewatch.get("mikrotik", {}).get("cores", [])
    presets = pulsewatch.get("list_presets", [])
    isps = pulsewatch.get("isps", [])
    core_tables = {core.get("id"): 200 + idx for idx, core in enumerate(cores, start=1) if core.get("id")}
    core_addrs = {}
    if presets:
        for preset in presets:
            core_id = preset.get("core_id")
            raw_ip = (preset.get("address") or "").strip()
            if not core_id or not raw_ip:
                continue
            core = next((item for item in cores if item.get("id") == core_id), None)
            if not core:
                continue
            prefix = str(core.get("prefix") or "24").strip()
            addr = raw_ip if "/" in raw_ip else f"{raw_ip}/{prefix}"
            core_addrs.setdefault(core_id, set()).add(addr)
    else:
        for isp in isps:
            sources = isp.get("sources") or {}
            for core in cores:
                core_id = core.get("id")
                if not core_id:
                    continue
                raw_ip = (sources.get(core_id) or "").strip()
                if not raw_ip:
                    continue
                prefix = str(core.get("prefix") or "24").strip()
                addr = raw_ip if "/" in raw_ip else f"{raw_ip}/{prefix}"
                core_addrs.setdefault(core_id, set()).add(addr)
    route_specs = []
    for core in cores:
        core_id = core.get("id")
        iface = (core.get("interface") or "").strip()
        gateway = (core.get("gateway") or "").strip()
        table = core_tables.get(core_id)
        sources = sorted(core_addrs.get(core_id, []))
        if not core_id or not iface or not gateway or not table or not sources:
            continue
        route_specs.append(
            {
                "core_id": core_id,
                "iface": iface,
                "gateway": gateway,
                "table": table,
                "sources": sources,
            }
        )
    path = os.path.join(host_dir, "90-threejnotif-pulsewatch.yaml")
    if not interface_map:
        if os.path.exists(path):
            os.remove(path)
            return path, "Netplan file removed (no Pulsewatch IPs configured).", interface_map, []
        return path, "Netplan unchanged (no Pulsewatch IPs configured).", interface_map, []

    lines = [
        "network:",
        "  version: 2",
        "  renderer: networkd",
        "  ethernets:",
    ]
    for iface in sorted(interface_map.keys()):
        lines.append(f"    {iface}:")
        lines.append("      addresses:")
        for addr in sorted(interface_map[iface]):
            lines.append(f"        - {addr}")
        spec = next((item for item in route_specs if item["iface"] == iface), None)
        if spec:
            lines.append("      routes:")
            lines.append("        - to: 0.0.0.0/0")
            lines.append(f"          via: {spec['gateway']}")
            lines.append(f"          table: {spec['table']}")
            lines.append("      routing-policy:")
            for addr in spec["sources"]:
                ip_only = addr.split("/", 1)[0]
                lines.append(f"        - from: {ip_only}/32")
                lines.append(f"          table: {spec['table']}")
    content = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, 0o600)
    return path, "Netplan file updated.", interface_map, route_specs


def parse_netplan_addresses():
    host_dir = "/host_netplan"
    if not os.path.isdir(host_dir):
        return {}
    result = {}
    try:
        files = sorted(
            entry
            for entry in os.listdir(host_dir)
            if entry.endswith((".yaml", ".yml"))
        )
    except OSError:
        return {}
    for filename in files:
        path = os.path.join(host_dir, filename)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        except OSError:
            continue
        in_ethernets = False
        ethernets_indent = None
        iface = None
        iface_indent = None
        addresses_indent = None
        for raw in lines:
            line = raw.split("#", 1)[0].rstrip("\n")
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip(" "))
            key = line.strip()
            if key == "ethernets:":
                in_ethernets = True
                ethernets_indent = indent
                iface = None
                iface_indent = None
                addresses_indent = None
                continue
            if in_ethernets and ethernets_indent is not None and indent <= ethernets_indent:
                in_ethernets = False
                iface = None
                iface_indent = None
                addresses_indent = None
                continue
            if in_ethernets:
                if key == "addresses:" and iface:
                    addresses_indent = indent
                    continue
                if key.endswith(":") and not key.startswith("- ") and key not in (
                    "addresses:",
                    "routes:",
                    "routing-policy:",
                    "nameservers:",
                ):
                    iface = key[:-1].strip()
                    iface_indent = indent
                    addresses_indent = None
                    continue
                if iface and iface_indent is not None:
                    if indent <= iface_indent:
                        iface = None
                        iface_indent = None
                        addresses_indent = None
                        continue
                    if addresses_indent is not None:
                        if indent <= addresses_indent:
                            addresses_indent = None
                            continue
                        if key.startswith("- "):
                            addr = key[2:].strip()
                            if addr:
                                result.setdefault(iface, set()).add(addr)
        continue
    return result


def apply_host_addresses(interface_map, route_specs):
    desired_map = parse_netplan_addresses()
    if desired_map and interface_map:
        desired_map = {iface: desired_map.get(iface, set()) for iface in interface_map.keys()}
    if not desired_map:
        desired_map = interface_map
    if not desired_map:
        return True, "No addresses to apply."
    sock = "/var/run/docker.sock"
    if not os.path.exists(sock):
        return False, "IP apply skipped (docker socket not available)."
    if not shutil.which("curl"):
        return False, "IP apply skipped (curl not available in container)."

    lines = []
    for iface, addrs in desired_map.items():
        if not addrs:
            continue
        iface_quoted = shlex.quote(iface)
        wanted = " ".join(shlex.quote(addr) for addr in sorted(addrs))
        lines.append(f"ip addr flush dev {iface_quoted} || true")
        for addr in sorted(addrs):
            lines.append(f"ip addr add {shlex.quote(addr)} dev {iface_quoted} || true")
    for spec in route_specs:
        gateway = spec.get("gateway")
        table = spec.get("table")
        iface = spec.get("iface")
        sources = spec.get("sources", [])
        if not gateway or not table or not iface:
            continue
        lines.append(
            f"ip route replace default via {shlex.quote(gateway)} dev {shlex.quote(iface)} table {int(table)}"
        )
        for addr in sources:
            ip_only = addr.split('/', 1)[0]
            lines.append(f"ip rule add from {shlex.quote(ip_only)}/32 table {int(table)} || true")
    script = " ; ".join(lines) if lines else "true"

    pull_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        "http://localhost/images/create?fromImage=ubuntu&tag=latest",
    ]
    pulled = subprocess.run(pull_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if pulled.returncode != 0:
        return False, f"IP apply failed: {pulled.stderr.strip() or pulled.stdout.strip()}"

    payload = {
        "Image": "ubuntu",
        "Cmd": ["bash", "-c", f"chroot /host bash -c {shlex.quote(script)} 2>&1"],
        "HostConfig": {
            "Privileged": True,
            "Binds": ["/:/host"],
            "AutoRemove": False,
            "NetworkMode": "host",
            "PidMode": "host",
        },
    }
    create_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-H",
        "Content-Type: application/json",
        "-X",
        "POST",
        "-d",
        json.dumps(payload),
        "http://localhost/containers/create",
    ]
    created = subprocess.run(create_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if created.returncode != 0:
        return False, f"IP apply failed: {created.stderr.strip() or created.stdout.strip()}"
    try:
        container_id = json.loads(created.stdout).get("Id")
    except json.JSONDecodeError:
        container_id = None
    if not container_id:
        return False, f"IP apply failed: {created.stdout.strip()}"

    start_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/start",
    ]
    started = subprocess.run(start_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if started.returncode != 0:
        return False, f"IP apply failed: {started.stderr.strip() or started.stdout.strip()}"

    wait_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/wait",
    ]
    waited = subprocess.run(wait_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if waited.returncode != 0:
        return False, f"IP apply failed: {waited.stderr.strip() or waited.stdout.strip()}"
    try:
        status = json.loads(waited.stdout).get("StatusCode", 1)
    except json.JSONDecodeError:
        status = 1

    delete_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "DELETE",
        f"http://localhost/containers/{container_id}?force=1",
    ]
    subprocess.run(delete_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

    if status != 0:
        return False, f"IP apply failed: container exit {status}"
    return True, "IP addresses applied."


def apply_netplan(interface_map, route_specs):
    def run_cmd(cmd, timeout_seconds=30):
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return None

    host_netplan_path = "/host_netplan/90-threejnotif-pulsewatch.yaml"
    chmod_cmd = ""
    if os.path.exists(host_netplan_path):
        chmod_cmd = "chmod 600 /etc/netplan/90-threejnotif-pulsewatch.yaml && "

    docker_path = None
    for candidate in ("/usr/bin/docker", "/usr/local/bin/docker"):
        if os.path.exists(candidate):
            docker_path = candidate
            break
    if docker_path is None:
        docker_path = shutil.which("docker")
    if docker_path:
        command = (
            f"{docker_path} run --rm --privileged --pid=host "
            "-v /:/host "
            "ubuntu bash -c "
            f"\"chroot /host bash -c '{chmod_cmd}netplan apply'\""
        )
        result = run_cmd(["/bin/sh", "-c", command], timeout_seconds=60)
        if result is None:
            ip_ok, ip_msg = apply_host_addresses(interface_map, route_specs)
            return ip_ok, f"Netplan apply timed out. {ip_msg}"
        if result.returncode != 0:
            stderr = (result.stderr or result.stdout or "").strip()
            return False, f"Netplan apply failed: {stderr}"
        ip_ok, ip_msg = apply_host_addresses(interface_map, route_specs)
        if not ip_ok:
            return False, f"Netplan applied. {ip_msg}"
        return True, "Netplan applied."

    sock = "/var/run/docker.sock"
    if not os.path.exists(sock):
        return False, "Netplan apply skipped (docker socket not available)."
    if not shutil.which("curl"):
        return False, "Netplan apply skipped (curl not available in container)."

    pull_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        "http://localhost/images/create?fromImage=ubuntu&tag=latest",
    ]
    pulled = run_cmd(pull_cmd, timeout_seconds=60)
    if pulled is None:
        ip_ok, ip_msg = apply_host_addresses(interface_map, route_specs)
        return ip_ok, f"Netplan apply timed out. {ip_msg}"
    if pulled.returncode != 0:
        return False, f"Netplan apply failed: {pulled.stderr.strip() or pulled.stdout.strip()}"

    payload = {
        "Image": "ubuntu",
        "Cmd": [
            "bash",
            "-c",
            f"chroot /host bash -c {shlex.quote(f'{chmod_cmd}netplan apply')} 2>&1",
        ],
        "HostConfig": {
            "Privileged": True,
            "Binds": ["/:/host"],
            "AutoRemove": False,
            "PidMode": "host",
        },
    }
    create_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-H",
        "Content-Type: application/json",
        "-X",
        "POST",
        "-d",
        json.dumps(payload),
        "http://localhost/containers/create",
    ]
    created = run_cmd(create_cmd)
    if created is None:
        ip_ok, ip_msg = apply_host_addresses(interface_map, route_specs)
        return ip_ok, f"Netplan apply timed out. {ip_msg}"
    if created.returncode != 0:
        return False, f"Netplan apply failed: {created.stderr.strip() or created.stdout.strip()}"
    try:
        container_id = json.loads(created.stdout).get("Id")
    except json.JSONDecodeError:
        container_id = None
    if not container_id:
        return False, f"Netplan apply failed: {created.stdout.strip()}"

    start_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/start",
    ]
    started = run_cmd(start_cmd)
    if started is None:
        ip_ok, ip_msg = apply_host_addresses(interface_map, route_specs)
        return ip_ok, f"Netplan apply timed out. {ip_msg}"
    if started.returncode != 0:
        return False, f"Netplan apply failed: {started.stderr.strip() or started.stdout.strip()}"

    wait_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/wait",
    ]
    waited = run_cmd(wait_cmd, timeout_seconds=15)
    if waited is None:
        ip_ok, ip_msg = apply_host_addresses(interface_map, route_specs)
        return ip_ok, f"Netplan apply timed out. {ip_msg}"
    if waited.returncode != 0:
        return False, f"Netplan apply failed: {waited.stderr.strip() or waited.stdout.strip()}"
    try:
        status = json.loads(waited.stdout).get("StatusCode", 1)
    except json.JSONDecodeError:
        status = 1
    logs_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "GET",
        f"http://localhost/containers/{container_id}/logs?stdout=1&stderr=1",
    ]
    logs = run_cmd(logs_cmd)
    if logs is None:
        logs = subprocess.CompletedProcess(args=logs_cmd, returncode=1, stdout="", stderr="")
    output = (logs.stdout or logs.stderr or "").strip()
    delete_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "DELETE",
        f"http://localhost/containers/{container_id}?force=1",
    ]
    run_cmd(delete_cmd)
    if status != 0:
        detail = output or f"container exit {status}"
        return False, f"Netplan apply failed: {detail}"
    ip_ok, ip_msg = apply_host_addresses(interface_map, route_specs)
    if not ip_ok:
        return False, f"Netplan applied. {ip_msg}"
    return True, "Netplan applied."


def run_host_command(script, timeout_seconds=60):
    def run_cmd(cmd, timeout_seconds=30):
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return None

    docker_path = None
    for candidate in ("/usr/bin/docker", "/usr/local/bin/docker"):
        if os.path.exists(candidate):
            docker_path = candidate
            break
    if docker_path is None:
        docker_path = shutil.which("docker")
    if docker_path:
        command = (
            f"{docker_path} run --rm --privileged --pid=host "
            "-v /:/host "
            "ubuntu bash -c "
            f"\"chroot /host bash -c {shlex.quote(script)}\""
        )
        result = run_cmd(["/bin/sh", "-c", command], timeout_seconds=timeout_seconds)
        if result is None:
            return False, "Host command timed out."
        if result.returncode != 0:
            stderr = (result.stderr or result.stdout or "").strip()
            return False, f"Host command failed: {stderr}"
        return True, (result.stdout or "").strip()

    sock = "/var/run/docker.sock"
    if not os.path.exists(sock):
        return False, "Host command skipped (docker socket not available)."
    if not shutil.which("curl"):
        return False, "Host command skipped (curl not available in container)."

    pull_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        "http://localhost/images/create?fromImage=ubuntu&tag=latest",
    ]
    pulled = run_cmd(pull_cmd, timeout_seconds=timeout_seconds)
    if pulled is None:
        return False, "Host command timed out."
    if pulled.returncode != 0:
        return False, f"Host command failed: {pulled.stderr.strip() or pulled.stdout.strip()}"

    payload = {
        "Image": "ubuntu",
        "Cmd": [
            "bash",
            "-c",
            f"chroot /host bash -c {shlex.quote(script)} 2>&1",
        ],
        "HostConfig": {
            "Privileged": True,
            "Binds": ["/:/host"],
            "AutoRemove": False,
            "PidMode": "host",
        },
    }
    create_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-H",
        "Content-Type: application/json",
        "-X",
        "POST",
        "-d",
        json.dumps(payload),
        "http://localhost/containers/create",
    ]
    created = run_cmd(create_cmd, timeout_seconds=timeout_seconds)
    if created is None or created.returncode != 0:
        return False, f"Host command failed: {created.stderr.strip() if created else 'timeout'}"
    try:
        container_id = json.loads(created.stdout).get("Id")
    except json.JSONDecodeError:
        container_id = None
    if not container_id:
        return False, f"Host command failed: {created.stdout.strip()}"

    start_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/start",
    ]
    started = run_cmd(start_cmd, timeout_seconds=timeout_seconds)
    if started is None or started.returncode != 0:
        return False, f"Host command failed: {started.stderr.strip() if started else 'timeout'}"

    wait_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "POST",
        f"http://localhost/containers/{container_id}/wait",
    ]
    waited = run_cmd(wait_cmd, timeout_seconds=timeout_seconds)
    status = 1
    if waited and waited.returncode == 0:
        try:
            status = json.loads(waited.stdout).get("StatusCode", 1)
        except json.JSONDecodeError:
            status = 1

    delete_cmd = [
        "curl",
        "-sS",
        "--unix-socket",
        sock,
        "-X",
        "DELETE",
        f"http://localhost/containers/{container_id}?force=1",
    ]
    run_cmd(delete_cmd)

    if status != 0:
        return False, f"Host command failed: container exit {status}"
    return True, "Host command completed."


def normalize_pulsewatch_settings(settings):
    pulse = settings.setdefault("pulsewatch", {})
    pulse.setdefault("retention_days", 30)
    pulse.setdefault("rollup_retention_days", 365)
    dashboard = pulse.setdefault("dashboard", {})
    dashboard.setdefault("default_target", "all")
    dashboard.setdefault("refresh_seconds", 2)
    dashboard.setdefault("loss_history_minutes", 120)
    dashboard.setdefault("pie_default_days", 7)
    stability = pulse.setdefault("stability", {})
    stability.setdefault("stable_max_ms", 80)
    stability.setdefault("unstable_max_ms", 150)
    stability.setdefault("down_source", "wan")
    mikrotik = pulse.setdefault("mikrotik", {})
    cores = mikrotik.get("cores")
    if cores is None:
        cores = []
        core2 = mikrotik.get("core2")
        core3 = mikrotik.get("core3")
        if core2 is not None:
            cores.append(
                {
                    "id": "core2",
                    "label": "Core2",
                    "host": core2.get("host", ""),
                    "port": core2.get("port", 8728),
                    "username": core2.get("username", ""),
                    "password": core2.get("password", ""),
                }
            )
        if core3 is not None:
            cores.append(
                {
                    "id": "core3",
                    "label": "Core3",
                    "host": core3.get("host", ""),
                    "port": core3.get("port", 8728),
                    "username": core3.get("username", ""),
                    "password": core3.get("password", ""),
                }
            )
        mikrotik["cores"] = cores

    for idx, core in enumerate(cores, start=1):
        core.setdefault("id", f"core{idx}")
        core.setdefault("label", core["id"].upper())
        core.setdefault("host", "")
        core.setdefault("port", 8728)
        core.setdefault("username", "")
        core.setdefault("password", "")
        core.setdefault("interface", "")
        core.setdefault("prefix", 24)
        core.setdefault("gateway", "")

    for isp in pulse.get("isps", []):
        sources = isp.get("sources")
        if not isinstance(sources, dict):
            sources = {}
        if not sources:
            core2_ip = isp.get("core2_source_ip")
            core3_ip = isp.get("core3_source_ip")
            if core2_ip:
                sources["core2"] = core2_ip
            if core3_ip:
                sources["core3"] = core3_ip
        isp["sources"] = sources
        if "ping_core_id" not in isp:
            ping_core = isp.get("ping_router")
            isp["ping_core_id"] = ping_core if ping_core in ("core2", "core3") else "auto"
    pulse.setdefault("list_presets", [])
    return settings


def normalize_wan_ping_settings(settings):
    settings.setdefault("enabled", False)
    telegram = settings.setdefault("telegram", {})
    telegram.setdefault("bot_token", "")
    telegram.setdefault("chat_id", "")
    general = settings.setdefault("general", {})
    general.setdefault("interval_seconds", 30)
    settings.setdefault("wans", [])
    settings.setdefault("pppoe_routers", [])
    settings.setdefault("messages", {})
    summary = settings.setdefault("summary", {})
    summary.setdefault("enabled", WAN_SUMMARY_DEFAULTS["enabled"])
    summary.setdefault("daily_time", WAN_SUMMARY_DEFAULTS["daily_time"])
    summary.setdefault("all_up_msg", WAN_SUMMARY_DEFAULTS["all_up_msg"])
    summary.setdefault("partial_msg", WAN_SUMMARY_DEFAULTS["partial_msg"])
    summary.setdefault("line_template", WAN_SUMMARY_DEFAULTS["line_template"])
    return settings


def wan_row_id(core_id, list_name):
    raw = f"{core_id}|{list_name}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def is_wan_list_name(list_name):
    return "TO-ISP" in (list_name or "").upper()


def build_wan_rows(pulsewatch_settings, wan_settings):
    cores = pulsewatch_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    list_map = fetch_mikrotik_lists(cores)
    preset_map = {}
    for preset in pulsewatch_settings.get("pulsewatch", {}).get("list_presets", []):
        core_id = preset.get("core_id")
        list_name = preset.get("list")
        identifier = (preset.get("identifier") or "").strip()
        if core_id and list_name:
            preset_map[(core_id, list_name)] = {
                "identifier": identifier,
                "address": (preset.get("address") or "").strip(),
            }
    saved_wans = {
        (item.get("core_id"), item.get("list_name")): item
        for item in wan_settings.get("wans", [])
        if item.get("core_id") and item.get("list_name")
    }
    rows = []
    for core in cores:
        core_id = core.get("id")
        if not core_id:
            continue
        lists = [name for name in list_map.get(core_id, []) if is_wan_list_name(name)]
        if not lists:
            lists = sorted(
                {
                    list_name
                    for (saved_core_id, list_name) in saved_wans.keys()
                    if saved_core_id == core_id
                }
            )
        for list_name in sorted(lists):
            saved = saved_wans.get((core_id, list_name), {}) or {}
            mode = (saved.get("mode") or "routed").strip().lower()
            if mode not in ("routed", "bridged"):
                mode = "routed"
            preset_data = preset_map.get((core_id, list_name), {}) or {}
            identifier = (preset_data.get("identifier") or "").strip()
            rows.append(
                {
                    "wan_id": wan_row_id(core_id, list_name),
                    "core_id": core_id,
                    "core_label": core.get("label") or core_id,
                    "list_name": list_name,
                    "identifier": identifier,
                    "identifier_missing": not identifier,
                    "mode": mode,
                    "local_ip": saved.get("local_ip", ""),
                    "gateway_ip": saved.get("gateway_ip", ""),
                    "preset_address": preset_data.get("address", ""),
                    "pppoe_router_id": saved.get("pppoe_router_id", ""),
                    "enabled": bool(saved.get("enabled", True)),
                }
            )
    return rows


def preset_row_id(core_id, list_name):
    raw = f"{core_id}|{list_name}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def fetch_mikrotik_lists(cores):
    list_map = {}
    for core in cores:
        core_id = core.get("id") or "core"
        host = core.get("host")
        if not host:
            list_map[core_id] = []
            continue
        client = RouterOSClient(
            host,
            int(core.get("port", 8728)),
            core.get("username", ""),
            core.get("password", ""),
        )
        try:
            client.connect()
            mangle_entries = client.list_mangle_rules()
            names = sorted(
                {
                    entry.get("src-address-list")
                    for entry in mangle_entries
                    if entry.get("src-address-list")
                }
            )
            if not names:
                entries = client.list_address_list()
                names = sorted({entry.get("list") for entry in entries if entry.get("list")})
            list_map[core_id] = names
        except Exception:
            list_map[core_id] = []
        finally:
            client.close()
    return list_map


def build_pulsewatch_rows(settings):
    cores = settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    list_map = fetch_mikrotik_lists(cores)
    preset_rows = []
    preset_lookup = {
        (item.get("core_id"), item.get("list")): item
        for item in settings.get("pulsewatch", {}).get("list_presets", [])
    }
    all_presets_blank = True
    for preset in preset_lookup.values():
        if (preset.get("address") or "").strip():
            all_presets_blank = False
            break
    recommendations = {}
    for core in cores:
        core_id = core.get("id")
        if not core_id:
            continue
        lists = list_map.get(core_id, [])
        if not lists:
            lists = sorted(
                {
                    item.get("list")
                    for item in settings.get("pulsewatch", {}).get("list_presets", [])
                    if item.get("core_id") == core_id and item.get("list")
                }
            )
        blank_count = 0
        for list_name in lists:
            preset = preset_lookup.get((core_id, list_name), {}) or {}
            if not (preset.get("address") or "").strip():
                blank_count += 1
        if all_presets_blank and blank_count > 1:
            gateway = (core.get("gateway") or "").strip()
            parts = gateway.split(".") if gateway else []
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                base = ".".join(parts[:3])
                start = 50
                recommendations[core_id] = [f"{base}.{start + idx}" for idx in range(len(lists))]
        for list_name in lists:
            preset = preset_lookup.get((core_id, list_name), {}) or {}
            recommended = ""
            if all_presets_blank and blank_count > 1:
                rec_list = recommendations.get(core_id, [])
                if rec_list:
                    recommended = rec_list.pop(0)
            preset_rows.append(
                {
                    "row_id": preset_row_id(core_id, list_name),
                    "core_id": core_id,
                    "core_label": core.get("label") or core_id,
                    "list_name": list_name,
                    "identifier": preset.get("identifier", ""),
                    "color": preset.get("color", ""),
                    "address": preset.get("address", ""),
                    "recommended_address": recommended,
                    "latency_ms": preset.get("latency_ms", 120),
                    "loss_pct": preset.get("loss_pct", 20),
                    "breach_count": preset.get("breach_count", 3),
                    "cooldown_minutes": preset.get("cooldown_minutes", 10),
                    "ping_targets": preset.get("ping_targets", ["1.1.1.1", "8.8.8.8"]),
                }
            )
    show_recommendation = all_presets_blank and any(row.get("recommended_address") for row in preset_rows)
    return preset_rows, show_recommendation


def render_pulsewatch_response(request, settings, message):
    preset_rows, show_recommendation = build_pulsewatch_rows(settings)
    state = get_state("isp_ping_state", {})
    reach_map = state.get("pulsewatch_reachability", {})
    reach_checked_at = state.get("pulsewatch_reachability_checked_at")
    targets = []
    for row in preset_rows:
        reach = reach_map.get(row.get("row_id"), {})
        if not (row.get("address") or "").strip():
            reach = {"status": "missing", "target": "", "source_ip": "", "last_check": None}
        row["reachability"] = {
            "status": reach.get("status", "unknown"),
            "target": reach.get("target", ""),
            "source_ip": reach.get("source_ip", ""),
            "last_check": format_ts_ph(reach.get("last_check")),
        }
        for target in row.get("ping_targets", []) or []:
            if target and target not in targets:
                targets.append(target)
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "preset_rows": preset_rows,
                "show_preset_recommendation": show_recommendation,
                "pulsewatch_targets": targets,
                "pulsewatch_reachability_checked_at": format_ts_ph(reach_checked_at),
            },
        ),
    )


def find_pulsewatch_row(settings, row_id):
    for row in build_pulsewatch_rows(settings)[0]:
        if row.get("row_id") == row_id:
            return row
    return None


def pulsewatch_row_label(row):
    if not row:
        return ""
    core_label = row.get("core_label") or ""
    identifier = row.get("identifier") or ""
    list_name = row.get("list_name") or ""
    label_value = identifier or list_name
    return f"{core_label} {label_value}".strip()


def format_pulsewatch_speedtest_summary(settings, results):
    if not results:
        return []
    row_map = {row["row_id"]: row for row in build_pulsewatch_rows(settings)[0]}
    messages = []
    for isp_id, result in results.items():
        row = row_map.get(isp_id)
        label = pulsewatch_row_label(row) if row else isp_id
        download = result.get("download_mbps")
        upload = result.get("upload_mbps")
        latency = result.get("latency_ms")
        server = result.get("server_name")
        parts = []
        if download is not None:
            parts.append(f"dl {download} Mbps")
        if upload is not None:
            parts.append(f"ul {upload} Mbps")
        if latency is not None:
            parts.append(f"ping {latency} ms")
        if server:
            parts.append(f"server {server}")
        summary = ", ".join(parts) if parts else "speedtest completed"
        messages.append(f"{label} {summary}")
    return messages


def _read_cpu_times():
    try:
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            line = handle.readline()
        parts = line.split()
        if len(parts) < 5 or parts[0] != "cpu":
            return None
        values = [int(value) for value in parts[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        return total, idle
    except Exception:
        return None


def _cpu_percent():
    sample = _read_cpu_times()
    if not sample:
        return 0.0
    total, idle = sample
    last_total = _cpu_sample.get("total")
    last_idle = _cpu_sample.get("idle")
    _cpu_sample["total"] = total
    _cpu_sample["idle"] = idle
    if last_total is None or last_idle is None:
        return 0.0
    total_delta = total - last_total
    idle_delta = idle - last_idle
    if total_delta <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta))


def _memory_percent():
    try:
        mem_total = 0
        mem_available = 0
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1])
        if mem_total <= 0:
            return 0.0
        used = mem_total - mem_available
        return max(0.0, min(100.0, 100.0 * used / mem_total))
    except Exception:
        return 0.0


def _disk_percent():
    try:
        usage = shutil.disk_usage("/")
        if usage.total <= 0:
            return 0.0
        return max(0.0, min(100.0, 100.0 * usage.used / usage.total))
    except Exception:
        return 0.0


def _uptime_seconds():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as handle:
            value = handle.read().split()[0]
        return int(float(value))
    except Exception:
        return 0


def _get_first_target(ping_targets):
    if isinstance(ping_targets, str):
        targets = parse_lines(ping_targets)
    else:
        targets = ping_targets or []
    return targets[0].strip() if targets else ""


def _sparkline_points(values, width=120, height=30):
    if not values:
        return ""
    max_val = max(values)
    min_val = min(values)
    span = max(max_val - min_val, 1)
    step = width / max(len(values) - 1, 1)
    points = []
    for idx, value in enumerate(values):
        x = idx * step
        y = height - ((value - min_val) / span) * height
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def _sparkline_points_fixed(values, min_val, max_val, width=120, height=30):
    if not values:
        return ""
    span = max(max_val - min_val, 1)
    step = width / max(len(values) - 1, 1)
    points = []
    for idx, value in enumerate(values):
        value = max(min_val, min(max_val, value))
        x = idx * step
        y = height - ((value - min_val) / span) * height
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


RTO_WINDOW_OPTIONS = [
    ("3H", 3),
    ("6H", 6),
    ("12H", 12),
    ("1D", 24),
    ("7D", 168),
    ("15D", 360),
    ("30D", 720),
]


def _normalize_rto_window(value):
    if value is None:
        return 24
    raw = str(value).strip().lower()
    if not raw:
        return 24
    for label, hours in RTO_WINDOW_OPTIONS:
        if raw == label.lower():
            return hours
    try:
        hours = int(raw)
        if hours in {opt[1] for opt in RTO_WINDOW_OPTIONS}:
            return hours
    except ValueError:
        pass
    return 24


def format_ts_ph(value):
    if not value:
        return "n/a"
    try:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1]
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_ph = dt.astimezone(PH_TZ)
        return dt_ph.strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        return str(value)


def build_pulsewatch_dashboard_rows(settings, isp_state, speedtests, ping_history):
    rows, _ = build_pulsewatch_rows(settings)
    state_map = isp_state.get("pulsewatch", {}).get("isps", {})
    dashboard_rows = []
    for row in rows:
        row_id = row.get("row_id")
        history = ping_history.get(row_id, [])
        loss_series = [item["loss"] for item in history if item.get("loss") is not None]
        avg_series = [item["avg_ms"] for item in history if item.get("avg_ms") is not None]
        down_samples = sum(1 for item in history if (item.get("loss") or 0) >= 100)
        total_samples = len(history)
        summary = state_map.get(row_id, {}).get("last_summary", {})
        speed = speedtests.get(row_id)
        label = pulsewatch_row_label(row)
        dashboard_rows.append(
            {
                "row_id": row_id,
                "label": label,
                "list_name": row.get("list_name"),
                "core_id": row.get("core_id"),
                "core_label": row.get("core_label"),
                "color": row.get("color"),
                "source_ip": row.get("address"),
                "last_check": format_ts_ph(summary.get("last_check")),
                "loss_max": summary.get("loss_max"),
                "avg_max": summary.get("avg_max"),
                "down_samples": down_samples,
                "total_samples": total_samples,
                "loss_points": _sparkline_points(loss_series),
                "avg_points": _sparkline_points(avg_series),
                "speed": speed or {},
                "history": history,
            }
        )
    return dashboard_rows


def build_pulsewatch_latency_series(rows, history_map=None):
    palette = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
        "#e377c2",
        "#7f7f7f",
        "#bcbd22",
        "#17becf",
        "#e41a1c",
        "#377eb8",
        "#4daf4a",
        "#984ea3",
        "#ff7f00",
        "#a65628",
        "#f781bf",
        "#999999",
    ]
    series = []
    for idx, row in enumerate(rows):
        targets = {}
        history = history_map.get(row.get("row_id"), []) if history_map is not None else row.get("history", [])
        for item in history:
            value = item.get("avg_ms")
            ts = item.get("timestamp") or item.get("bucket_ts")
            target = item.get("target")
            if value is None or not ts or not target:
                continue
            targets.setdefault(target, []).append({"ts": ts, "value": value})
        for target, points in targets.items():
            preset_color = (row.get("color") or "").strip()
            label = pulsewatch_row_label(row) or row.get("label") or ""
            series.append(
                {
                    "id": f"{row.get('row_id')}|{target}",
                    "name": f"{label} {target}".strip(),
                    "target": target,
                    "core_id": row.get("core_id"),
                    "core_label": row.get("core_label"),
                    "color": preset_color or palette[len(series) % len(palette)],
                    "points": points,
                }
            )
    return series


def build_wan_latency_series(rows, state, hours=24, window_start=None, window_end=None):
    palette = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
        "#e377c2",
        "#7f7f7f",
        "#bcbd22",
        "#17becf",
        "#e41a1c",
        "#377eb8",
        "#4daf4a",
        "#984ea3",
        "#ff7f00",
        "#a65628",
        "#f781bf",
        "#999999",
    ]
    def _parse_ts(value):
        if not value:
            return None
        raw = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    wan_state = (state or {}).get("wans", {})
    series = []
    all_times = []
    row_points = {}
    for idx, row in enumerate(rows):
        wan_id = row.get("wan_id")
        if not wan_id:
            continue
        mode = (row.get("mode") or "routed").lower()
        if not row.get("local_ip"):
            continue
        if mode == "bridged":
            if not row.get("pppoe_router_id"):
                continue
        state_row = wan_state.get(wan_id, {})
        history = state_row.get("history", [])
        target = state_row.get("target") or ""
        label = row.get("identifier") or row.get("list_name") or wan_id
        points = []
        for item in history:
            ts_raw = item.get("ts")
            ts = _parse_ts(ts_raw)
            if ts is None:
                continue
            points.append(
                {
                    "ts": ts,
                    "status": item.get("status"),
                }
            )
            all_times.append(ts)
        row_points[wan_id] = points
        series.append(
            {
                "id": wan_id,
                "name": f"{row.get('core_label')} {label}".strip(),
                "target": target,
                "core_id": row.get("core_id"),
                "core_label": row.get("core_label"),
                "color": palette[idx % len(palette)],
                "points": [],
            }
        )

    if not all_times:
        return []

    min_all = min(all_times)
    max_all = max(all_times)
    if window_start or window_end:
        if window_start is None:
            window_start = min_all
        if window_end is None:
            window_end = max_all
    else:
        window_end = max_all
        window_start = window_end - timedelta(hours=max(int(hours or 24), 1))
    if window_start > window_end:
        window_start, window_end = window_end, window_start

    def _iso(dt):
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    for item in series:
        wan_id = item["id"]
        points = row_points.get(wan_id, [])
        if not points:
            continue
        points.sort(key=lambda entry: entry["ts"])
        state = None
        first_in_window = None
        for point in points:
            if point["ts"] <= window_start:
                state = point.get("status") or state
            elif first_in_window is None:
                first_in_window = point
                break
        if state is None:
            if first_in_window is not None:
                state = first_in_window.get("status") or "down"
            else:
                state = points[-1].get("status") or "down"
        uptime = 0.0
        downtime = 0.0
        cursor = window_start
        render_points = []
        initial_value = 0 if state == "down" else 100
        render_points.append(
            {"ts": _iso(window_start), "value": initial_value, "downtime_seconds": downtime}
        )
        for point in points:
            ts = point["ts"]
            if ts < window_start:
                continue
            if ts > window_end:
                break
            delta = (ts - cursor).total_seconds()
            if delta > 0:
                if state == "up":
                    uptime += delta
                else:
                    downtime += delta
            cursor = ts
            state = point.get("status") or state
            total = uptime + downtime
            pct = (uptime / total * 100) if total > 0 else (100 if state == "up" else 0)
            y_value = 0 if state == "down" else pct
            render_points.append(
                {"ts": _iso(ts), "value": y_value, "downtime_seconds": downtime}
            )
        if cursor < window_end:
            delta = (window_end - cursor).total_seconds()
            if delta > 0:
                if state == "up":
                    uptime += delta
                else:
                    downtime += delta
            total = uptime + downtime
            pct = (uptime / total * 100) if total > 0 else (100 if state == "up" else 0)
            y_value = 0 if state == "down" else pct
            render_points.append(
                {"ts": _iso(window_end), "value": y_value, "downtime_seconds": downtime}
            )
        item["points"] = render_points
    return series


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    for status in job_status.values():
        status["last_run_at_ph"] = format_ts_ph(status.get("last_run_at"))
        status["last_success_at_ph"] = format_ts_ph(status.get("last_success_at"))
        status["last_error_at_ph"] = format_ts_ph(status.get("last_error_at"))
    isp_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    isp_state = get_state(
        "isp_ping_state",
        {
            "last_status": {},
            "last_report_date": None,
            "last_report_time": None,
            "last_report_timezone": None,
            "pulsewatch": {},
        },
    )
    pulse_rows, _ = build_pulsewatch_rows(isp_settings)
    pulse_ids = [row.get("row_id") for row in pulse_rows if row.get("row_id")]
    speedtests = get_latest_speedtest_map(pulse_ids)
    dashboard_cfg = isp_settings.get("pulsewatch", {}).get("dashboard", {})
    summary_target = (dashboard_cfg.get("default_target") or "all").strip() or "all"
    summary_minutes = int(dashboard_cfg.get("loss_history_minutes", 120) or 120)
    summary_since = (datetime.now(timezone.utc) - timedelta(minutes=summary_minutes)).isoformat().replace("+00:00", "Z")
    target_filter = None if summary_target == "all" else summary_target
    ping_history = get_ping_rollup_history_map(pulse_ids, summary_since, target=target_filter)
    latency_since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    latency_history = get_ping_latency_trend_map(pulse_ids, latency_since)
    pulse_dashboard_rows = build_pulsewatch_dashboard_rows(isp_settings, isp_state, speedtests, ping_history)
    pulse_display_rows = [row for row in pulse_dashboard_rows if (row.get("source_ip") or "").strip()]
    pulse_latency_series = build_pulsewatch_latency_series(pulse_display_rows, latency_history)
    pulse_targets = sorted({item.get("target") for item in pulse_latency_series if item.get("target")})
    pulse_enabled = bool(isp_settings.get("pulsewatch", {}).get("enabled"))
    pulse_state = isp_state.get("pulsewatch", {})
    pulse_last_reconcile = format_ts_ph(pulse_state.get("last_mikrotik_reconcile_at"))
    pulse_last_check = format_ts_ph(pulse_state.get("last_check_at"))
    pulse_total = len(pulse_display_rows)
    return templates.TemplateResponse(
        "dashboard.html",
        make_context(
            request,
            {
                "job_status": job_status,
                "isp_settings": isp_settings,
                "isp_state": isp_state,
                "speedtests": speedtests,
                "pulse_rows": pulse_display_rows,
                "pulse_latency_series": pulse_latency_series,
                "pulse_targets": pulse_targets,
                "pulse_enabled": pulse_enabled,
                "pulse_last_reconcile": pulse_last_reconcile,
                "pulse_last_check": pulse_last_check,
                "pulse_total": pulse_total,
                "pulse_summary_target": summary_target,
                "pulse_summary_refresh": int(dashboard_cfg.get("refresh_seconds", 2) or 2),
                "pulse_summary_loss_minutes": summary_minutes,
            },
        ),
    )


@app.get("/pulsewatch/latency-series")
async def pulsewatch_latency_series(
    core_id: str = "all",
    target: str = "all",
    hours: int = 24,
    start: str | None = None,
    end: str | None = None,
):
    def _parse_iso_utc(value):
        if not value:
            return None
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1]
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    start_dt = _parse_iso_utc(start)
    end_dt = _parse_iso_utc(end)
    if start_dt or end_dt:
        if start_dt and end_dt:
            window_start = start_dt
            window_end = end_dt
        elif start_dt:
            window_start = start_dt
            window_end = start_dt + timedelta(hours=max(int(hours), 1))
        else:
            window_end = end_dt
            window_start = end_dt - timedelta(hours=max(int(hours), 1))
    else:
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(hours=max(int(hours), 1))
    if window_start > window_end:
        window_start, window_end = window_end, window_start
    max_window = timedelta(days=370)
    if window_end - window_start > max_window:
        window_start = window_end - max_window

    start_iso = window_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    end_iso = window_end.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    isp_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    pulse_rows, _ = build_pulsewatch_rows(isp_settings)
    pulse_display_rows = [row for row in pulse_rows if (row.get("address") or "").strip()]
    if core_id and core_id != "all":
        pulse_display_rows = [row for row in pulse_display_rows if row.get("core_id") == core_id]
    pulse_ids = [row.get("row_id") for row in pulse_display_rows if row.get("row_id")]
    latency_history = get_ping_latency_trend_window(pulse_ids, start_iso, end_iso)
    series = build_pulsewatch_latency_series(pulse_display_rows, latency_history)
    if target and target != "all":
        series = [item for item in series if item.get("target") == target]
    return JSONResponse({"series": series, "window": {"start": start_iso, "end": end_iso}})


@app.get("/wan/latency-series")
async def wan_latency_series(
    core_id: str = "all",
    target: str = "all",
    hours: int = 24,
    start: str | None = None,
    end: str | None = None,
):
    def _parse_iso_utc(value):
        if not value:
            return None
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1]
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    start_dt = _parse_iso_utc(start)
    end_dt = _parse_iso_utc(end)
    if start_dt or end_dt:
        if start_dt and end_dt:
            window_start = start_dt
            window_end = end_dt
        elif start_dt:
            window_start = start_dt
            window_end = start_dt + timedelta(hours=max(int(hours), 1))
        else:
            window_end = end_dt
            window_start = end_dt - timedelta(hours=max(int(hours), 1))
    else:
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(hours=max(int(hours), 1))
    if window_start > window_end:
        window_start, window_end = window_end, window_start
    max_window = timedelta(days=14)
    if window_end - window_start > max_window:
        window_start = window_end - max_window

    start_iso = window_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    end_iso = window_end.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_state = get_state("wan_ping_state", {})
    series = build_wan_latency_series(wan_rows, wan_state, hours=hours, window_start=window_start, window_end=window_end)
    if core_id and core_id != "all":
        series = [item for item in series if item.get("core_id") == core_id]
    if target and target != "all":
        series = [item for item in series if item.get("target") == target]
    return JSONResponse({"series": series, "window": {"start": start_iso, "end": end_iso}})


@app.get("/wan/status")
async def wan_status():
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_state = get_state("wan_ping_state", {})
    payload = []
    for row in wan_rows:
        wan_id = row.get("wan_id")
        mode = (row.get("mode") or "routed").lower()
        if not row.get("local_ip"):
            continue
        if mode == "bridged":
            if not row.get("pppoe_router_id"):
                continue
        state = wan_state.get("wans", {}).get(wan_id, {})
        label = f"{row.get('core_label')} - {(row.get('identifier') or row.get('list_name') or '')}".strip()
        payload.append(
            {
                "id": wan_id,
                "label": label,
                "status": state.get("status"),
                "target": state.get("target"),
                "last_check": state.get("last_check"),
                "last_rtt_ms": state.get("last_rtt_ms"),
                "last_error": state.get("last_error"),
            }
        )
    return JSONResponse({"rows": payload, "updated_at": utc_now_iso()})


@app.get("/pulsewatch/summary")
async def pulsewatch_summary(target: str = "all", loss_minutes: int = 120):
    isp_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    isp_state = get_state(
        "isp_ping_state",
        {
            "last_status": {},
            "last_report_date": None,
            "last_report_time": None,
            "last_report_timezone": None,
            "pulsewatch": {},
        },
    )
    pulse_rows, _ = build_pulsewatch_rows(isp_settings)
    pulse_ids = [row.get("row_id") for row in pulse_rows if row.get("row_id")]
    speedtests = get_latest_speedtest_map(pulse_ids)
    minutes = max(int(loss_minutes or 120), 1)
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    target_filter = None if target == "all" else target
    rollup_history = get_ping_rollup_history_map(pulse_ids, since, target=target_filter)
    pulse_dashboard_rows = build_pulsewatch_dashboard_rows(isp_settings, isp_state, speedtests, rollup_history)
    pulse_display_rows = [row for row in pulse_dashboard_rows if (row.get("source_ip") or "").strip()]
    return JSONResponse(
        {
            "total": len(pulse_display_rows),
            "last_check": format_ts_ph(isp_state.get("pulsewatch", {}).get("last_check_at")),
            "rows": pulse_display_rows,
        }
    )


@app.get("/pulsewatch/stability")
async def pulsewatch_stability(days: int = 7, hours: int | None = None):
    days = max(int(days or 7), 1)
    hours = int(hours) if hours is not None else None
    isp_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    pulse_rows, _ = build_pulsewatch_rows(isp_settings)
    pulse_display_rows = [row for row in pulse_rows if (row.get("address") or "").strip()]
    isp_ids = [row.get("row_id") for row in pulse_display_rows if row.get("row_id")]
    if hours:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    else:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    stability_cfg = isp_settings.get("pulsewatch", {}).get("stability", {})
    stable_max_ms = stability_cfg.get("stable_max_ms", 80)
    unstable_max_ms = stability_cfg.get("unstable_max_ms", 150)
    counts = get_ping_stability_counts(isp_ids, since, stable_max_ms, unstable_max_ms)
    wan_state = get_state("wan_ping_state", {})
    payload = []
    for row in pulse_display_rows:
        isp_id = row.get("row_id")
        stats = counts.get(isp_id, {"healthy": 0, "degraded": 0, "poor": 0, "outage": 0, "total": 0})
        wan_id = wan_row_id(row.get("core_id"), row.get("list_name"))
        wan_status = (wan_state.get("wans", {}).get(wan_id, {}).get("status") or "").lower()
        if wan_status == "down":
            total = stats.get("total", 0) or 0
            outage = total if total > 0 else 1
            stats = {
                "healthy": 0,
                "degraded": 0,
                "poor": 0,
                "outage": outage,
                "total": outage,
            }
        label_value = (row.get("identifier") or row.get("list_name") or "").strip()
        label_value = label_value or pulsewatch_row_label(row)
        payload.append(
            {
                "id": isp_id,
                "label": label_value,
                "full_label": pulsewatch_row_label(row),
                "source_ip": row.get("address"),
                "healthy": stats.get("healthy", 0) or 0,
                "degraded": stats.get("degraded", 0) or 0,
                "poor": stats.get("poor", 0) or 0,
                "outage": stats.get("outage", 0) or 0,
                "total": stats.get("total", 0) or 0,
            }
        )
    return JSONResponse({"days": days, "rows": payload})


@app.get("/settings/export")
async def export_settings_route():
    payload = export_settings()
    data = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
    headers = {"Content-Disposition": "attachment; filename=threejnotif-settings.json"}
    return Response(content=data, media_type="application/json", headers=headers)


@app.post("/settings/import", response_class=HTMLResponse)
async def import_settings_route(request: Request):
    form = await request.form()
    uploaded = form.get("settings_file")
    message = ""
    if not uploaded:
        message = "No file uploaded."
    else:
        try:
            content = await uploaded.read()
            payload = json.loads(content.decode("utf-8"))
            import_settings(payload)
            message = "Settings imported successfully."
        except json.JSONDecodeError:
            message = "Invalid JSON file."
        except Exception as exc:
            message = f"Import failed: {exc}"
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    if message.startswith("Settings imported"):
        netplan_msg = None
        apply_msg = None
        try:
            netplan_path, netplan_msg, interface_map, route_specs = build_pulsewatch_netplan(settings)
            if netplan_path:
                _, apply_msg = apply_netplan(interface_map, route_specs)
        except Exception as exc:
            apply_msg = f"Netplan update failed: {exc}"
        if netplan_msg and "no Pulsewatch IPs configured" not in netplan_msg:
            message = f"{message} {netplan_msg}"
        if apply_msg and not apply_msg.startswith("Netplan applied"):
            message = f"{message} {apply_msg}"
    interfaces = get_interface_options()
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message, "settings": settings, "interfaces": interfaces}),
    )


@app.get("/settings/db/export")
async def export_db_route():
    db_path = os.environ.get("THREEJ_DB_PATH", "/data/threejnotif.db")
    if not os.path.exists(db_path):
        return Response(content=b"Database not found.", media_type="text/plain", status_code=404)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    headers = {"Content-Disposition": f"attachment; filename=threejnotif-db-{timestamp}.db"}
    with open(db_path, "rb") as handle:
        content = handle.read()
    return Response(content=content, media_type="application/octet-stream", headers=headers)


@app.post("/settings/db/import", response_class=HTMLResponse)
async def import_db_route(request: Request):
    form = await request.form()
    uploaded = form.get("db_file")
    message = ""
    db_path = os.environ.get("THREEJ_DB_PATH", "/data/threejnotif.db")
    if not uploaded:
        message = "No database file uploaded."
    else:
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            if os.path.exists(db_path):
                shutil.copy(db_path, f"{db_path}.bak-{timestamp}")
            content = await uploaded.read()
            with open(db_path, "wb") as handle:
                handle.write(content)
            init_db()
            message = "Database restored successfully."
        except Exception as exc:
            message = f"Database restore failed: {exc}"
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message, "settings": settings, "interfaces": interfaces}),
    )


@app.get("/settings/optical", response_class=HTMLResponse)
async def optical_settings(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(request, {"settings": settings, "message": ""}),
    )


@app.post("/settings/optical", response_class=HTMLResponse)
async def optical_settings_save(request: Request):
    form = await request.form()
    settings = {
        "enabled": parse_bool(form, "enabled"),
        "genieacs": {
            "base_url": form.get("genieacs_base_url", ""),
            "username": form.get("genieacs_username", ""),
            "password": form.get("genieacs_password", ""),
            "page_size": parse_int(form, "genieacs_page_size", 100),
        },
        "telegram": {
            "bot_token": form.get("telegram_bot_token", ""),
            "chat_id": form.get("telegram_chat_id", ""),
        },
        "optical": {
            "rx_threshold_dbm": parse_float(form, "rx_threshold_dbm", -26.0),
            "tx_low_threshold_dbm": parse_float(form, "tx_low_threshold_dbm", -1.0),
            "priority_rx_threshold_dbm": parse_float(form, "priority_rx_threshold_dbm", -29.0),
            "rx_paths": parse_lines(form.get("rx_paths", "")),
            "tx_paths": parse_lines(form.get("tx_paths", "")),
            "pppoe_paths": parse_lines(form.get("pppoe_paths", "")),
            "ip_paths": parse_lines(form.get("ip_paths", "")),
        },
        "general": {
            "message_title": form.get("message_title", "Optical Power Alert"),
            "include_header": parse_bool(form, "include_header"),
            "max_chars": parse_int(form, "max_chars", 3800),
            "schedule_time_ph": form.get("schedule_time_ph", "07:00"),
            "timezone": form.get("timezone", "Asia/Manila"),
        },
    }
    save_settings("optical", settings)
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(request, {"settings": settings, "message": "Saved."}),
    )


@app.post("/settings/optical/test", response_class=HTMLResponse)
async def optical_settings_test(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    message = ""
    try:
        token = settings["telegram"].get("bot_token", "")
        chat_id = settings["telegram"].get("chat_id", "")
        send_telegram(token, chat_id, "ThreeJ Optical test message.")
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/settings/optical/run", response_class=HTMLResponse)
async def optical_settings_run(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    message = ""
    try:
        optical_notifier.run(settings)
        message = "Actual optical check sent."
    except TelegramError as exc:
        message = str(exc)
    except Exception as exc:
        message = f"Run failed: {exc}"
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.get("/settings/rto", response_class=HTMLResponse)
async def rto_settings(request: Request):
    settings = get_settings("rto", RTO_DEFAULTS)
    window_hours = _normalize_rto_window(request.query_params.get("window"))
    return render_rto_response(request, settings, "", "status", "general", window_hours)


@app.get("/rto/series", response_class=JSONResponse)
async def rto_series(ip: str, window: int = 24):
    hours = _normalize_rto_window(window)
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    rows = get_rto_results_for_ip_since(ip, since_iso)
    series = [{"ts": row.get("timestamp"), "value": 100 if row.get("ok") else 0} for row in rows]
    return JSONResponse({"hours": hours, "series": series})


def build_rto_status(settings, window_hours=24):
    history = get_state("rto_history", {})
    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).replace(microsecond=0).isoformat() + "Z"
    raw_results = get_rto_results_since(since_iso)
    rows = []
    by_ip = {}
    for row in raw_results:
        ip = row.get("ip")
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(row)
    for ip, items in by_ip.items():
        items = sorted(items, key=lambda x: x.get("timestamp") or "")
        total = len(items)
        failures = sum(1 for item in items if not item.get("ok"))
        rto_pct = (failures / total) * 100.0 if total else 0.0
        streak = 0
        for item in reversed(items):
            if not item.get("ok"):
                streak += 1
            else:
                break
        last_ok = items[-1].get("ok")
        name = items[-1].get("name") or ip
        last_check = format_ts_ph(items[-1].get("timestamp"))
        spark_values = [100 if item.get("ok") else 0 for item in items]
        rows.append(
            {
                "name": name,
                "ip": ip,
                "total": total,
                "failures": failures,
                "rto_pct": rto_pct,
                "uptime_pct": 100.0 - rto_pct,
                "streak": streak,
                "last_status": "down" if not last_ok else "up",
                "last_check": last_check,
                "spark_points_window": _sparkline_points_fixed(spark_values, 0, 100, width=120, height=30),
                "spark_points_window_large": _sparkline_points_fixed(spark_values, 0, 100, width=640, height=200),
            }
        )
    issue_rto_pct = float(settings.get("classification", {}).get("issue_rto_pct", 5.0))
    issue_streak = int(settings.get("classification", {}).get("issue_streak", 2))
    stable_rto_pct = float(settings.get("classification", {}).get("stable_rto_pct", 1.0))
    since_iso = (datetime.utcnow() - timedelta(hours=24)).replace(microsecond=0).isoformat() + "Z"
    raw_results = get_rto_results_since(since_iso)
    spark_map = {}
    for row in raw_results:
        ip = row.get("ip")
        if not ip:
            continue
        spark_map.setdefault(ip, []).append(100 if row.get("ok") else 0)

    issue_rows = []
    stable_rows = []
    for row in rows:
        spark_values = spark_map.get(row["ip"], [])
        row["spark_points_24h"] = _sparkline_points_fixed(spark_values, 0, 100, width=140, height=28)
        row["spark_points_24h_large"] = _sparkline_points_fixed(spark_values, 0, 100, width=640, height=200)
        reasons = []
        if row["last_status"] == "down":
            reasons.append("Currently down")
        if row["rto_pct"] >= issue_rto_pct:
            reasons.append(f"RTO >= {issue_rto_pct:g}%")
        if row["streak"] >= issue_streak:
            reasons.append(f"Down streak >= {issue_streak}")

        if reasons:
            row["reasons"] = reasons
            issue_rows.append(row)
        elif row["last_status"] == "up" and row["rto_pct"] <= stable_rto_pct:
            stable_rows.append(row)
        else:
            row["reasons"] = [f"RTO > {stable_rto_pct:g}%"]
            issue_rows.append(row)

    issue_rows = sorted(issue_rows, key=lambda x: (-x["rto_pct"], -x["streak"], x["name"].lower()))
    stable_rows = sorted(stable_rows, key=lambda x: x["name"].lower())

    window_label = next((label for label, hours in RTO_WINDOW_OPTIONS if hours == window_hours), "1D")
    return {
        "total": len(rows),
        "issue_total": len(issue_rows),
        "stable_total": len(stable_rows),
        "issue_rows": issue_rows,
        "stable_rows": stable_rows,
        "window_hours": window_hours,
        "window_label": window_label,
        "rules": {
            "issue_rto_pct": issue_rto_pct,
            "issue_streak": issue_streak,
            "stable_rto_pct": stable_rto_pct,
        },
    }


def render_rto_response(request, settings, message, active_tab, settings_tab, window_hours=24):
    status_map = {item["job_name"]: dict(item) for item in get_job_status()}
    job_status = status_map.get("rto", {})
    job_status["last_run_at_ph"] = format_ts_ph(job_status.get("last_run_at"))
    job_status["last_success_at_ph"] = format_ts_ph(job_status.get("last_success_at"))
    status = build_rto_status(settings, window_hours)
    return templates.TemplateResponse(
        "settings_rto.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "rto_status": status,
                "rto_job": job_status,
                "rto_window_options": RTO_WINDOW_OPTIONS,
            },
        ),
    )


@app.post("/settings/rto", response_class=HTMLResponse)
async def rto_settings_save(request: Request):
    form = await request.form()
    settings = {
        "enabled": parse_bool(form, "enabled"),
        "ssh": {
            "host": form.get("ssh_host", ""),
            "port": parse_int(form, "ssh_port", 22),
            "user": form.get("ssh_user", ""),
            "password": form.get("ssh_password", ""),
            "use_key": parse_bool(form, "ssh_use_key"),
            "key_path": form.get("ssh_key_path", ""),
            "remote_csv_path": form.get("ssh_remote_csv_path", ""),
        },
        "telegram": {
            "bot_token": form.get("telegram_bot_token", ""),
            "chat_id": form.get("telegram_chat_id", ""),
        },
        "ping": {
            "count": parse_int(form, "ping_count", 5),
            "per_ping_timeout_sec": parse_int(form, "per_ping_timeout_sec", 1),
            "max_workers": parse_int(form, "max_workers", 64),
        },
        "general": {
            "message_title": form.get("message_title", "RTO Customers"),
            "include_header": parse_bool(form, "include_header"),
            "output_mode": form.get("output_mode", "split"),
            "max_chars": parse_int(form, "max_chars", 3800),
            "max_lines": parse_int(form, "max_lines", 200),
            "top_n": parse_int(form, "top_n", 20),
            "ping_interval_minutes": parse_int(form, "ping_interval_minutes", 5),
            "schedule_time_ph": form.get("schedule_time_ph", "07:00"),
            "timezone": form.get("timezone", "Asia/Manila"),
        },
        "history": {
            "window_size": parse_int(form, "window_size", 30),
        },
        "storage": {
            "raw_retention_days": parse_int(form, "rto_raw_retention_days", 30),
        },
        "classification": {
            "issue_rto_pct": parse_float(form, "issue_rto_pct", 5.0),
            "issue_streak": parse_int(form, "issue_streak", 2),
            "stable_rto_pct": parse_float(form, "stable_rto_pct", 1.0),
        },
    }
    save_settings("rto", settings)
    active_tab = form.get("active_tab", "settings")
    settings_tab = form.get("settings_tab", "general")
    return render_rto_response(request, settings, "Saved.", active_tab, settings_tab)


@app.post("/settings/rto/test", response_class=HTMLResponse)
async def rto_settings_test(request: Request):
    settings = get_settings("rto", RTO_DEFAULTS)
    message = ""
    try:
        token = settings["telegram"].get("bot_token", "")
        chat_id = settings["telegram"].get("chat_id", "")
        send_telegram(token, chat_id, "ThreeJ RTO test message.")
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return render_rto_response(request, settings, message, "settings", "notifications")


@app.post("/settings/rto/run", response_class=HTMLResponse)
async def rto_settings_run(request: Request):
    settings = get_settings("rto", RTO_DEFAULTS)
    message = ""
    try:
        history = get_state("rto_history", {})
        history = rto_notifier.run(settings, history)
        save_state("rto_history", history)
        message = "Actual RTO check sent."
    except TelegramError as exc:
        message = str(exc)
    except Exception as exc:
        message = f"Run failed: {exc}"
    return render_rto_response(request, settings, message, "status", "general")


@app.post("/settings/rto/format", response_class=HTMLResponse)
async def rto_settings_format(request: Request):
    form = await request.form()
    settings = get_settings("rto", RTO_DEFAULTS)
    message = ""
    if parse_bool(form, "confirm_format"):
        save_state("rto_history", {})
        clear_rto_results()
        pause_minutes = int(settings.get("general", {}).get("ping_interval_minutes", 5) or 5)
        pause_until = datetime.utcnow() + timedelta(minutes=max(pause_minutes, 1))
        save_state(
            "rto_state",
            {
                "last_run_date": None,
                "last_ping_at": utc_now_iso(),
                "last_report_date": None,
                "last_prune_at": None,
                "devices_cache": [],
                "pause_until": pause_until.replace(microsecond=0).isoformat() + "Z",
            },
        )
        message = "RTO database formatted."
    else:
        message = "Please confirm format before proceeding."
    return render_rto_response(request, settings, message, "settings", "general")




def render_wan_ping_response(request, pulse_settings, wan_settings, message, active_tab):
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_state = get_state("wan_ping_state", {})
    wan_latency_series = build_wan_latency_series(wan_rows, wan_state, hours=24)
    wan_targets = sorted({item.get("target") for item in wan_latency_series if item.get("target")})
    wan_refresh_seconds = int(wan_settings.get("general", {}).get("interval_seconds", 30) or 30)
    return templates.TemplateResponse(
        "settings_wan_ping.html",
        make_context(
            request,
            {
                "pulsewatch_settings": pulse_settings,
                "settings": wan_settings,
                "wan_rows": wan_rows,
                "wan_state": wan_state,
                "wan_latency_series": wan_latency_series,
                "wan_targets": wan_targets,
                "wan_refresh_seconds": wan_refresh_seconds,
                "wan_message_defaults": WAN_MESSAGE_DEFAULTS,
                "wan_summary_defaults": WAN_SUMMARY_DEFAULTS,
                "message": message,
                "active_tab": active_tab,
            },
        ),
    )


@app.get("/settings/wan", response_class=HTMLResponse)
async def wan_settings(request: Request):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "", "status")


@app.post("/settings/wan/wans", response_class=HTMLResponse)
async def wan_settings_save_wans(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "wan_count", 0)
    wans = []
    for idx in range(count):
        core_id = (form.get(f"wan_{idx}_core_id") or "").strip()
        list_name = (form.get(f"wan_{idx}_list") or "").strip()
        if not core_id or not list_name:
            continue
        mode = (form.get(f"wan_{idx}_mode") or "routed").strip().lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"
        local_ip = (form.get(f"wan_{idx}_local_ip") or "").strip()
        enabled = parse_bool(form, f"wan_{idx}_enabled")
        if not local_ip:
            enabled = False
        wans.append(
            {
                "id": wan_row_id(core_id, list_name),
                "core_id": core_id,
                "list_name": list_name,
                "enabled": enabled,
                "mode": mode,
                "local_ip": local_ip,
                "gateway_ip": "",
                "pppoe_router_id": (form.get(f"wan_{idx}_pppoe_router_id") or "").strip(),
            }
        )
    wan_settings_data["wans"] = wans
    save_settings("wan_ping", wan_settings_data)
    sync_errors = wan_ping_notifier.sync_netwatch(wan_settings_data, pulse_settings)
    if sync_errors:
        message = "WAN list saved with Netwatch warnings: " + "; ".join(sync_errors)
    else:
        message = "WAN list saved and Netwatch synced."
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, message, "add")


@app.post("/settings/wan/routers", response_class=HTMLResponse)
async def wan_settings_save_routers(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "router_count", 0)
    routers = []
    removed_ids = set()
    for idx in range(count):
        router_id = (form.get(f"router_{idx}_id") or "").strip()
        if not router_id:
            continue
        if parse_bool(form, f"router_{idx}_remove"):
            removed_ids.add(router_id)
            continue
        routers.append(
            {
                "id": router_id,
                "name": (form.get(f"router_{idx}_name") or "").strip(),
                "host": (form.get(f"router_{idx}_host") or "").strip(),
                "port": parse_int(form, f"router_{idx}_port", 8728),
                "username": (form.get(f"router_{idx}_username") or "").strip(),
                "password": (form.get(f"router_{idx}_password") or "").strip(),
                "use_tls": parse_bool(form, f"router_{idx}_use_tls"),
            }
        )
    wan_settings_data["pppoe_routers"] = routers
    if removed_ids:
        for wan in wan_settings_data.get("wans", []):
            if wan.get("pppoe_router_id") in removed_ids:
                wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "PPPoE routers saved.", "routers")


@app.post("/settings/wan/routers/add", response_class=HTMLResponse)
async def wan_settings_add_router(request: Request):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = wan_settings_data.get("pppoe_routers", [])
    existing_ids = {router.get("id") for router in routers if router.get("id")}
    next_idx = 1
    while f"router{next_idx}" in existing_ids:
        next_idx += 1
    routers.append(
        {
            "id": f"router{next_idx}",
            "name": f"Router {next_idx}",
            "host": "",
            "port": 8728,
            "username": "",
            "password": "",
            "use_tls": False,
        }
    )
    wan_settings_data["pppoe_routers"] = routers
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "PPPoE router added.", "routers")


@app.post("/settings/wan/routers/remove/{router_id}", response_class=HTMLResponse)
async def wan_settings_remove_router(request: Request, router_id: str):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = [router for router in wan_settings_data.get("pppoe_routers", []) if router.get("id") != router_id]
    wan_settings_data["pppoe_routers"] = routers
    for wan in wan_settings_data.get("wans", []):
        if wan.get("pppoe_router_id") == router_id:
            wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "PPPoE router removed.", "routers")


@app.post("/settings/wan/routers/test/{router_id}", response_class=HTMLResponse)
async def wan_settings_test_router(request: Request, router_id: str):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router = next(
        (item for item in wan_settings_data.get("pppoe_routers", []) if item.get("id") == router_id),
        None,
    )
    if not router:
        return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Router not found.", "routers")
    if router.get("use_tls"):
        return render_wan_ping_response(
            request,
            pulse_settings,
            wan_settings_data,
            "TLS test not supported yet. Disable TLS or use port 8728.",
            "routers",
        )
    host = (router.get("host") or "").strip()
    if not host:
        return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Router host is required.", "routers")
    client = RouterOSClient(
        host,
        int(router.get("port", 8728)),
        router.get("username", ""),
        router.get("password", ""),
    )
    try:
        client.connect()
        message = f"Router {router.get('name') or router_id} connected successfully."
    except Exception as exc:
        message = f"Router test failed: {exc}"
    finally:
        client.close()
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, message, "routers")


@app.post("/settings/wan/telegram", response_class=HTMLResponse)
async def wan_settings_save_telegram(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_settings_data["telegram"] = {
        "bot_token": form.get("telegram_bot_token", ""),
        "chat_id": form.get("telegram_chat_id", ""),
    }
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Telegram settings saved.", "settings")


@app.post("/settings/wan/messages", response_class=HTMLResponse)
async def wan_settings_save_messages(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    summary = wan_settings_data.setdefault("summary", {})
    summary["enabled"] = parse_bool(form, "summary_enabled")
    summary["daily_time"] = (form.get("summary_daily_time") or WAN_SUMMARY_DEFAULTS["daily_time"]).strip()
    summary["all_up_msg"] = form.get("summary_all_up_msg") or WAN_SUMMARY_DEFAULTS["all_up_msg"]
    summary["partial_msg"] = form.get("summary_partial_msg") or WAN_SUMMARY_DEFAULTS["partial_msg"]
    summary["line_template"] = form.get("summary_line_template") or WAN_SUMMARY_DEFAULTS["line_template"]
    count = parse_int(form, "message_count", 0)
    messages = {}
    for idx in range(count):
        wan_id = (form.get(f"message_{idx}_id") or "").strip()
        if not wan_id:
            continue
        send_down_once = parse_bool(form, f"message_{idx}_send_down_once")
        messages[wan_id] = {
            "down_msg": form.get(f"message_{idx}_down_msg", ""),
            "up_msg": form.get(f"message_{idx}_up_msg", ""),
            "still_down_msg": form.get(f"message_{idx}_still_down_msg", ""),
            "send_down_once": send_down_once,
            "repeat_down_interval_minutes": parse_int(form, f"message_{idx}_repeat_minutes", 30),
            "still_down_interval_hours": parse_int(form, f"message_{idx}_still_hours", 8),
        }
    wan_settings_data["messages"] = messages
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Messages saved.", "messages")


@app.post("/settings/wan/interval", response_class=HTMLResponse)
async def wan_settings_save_interval(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    interval = parse_int(form, "wan_interval_seconds", 30)
    wan_settings_data.setdefault("general", {})["interval_seconds"] = max(interval, 5)
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Interval saved.", "settings")


@app.post("/settings/wan/format", response_class=HTMLResponse)
async def wan_format_db(request: Request):
    form = await request.form()
    if not parse_bool(form, "confirm_format"):
        pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
        wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
        return render_wan_ping_response(
            request,
            pulse_settings,
            wan_settings_data,
            "Format canceled. Please confirm before formatting.",
            "settings",
        )
    save_state("wan_ping_state", {"reset_at": utc_now_iso(), "wans": {}})
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    return render_wan_ping_response(
        request,
        pulse_settings,
        wan_settings_data,
        "WAN status database cleared. History removed. Settings preserved.",
        "settings",
    )


@app.get("/settings/pulsewatch", response_class=HTMLResponse)
async def pulsewatch_settings(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    return render_pulsewatch_response(request, settings, "")


@app.get("/system/resources")
async def system_resources():
    return JSONResponse(
        {
            "cpu_pct": round(_cpu_percent(), 1),
            "ram_pct": round(_memory_percent(), 1),
            "disk_pct": round(_disk_percent(), 1),
            "uptime_seconds": _uptime_seconds(),
        }
    )


@app.post("/settings/pulsewatch", response_class=HTMLResponse)
async def pulsewatch_settings_save(request: Request):
    form = await request.form()
    current_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    prev_settings = copy.deepcopy(current_settings)
    cores = current_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    pulse_isps = []
    for idx, existing in enumerate(current_settings.get("pulsewatch", {}).get("isps", []), start=1):
        isp_id = existing.get("id") or f"isp{idx}"
        sources = {}
        for core in cores:
            core_id = core.get("id")
            if not core_id:
                continue
            value = (form.get(f"{isp_id}_source_{core_id}", "") or "").strip()
            if value:
                sources[core_id] = value
        ping_core_id = (form.get(f"{isp_id}_ping_core_id") or existing.get("ping_core_id") or "auto").strip()
        pulse_isps.append(
            {
                "id": isp_id,
                "label": form.get(f"{isp_id}_label", existing.get("label") or f"ISP {idx}"),
                "source_ip": (existing.get("source_ip") or "").strip(),
                "core2_source_ip": sources.get("core2", ""),
                "core3_source_ip": sources.get("core3", ""),
                "sources": sources,
                "router_scope": form.get(f"{isp_id}_router_scope", existing.get("router_scope") or "both"),
                "ping_router": ping_core_id,
                "ping_core_id": ping_core_id,
                "ping_targets": parse_lines(form.get(f"{isp_id}_ping_targets", "")),
                "thresholds": {
                    "latency_ms": parse_float(form, f"{isp_id}_latency_ms", 120.0),
                    "loss_pct": parse_float(form, f"{isp_id}_loss_pct", 20.0),
                },
                "consecutive_breach_count": parse_int(form, f"{isp_id}_breach_count", 3),
                "cooldown_minutes": parse_int(form, f"{isp_id}_cooldown_minutes", 10),
            }
        )
    preset_count_raw = form.get("preset_count")
    presets = []
    if preset_count_raw is None:
        presets = current_settings.get("pulsewatch", {}).get("list_presets", [])
    else:
        preset_count = parse_int(form, "preset_count", 0)
        for idx in range(preset_count):
            core_id = (form.get(f"preset_{idx}_core_id") or "").strip()
            list_name = (form.get(f"preset_{idx}_list") or "").strip()
            identifier = (form.get(f"preset_{idx}_identifier") or "").strip()
            address = (form.get(f"preset_{idx}_address") or "").strip()
            if core_id and list_name:
                presets.append(
                    {
                        "core_id": core_id,
                        "list": list_name,
                        "identifier": identifier,
                        "color": (form.get(f"preset_{idx}_color") or "").strip(),
                        "address": address,
                        "latency_ms": parse_float(form, f"preset_{idx}_latency_ms", 120.0),
                        "loss_pct": parse_float(form, f"preset_{idx}_loss_pct", 20.0),
                        "breach_count": parse_int(form, f"preset_{idx}_breach_count", 3),
                        "cooldown_minutes": parse_int(form, f"preset_{idx}_cooldown_minutes", 10),
                        "ping_targets": parse_lines(form.get(f"preset_{idx}_ping_targets", "")),
                    }
                )
    pulsewatch = current_settings.get("pulsewatch", {})
    def _form_has(name):
        return name in form
    current_pulse = current_settings.get("pulsewatch", {})
    current_dashboard = current_pulse.get("dashboard", {})
    current_stability = current_pulse.get("stability", {})
    current_speedtest = current_pulse.get("speedtest", {})
    current_ping = current_pulse.get("ping", {})
    pulsewatch.update(
        {
            "enabled": parse_bool(form, "pulsewatch_enabled") if _form_has("pulsewatch_enabled") else current_pulse.get("enabled", False),
            "manage_address_lists": parse_bool(form, "pulsewatch_manage_address_lists") if _form_has("pulsewatch_manage_address_lists") else current_pulse.get("manage_address_lists", False),
            "reconcile_interval_minutes": parse_int(form, "pulsewatch_reconcile_interval_minutes", 10) if _form_has("pulsewatch_reconcile_interval_minutes") else current_pulse.get("reconcile_interval_minutes", 10),
            "store_raw_output": parse_bool(form, "pulsewatch_store_raw_output") if _form_has("pulsewatch_store_raw_output") else current_pulse.get("store_raw_output", False),
            "retention_days": parse_int(form, "pulsewatch_retention_days", 30) if _form_has("pulsewatch_retention_days") else current_pulse.get("retention_days", 30),
            "rollup_retention_days": parse_int(form, "pulsewatch_rollup_retention_days", 365) if _form_has("pulsewatch_rollup_retention_days") else current_pulse.get("rollup_retention_days", 365),
            "dashboard": {
                "default_target": (form.get("pulsewatch_dashboard_default_target") or current_dashboard.get("default_target") or "all").strip() or "all",
                "refresh_seconds": parse_int(form, "pulsewatch_dashboard_refresh_seconds", 2) if _form_has("pulsewatch_dashboard_refresh_seconds") else current_dashboard.get("refresh_seconds", 2),
                "loss_history_minutes": parse_int(form, "pulsewatch_dashboard_loss_history_minutes", 120) if _form_has("pulsewatch_dashboard_loss_history_minutes") else current_dashboard.get("loss_history_minutes", 120),
                "pie_default_days": parse_int(form, "pulsewatch_dashboard_pie_days", 7) if _form_has("pulsewatch_dashboard_pie_days") else current_dashboard.get("pie_default_days", 7),
            },
            "stability": {
                "stable_max_ms": parse_int(form, "pulsewatch_stability_stable_max_ms", 80) if _form_has("pulsewatch_stability_stable_max_ms") else current_stability.get("stable_max_ms", 80),
                "unstable_max_ms": parse_int(form, "pulsewatch_stability_unstable_max_ms", 150) if _form_has("pulsewatch_stability_unstable_max_ms") else current_stability.get("unstable_max_ms", 150),
                "down_source": "wan",
            },
            "list_presets": presets,
            "speedtest": {
                "enabled": parse_bool(form, "speedtest_enabled") if _form_has("speedtest_enabled") else current_speedtest.get("enabled", False),
                "min_interval_minutes": parse_int(form, "speedtest_min_interval_minutes", 60) if _form_has("speedtest_min_interval_minutes") else current_speedtest.get("min_interval_minutes", 60),
                "command": form.get("speedtest_command", "speedtest") if _form_has("speedtest_command") else current_speedtest.get("command", "speedtest"),
                "args": form.get("speedtest_args", "--format=json") if _form_has("speedtest_args") else current_speedtest.get("args", "--format=json"),
                "use_netns": parse_bool(form, "speedtest_use_netns") if _form_has("speedtest_use_netns") else current_speedtest.get("use_netns", False),
                "netns_prefix": form.get("speedtest_netns_prefix", "isp") if _form_has("speedtest_netns_prefix") else current_speedtest.get("netns_prefix", "isp"),
            },
            "ping": {
                "timeout_seconds": parse_int(form, "pulsewatch_ping_timeout_seconds", 1) if _form_has("pulsewatch_ping_timeout_seconds") else current_ping.get("timeout_seconds", 1),
                "count": parse_int(form, "pulsewatch_ping_count", 5) if _form_has("pulsewatch_ping_count") else current_ping.get("count", 5),
                "max_parallel": parse_int(form, "pulsewatch_ping_max_parallel", 8) if _form_has("pulsewatch_ping_max_parallel") else current_ping.get("max_parallel", 8),
                "interval_seconds": parse_int(form, "pulsewatch_ping_interval_seconds", 1) if _form_has("pulsewatch_ping_interval_seconds") else current_ping.get("interval_seconds", 1),
            },
            "isps": pulse_isps,
        }
    )
    telegram = dict(current_settings.get("telegram", ISP_PING_DEFAULTS.get("telegram", {})))
    if "telegram_bot_token" in form:
        telegram["bot_token"] = form.get("telegram_bot_token", "")
    if "pulsewatch_bot_token" in form:
        telegram["pulsewatch_bot_token"] = form.get("pulsewatch_bot_token", "")
    if "telegram_alert_channel_id" in form:
        telegram["alert_channel_id"] = form.get("telegram_alert_channel_id", "")
    settings = {
        "enabled": current_settings.get("enabled", False),
        "telegram": telegram,
        "general": current_settings.get("general", {}),
        "report": current_settings.get("report", {}),
        "targets": current_settings.get("targets", []),
        "pulsewatch": pulsewatch,
    }
    save_settings("isp_ping", settings)
    message_lines = ["ISP Pulsewatch modification saved!"]
    changes = []
    def _json_dump(value):
        try:
            return json.dumps(value, sort_keys=True, default=str)
        except TypeError:
            return str(value)
    if prev_settings.get("pulsewatch", {}).get("enabled") != settings.get("pulsewatch", {}).get("enabled"):
        changes.append("Core: enable pulsewatch updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("manage_address_lists") != settings.get("pulsewatch", {}).get("manage_address_lists"):
        changes.append("Core: auto-manage address lists updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("reconcile_interval_minutes") != settings.get("pulsewatch", {}).get("reconcile_interval_minutes"):
        changes.append("Core: reconcile interval updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("store_raw_output") != settings.get("pulsewatch", {}).get("store_raw_output"):
        changes.append("Core: store raw output updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("retention_days") != settings.get("pulsewatch", {}).get("retention_days"):
        changes.append("Core: raw retention days updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("rollup_retention_days") != settings.get("pulsewatch", {}).get("rollup_retention_days"):
        changes.append("Core: rollup retention updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("ping", {}).get("timeout_seconds") != settings.get("pulsewatch", {}).get("ping", {}).get("timeout_seconds"):
        changes.append("Ping: timeout seconds updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("ping", {}).get("count") != settings.get("pulsewatch", {}).get("ping", {}).get("count"):
        changes.append("Ping: count updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("ping", {}).get("max_parallel") != settings.get("pulsewatch", {}).get("ping", {}).get("max_parallel"):
        changes.append("Ping: max parallel ping updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("speedtest", {}).get("enabled") != settings.get("pulsewatch", {}).get("speedtest", {}).get("enabled"):
        changes.append("Speedtest: enabled updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("speedtest", {}).get("min_interval_minutes") != settings.get("pulsewatch", {}).get("speedtest", {}).get("min_interval_minutes"):
        changes.append("Speedtest: min interval updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("speedtest", {}).get("command") != settings.get("pulsewatch", {}).get("speedtest", {}).get("command"):
        changes.append("Speedtest: command updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("speedtest", {}).get("args") != settings.get("pulsewatch", {}).get("speedtest", {}).get("args"):
        changes.append("Speedtest: args updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("speedtest", {}).get("use_netns") != settings.get("pulsewatch", {}).get("speedtest", {}).get("use_netns"):
        changes.append("Speedtest: use netns updated [ok]")
    if prev_settings.get("pulsewatch", {}).get("speedtest", {}).get("netns_prefix") != settings.get("pulsewatch", {}).get("speedtest", {}).get("netns_prefix"):
        changes.append("Speedtest: netns prefix updated [ok]")
    if prev_settings.get("telegram", {}).get("bot_token") != settings.get("telegram", {}).get("bot_token"):
        changes.append("Telegram: bot token updated [ok]")
    if prev_settings.get("telegram", {}).get("alert_channel_id") != settings.get("telegram", {}).get("alert_channel_id"):
        changes.append("Telegram: alert channel updated [ok]")
    if changes:
        message_lines.append("Changes: " + ", ".join(changes))
    else:
        message_lines.append("Changes: none")
    netplan_msg = None
    apply_msg = None
    sync_msg = None
    had_addresses = bool(compute_pulsewatch_interface_map(prev_settings))
    presets_before = prev_settings.get("pulsewatch", {}).get("list_presets", [])
    presets_after = settings.get("pulsewatch", {}).get("list_presets", [])
    presets_changed = _json_dump(presets_before) != _json_dump(presets_after)
    cores_before = prev_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    cores_after = settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_netplan_fields = ["id", "interface", "prefix", "gateway"]
    cores_before_net = [
        {key: core.get(key) for key in core_netplan_fields} for core in cores_before
    ]
    cores_after_net = [
        {key: core.get(key) for key in core_netplan_fields} for core in cores_after
    ]
    netplan_needed = presets_changed or _json_dump(cores_before_net) != _json_dump(cores_after_net)
    if netplan_needed:
        try:
            netplan_path, netplan_msg, interface_map, route_specs = build_pulsewatch_netplan(settings)
            if netplan_path:
                _, apply_msg = apply_netplan(interface_map, route_specs)
        except Exception as exc:
            apply_msg = f"Netplan update failed: {exc}"
    presets_with_address = any((item.get("address") or "").strip() for item in presets_after)
    manage_enabled = bool(pulsewatch.get("manage_address_lists"))
    if manage_enabled and (presets_changed or presets_with_address):
        try:
            state = get_state("isp_ping_state", {})
            isp_ping_notifier.sync_mikrotik_lists(settings, state)
            save_state("isp_ping_state", state)
            sync_msg = "MikroTik address-list sync completed."
        except Exception as exc:
            sync_msg = f"MikroTik sync failed: {exc}"
    if netplan_msg:
        if "Netplan file updated" in netplan_msg:
            message_lines.append("Network IPs updated.")
        elif "Netplan file removed" in netplan_msg:
            if had_addresses:
                message_lines.append("Network IPs removed.")
        elif "Netplan unchanged" in netplan_msg:
            if had_addresses:
                message_lines.append("Network IPs unchanged.")
        elif "no Pulsewatch IPs configured" not in netplan_msg:
            message_lines.append(netplan_msg)
    if not netplan_needed:
        message_lines.append("Network IPs unchanged (no preset/IP changes).")
    if apply_msg:
        if "Netplan apply timed out" in apply_msg:
            message_lines.append("Applied IPs directly (netplan timeout).")
        elif apply_msg.startswith("Netplan apply failed"):
            message_lines.append(apply_msg)
    if sync_msg:
        if "sync completed" in sync_msg:
            message_lines.append("MikroTik address-lists synced.")
        else:
            message_lines.append(sync_msg)
    try:
        state = get_state("isp_ping_state", {})
        state = isp_ping_notifier.check_preset_reachability(settings, state)
        save_state("isp_ping_state", state)
    except Exception:
        pass
    message = "\n".join(message_lines)
    return render_pulsewatch_response(request, settings, message)


@app.post("/settings/pulsewatch/format", response_class=HTMLResponse)
async def pulsewatch_format_db(request: Request):
    form = await request.form()
    if not parse_bool(form, "confirm_format"):
        settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
        return render_pulsewatch_response(request, settings, "Format canceled. Please confirm before formatting.")
    clear_pulsewatch_data()
    save_state(
        "isp_ping_state",
        {
            "last_status": {},
            "last_report_date": None,
            "last_report_time": None,
            "last_report_timezone": None,
            "pulsewatch": {"isps": {}, "last_check_at": None, "speedtest_last": {}},
            "pulsewatch_pause_until": (datetime.utcnow() + timedelta(minutes=2)).replace(microsecond=0).isoformat()
            + "Z",
        },
    )
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    return render_pulsewatch_response(
        request,
        settings,
        "Pulsewatch database cleared. Ping, speedtest, alerts, and rollups removed. Settings preserved.",
    )


@app.get("/pulsewatch/reachability", response_class=JSONResponse)
async def pulsewatch_reachability(refresh: int = 0):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    state = get_state("isp_ping_state", {})
    if refresh:
        state = isp_ping_notifier.check_preset_reachability(settings, state)
        save_state("isp_ping_state", state)
    reach_map = state.get("pulsewatch_reachability", {})
    payload = {}
    for row_id, item in reach_map.items():
        payload[row_id] = {
            "status": item.get("status", "unknown"),
            "target": item.get("target", ""),
            "source_ip": item.get("source_ip", ""),
            "last_check": format_ts_ph(item.get("last_check")),
        }
    return JSONResponse(
        {
            "checked_at": format_ts_ph(state.get("pulsewatch_reachability_checked_at")),
            "items": payload,
        }
    )


@app.post("/settings/pulsewatch/reachability/fix", response_class=JSONResponse)
async def pulsewatch_reachability_fix():
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    netplan_path, _, interface_map, route_specs = build_pulsewatch_netplan(settings)
    netplan_msg = "Netplan file not found."
    if netplan_path:
        ok, netplan_msg = apply_netplan(interface_map, route_specs)
        if ok:
            netplan_msg = "Netplan applied."
    restart_ok, restart_msg = run_host_command(
        "systemctl restart systemd-networkd || systemctl restart networking || true"
    )
    status = "ok" if restart_ok else "error"
    return JSONResponse(
        {
            "status": status,
            "netplan": netplan_msg,
            "restart": restart_msg,
        }
    )




@app.post("/settings/pulsewatch/test", response_class=HTMLResponse)
async def pulsewatch_settings_test(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        token = settings["telegram"].get("command_bot_token") or settings["telegram"].get("bot_token", "")
        chat_id = settings["telegram"].get("command_chat_id") or settings["telegram"].get("chat_id", "")
        send_telegram(token, chat_id, "ThreeJ Pulsewatch test message.")
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return render_pulsewatch_response(request, settings, message)


@app.post("/settings/pulsewatch/mikrotik/test", response_class=HTMLResponse)
async def isp_mikrotik_test(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    pulse_cfg = settings.get("pulsewatch", {})
    routers = pulse_cfg.get("mikrotik", {}).get("cores", [])
    results = []
    for router in routers:
        core_id = router.get("id") or "core"
        host = router.get("host", "")
        if not host:
            results.append(f"{core_id}: skipped (no host)")
            continue
        client = RouterOSClient(
            host,
            int(router.get("port", 8728)),
            router.get("username", ""),
            router.get("password", ""),
        )
        try:
            client.connect()
            entries = client.list_address_list()
            results.append(f"{core_id}: OK ({len(entries)} entries)")
        except Exception as exc:
            results.append(f"{core_id}: failed ({exc})")
        finally:
            client.close()
    message = " | ".join(results)
    interfaces = get_interface_options()
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"settings": settings, "message": message, "interfaces": interfaces}),
    )


@app.post("/settings/pulsewatch/mikrotik/sync", response_class=HTMLResponse)
async def isp_mikrotik_sync(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        state = get_state(
            "isp_ping_state",
            {
                "last_status": {},
                "last_report_date": None,
                "last_report_time": None,
                "last_report_timezone": None,
                "pulsewatch": {},
            },
        )
        state, _ = isp_ping_notifier.run_pulsewatch_check(settings, state, only_isps=[])
        save_state("isp_ping_state", state)
        message = "MikroTik address-list sync completed."
    except Exception as exc:
        message = f"Sync failed: {exc}"
    interfaces = get_interface_options()
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"settings": settings, "message": message, "interfaces": interfaces}),
    )


@app.post("/isp/pulsewatch/ping", response_class=HTMLResponse)
async def isp_pulsewatch_ping_all(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        state = get_state(
            "isp_ping_state",
            {
                "last_status": {},
                "last_report_date": None,
                "last_report_time": None,
                "last_report_timezone": None,
                "pulsewatch": {},
            },
        )
        state, _ = isp_ping_notifier.run_pulsewatch_check(settings, state, force=True)
        save_state("isp_ping_state", state)
        message = "Pulsewatch ping completed for all ISPs."
    except Exception as exc:
        message = f"Pulsewatch ping failed: {exc}"
    return render_pulsewatch_response(request, settings, message)


async def _stream_ping_process(request, label, source_ip, target):
    if not source_ip:
        yield f"data: {label} missing source IP\n\n"
        return
    if not target:
        yield f"data: {label} missing ping target\n\n"
        return

    cmd = ["ping", "-I", source_ip, "-n", target]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        while True:
            if await request.is_disconnected():
                break
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                yield f"data: {label} {text}\n\n"
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                proc.kill()


@app.get("/isp/pulsewatch/ping/stream/{row_id}")
async def isp_pulsewatch_ping_stream_one(request: Request, row_id: str):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    row = find_pulsewatch_row(settings, row_id)
    qp = request.query_params
    override_source = (qp.get("source_ip") or "").strip()
    override_target = (qp.get("target") or "").strip()
    override_label = (qp.get("label") or "").strip()
    if not row:
        async def _missing():
            yield "data: Unknown preset\n\n"
            yield "event: done\ndata: complete\n\n"
        return StreamingResponse(_missing(), media_type="text/event-stream")
    label = override_label or f"{row.get('core_label')} {row.get('list_name')}".strip()
    source_ip = override_source or (row.get("address") or "").strip()
    target = override_target or _get_first_target(row.get("ping_targets"))

    async def _stream():
        yield f"data: Starting ping for {label} -> {target}\n\n"
        async for chunk in _stream_ping_process(request, label, source_ip, target):
            yield chunk
        yield "event: done\ndata: complete\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


@app.get("/isp/pulsewatch/ping/stream")
async def isp_pulsewatch_ping_stream_all(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    rows = build_pulsewatch_rows(settings)[0]
    if not rows:
        async def _empty():
            yield "data: No presets available\n\n"
            yield "event: done\ndata: complete\n\n"
        return StreamingResponse(_empty(), media_type="text/event-stream")

    queue = asyncio.Queue()
    tasks = []

    async def _pump(label, source_ip, target):
        async for chunk in _stream_ping_process(request, label, source_ip, target):
            await queue.put(chunk)
        await queue.put(f"data: {label} stopped\n\n")
        await queue.put(None)

    async def _stream():
        for row in rows:
            identifier = (row.get("identifier") or "").strip()
            label_value = identifier or row.get("list_name")
            label = f"{row.get('core_label')} {label_value}".strip()
            source_ip = (row.get("address") or "").strip()
            targets = row.get("ping_targets") or []
            if not isinstance(targets, list):
                targets = parse_lines(str(targets))
            targets = [target.strip() for target in targets if str(target).strip()]
            if not targets:
                targets = [_get_first_target(row.get("ping_targets"))]
            for target in targets:
                tasks.append(asyncio.create_task(_pump(label, source_ip, target)))
        active = len(tasks)
        while active > 0:
            if await request.is_disconnected():
                break
            try:
                chunk = await asyncio.wait_for(queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if chunk is None:
                active -= 1
                continue
            yield chunk
        for task in tasks:
            if not task.done():
                task.cancel()
        yield "event: done\ndata: complete\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


@app.post("/isp/pulsewatch/ping/{isp_id}", response_class=HTMLResponse)
async def isp_pulsewatch_ping_one(request: Request, isp_id: str):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        state = get_state(
            "isp_ping_state",
            {
                "last_status": {},
                "last_report_date": None,
                "last_report_time": None,
                "last_report_timezone": None,
                "pulsewatch": {},
            },
        )
        state, _ = isp_ping_notifier.run_pulsewatch_check(settings, state, only_isps=[isp_id], force=True)
        save_state("isp_ping_state", state)
        label = isp_id
        for row in build_pulsewatch_rows(settings)[0]:
            if row.get("row_id") == isp_id:
                label = f"{row.get('core_label')} {row.get('list_name')}"
                break
        message = f"Pulsewatch ping completed for {label}."
    except Exception as exc:
        message = f"Pulsewatch ping failed: {exc}"
    return render_pulsewatch_response(request, settings, message)


@app.post("/isp/pulsewatch/speedtest", response_class=HTMLResponse)
async def isp_pulsewatch_speedtest_all(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        state = get_state(
            "isp_ping_state",
            {
                "last_status": {},
                "last_report_date": None,
                "last_report_time": None,
                "last_report_timezone": None,
                "pulsewatch": {},
            },
        )
        results, messages = isp_ping_notifier.run_speedtests(settings, state, force=True)
        save_state("isp_ping_state", state)
        if results:
            summary_lines = format_pulsewatch_speedtest_summary(settings, results)
            message = "\n".join(summary_lines) if summary_lines else "Pulsewatch speedtests completed."
        else:
            message = " ".join(messages) if messages else "Pulsewatch speedtests completed."
    except Exception as exc:
        message = f"Speedtest failed: {exc}"
    return render_pulsewatch_response(request, settings, message)


@app.post("/isp/pulsewatch/speedtest/{isp_id}", response_class=HTMLResponse)
async def isp_pulsewatch_speedtest_one(request: Request, isp_id: str):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        state = get_state(
            "isp_ping_state",
            {
                "last_status": {},
                "last_report_date": None,
                "last_report_time": None,
                "last_report_timezone": None,
                "pulsewatch": {},
            },
        )
        results, messages = isp_ping_notifier.run_speedtests(settings, state, only_isps=[isp_id], force=True)
        save_state("isp_ping_state", state)
        if results:
            summary_lines = format_pulsewatch_speedtest_summary(settings, results)
            message = "\n".join(summary_lines) if summary_lines else f"Speedtest completed for {isp_id}."
        else:
            message = " ".join(messages) if messages else f"Speedtest completed for {isp_id}."
    except Exception as exc:
        message = f"Speedtest failed: {exc}"
    return render_pulsewatch_response(request, settings, message)


@app.get("/isp/pulsewatch/speedtest/servers/{isp_id}", response_class=JSONResponse)
async def isp_pulsewatch_speedtest_servers(request: Request, isp_id: str):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    row = find_pulsewatch_row(settings, isp_id)
    if not row:
        return JSONResponse({"ok": False, "message": "Preset not found.", "servers": []})
    try:
        isp = {
            "id": isp_id,
            "sources": {row.get("core_id"): row.get("address")},
            "source_ip": row.get("address"),
        }
        servers = isp_ping_notifier.list_speedtest_servers(settings, isp)
        return JSONResponse({"ok": True, "servers": servers})
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc), "servers": []})


@app.post("/isp/pulsewatch/speedtest/run/{isp_id}", response_class=JSONResponse)
async def isp_pulsewatch_speedtest_run(request: Request, isp_id: str):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    row = find_pulsewatch_row(settings, isp_id)
    if not row:
        return JSONResponse({"ok": False, "message": "Preset not found."})
    try:
        payload = {}
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        server_id = payload.get("server_id") if isinstance(payload, dict) else None
        state = get_state(
            "isp_ping_state",
            {
                "last_status": {},
                "last_report_date": None,
                "last_report_time": None,
                "last_report_timezone": None,
                "pulsewatch": {},
            },
        )
        results, messages = isp_ping_notifier.run_speedtests(
            settings,
            state,
            only_isps=[isp_id],
            force=True,
            server_id=server_id,
        )
        save_state("isp_ping_state", state)
        if results:
            summary_lines = format_pulsewatch_speedtest_summary(settings, results)
            return JSONResponse(
                {
                    "ok": True,
                    "label": pulsewatch_row_label(row) or isp_id,
                    "result": results.get(isp_id, {}),
                    "summary": summary_lines[0] if summary_lines else "",
                }
            )
        message = " ".join(messages) if messages else "Speedtest completed."
        return JSONResponse({"ok": False, "message": message})
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)})


@app.get("/settings", response_class=HTMLResponse)
async def settings_root():
    return RedirectResponse(url="/settings/optical", status_code=302)

@app.get("/settings/system", response_class=HTMLResponse)
async def system_settings(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    telegram_state = get_state("telegram_state", {})
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": "", "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state}),
    )


@app.post("/settings/system/mikrotik", response_class=HTMLResponse)
async def system_mikrotik_save(request: Request):
    form = await request.form()
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    pulsewatch = settings.get("pulsewatch", {})
    core_ids = parse_lines(form.get("core_ids", ""))
    cores = []
    for core_id in core_ids:
        if not core_id:
            continue
        cores.append(
            {
                "id": core_id,
                "label": form.get(f"{core_id}_label", core_id.upper()),
                "host": form.get(f"{core_id}_host", ""),
                "port": parse_int(form, f"{core_id}_port", 8728),
                "username": form.get(f"{core_id}_username", ""),
                "password": form.get(f"{core_id}_password", ""),
                "interface": form.get(f"{core_id}_interface", ""),
                "prefix": parse_int(form, f"{core_id}_prefix", 24),
                "gateway": form.get(f"{core_id}_gateway", ""),
            }
        )
    pulsewatch["mikrotik"] = {"cores": cores}
    settings["pulsewatch"] = pulsewatch
    save_settings("isp_ping", settings)
    interfaces = get_interface_options()
    message = "MikroTik settings saved."
    netplan_msg = None
    apply_msg = None
    try:
        netplan_path, netplan_msg, interface_map, route_specs = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map, route_specs)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if netplan_msg and "no Pulsewatch IPs configured" not in netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg and not apply_msg.startswith("Netplan applied"):
        message = f"{message} {apply_msg}"
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": get_state("telegram_state", {})},
        ),
    )


@app.post("/settings/system/telegram", response_class=HTMLResponse)
async def system_telegram_save(request: Request):
    form = await request.form()
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    telegram = dict(settings.get("telegram", ISP_PING_DEFAULTS.get("telegram", {})))
    telegram["command_bot_token"] = form.get("telegram_command_bot_token", "")
    telegram["command_chat_id"] = form.get("telegram_command_chat_id", "")
    telegram["allowed_user_ids"] = parse_int_list(form.get("telegram_allowed_user_ids", ""))
    telegram["command_feedback_seconds"] = parse_int(form, "telegram_command_feedback_seconds", 10)
    settings["telegram"] = telegram
    save_settings("isp_ping", settings)
    interfaces = get_interface_options()
    message = "Telegram command settings saved."
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": get_state("telegram_state", {})},
        ),
    )


@app.post("/settings/system/mikrotik/add", response_class=HTMLResponse)
async def system_mikrotik_add(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    pulsewatch = settings.get("pulsewatch", {})
    mikrotik = pulsewatch.get("mikrotik", {})
    cores = mikrotik.get("cores", [])
    existing_ids = {core.get("id") for core in cores if core.get("id")}
    next_idx = 1
    while f"core{next_idx}" in existing_ids:
        next_idx += 1
    core_id = f"core{next_idx}"
    cores.append(
        {
            "id": core_id,
            "label": f"Core {next_idx}",
            "host": "",
            "port": 8728,
            "username": "",
            "password": "",
            "interface": "",
            "prefix": 24,
            "gateway": "",
        }
    )
    mikrotik["cores"] = cores
    pulsewatch["mikrotik"] = mikrotik
    settings["pulsewatch"] = pulsewatch
    save_settings("isp_ping", settings)
    message = "MikroTik core added."
    netplan_msg = None
    apply_msg = None
    try:
        netplan_path, netplan_msg, interface_map, route_specs = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map, route_specs)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if netplan_msg and "no Pulsewatch IPs configured" not in netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg and not apply_msg.startswith("Netplan applied"):
        message = f"{message} {apply_msg}"
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message, "settings": settings, "interfaces": interfaces}),
    )


@app.post("/settings/system/mikrotik/remove/{core_id}", response_class=HTMLResponse)
async def system_mikrotik_remove(request: Request, core_id: str):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    pulsewatch = settings.get("pulsewatch", {})
    mikrotik = pulsewatch.get("mikrotik", {})
    mikrotik["cores"] = [core for core in mikrotik.get("cores", []) if core.get("id") != core_id]
    for isp in pulsewatch.get("isps", []):
        sources = isp.get("sources", {})
        if isinstance(sources, dict) and core_id in sources:
            sources.pop(core_id, None)
        if isp.get("ping_core_id") == core_id:
            isp["ping_core_id"] = "auto"
            isp["ping_router"] = "auto"
    pulsewatch["mikrotik"] = mikrotik
    settings["pulsewatch"] = pulsewatch
    save_settings("isp_ping", settings)
    message = f"{core_id} removed."
    netplan_msg = None
    apply_msg = None
    try:
        netplan_path, netplan_msg, interface_map, route_specs = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map, route_specs)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if netplan_msg and "no Pulsewatch IPs configured" not in netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg and not apply_msg.startswith("Netplan applied"):
        message = f"{message} {apply_msg}"
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message, "settings": settings, "interfaces": interfaces}),
    )


@app.post("/settings/system/uninstall", response_class=HTMLResponse)
async def system_uninstall(request: Request):
    form = await request.form()
    confirm_text = (form.get("confirm_text") or "").strip().upper()
    message = ""
    if confirm_text != "UNINSTALL":
        message = "Confirmation text does not match. Type UNINSTALL to proceed."
        return await system_settings(request)

    host_repo = os.environ.get("THREEJ_HOST_REPO", "/opt/threejnotif")
    command = (
        "docker run --rm --privileged "
        "-v /:/host "
        f"-v {shlex.quote(host_repo)}:/repo "
        "ubuntu bash -c "
        "\"cp /repo/scripts/uninstall_all.sh /host/tmp/threej_uninstall.sh && "
        "chroot /host /bin/bash /tmp/threej_uninstall.sh "
        f"{shlex.quote(host_repo)}\""
    )
    try:
        subprocess.Popen(
            ["/bin/sh", "-c", command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        message = "Uninstall started. This will remove Docker and all app data."
    except Exception as exc:
        message = f"Uninstall failed: {exc}"

    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message, "settings": settings, "interfaces": interfaces}),
    )
