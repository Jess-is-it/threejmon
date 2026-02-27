from pathlib import Path

import copy

import asyncio
import json
import os
import base64
import re
import shlex
import shutil
import time
import subprocess
import threading
import urllib.parse
import urllib.request
import ipaddress
from datetime import datetime, timezone, timedelta, time as dt_time
from zoneinfo import ZoneInfo

import imghdr

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import (
    clear_accounts_ping_data,
    clear_pppoe_usage_samples,
    clear_wan_history,
    delete_wan_target_ping_results_for_targets,
    end_surveillance_session,
    ensure_surveillance_session,
    fetch_wan_history_map,
    fetch_wan_target_ping_series_map,
    get_accounts_ping_latest_ip_since,
    get_accounts_ping_rollups_range,
    get_accounts_ping_rollups_since,
    get_accounts_ping_series,
    get_accounts_ping_series_range,
    get_accounts_ping_window_stats,
    get_accounts_ping_window_stats_by_ip,
    get_job_status,
    get_latest_accounts_ping_map,
    get_latest_optical_by_pppoe,
    get_latest_optical_device_for_ip,
    get_latest_optical_identity,
    get_optical_latest_results_since,
    get_optical_results_for_device_since,
    get_optical_rx_series_for_devices_since,
    get_optical_samples_for_devices_since,
    get_optical_worst_candidates,
    get_wan_status_counts,
    get_offline_history_since,
    get_pppoe_usage_series_since,
    get_recent_optical_readings,
    init_db,
    list_surveillance_history,
    search_optical_customers,
    touch_surveillance_session,
    insert_wan_target_ping_result,
    utc_now_iso,
)
from .forms import parse_bool, parse_float, parse_int, parse_int_list, parse_lines
from .jobs import JobsManager
from .mikrotik import RouterOSClient
from .notifiers import optical as optical_notifier
from .notifiers import rto as rto_notifier
from .notifiers import wan_ping as wan_ping_notifier
from .notifiers.telegram import TelegramError, send_telegram
from .settings_defaults import (
    ACCOUNTS_PING_DEFAULTS,
    ISP_PING_DEFAULTS,
    OFFLINE_DEFAULTS,
    OPTICAL_DEFAULTS,
    SURVEILLANCE_DEFAULTS,
    USAGE_DEFAULTS,
    WAN_PING_DEFAULTS,
    WAN_MESSAGE_DEFAULTS,
    WAN_SUMMARY_DEFAULTS,
)
from .settings_store import export_settings, get_settings, get_state, import_settings, save_settings, save_state

BASE_DIR = Path(__file__).resolve().parent
PH_TZ = ZoneInfo("Asia/Manila")
DATA_DIR = Path("/data")

SYSTEM_DEFAULTS = {
    "branding": {
        "company_logo": {
            "path": "",
            "content_type": "",
            "updated_at": "",
        },
        "browser_logo": {
            "path": "",
            "content_type": "",
            "updated_at": "",
        },
    }
}

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
    try:
        system_settings = get_settings("system", SYSTEM_DEFAULTS)
        branding = system_settings.get("branding") or {}

        company_logo = branding.get("company_logo") or {}
        company_logo_path = (company_logo.get("path") or "").strip()
        if company_logo_path and os.path.isfile(company_logo_path):
            version = urllib.parse.quote((company_logo.get("updated_at") or "").strip() or str(int(os.path.getmtime(company_logo_path))))
            ctx["company_logo_url"] = f"/company-logo?v={version}"
        else:
            ctx["company_logo_url"] = ""

        browser_logo = branding.get("browser_logo") or {}
        browser_logo_path = (browser_logo.get("path") or "").strip()
        if browser_logo_path and os.path.isfile(browser_logo_path):
            version = urllib.parse.quote((browser_logo.get("updated_at") or "").strip() or str(int(os.path.getmtime(browser_logo_path))))
            ctx["browser_logo_url"] = f"/browser-logo?v={version}"
            ctx["browser_logo_type"] = (browser_logo.get("content_type") or "").strip() or "image/png"
        else:
            ctx["browser_logo_url"] = ""
            ctx["browser_logo_type"] = ""
    except Exception:
        ctx["company_logo_url"] = ""
        ctx["browser_logo_url"] = ""
        ctx["browser_logo_type"] = ""
    try:
        surv = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
        entries = surv.get("entries") if isinstance(surv.get("entries"), list) else []
        index = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            key = (entry.get("pppoe") or "").strip()
            if not key:
                continue
            index[key] = (entry.get("status") or "under").strip() or "under"
        ctx["surveillance_index"] = index
        ctx["surveillance_count"] = len(index)
    except Exception:
        ctx["surveillance_index"] = {}
        ctx["surveillance_count"] = 0
    if extra:
        ctx.update(extra)
    return ctx


@app.get("/company-logo")
async def company_logo():
    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    company_logo = (system_settings.get("branding") or {}).get("company_logo") or {}
    logo_path = (company_logo.get("path") or "").strip()
    if not logo_path or not os.path.isfile(logo_path):
        return Response(status_code=404)
    media_type = (company_logo.get("content_type") or "").strip() or "application/octet-stream"
    return FileResponse(logo_path, media_type=media_type)


@app.get("/browser-logo")
async def browser_logo():
    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    browser_logo_cfg = (system_settings.get("branding") or {}).get("browser_logo") or {}
    logo_path = (browser_logo_cfg.get("path") or "").strip()
    if not logo_path or not os.path.isfile(logo_path):
        return Response(status_code=404)
    media_type = (browser_logo_cfg.get("content_type") or "").strip() or "application/octet-stream"
    return FileResponse(logo_path, media_type=media_type)


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
            return path, "Netplan file removed (no router source IPs configured).", interface_map, []
        return path, "Netplan unchanged (no router source IPs configured).", interface_map, []

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
    general.setdefault("target_latency_interval_seconds", general.get("interval_seconds", 30))
    general.setdefault("target_rotation_enabled", False)
    general.setdefault("target_parallel_workers", 0)
    general.setdefault("targets_per_wan_per_run", 1)
    general.setdefault("target_ping_timeout_ms", 1000)
    general.setdefault("target_ping_count", 1)
    general.setdefault("history_retention_days", 400)
    general.setdefault("targets_configured", False)

    try:
        general["interval_seconds"] = max(int(general.get("interval_seconds") or 30), 1)
    except Exception:
        general["interval_seconds"] = 30
    try:
        general["target_latency_interval_seconds"] = max(
            int(general.get("target_latency_interval_seconds") or general.get("interval_seconds") or 30),
            1,
        )
    except Exception:
        general["target_latency_interval_seconds"] = general.get("interval_seconds", 30)
    rotation_raw = general.get("target_rotation_enabled", False)
    if isinstance(rotation_raw, str):
        general["target_rotation_enabled"] = rotation_raw.strip().lower() in ("1", "true", "yes", "on")
    else:
        general["target_rotation_enabled"] = bool(rotation_raw)
    parallel_workers_raw = general.get("target_parallel_workers", 0)
    if parallel_workers_raw in (None, ""):
        parallel_workers_raw = 0
    try:
        general["target_parallel_workers"] = max(min(int(parallel_workers_raw), 64), 0)
    except Exception:
        general["target_parallel_workers"] = 0
    targets_per_wan_raw = general.get("targets_per_wan_per_run", 1)
    if targets_per_wan_raw in (None, ""):
        targets_per_wan_raw = 1
    try:
        general["targets_per_wan_per_run"] = max(int(targets_per_wan_raw), 0)
    except Exception:
        general["targets_per_wan_per_run"] = 1
    try:
        general["target_ping_timeout_ms"] = max(min(int(general.get("target_ping_timeout_ms") or 1000), 60000), 100)
    except Exception:
        general["target_ping_timeout_ms"] = 1000
    try:
        general["target_ping_count"] = max(min(int(general.get("target_ping_count") or 1), 20), 1)
    except Exception:
        general["target_ping_count"] = 1

    targets = general.get("targets")
    default_targets = copy.deepcopy(WAN_PING_DEFAULTS.get("general", {}).get("targets", []))
    if not isinstance(targets, list):
        general["targets"] = copy.deepcopy(default_targets)
    else:
        cleaned = []
        for idx, item in enumerate(targets):
            if not isinstance(item, dict):
                continue
            host = (item.get("host") or "").strip()
            label = (item.get("label") or "").strip()
            if not host:
                continue
            cleaned.append(
                {
                    "id": (item.get("id") or "").strip() or f"target-{idx+1}",
                    "label": label or host,
                    "host": host,
                    "enabled": bool(item.get("enabled", True)),
                }
            )
        if not bool(general.get("targets_configured")):
            if not cleaned:
                cleaned = copy.deepcopy(default_targets)
            else:
                existing_hosts = {((t.get("host") or "").strip().lower()) for t in cleaned if (t.get("host") or "").strip()}
                existing_ids = {((t.get("id") or "").strip()) for t in cleaned if (t.get("id") or "").strip()}
                for item in default_targets:
                    if not isinstance(item, dict):
                        continue
                    host = (item.get("host") or "").strip()
                    if not host:
                        continue
                    host_key = host.lower()
                    item_id = (item.get("id") or "").strip()
                    if host_key in existing_hosts:
                        continue
                    if item_id and item_id in existing_ids:
                        continue
                    cleaned.append(
                        {
                            "id": item_id or f"default-{len(cleaned)+1}",
                            "label": (item.get("label") or "").strip() or host,
                            "host": host,
                            "enabled": bool(item.get("enabled", True)),
                        }
                    )
        general["targets"] = cleaned
    wans = settings.get("wans")
    if not isinstance(wans, list):
        wans = []
    cleaned_wans = []
    for item in wans:
        if not isinstance(item, dict):
            continue
        core_id = (item.get("core_id") or "").strip()
        list_name = (item.get("list_name") or "").strip()
        if not core_id or not list_name:
            continue
        mode = (item.get("mode") or "routed").strip().lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"
        local_ip = (item.get("local_ip") or "").strip()
        netwatch_host = (item.get("netwatch_host") or "").strip()
        if mode == "bridged" and not netwatch_host:
            netwatch_host = local_ip
        enabled = bool(item.get("enabled", True))
        if not local_ip:
            enabled = False
        elif mode == "routed" and not netwatch_host and not enabled:
            enabled = True
        cleaned_wans.append(
            {
                "id": (item.get("id") or wan_row_id(core_id, list_name)).strip(),
                "core_id": core_id,
                "list_name": list_name,
                "identifier": (item.get("identifier") or "").strip(),
                "color": _sanitize_hex_color((item.get("color") or "").strip()),
                "enabled": enabled,
                "mode": mode,
                "local_ip": local_ip,
                "gateway_ip": (item.get("gateway_ip") or "").strip(),
                "netwatch_host": netwatch_host,
                "pppoe_router_id": (item.get("pppoe_router_id") or "").strip(),
            }
        )
    settings["wans"] = cleaned_wans
    settings.setdefault("pppoe_routers", [])
    settings.setdefault("messages", {})
    summary = settings.setdefault("summary", {})
    summary.setdefault("enabled", WAN_SUMMARY_DEFAULTS["enabled"])
    summary.setdefault("daily_time", WAN_SUMMARY_DEFAULTS["daily_time"])
    summary.setdefault("all_up_msg", WAN_SUMMARY_DEFAULTS["all_up_msg"])
    summary.setdefault("partial_msg", WAN_SUMMARY_DEFAULTS["partial_msg"])
    summary.setdefault("line_template", WAN_SUMMARY_DEFAULTS["line_template"])
    return settings


WAN_STATUS_WINDOW_OPTIONS = [
    ("1H", 1),
    ("6H", 6),
    ("12H", 12),
    ("1D", 24),
    ("7D", 168),
    ("15D", 360),
    ("30D", 720),
]


def _normalize_wan_window(value):
    if value is None:
        return 24
    raw = str(value).strip().lower()
    if not raw:
        return 24
    for label, hours in WAN_STATUS_WINDOW_OPTIONS:
        if raw == label.lower():
            return hours
    try:
        hours = int(raw)
        if hours in {opt[1] for opt in WAN_STATUS_WINDOW_OPTIONS}:
            return hours
    except ValueError:
        pass
    return 24


def _wan_target_bucket_seconds(hours, max_points_per_series=1800):
    try:
        window_hours = max(int(hours or 24), 1)
    except Exception:
        window_hours = 24
    try:
        max_points = max(int(max_points_per_series or 1800), 300)
    except Exception:
        max_points = 1800
    total_seconds = window_hours * 3600
    return max((total_seconds + max_points - 1) // max_points, 1)


TABLE_PAGE_SIZE_OPTIONS = [50, 100, 200, 500, 1000]


def _parse_table_limit(value, default=50):
    raw = str(value or "").strip().lower()
    if raw in ("all", "0"):
        return 0
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return default
    if parsed in TABLE_PAGE_SIZE_OPTIONS:
        return parsed
    return default


def _parse_table_page(value, default=1):
    try:
        parsed = int(str(value or "").strip() or default)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _paginate_items(items, page, limit):
    total = len(items)
    if not limit or int(limit) <= 0:
        return items, {
            "page": 1,
            "pages": 1,
            "limit": 0,
            "total": total,
            "start": 1 if total else 0,
            "end": total,
            "has_prev": False,
            "has_next": False,
        }
    limit = int(limit)
    pages = max((total + limit - 1) // limit, 1)
    page = max(int(page or 1), 1)
    if page > pages:
        page = pages
    start_idx = (page - 1) * limit
    end_idx = min(start_idx + limit, total)
    return items[start_idx:end_idx], {
        "page": page,
        "pages": pages,
        "limit": limit,
        "total": total,
        "start": start_idx + 1 if total else 0,
        "end": end_idx,
        "has_prev": page > 1,
        "has_next": page < pages,
    }


def build_wan_status_summary(wan_rows, wan_state, history_map, window_hours=24):
    history_map = history_map or {}
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=max(int(window_hours or 24), 1))
    window_label = next((label for label, hours in WAN_STATUS_WINDOW_OPTIONS if hours == window_hours), "1D")
    rows = []
    total = 0
    down_total = 0
    for row in wan_rows:
        if not row.get("local_ip"):
            continue
        if (row.get("mode") or "routed").lower() == "bridged" and not row.get("pppoe_router_id"):
            continue
        wan_id = row.get("wan_id")
        total += 1
        state_row = wan_state.get("wans", {}).get(wan_id, {})
        history = history_map.get(wan_id, [])
        values = []
        for item in history:
            ts_raw = item.get("ts")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                else:
                    ts = ts.astimezone(timezone.utc)
            except Exception:
                continue
            if ts < window_start:
                continue
            status = (item.get("status") or "").lower()
            values.append(100 if status == "up" else 0)
        if not values:
            state_hist = state_row.get("history", [])
            for item in state_hist:
                ts_raw = item.get("ts")
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    else:
                        ts = ts.astimezone(timezone.utc)
                except Exception:
                    continue
                if ts < window_start:
                    continue
                status = (item.get("status") or "").lower()
                values.append(100 if status == "up" else 0)
        uptime_pct = sum(values) / len(values) if values else None
        spark_points = _sparkline_points_fixed(values or [0], 0, 100, width=120, height=28)
        last_status = (history[-1].get("status") if history else state_row.get("status")) or "n/a"
        if str(last_status).lower() == "down":
            down_total += 1
        rows.append(
            {
                "label": f"{row.get('core_label')} - {(row.get('identifier') or row.get('list_name') or '')}".strip(),
                "status": last_status,
                "target": state_row.get("target") or "",
                "last_check": format_ts_ph(state_row.get("last_check")),
                "last_rtt_ms": state_row.get("last_rtt_ms"),
                "last_error": state_row.get("last_error") or "",
                "uptime_pct": uptime_pct,
                "spark_points": spark_points,
            }
        )
    up_total = max(total - down_total, 0)
    return {
        "total": total,
        "up_total": up_total,
        "down_total": down_total,
        "rows": rows,
        "window_hours": window_hours,
        "window_label": window_label,
    }


def wan_row_id(core_id, list_name):
    raw = f"{core_id}|{list_name}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def is_wan_list_name(list_name):
    return "TO-ISP" in (list_name or "").upper()


_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _sanitize_hex_color(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if _HEX_COLOR_RE.match(raw):
        return raw.lower()
    return ""


def _routeros_sentence_to_dict(sentence):
    data = {}
    for word in sentence[1:]:
        if not word:
            continue
        token = word[1:] if word.startswith("=") else word
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        data[key] = value
    return data


def _routeros_rows(client, words):
    replies = client.talk(words)
    rows = []
    for sentence in replies:
        if not sentence or sentence[0] != "!re":
            continue
        rows.append(_routeros_sentence_to_dict(sentence))
    return rows


def _routeros_trap_message(replies):
    for sentence in replies:
        if not sentence or sentence[0] != "!trap":
            continue
        data = _routeros_sentence_to_dict(sentence)
        message = (data.get("message") or "").strip()
        return message or "RouterOS trap"
    return ""


def _routeros_flag_true(value):
    return str(value or "").strip().lower() in {"true", "yes", "on", "1"}


def _extract_route_interface(route):
    for key in ("immediate-gw", "gateway"):
        raw = (route.get(key) or "").strip()
        if not raw:
            continue
        if "%" in raw:
            iface = raw.split("%", 1)[1].strip()
            if iface:
                return iface
        if raw and re.match(r"^[A-Za-z].*", raw) and "." not in raw:
            return raw
    status = (route.get("gateway-status") or "").strip()
    match = re.search(r"\bvia\s+([^\s,]+)", status)
    if match:
        return (match.group(1) or "").strip()
    return (route.get("out-interface") or "").strip()


def _extract_route_gateway_ip(route):
    for key in ("immediate-gw", "gateway"):
        raw = (route.get(key) or "").strip()
        if not raw:
            continue
        ip_part = raw.split("%", 1)[0].strip()
        try:
            ip_obj = ipaddress.ip_address(ip_part)
            if ip_obj.version == 4:
                return str(ip_obj)
        except Exception:
            continue
    status = (route.get("gateway-status") or "").strip()
    for token in _IPV4_RE.findall(status):
        try:
            ip_obj = ipaddress.ip_address(token)
            if ip_obj.version == 4:
                return str(ip_obj)
        except Exception:
            continue
    return ""


def _pick_interface_local_ip(address_rows, interface_name="", gateway_ip=""):
    iface_name = (interface_name or "").strip()
    gateway_obj = None
    if gateway_ip:
        try:
            parsed = ipaddress.ip_address(str(gateway_ip).strip())
            if parsed.version == 4:
                gateway_obj = parsed
        except Exception:
            gateway_obj = None
    candidates = []
    for row in address_rows:
        if _routeros_flag_true(row.get("disabled")):
            continue
        row_iface = (row.get("interface") or "").strip()
        if iface_name and row_iface != iface_name:
            continue
        raw = (row.get("address") or "").strip()
        if not raw:
            continue
        try:
            iface = ipaddress.ip_interface(raw)
        except Exception:
            continue
        if iface.version != 4:
            continue
        if gateway_obj is not None:
            try:
                if gateway_obj in iface.network:
                    return str(iface.ip)
            except Exception:
                pass
        dynamic_rank = 0 if _routeros_flag_true(row.get("dynamic")) else 1
        candidates.append((dynamic_rank, str(iface.ip)))
    if not candidates:
        return ""
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][1]


def _remove_mangle_rules_by_comment(client, comment):
    if not comment:
        return
    try:
        rows = _routeros_rows(client, ["/ip/firewall/mangle/print", f"?comment={comment}"])
    except Exception:
        return
    for row in rows:
        rule_id = (row.get(".id") or "").strip()
        if not rule_id:
            continue
        try:
            client.talk(["/ip/firewall/mangle/remove", f"=.id={rule_id}"])
        except Exception:
            continue


def _is_public_ipv4(value):
    raw = (value or "").strip()
    if not raw:
        return False
    try:
        ip_obj = ipaddress.ip_address(raw)
    except Exception:
        return False
    if ip_obj.version != 4:
        return False
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified)


def _detect_public_ip_for_source(client, src_address, routing_mark="", sample_index=0):
    src = (src_address or "").strip()
    if not src:
        return ""
    mark = (routing_mark or "").strip()
    providers = [
        "http://1.1.1.1/cdn-cgi/trace",
        "http://ifconfig.me/ip",
    ]
    safe_src = re.sub(r"[^0-9A-Za-z_.-]", "_", src)
    probe_comment = ""
    probe_rule_added = False
    if mark:
        probe_comment = f"threej_wanip_probe_{safe_src}_{int(time.time() * 1000)}_{sample_index}"
        try:
            replies = client.talk(
                [
                    "/ip/firewall/mangle/add",
                    "=chain=output",
                    "=action=mark-routing",
                    f"=new-routing-mark={mark}",
                    "=passthrough=no",
                    f"=src-address={src}",
                    f"=comment={probe_comment}",
                ]
            )
            trap_message = _routeros_trap_message(replies)
            if not trap_message:
                probe_rule_added = True
        except Exception:
            probe_rule_added = False
    try:
        for idx, url in enumerate(providers):
            stamp = int(time.time() * 1000)
            delimiter = "&" if "?" in url else "?"
            probe_url = f"{url}{delimiter}threej_probe={stamp}_{sample_index}_{idx}"
            file_name = f"threej_wanip_{safe_src}_{stamp}_{idx}.txt"
            try:
                replies = client.talk(
                    [
                        "/tool/fetch",
                        f"=url={probe_url}",
                        f"=dst-path={file_name}",
                        f"=src-address={src}",
                        "=keep-result=yes",
                    ]
                )
                trap_message = _routeros_trap_message(replies)
                if trap_message:
                    continue
                file_rows = _routeros_rows(client, ["/file/print", "=detail=yes", f"?name={file_name}"])
                if not file_rows:
                    continue
                contents = (file_rows[0].get("contents") or "").strip()
                if not contents:
                    continue
                for token in _IPV4_RE.findall(contents):
                    try:
                        ip_obj = ipaddress.ip_address(token)
                        if ip_obj.version == 4:
                            return str(ip_obj)
                    except Exception:
                        continue
            except Exception:
                continue
            finally:
                try:
                    client.talk(["/file/remove", f"=numbers={file_name}"])
                except Exception:
                    pass
    finally:
        if probe_rule_added:
            _remove_mangle_rules_by_comment(client, probe_comment)
    return ""


def _collect_public_ip_samples(client, local_ip, routing_mark, attempts=1, start_index=0):
    src = (local_ip or "").strip()
    if not src:
        return []
    samples = []
    for idx in range(max(int(attempts or 1), 1)):
        probe = _detect_public_ip_for_source(
            client,
            src,
            routing_mark=routing_mark,
            sample_index=max(int(start_index or 0), 0) + idx,
        )
        if probe:
            samples.append(probe)
        if idx < max(int(attempts or 1), 1) - 1:
            time.sleep(0.2)
    return samples


def detect_routed_wan_autofill(pulsewatch_settings, wan_rows, probe_public=True):
    wanted_by_core = {}
    existing_by_key = {}
    for row in (wan_rows or []):
        if not isinstance(row, dict):
            continue
        mode = (row.get("mode") or "routed").strip().lower()
        if mode != "routed":
            continue
        core_id = (row.get("core_id") or "").strip()
        list_name = (row.get("list_name") or "").strip()
        if not core_id or not list_name:
            continue
        existing_by_key[(core_id, list_name)] = {
            "local_ip": (row.get("local_ip") or "").strip(),
            "netwatch_host": (row.get("netwatch_host") or "").strip(),
        }
        if not is_wan_list_name(list_name):
            continue
        wanted_by_core.setdefault(core_id, set()).add(list_name)

    if not wanted_by_core:
        return {}, []

    cores = pulsewatch_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_map = {
        (item.get("id") or "").strip(): item
        for item in (cores or [])
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }
    detected = {}
    warnings = []

    for core_id, wanted_lists in wanted_by_core.items():
        core = core_map.get(core_id)
        if not core:
            for list_name in wanted_lists:
                detected[(core_id, list_name)] = {"local_ip": "", "netwatch_host": "", "interface": "", "routing_mark": ""}
            warnings.append(f"{core_id}: core not found")
            continue
        host = (core.get("host") or "").strip()
        if not host:
            for list_name in wanted_lists:
                detected[(core_id, list_name)] = {"local_ip": "", "netwatch_host": "", "interface": "", "routing_mark": ""}
            warnings.append(f"{core_id}: core host not configured")
            continue

        client = RouterOSClient(
            host,
            int(core.get("port", 8728)),
            core.get("username", ""),
            core.get("password", ""),
        )
        try:
            client.connect()
            mangle_rows = client.list_mangle_rules()
            address_rows = _routeros_rows(client, ["/ip/address/print"])
            route_rows = _routeros_rows(client, ["/ip/route/print"])

            marks_by_list = {}
            iface_hint_by_list = {}
            for rule in mangle_rows:
                if not isinstance(rule, dict):
                    continue
                if _routeros_flag_true(rule.get("disabled")):
                    continue
                list_name = (rule.get("src-address-list") or "").strip()
                if not list_name or list_name not in wanted_lists:
                    continue
                mark = (
                    (rule.get("new-routing-mark") or "").strip()
                    or (rule.get("new-routing-table") or "").strip()
                    or (rule.get("routing-mark") or "").strip()
                )
                if mark:
                    marks_by_list.setdefault(list_name, []).append(mark)
                iface_hint = (rule.get("out-interface") or "").strip()
                if iface_hint and list_name not in iface_hint_by_list:
                    iface_hint_by_list[list_name] = iface_hint

            default_routes = []
            for route in route_rows:
                if not isinstance(route, dict):
                    continue
                if _routeros_flag_true(route.get("disabled")):
                    continue
                if (route.get("dst-address") or "").strip() != "0.0.0.0/0":
                    continue
                default_routes.append(route)

            def _pick_route(list_name):
                marks = [item for item in marks_by_list.get(list_name, []) if item]
                candidates = []
                if marks:
                    mark_set = set(marks)
                    for route in default_routes:
                        routing_key = ((route.get("routing-table") or "").strip() or (route.get("routing-mark") or "").strip())
                        if routing_key and routing_key in mark_set:
                            candidates.append(route)
                if not candidates:
                    suffix_match = re.search(r"(\d+)$", list_name)
                    if suffix_match:
                        suffix = suffix_match.group(1)
                        tag = f"ISP{suffix}"
                        via_tag = f"via-{tag}"
                        for route in default_routes:
                            comment = (route.get("comment") or "").strip().upper()
                            routing_key = ((route.get("routing-table") or "").strip() or (route.get("routing-mark") or "").strip())
                            if tag in comment or routing_key == via_tag:
                                candidates.append(route)
                if not candidates and iface_hint_by_list.get(list_name):
                    iface_hint = iface_hint_by_list.get(list_name) or ""
                    for route in default_routes:
                        route_iface = _extract_route_interface(route)
                        if route_iface and route_iface == iface_hint:
                            candidates.append(route)
                if not candidates:
                    candidates = list(default_routes)
                if not candidates:
                    return None

                def _route_score(route):
                    active = 0 if _routeros_flag_true(route.get("active")) else 1
                    try:
                        distance = int(str(route.get("distance") or "999").strip())
                    except Exception:
                        distance = 999
                    return (active, distance)

                candidates.sort(key=_route_score)
                return candidates[0]

            used_wan_ips = set()
            for list_name in sorted(wanted_lists):
                route = _pick_route(list_name) or {}
                routing_mark = (
                    (route.get("routing-table") or "").strip()
                    or (route.get("routing-mark") or "").strip()
                    or (marks_by_list.get(list_name, [""])[0] if marks_by_list.get(list_name) else "")
                )
                iface_name = _extract_route_interface(route) or (iface_hint_by_list.get(list_name) or "")
                gateway_ip = _extract_route_gateway_ip(route)
                local_ip = _pick_interface_local_ip(address_rows, iface_name, gateway_ip)
                if not local_ip and gateway_ip:
                    local_ip = _pick_interface_local_ip(address_rows, "", gateway_ip)

                netwatch_host = ""
                existing = existing_by_key.get((core_id, list_name), {}) or {}
                existing_local_ip = (existing.get("local_ip") or "").strip()
                existing_netwatch = (existing.get("netwatch_host") or "").strip()
                if local_ip and existing_local_ip == local_ip and _is_public_ipv4(existing_netwatch):
                    netwatch_host = existing_netwatch
                elif local_ip and probe_public:
                    samples = _collect_public_ip_samples(client, local_ip, routing_mark, attempts=1)
                    if (
                        routing_mark
                        and samples
                        and samples[0] in used_wan_ips
                    ):
                        extra = _collect_public_ip_samples(client, local_ip, routing_mark, attempts=2, start_index=1)
                        if extra:
                            samples.extend(extra)
                    if not samples:
                        samples = _collect_public_ip_samples(client, local_ip, "", attempts=1)
                    if samples:
                        counts = {}
                        order = []
                        for item in samples:
                            if item not in counts:
                                counts[item] = 0
                                order.append(item)
                            counts[item] += 1
                        order_index = {item: idx for idx, item in enumerate(order)}
                        ranked = sorted(order, key=lambda item: (-counts[item], order_index[item]))
                        for candidate in ranked:
                            if candidate not in used_wan_ips:
                                netwatch_host = candidate
                                break
                        if not netwatch_host:
                            netwatch_host = ranked[0]
                        if netwatch_host:
                            used_wan_ips.add(netwatch_host)
                        if len(counts) > 1:
                            warnings.append(
                                f"{core_id} {list_name}: WAN IP probe returned multiple values ({', '.join(order[:3])})"
                            )
                elif _is_public_ipv4(existing_netwatch):
                    netwatch_host = existing_netwatch

                detected[(core_id, list_name)] = {
                    "local_ip": local_ip,
                    "netwatch_host": netwatch_host,
                    "interface": iface_name,
                    "routing_mark": routing_mark,
                }
                if not local_ip:
                    warnings.append(f"{core_id} {list_name}: unable to auto-detect local IP")
                if local_ip and not netwatch_host:
                    warnings.append(f"{core_id} {list_name}: unable to auto-detect WAN/public IP")
        except Exception as exc:
            for list_name in wanted_lists:
                detected[(core_id, list_name)] = {"local_ip": "", "netwatch_host": "", "interface": "", "routing_mark": ""}
            warnings.append(f"{core_id}: auto-detect failed ({exc})")
        finally:
            client.close()

    return detected, warnings


def build_wan_rows(pulsewatch_settings, wan_settings):
    cores = pulsewatch_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    list_map = fetch_mikrotik_lists(cores)
    preset_map = {}
    for preset in pulsewatch_settings.get("pulsewatch", {}).get("list_presets", []):
        core_id = preset.get("core_id")
        list_name = preset.get("list")
        identifier = (preset.get("identifier") or "").strip()
        color = _sanitize_hex_color(preset.get("color") or "")
        if core_id and list_name:
            preset_map[(core_id, list_name)] = {
                "identifier": identifier,
                "address": (preset.get("address") or "").strip(),
                "color": color,
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
            identifier = (saved.get("identifier") or "").strip() or (preset_data.get("identifier") or "").strip()
            color = _sanitize_hex_color((saved.get("color") or "").strip()) or _sanitize_hex_color(preset_data.get("color") or "")
            rows.append(
                {
                    "wan_id": wan_row_id(core_id, list_name),
                    "core_id": core_id,
                    "core_label": core.get("label") or core_id,
                    "list_name": list_name,
                    "identifier": identifier,
                    "identifier_missing": not identifier,
                    "color": color,
                    "mode": mode,
                    "local_ip": saved.get("local_ip", ""),
                    "netwatch_host": saved.get("netwatch_host", ""),
                    "gateway_ip": saved.get("gateway_ip", ""),
                    "preset_address": preset_data.get("address", ""),
                    "pppoe_router_id": saved.get("pppoe_router_id", ""),
                    "enabled": bool(saved.get("enabled", True)),
                }
            )
    return rows


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


def _memory_used_including_cache_percent():
    """Proxmox-like 'used' view: MemTotal - MemFree (includes page cache/buffers)."""
    try:
        mem_total = 0
        mem_free = 0
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemFree:"):
                    mem_free = int(line.split()[1])
        if mem_total <= 0:
            return 0.0
        used = mem_total - mem_free
        return max(0.0, min(100.0, 100.0 * used / mem_total))
    except Exception:
        return 0.0


def _memory_details_kb():
    try:
        values = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                key, rest = line.split(":", 1)
                parts = rest.strip().split()
                if not parts:
                    continue
                try:
                    values[key] = int(parts[0])
                except Exception:
                    continue
        return {
            "mem_total_kb": int(values.get("MemTotal") or 0),
            "mem_free_kb": int(values.get("MemFree") or 0),
            "mem_available_kb": int(values.get("MemAvailable") or 0),
            "buffers_kb": int(values.get("Buffers") or 0),
            "cached_kb": int(values.get("Cached") or 0),
            "swap_total_kb": int(values.get("SwapTotal") or 0),
            "swap_free_kb": int(values.get("SwapFree") or 0),
        }
    except Exception:
        return {
            "mem_total_kb": 0,
            "mem_free_kb": 0,
            "mem_available_kb": 0,
            "buffers_kb": 0,
            "cached_kb": 0,
            "swap_total_kb": 0,
            "swap_free_kb": 0,
        }


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


def _sparkline_points_fixed(values, min_val, max_val, width=120, height=30):
    if not values:
        return ""
    max_points = max(int(width) + 1, 2)
    if len(values) > max_points:
        last_idx = len(values) - 1
        values = [values[int(i * last_idx / (max_points - 1))] for i in range(max_points)]
    span = max(max_val - min_val, 1)
    step = width / max(len(values) - 1, 1)
    points = []
    for idx, value in enumerate(values):
        value = max(min_val, min(max_val, value))
        x = idx * step
        y = height - ((value - min_val) / span) * height
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


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


def format_bytes(value):
    try:
        value = int(value)
    except Exception:
        return "n/a"
    if value < 0:
        value = 0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(value)
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def format_bps(value):
    try:
        value = float(value)
    except Exception:
        return "n/a"
    if value < 0:
        value = 0.0
    units = ["bps", "kbps", "Mbps", "Gbps"]
    size = value
    idx = 0
    while size >= 1000 and idx < len(units) - 1:
        size /= 1000.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    if size >= 100:
        return f"{size:.0f} {units[idx]}"
    if size >= 10:
        return f"{size:.1f} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def _parse_hhmm(value, default=(0, 0)):
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        return default
    try:
        return int(parts[0]), int(parts[1])
    except Exception:
        return default


def is_time_window_ph(now_ph, start_hhmm, end_hhmm):
    sh, sm = _parse_hhmm(start_hhmm, default=(17, 30))
    eh, em = _parse_hhmm(end_hhmm, default=(21, 0))
    start_t = dt_time(hour=max(min(sh, 23), 0), minute=max(min(sm, 59), 0))
    end_t = dt_time(hour=max(min(eh, 23), 0), minute=max(min(em, 59), 0))
    current_t = now_ph.time()
    if start_t <= end_t:
        return start_t <= current_t <= end_t
    # crosses midnight
    return current_t >= start_t or current_t <= end_t


def build_wan_latency_series(rows, state, hours=24, window_start=None, window_end=None, history_map=None):
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
        if history_map and wan_id in history_map:
            history = history_map.get(wan_id, [])
        else:
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
    return templates.TemplateResponse(
        "dashboard.html",
        make_context(request, {"job_status": job_status}),
    )


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
    max_window = timedelta(days=370)
    if window_end - window_start > max_window:
        window_start = window_end - max_window

    start_iso = window_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    end_iso = window_end.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    history_start_iso = (window_start - timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_state = get_state("wan_ping_state", {})
    wan_ids = [row.get("wan_id") for row in wan_rows if row.get("wan_id")]
    history_map = fetch_wan_history_map(wan_ids, history_start_iso, end_iso)
    series = build_wan_latency_series(
        wan_rows,
        wan_state,
        hours=hours,
        window_start=window_start,
        window_end=window_end,
        history_map=history_map,
    )
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
    routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
    router_map = {
        (item.get("id") or "").strip(): item
        for item in routers
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }
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
        router_id = (row.get("pppoe_router_id") or "").strip()
        router_name = ((router_map.get(router_id) or {}).get("name") or "").strip() if router_id else ""
        payload.append(
            {
                "id": wan_id,
                "label": label,
                "core_id": row.get("core_id") or "",
                "core_label": row.get("core_label") or "",
                "mode": row.get("mode") or "",
                "local_ip": row.get("local_ip") or "",
                "pppoe_router_id": row.get("pppoe_router_id") or "",
                "pppoe_router_name": router_name,
                "status": state.get("status"),
                "target": state.get("target"),
                "last_check": state.get("last_check"),
                "last_target_check": state.get("last_target_check"),
                "target_src_address": state.get("target_src_address"),
                "last_rtt_ms": state.get("last_rtt_ms"),
                "last_error": state.get("last_error"),
            }
        )
    return JSONResponse({"rows": payload, "updated_at": utc_now_iso()})


@app.get("/wan/targets/series")
async def wan_targets_series(target_id: str, hours: int = 24, core_id: str = "all"):
    target_id = (target_id or "").strip()
    if not target_id:
        return JSONResponse({"series": [], "window": {"start": "", "end": ""}}, status_code=400)
    hours = _normalize_wan_window(hours)
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    start_dt = now_dt - timedelta(hours=max(int(hours or 24), 1))
    start_iso = start_dt.isoformat().replace("+00:00", "Z")
    end_iso = now_dt.isoformat().replace("+00:00", "Z")

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    targets = (wan_settings.get("general") or {}).get("targets") if isinstance(wan_settings.get("general"), dict) else []
    target = next((item for item in (targets or []) if isinstance(item, dict) and (item.get("id") or "").strip() == target_id), None)
    if not target:
        return JSONResponse({"series": [], "window": {"start": start_iso, "end": end_iso}, "error": "Target not found."}, status_code=404)

    core_id = (core_id or "all").strip()
    cores = pulse_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_map = {item.get("id"): item for item in cores if isinstance(item, dict) and item.get("id")}
    preset_map = {}
    for preset in pulse_settings.get("pulsewatch", {}).get("list_presets", []):
        if not isinstance(preset, dict):
            continue
        preset_core_id = (preset.get("core_id") or "").strip()
        preset_list_name = (preset.get("list") or "").strip()
        if not preset_core_id or not preset_list_name:
            continue
        preset_map[(preset_core_id, preset_list_name)] = {
            "identifier": (preset.get("identifier") or "").strip(),
            "color": _sanitize_hex_color((preset.get("color") or "").strip()),
        }
    wan_rows = []
    for item in (wan_settings.get("wans") or []):
        if not isinstance(item, dict):
            continue
        if not item.get("enabled", True):
            continue
        if not (item.get("local_ip") or "").strip():
            continue
        if core_id != "all" and (item.get("core_id") or "") != core_id:
            continue
        wan_id = (item.get("id") or "").strip() or wan_row_id(item.get("core_id"), item.get("list_name"))
        if not wan_id:
            continue
        list_name = (item.get("list_name") or "").strip()
        preset_data = preset_map.get(((item.get("core_id") or "").strip(), list_name), {})
        identifier = (item.get("identifier") or "").strip() or (preset_data.get("identifier") or "").strip()
        color = _sanitize_hex_color((item.get("color") or "").strip()) or _sanitize_hex_color((preset_data.get("color") or "").strip())
        display_name = identifier or list_name or wan_id
        core_ref = (core_map.get(item.get("core_id")) or {})
        core_label = (core_ref.get("label") or item.get("core_id") or "").strip()
        wan_rows.append(
            {
                "id": wan_id,
                "name": display_name,
                "core_id": item.get("core_id") or "",
                "core_label": core_label,
                "label": display_name,
                "color": color,
            }
        )

    name_counts = {}
    for row in wan_rows:
        key = (row.get("name") or "").strip().lower()
        if not key:
            continue
        name_counts[key] = name_counts.get(key, 0) + 1
    for row in wan_rows:
        key = (row.get("name") or "").strip().lower()
        if key and name_counts.get(key, 0) > 1:
            core_label = (row.get("core_label") or "").strip()
            if core_label:
                row["name"] = f"{core_label} · {row.get('name')}"

    wan_ids = [item.get("id") for item in wan_rows if item.get("id")]
    bucket_seconds = _wan_target_bucket_seconds(hours, max_points_per_series=1800)
    series_map = fetch_wan_target_ping_series_map(wan_ids, target_id, start_iso, end_iso, bucket_seconds=bucket_seconds)
    out_series = []
    for row in wan_rows:
        wan_id = row.get("id")
        points = []
        for item in series_map.get(wan_id, []) or []:
            ts = item.get("timestamp")
            if not ts:
                continue
            points.append({"ts": ts, "rtt_ms": item.get("rtt_ms"), "ok": item.get("ok")})
        out_series.append(
            {
                "id": wan_id,
                "name": row.get("name") or wan_id,
                "color": row.get("color") or "",
                "points": points,
            }
        )

    return JSONResponse(
        {
            "target": {"id": target_id, "label": (target.get("label") or "").strip() or (target.get("host") or ""), "host": (target.get("host") or "").strip()},
            "window": {"start": start_iso, "end": end_iso, "hours": hours, "bucket_seconds": bucket_seconds, "max_points_per_series": 1800},
            "series": out_series,
        }
    )


@app.get("/wan/targets/ping/stream")
async def wan_targets_ping_stream(
    request: Request,
    wan_ids: str = "",
    sel: str = "",
    target_id: str = "",
    interval_s: int = 1,
    count: int = 1,
):
    count = max(min(int(count or 1), 5), 1)
    interval_s = max(min(int(interval_s or 1), 60), 1)
    selected_wan_ids = {part.strip() for part in (wan_ids or "").split(",") if part.strip()}
    selection = {}
    for entry in (sel or "").split(","):
        raw = entry.strip()
        if not raw or ":" not in raw:
            continue
        sel_wan_id, sel_target_id = raw.split(":", 1)
        sel_wan_id = sel_wan_id.strip()
        sel_target_id = sel_target_id.strip()
        if sel_wan_id and sel_target_id:
            selection[sel_wan_id] = sel_target_id

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))

    general_cfg = wan_settings.get("general") if isinstance(wan_settings.get("general"), dict) else {}
    history_retention_days = max(int(general_cfg.get("history_retention_days") or 400), 1)
    enabled_targets = [
        {
            "id": (item.get("id") or "").strip(),
            "label": (item.get("label") or "").strip() or (item.get("host") or "").strip(),
            "host": (item.get("host") or "").strip(),
        }
        for item in (general_cfg.get("targets") or [])
        if isinstance(item, dict)
        and (item.get("id") or "").strip()
        and (item.get("host") or "").strip()
        and bool(item.get("enabled", True))
    ]
    target_map = {item.get("id"): item for item in enabled_targets if item.get("id")}
    target_filter_id = (target_id or "").strip()
    if target_filter_id and target_filter_id not in target_map:
        target_filter_id = ""
    if not enabled_targets:
        async def _empty():
            yield f"event: init\ndata: {json.dumps({'wans': [], 'targets': [], 'error': 'No enabled ping targets configured.'})}\n\n"
            yield "event: done\ndata: complete\n\n"
        return StreamingResponse(_empty(), media_type="text/event-stream")

    cores = pulse_settings.get("pulsewatch", {}).get("mikrotik", {}).get("cores", [])
    core_map = {
        (item.get("id") or "").strip(): item
        for item in (cores or [])
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }
    routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
    router_map = {
        (item.get("id") or "").strip(): item
        for item in (routers or [])
        if isinstance(item, dict) and (item.get("id") or "").strip()
    }

    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wans_meta = []
    groups = {}
    skipped = []
    resolved_selection = {}

    for row in wan_rows:
        wan_id = (row.get("wan_id") or "").strip()
        if not wan_id:
            continue
        if selected_wan_ids and wan_id not in selected_wan_ids:
            continue
        if not row.get("enabled", True):
            continue
        local_ip = (row.get("local_ip") or "").strip()
        if not local_ip:
            continue
        mode = (row.get("mode") or "routed").strip().lower()
        if mode not in ("routed", "bridged"):
            mode = "routed"

        label_value = (row.get("identifier") or "").strip() or (row.get("list_name") or "").strip() or wan_id
        series_name = f"{(row.get('core_label') or '').strip()} {label_value}".strip() or wan_id
        source_ip = local_ip

        selected_target_id = (selection.get(wan_id) or "").strip()
        if selected_target_id and selected_target_id not in target_map:
            selected_target_id = ""
        if target_filter_id:
            selected_targets = [target_map[target_filter_id]]
        elif selected_target_id:
            selected_targets = [target_map[selected_target_id]]
        else:
            selected_targets = list(enabled_targets)
        if not selected_targets:
            skipped.append({"wan_id": wan_id, "reason": "No enabled ping targets available."})
            continue
        resolved_selection[wan_id] = selected_target_id

        router_name = ""
        router_cfg = None
        if mode == "bridged":
            router_id = (row.get("pppoe_router_id") or "").strip()
            if not router_id:
                skipped.append({"wan_id": wan_id, "reason": "PPPoE router not selected (bridged mode)."})
                continue
            router_cfg = router_map.get(router_id)
            if not router_cfg:
                skipped.append({"wan_id": wan_id, "reason": f"PPPoE router '{router_id}' not found."})
                continue
            if router_cfg.get("use_tls"):
                skipped.append({"wan_id": wan_id, "reason": f"PPPoE router '{router_id}' uses TLS (not supported)."})
                continue
            router_name = ((router_cfg.get("name") or router_id).strip() or router_id)
        else:
            core_id = (row.get("core_id") or "").strip()
            router_cfg = core_map.get(core_id)
            if not router_cfg:
                skipped.append({"wan_id": wan_id, "reason": f"Core router '{core_id}' not found."})
                continue
            router_name = ((router_cfg.get("label") or core_id).strip() or core_id)

        host = (router_cfg.get("host") or "").strip() if isinstance(router_cfg, dict) else ""
        if not host:
            skipped.append({"wan_id": wan_id, "reason": "Router host not configured."})
            continue

        port = int(router_cfg.get("port", 8728)) if isinstance(router_cfg, dict) else 8728
        username = router_cfg.get("username", "") if isinstance(router_cfg, dict) else ""
        password = router_cfg.get("password", "") if isinstance(router_cfg, dict) else ""

        group_key = (host, port, username, password)
        groups.setdefault(
            group_key,
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "wans": [],
            },
        )["wans"].append(
            {
                "id": wan_id,
                "name": series_name,
                "label": label_value,
                "core_id": (row.get("core_id") or "").strip(),
                "core_label": (row.get("core_label") or "").strip(),
                "mode": mode,
                "router_name": router_name,
                "src_address": source_ip,
                "targets": selected_targets,
            }
        )
        wans_meta.append(
            {
                "id": wan_id,
                "name": series_name,
                "router_name": router_name,
                "src_address": source_ip,
                "mode": mode,
                "color": (row.get("color") or "").strip(),
                "target_ids": [str(item.get("id") or "").strip() for item in selected_targets if (item.get("id") or "").strip()],
            }
        )

    if selected_wan_ids:
        want = selected_wan_ids
        have = {item.get("id") for item in wans_meta}
        missing = sorted(want - have)
        for wan_id in missing:
            skipped.append({"wan_id": wan_id, "reason": "WAN not found or not eligible for ping."})

    if not wans_meta:
        async def _empty_wans():
            payload = {"wans": [], "targets": enabled_targets, "skipped": skipped, "error": "No eligible ISPs found."}
            yield f"event: init\ndata: {json.dumps(payload)}\n\n"
            yield "event: done\ndata: complete\n\n"
        return StreamingResponse(_empty_wans(), media_type="text/event-stream")

    queue: asyncio.Queue = asyncio.Queue()
    stop_flag = threading.Event()
    loop = asyncio.get_running_loop()

    def _queue_put(item):
        try:
            loop.call_soon_threadsafe(queue.put_nowait, item)
            return
        except Exception:
            pass
        try:
            asyncio.run_coroutine_threadsafe(queue.put(item), loop)
        except Exception:
            pass

    def _worker(group, wans):
        client = RouterOSClient(
            group.get("host", ""),
            int(group.get("port", 8728)),
            group.get("username", ""),
            group.get("password", ""),
        )
        try:
            client.connect()
            # Fetch router interface IPs once so we can validate src-address strictly against
            # real local router interface IPs.
            iface_ips = []
            try:
                replies = client.talk(["/ip/address/print"])
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
                        iface_ips.append(ipaddress.ip_interface(addr))
                    except Exception:
                        continue
            except Exception:
                iface_ips = []

            def pick_src(hint):
                raw = (hint or "").strip()
                if not raw or not iface_ips:
                    return None
                try:
                    ip_obj = ipaddress.ip_address(raw)
                except Exception:
                    return None
                for iface in iface_ips:
                    try:
                        if iface.ip == ip_obj:
                            return str(iface.ip)
                    except Exception:
                        continue
                return None

            wan_list = [item for item in (wans or []) if isinstance(item, dict) and (item.get("id") or "").strip()]
            next_due = {item["id"]: time.monotonic() for item in wan_list}
            wan_lookup = {item["id"]: item for item in wan_list}

            while not stop_flag.is_set() and wan_list:
                due_wan_id = min(next_due, key=next_due.get)
                due_at = next_due.get(due_wan_id, 0.0)
                now = time.monotonic()
                sleep_s = due_at - now
                if sleep_s > 0:
                    time.sleep(min(sleep_s, 0.2))
                    continue

                wan = wan_lookup.get(due_wan_id) or {}
                wan_id = due_wan_id
                targets = wan.get("targets") if isinstance(wan.get("targets"), list) else []
                if not targets:
                    next_due[wan_id] = time.monotonic() + float(interval_s)
                    continue

                src_hint = (wan.get("src_address") or "").strip()
                src_address = pick_src(src_hint)
                has_src_hint = bool(src_hint)
                used_src = bool(src_address)
                for target in targets:
                    if stop_flag.is_set():
                        break
                    target_id = (target.get("id") or "").strip() if isinstance(target, dict) else ""
                    target_host = (target.get("host") or "").strip() if isinstance(target, dict) else ""
                    if not target_id or not target_host:
                        continue

                    now_iso = utc_now_iso()
                    ok = 0
                    rtt_ms = None
                    note = ""
                    if has_src_hint and not used_src:
                        note = f"Configured src-address {src_hint} is not a local router interface"
                    else:
                        try:
                            # Keep DNS resolution inside the router itself so results match manual
                            # `/tool/ping` from the same MikroTik.
                            times = client.ping_times(target_host, count=count, src_address=src_address, timeout="1000ms")
                            if times:
                                ok = 1
                                rtt_ms = float(times[-1])
                        except Exception as exc:
                            ok = 0
                            rtt_ms = None
                            note = str(exc)
                    try:
                        insert_wan_target_ping_result(
                            wan_id,
                            target_id,
                            target_host,
                            ok,
                        rtt_ms=rtt_ms,
                            timestamp=now_iso,
                            core_id=wan.get("core_id") or "",
                            label=wan.get("label") or "",
                            src_address=(src_address or "").strip(),
                            retention_days=history_retention_days,
                        )
                    except Exception:
                        pass
                    _queue_put(
                        (
                            "result",
                            {
                                "timestamp": now_iso,
                                "wan_id": wan_id,
                                "wan_name": wan.get("name") or wan_id,
                                "router_name": wan.get("router_name") or "",
                                "src_address": (src_address or "").strip(),
                                "configured_src_address": src_hint,
                                "target_id": target_id,
                                "target_label": target.get("label") or target_host,
                                "target_host": target_host,
                                "ok": ok,
                                "rtt_ms": rtt_ms,
                                "used_src_address": bool(used_src),
                                "note": note,
                            },
                        )
                    )
                if stop_flag.is_set():
                    break
                next_due[wan_id] = time.monotonic() + float(interval_s)
        except Exception as exc:
            _queue_put(("error", {"error": f"Router ping failed: {exc}"}))
        finally:
            try:
                client.close()
            except Exception:
                pass
            _queue_put(("done_group", None))

    tasks = []
    for group in groups.values():
        tasks.append(asyncio.create_task(asyncio.to_thread(_worker, group, group.get("wans") or [])))

    async def _stream():
        cancelled = False
        init_payload = {
            "wans": wans_meta,
            "targets": enabled_targets,
            "count": count,
            "interval_s": interval_s,
            "retention_days": history_retention_days,
            "skipped": skipped,
            "selection": resolved_selection,
            "target_filter_id": target_filter_id,
        }
        yield f"event: init\ndata: {json.dumps(init_payload)}\n\n"
        try:
            active = len(tasks)
            while active > 0:
                if await request.is_disconnected():
                    break
                try:
                    kind, payload = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                if kind == "done_group":
                    active -= 1
                    continue
                if kind == "result":
                    yield f"event: result\ndata: {json.dumps(payload)}\n\n"
                elif kind == "error":
                    yield f"event: error\ndata: {json.dumps(payload)}\n\n"
        except asyncio.CancelledError:
            cancelled = True
        finally:
            stop_flag.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
        if not cancelled:
            yield "event: done\ndata: complete\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


@app.get("/usage/summary")
async def usage_summary():
    settings = get_settings("usage", USAGE_DEFAULTS)
    state = get_state("usage_state", {})
    active_rows = state.get("active_rows") if isinstance(state.get("active_rows"), list) else []
    offline_rows = state.get("offline_rows") if isinstance(state.get("offline_rows"), list) else []
    hosts = state.get("pppoe_hosts") if isinstance(state.get("pppoe_hosts"), dict) else {}

    detect = settings.get("detection") if isinstance(settings.get("detection"), dict) else {}
    peak_enabled = bool(detect.get("peak_enabled", True))
    min_devices = max(int(detect.get("min_connected_devices", 2) or 2), 1)
    kbps_from = detect.get("total_kbps_from")
    kbps_to = detect.get("total_kbps_to")
    if kbps_from is None:
        kbps_from = 0
    if kbps_to is None:
        kbps_to = detect.get("min_total_kbps", 8)
    kbps_from = max(float(kbps_from or 0.0), 0.0)
    kbps_to = max(float(kbps_to or 0.0), 0.0)
    if kbps_to < kbps_from:
        kbps_from, kbps_to = kbps_to, kbps_from
    range_from_bps = kbps_from * 1000.0
    range_to_bps = kbps_to * 1000.0
    start_ph = (detect.get("peak_start_ph") or "17:30").strip()
    end_ph = (detect.get("peak_end_ph") or "21:00").strip()

    now_ph = datetime.now(PH_TZ)
    in_peak = is_time_window_ph(now_ph, start_ph, end_ph)

    anytime_issues = state.get("anytime_issues") if isinstance(state.get("anytime_issues"), dict) else {}

    issues = []
    stable = []
    for row in active_rows:
        pppoe = (row.get("pppoe") or "").strip()
        if not pppoe:
            continue
        host_info = hosts.get(pppoe) or hosts.get(pppoe.lower()) or {}
        host_count = int(host_info.get("host_count") or 0)
        hostnames = host_info.get("hostnames") if isinstance(host_info.get("hostnames"), list) else []

        # PPP active values are oriented relative to the router:
        # - bytes-out / tx-rate: router -> client (download)
        # - bytes-in / rx-rate: client -> router (upload)
        ul_bps = row.get("rx_bps")
        dl_bps = row.get("tx_bps")
        total_bps = float(ul_bps or 0.0) + float(dl_bps or 0.0)
        peak_issue = bool(
            peak_enabled
            and in_peak
            and host_count >= min_devices
            and (range_from_bps <= total_bps <= range_to_bps)
        )
        key = f"{(row.get('router_id') or '').strip()}|{pppoe.lower()}"
        anytime_issue = bool(anytime_issues.get(key))
        is_issue = bool(peak_issue or anytime_issue)
        target = issues if is_issue else stable
        target.append(
            {
                "pppoe": pppoe,
                "router_id": row.get("router_id") or "",
                "router_name": row.get("router_name") or row.get("router_id") or "",
                "address": row.get("address") or "",
                "uptime": row.get("uptime") or "",
                "session_id": row.get("session_id") or "",
                "dl_bps": dl_bps,
                "ul_bps": ul_bps,
                "dl_total_bytes": row.get("bytes_out"),
                "ul_total_bytes": row.get("bytes_in"),
                "host_count": host_count,
                "hostnames": hostnames,
                "last_seen": format_ts_ph(row.get("timestamp")),
                "last_seen_ts": row.get("timestamp") or "",
                "issue": is_issue,
                "issue_peak": peak_issue,
                "issue_anytime": anytime_issue,
            }
        )

    return JSONResponse(
        {
            "updated_at": utc_now_iso(),
            "last_check": format_ts_ph(state.get("last_check_at")),
            "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
            "genieacs_error": (state.get("genieacs_error") or "").strip(),
            "peak": {
                "in_peak": bool(in_peak),
                "start": start_ph,
                "end": end_ph,
                "min_devices": min_devices,
                "total_kbps_from": kbps_from,
                "total_kbps_to": kbps_to,
                "enabled": bool(peak_enabled),
            },
            "anytime": {
                "enabled": bool(detect.get("anytime_enabled", False)),
                "no_usage_minutes": int(detect.get("anytime_no_usage_minutes", 120) or 120),
                "min_devices": int(detect.get("anytime_min_connected_devices", 2) or 2),
                "total_kbps_from": float(detect.get("anytime_total_kbps_from", 0) or 0),
                "total_kbps_to": float(detect.get("anytime_total_kbps_to", 8) or 8),
                "work_start": (detect.get("anytime_work_start_ph") or "00:00").strip(),
                "work_end": (detect.get("anytime_work_end_ph") or "23:59").strip(),
                "last_eval": format_ts_ph(state.get("anytime_eval_at")),
            },
            "counts": {"issues": len(issues), "stable": len(stable), "offline": len(offline_rows)},
            "rows": {"issues": issues, "stable": stable, "offline": offline_rows},
        }
    )


@app.get("/usage/series", response_class=JSONResponse)
async def usage_series(pppoe: str, router_id: str = "", hours: int = 24):
    pppoe = (pppoe or "").strip()
    router_id = (router_id or "").strip()
    if not pppoe:
        return JSONResponse({"hours": 0, "points": 0, "series": []}, status_code=400)
    hours = max(int(hours or 24), 1)
    hours = min(hours, 24 * 30)
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    rows = get_pppoe_usage_series_since(router_id, pppoe, since_iso)
    max_points = 1500
    if len(rows) > max_points:
        step = max(1, int(len(rows) / max_points))
        sampled = rows[::step]
        if rows and (not sampled or sampled[-1].get("timestamp") != rows[-1].get("timestamp")):
            sampled.append(rows[-1])
        rows = sampled
    series = []
    last_devices = None
    for item in rows:
        ts = item.get("timestamp")
        if not ts:
            continue
        devices = item.get("host_count")
        if devices is not None:
            try:
                last_devices = int(devices)
            except Exception:
                last_devices = last_devices
        devices_filled = last_devices
        series.append(
            {
                "ts": ts,
                "dl_bps": item.get("tx_bps"),
                "ul_bps": item.get("rx_bps"),
                "dl_total_bytes": item.get("bytes_out"),
                "ul_total_bytes": item.get("bytes_in"),
                "devices": devices_filled,
            }
        )
    # If we only started storing devices recently, backfill earlier points in this window
    # using the first known device count in the series.
    if series:
        first_known = None
        for p in series:
            if p.get("devices") is not None:
                first_known = p.get("devices")
                break
        if first_known is not None:
            for p in series:
                if p.get("devices") is None:
                    p["devices"] = first_known
    return JSONResponse({"hours": hours, "points": len(series), "series": series})


@app.get("/offline/summary")
async def offline_summary():
    state = get_state("offline_state", {})
    rows = state.get("rows") if isinstance(state.get("rows"), list) else []
    payload_rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        offline_since_ts = row.get("offline_since")
        payload_rows.append(
            {
                **row,
                "offline_since_ts": offline_since_ts,
                "offline_since": format_ts_ph(offline_since_ts) if offline_since_ts else "",
            }
        )
    return JSONResponse(
        {
            "updated_at": utc_now_iso(),
            "last_check": format_ts_ph(state.get("last_check_at")),
            "mode": (state.get("mode") or "").strip() or "secrets",
            "counts": {"offline": len(payload_rows)},
            "rows": payload_rows,
            "router_errors": state.get("router_errors") if isinstance(state.get("router_errors"), list) else [],
            "radius_error": (state.get("radius_error") or "").strip(),
            "min_offline_minutes": int(state.get("min_offline_minutes") or 0),
        }
    )


@app.get("/offline/history", response_class=JSONResponse)
async def offline_history(days: int = 30, limit: int = 500):
    days = max(min(int(days or 30), 3650), 1)
    limit = max(min(int(limit or 500), 2000), 1)
    since_iso = (datetime.utcnow() - timedelta(days=days)).replace(microsecond=0).isoformat() + "Z"
    rows = get_offline_history_since(since_iso, limit=limit)
    payload = []
    for row in rows:
        payload.append(
            {
                "pppoe": (row.get("pppoe") or "").strip(),
                "router_id": (row.get("router_id") or "").strip(),
                "router_name": (row.get("router_name") or row.get("router_id") or "").strip(),
                "mode": (row.get("mode") or "").strip(),
                "offline_started_at": row.get("offline_started_at"),
                "offline_ended_at": row.get("offline_ended_at"),
                "offline_started": format_ts_ph(row.get("offline_started_at")),
                "offline_ended": format_ts_ph(row.get("offline_ended_at")),
                "duration_seconds": row.get("duration_seconds"),
                "duration": _format_duration_short(row.get("duration_seconds")),
                "radius_status": (row.get("radius_status") or "").strip(),
                "disabled": bool(row.get("disabled")) if row.get("disabled") is not None else None,
                "profile": (row.get("profile") or "").strip(),
                "last_logged_out": (row.get("last_logged_out") or "").strip(),
            }
        )
    return JSONResponse({"days": days, "count": len(payload), "rows": payload})


@app.get("/offline/radius/accounts", response_class=JSONResponse)
async def offline_radius_accounts(limit: int = 5000):
    limit = max(min(int(limit or 5000), 50000), 1)
    settings = get_settings("offline", OFFLINE_DEFAULTS)
    radius_cfg = settings.get("radius") if isinstance(settings.get("radius"), dict) else {}
    try:
        from .notifiers import offline as offline_notifier

        rows = offline_notifier.fetch_radius_account_details(radius_cfg, limit=limit)
        return JSONResponse({"ok": True, "count": len(rows), "rows": rows})
    except Exception as exc:
        # Do not include secrets in error output.
        return JSONResponse({"ok": False, "error": str(exc), "count": 0, "rows": []}, status_code=400)


@app.get("/wan/stability")
async def wan_stability(days: int = 1, hours: int | None = None, live: bool = False):
    days = max(int(days or 1), 1)
    hours = int(hours) if hours is not None else None

    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    if live:
        since_dt = now_dt
    elif hours:
        since_dt = now_dt - timedelta(hours=max(int(hours), 1))
    else:
        since_dt = now_dt - timedelta(days=days)
    start_iso = since_dt.isoformat().replace("+00:00", "Z")
    end_iso = now_dt.isoformat().replace("+00:00", "Z")

    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_display_rows = []
    for row in wan_rows:
        if not row.get("enabled", True):
            continue
        mode = (row.get("mode") or "routed").lower()
        if not (row.get("local_ip") or "").strip():
            continue
        if mode == "bridged" and not (row.get("pppoe_router_id") or "").strip():
            continue
        wan_display_rows.append(row)

    wan_ids = [row.get("wan_id") for row in wan_display_rows if row.get("wan_id")]
    counts = {} if live else get_wan_status_counts(wan_ids, start_iso, end_iso)
    wan_state = get_state("wan_ping_state", {})
    payload = []
    for row in wan_display_rows:
        wan_id = row.get("wan_id")
        stats = counts.get(wan_id, {"up": 0, "down": 0, "total": 0})
        up_total = int(stats.get("up") or 0)
        down_total = int(stats.get("down") or 0)
        total = int(stats.get("total") or 0)

        current_status = (wan_state.get("wans", {}).get(wan_id, {}).get("status") or "").lower()
        if live:
            if current_status == "up":
                up_total, down_total, total = 1, 0, 1
            elif current_status == "down":
                up_total, down_total, total = 0, 1, 1
            else:
                up_total, down_total, total = 0, 0, 0
        elif total <= 0:
            if current_status == "up":
                up_total, down_total, total = 1, 0, 1
            elif current_status == "down":
                up_total, down_total, total = 0, 1, 1
            else:
                up_total, down_total, total = 0, 0, 0

        label_value = (row.get("identifier") or row.get("list_name") or "").strip()
        label_value = label_value or (row.get("core_label") or wan_id or "").strip()
        full_label = f"{row.get('core_label') or ''} {(row.get('identifier') or row.get('list_name') or '')}".strip()
        full_label = full_label or label_value
        payload.append(
            {
                "id": wan_id,
                "label": label_value,
                "full_label": full_label,
                "status": current_status or "n/a",
                "up": up_total,
                "down": down_total,
                "total": total,
            }
        )
    return JSONResponse({"live": bool(live), "days": days, "rows": payload})


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
        if netplan_msg and "no router source IPs configured" not in netplan_msg:
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
    db_url = (os.environ.get("THREEJ_DATABASE_URL") or "").strip().lower()
    if db_url.startswith("postgres://") or db_url.startswith("postgresql://"):
        return Response(
            content=b"Database export is not available in the UI when using Postgres. Use pg_dump instead.",
            media_type="text/plain",
            status_code=501,
        )
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
    db_url = (os.environ.get("THREEJ_DATABASE_URL") or "").strip().lower()
    if db_url.startswith("postgres://") or db_url.startswith("postgresql://"):
        message = "Database restore is not available in the UI when using Postgres. Use psql/pg_restore instead."
        settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
        interfaces = get_interface_options()
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(request, {"message": message, "settings": settings, "interfaces": interfaces}),
        )
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


OPTICAL_WINDOW_OPTIONS = WAN_STATUS_WINDOW_OPTIONS


def build_optical_status(
    settings,
    window_hours=24,
    limit=50,
    issues_page=1,
    stable_page=1,
    issues_sort="",
    issues_dir="",
    stable_sort="",
    stable_dir="",
    query="",
):
    window_hours = max(int(window_hours or 24), 1)
    limit = _parse_table_limit(limit, default=50)
    issues_page = _parse_table_page(issues_page, default=1)
    stable_page = _parse_table_page(stable_page, default=1)
    optical_cfg = settings.get("optical", {})
    classification = settings.get("classification", {})
    window_label = next((label for label, hours in OPTICAL_WINDOW_OPTIONS if hours == window_hours), "1D")
    issue_rx = float(classification.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]))
    issue_tx = float(classification.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]))
    priority_rx = float(optical_cfg.get("priority_rx_threshold_dbm", OPTICAL_DEFAULTS["optical"]["priority_rx_threshold_dbm"]))
    stable_rx = float(classification.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]))
    stable_tx = float(classification.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]))
    rx_realistic_min = float(classification.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]))
    rx_realistic_max = float(classification.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]))
    tx_realistic_min = float(classification.get("tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]))
    tx_realistic_max = float(classification.get("tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]))
    chart_min = float(classification.get("chart_min_dbm", OPTICAL_DEFAULTS["classification"]["chart_min_dbm"]))
    chart_max = float(classification.get("chart_max_dbm", OPTICAL_DEFAULTS["classification"]["chart_max_dbm"]))
    genie_base = (optical_cfg.get("genieacs_base_url") or settings.get("genieacs", {}).get("base_url") or "").rstrip("/")

    def genie_device_url(base_url, device_id):
        if not base_url or not device_id:
            return ""
        try:
            parsed = urllib.parse.urlparse(base_url)
            scheme = parsed.scheme or "http"
            host = parsed.hostname or parsed.netloc or ""
            device_path = f"/devices/{urllib.parse.quote(str(device_id))}"
            netloc = f"{host}:3000" if host else ""
            return urllib.parse.urlunparse((scheme, netloc, "/", "", "", f"/{device_path.lstrip('/')}"))
        except Exception:
            return ""

    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).replace(microsecond=0).isoformat() + "Z"
    latest_rows = get_optical_latest_results_since(since_iso)

    issue_candidates = []
    stable_candidates = []
    for last in latest_rows:
        dev_id = last.get("device_id")
        if not dev_id:
            continue
        rx_raw = last.get("rx")
        tx_raw = last.get("tx")
        rx_invalid = rx_raw is None or rx_raw < rx_realistic_min or rx_raw > rx_realistic_max
        tx_missing = tx_raw is None
        tx_invalid = False
        if tx_raw is not None:
            tx_invalid = tx_raw < tx_realistic_min or tx_raw > tx_realistic_max
        rx_reason = ""
        tx_reason = ""
        if rx_invalid:
            rx_reason = f"RX missing/unrealistic (raw={rx_raw})"
        if tx_missing:
            tx_reason = "TX missing"
        elif tx_invalid:
            tx_reason = f"TX missing/unrealistic (raw={tx_raw})"
        reasons = []
        status = "stable"

        if rx_invalid:
            status = "issue"
            reasons.append("Missing/Unrealistic RX")
        else:
            issue_hit = False
            if rx_raw is not None and rx_raw <= issue_rx:
                issue_hit = True
                reasons.append(f"RX <= {issue_rx:g}")
            if tx_raw is not None and not tx_invalid and tx_raw <= issue_tx:
                issue_hit = True
                reasons.append(f"TX <= {issue_tx:g}")
            if rx_raw is not None and rx_raw <= priority_rx:
                issue_hit = True
                reasons.append(f"Priority RX <= {priority_rx:g}")

            if issue_hit:
                status = "issue"
            else:
                is_stable = rx_raw is not None and rx_raw >= stable_rx and (
                    tx_raw is None or tx_invalid or tx_raw >= stable_tx
                )
                if is_stable:
                    status = "stable"
                else:
                    status = "monitor"
                    if rx_raw is not None and rx_raw < stable_rx:
                        reasons.append(f"RX below stable {stable_rx:g}")
                    if tx_raw is not None and not tx_invalid and tx_raw < stable_tx:
                        reasons.append(f"TX below stable {stable_tx:g}")

        entry = {
            "device_id": dev_id,
            "name": last.get("pppoe") or dev_id,
            "ip": last.get("ip") or "",
            "last_ts": (last.get("timestamp") or "").strip(),
            "status": status,
            "rx": rx_raw,
            "tx": tx_raw,
            "rx_raw": rx_raw,
            "tx_raw": tx_raw,
            "rx_invalid": rx_invalid,
            "tx_invalid": tx_invalid,
            "tx_missing": tx_missing,
            "rx_reason": rx_reason,
            "tx_reason": tx_reason,
            "samples": 0,
            "last_check": format_ts_ph(last.get("timestamp")),
            # sparklines are computed after pagination to keep rendering fast
            "spark_points_window": "",
            "spark_points_window_large": "",
            "reasons": reasons or ([] if status == "stable" else ["Monitor"]),
            "device_url": genie_device_url(genie_base, dev_id),
        }
        if status == "issue":
            issue_candidates.append(entry)
        else:
            stable_candidates.append(entry)

    q = (query or "").strip().lower()
    if q:
        def matches(entry):
            hay = " ".join(
                [
                    str(entry.get("name") or ""),
                    str(entry.get("ip") or ""),
                    str(entry.get("device_id") or ""),
                    " ".join(entry.get("reasons") or []),
                ]
            ).lower()
            return q in hay

        issue_candidates = [row for row in issue_candidates if matches(row)]
        stable_candidates = [row for row in stable_candidates if matches(row)]

    def _sort_numeric(val, desc=False):
        if val is None:
            return (1, 0.0)
        try:
            num = float(val)
        except Exception:
            return (1, 0.0)
        return (0, -num if desc else num)

    def _sort_text(val, desc=False):
        text = (val or "").strip().lower()
        return (0, "".join(reversed(text)) if desc else text)

    def _sort_key_for(entry, key, desc=False):
        if key in ("customer", "name"):
            return _sort_text(entry.get("name"), desc=desc)
        if key in ("ip", "ipv4"):
            return _sort_text(entry.get("ip"), desc=desc)
        if key == "status":
            order = {"issue": 0, "monitor": 1, "stable": 2}
            return (0, -order.get(entry.get("status"), 9) if desc else order.get(entry.get("status"), 9))
        if key == "rx":
            return _sort_numeric(entry.get("rx"), desc=desc)
        if key == "tx":
            return _sort_numeric(entry.get("tx"), desc=desc)
        if key == "samples":
            return _sort_numeric(entry.get("samples"), desc=desc)
        if key in ("last_check_at", "last_ts"):
            return _sort_text(entry.get("last_ts"), desc=desc)
        if key == "reason":
            return _sort_text(", ".join(entry.get("reasons") or []), desc=desc)
        return _sort_text(entry.get("name"), desc=desc)

    issues_sort = (issues_sort or "").strip()
    stable_sort = (stable_sort or "").strip()
    issues_desc = (issues_dir or "").lower() != "asc"
    stable_desc = (stable_dir or "").lower() != "asc"

    # default by name
    issue_candidates = sorted(issue_candidates, key=lambda x: (x.get("name") or "").lower())
    stable_candidates = sorted(stable_candidates, key=lambda x: (x.get("name") or "").lower())

    if issues_sort == "samples" or stable_sort == "samples":
        all_ids = sorted({e.get("device_id") for e in (issue_candidates + stable_candidates) if e.get("device_id")})
        samples_map_all = get_optical_samples_for_devices_since(all_ids, since_iso) if all_ids else {}
        for entry in issue_candidates:
            dev = entry.get("device_id")
            entry["samples"] = int(samples_map_all.get(dev, 0) or 0)
        for entry in stable_candidates:
            dev = entry.get("device_id")
            entry["samples"] = int(samples_map_all.get(dev, 0) or 0)
    else:
        samples_map_all = {}

    if issues_sort:
        issue_candidates = sorted(issue_candidates, key=lambda row: _sort_key_for(row, issues_sort, desc=issues_desc))
    if stable_sort:
        stable_candidates = sorted(stable_candidates, key=lambda row: _sort_key_for(row, stable_sort, desc=stable_desc))

    paged_issue, issue_page_meta = _paginate_items(issue_candidates, issues_page, limit)
    paged_stable, stable_page_meta = _paginate_items(stable_candidates, stable_page, limit)

    page_device_ids = sorted({row.get("device_id") for row in (paged_issue + paged_stable) if row.get("device_id")})
    samples_map = (
        {dev: int(samples_map_all.get(dev, 0) or 0) for dev in page_device_ids}
        if samples_map_all
        else (get_optical_samples_for_devices_since(page_device_ids, since_iso) if page_device_ids else {})
    )
    rx_series_map = get_optical_rx_series_for_devices_since(page_device_ids, since_iso) if page_device_ids else {}

    def with_spark(entry):
        dev = entry.get("device_id")
        values = rx_series_map.get(dev, [])
        points = _sparkline_points_fixed(values or [0], chart_min, chart_max, width=120, height=30)
        points_large = _sparkline_points_fixed(values or [0], chart_min, chart_max, width=640, height=200)
        next_entry = dict(entry)
        next_entry["samples"] = int(samples_map.get(dev, 0) or 0)
        next_entry["spark_points_window"] = points
        next_entry["spark_points_window_large"] = points_large
        return next_entry

    issue_rows = [with_spark(entry) for entry in paged_issue]
    stable_rows = [with_spark(entry) for entry in paged_stable]
    return {
        "total": len(issue_candidates) + len(stable_candidates),
        "issue_total": len(issue_candidates),
        "stable_total": len(stable_candidates),
        "issue_rows": issue_rows,
        "stable_rows": stable_rows,
        "window_hours": window_hours,
        "window_label": window_label,
        "pagination": {
            "limit": limit,
            "limit_label": "ALL" if not limit else str(limit),
            "options": TABLE_PAGE_SIZE_OPTIONS,
            "issues": issue_page_meta,
            "stable": stable_page_meta,
        },
        "sort": {
            "issues": {"key": issues_sort, "dir": "desc" if issues_desc else "asc"},
            "stable": {"key": stable_sort, "dir": "desc" if stable_desc else "asc"},
        },
        "query": query or "",
        "rules": {
            "issue_rx_dbm": issue_rx,
            "issue_tx_dbm": issue_tx,
            "priority_rx_dbm": priority_rx,
            "stable_rx_dbm": stable_rx,
            "stable_tx_dbm": stable_tx,
        },
        "chart": {"min_dbm": chart_min, "max_dbm": chart_max},
    }


@app.get("/settings/optical", response_class=HTMLResponse)
async def optical_settings(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    limit = _parse_table_limit(request.query_params.get("limit"), default=50)
    issues_page = _parse_table_page(request.query_params.get("issues_page"), default=1)
    stable_page = _parse_table_page(request.query_params.get("stable_page"), default=1)
    issues_sort = (request.query_params.get("issues_sort") or "").strip()
    issues_dir = (request.query_params.get("issues_dir") or "").strip().lower()
    stable_sort = (request.query_params.get("stable_sort") or "").strip()
    stable_dir = (request.query_params.get("stable_dir") or "").strip().lower()
    query = (request.query_params.get("q") or "").strip()
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    optical_status = build_optical_status(
        settings,
        window_hours,
        limit,
        issues_page,
        stable_page,
        issues_sort=issues_sort,
        issues_dir=issues_dir,
        stable_sort=stable_sort,
        stable_dir=stable_dir,
        query=query,
    )
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "",
                "optical_status": optical_status,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "status",
                "settings_tab": "general",
            },
        ),
    )


@app.post("/settings/optical", response_class=HTMLResponse)
async def optical_settings_save(request: Request):
    form = await request.form()
    action = (form.get("action") or "").strip()
    settings_tab = form.get("settings_tab") or "general"
    settings = get_settings("optical", OPTICAL_DEFAULTS)

    genieacs = settings.get("genieacs") if isinstance(settings.get("genieacs"), dict) else {}
    settings["genieacs"] = genieacs

    telegram = settings.get("telegram") if isinstance(settings.get("telegram"), dict) else {}
    settings["telegram"] = telegram

    optical = settings.get("optical") if isinstance(settings.get("optical"), dict) else {}
    settings["optical"] = optical

    general = settings.get("general") if isinstance(settings.get("general"), dict) else {}
    settings["general"] = general

    storage = settings.get("storage") if isinstance(settings.get("storage"), dict) else {}
    settings["storage"] = storage

    classification = (
        settings.get("classification") if isinstance(settings.get("classification"), dict) else {}
    )
    settings["classification"] = classification

    if action != "test_genieacs":
        if settings_tab == "general":
            settings["enabled"] = parse_bool(form, "enabled")
            general["check_interval_minutes"] = parse_int(
                form, "check_interval_minutes", general.get("check_interval_minutes", 60)
            )

        elif settings_tab == "data":
            genieacs["base_url"] = form.get("genieacs_base_url", genieacs.get("base_url", ""))
            genieacs["username"] = form.get("genieacs_username", genieacs.get("username", ""))
            genieacs["password"] = form.get("genieacs_password", genieacs.get("password", ""))
            genieacs["page_size"] = parse_int(
                form, "genieacs_page_size", genieacs.get("page_size", 100)
            )

            optical["rx_paths"] = parse_lines(form.get("rx_paths", ""))
            optical["tx_paths"] = parse_lines(form.get("tx_paths", ""))
            optical["pppoe_paths"] = parse_lines(form.get("pppoe_paths", ""))
            optical["ip_paths"] = parse_lines(form.get("ip_paths", ""))

        elif settings_tab == "notifications":
            telegram["bot_token"] = form.get("telegram_bot_token", telegram.get("bot_token", ""))
            telegram["chat_id"] = form.get("telegram_chat_id", telegram.get("chat_id", ""))

            general["message_title"] = form.get(
                "message_title", general.get("message_title", "Optical Power Alert")
            )
            general["include_header"] = parse_bool(form, "include_header")
            general["max_chars"] = parse_int(form, "max_chars", general.get("max_chars", 3800))
            general["schedule_time_ph"] = form.get(
                "schedule_time_ph", general.get("schedule_time_ph", "07:00")
            )

        elif settings_tab == "thresholds":
            optical["rx_threshold_dbm"] = parse_float(
                form, "rx_threshold_dbm", optical.get("rx_threshold_dbm", -26.0)
            )
            optical["tx_low_threshold_dbm"] = parse_float(
                form, "tx_low_threshold_dbm", optical.get("tx_low_threshold_dbm", -1.0)
            )
            optical["priority_rx_threshold_dbm"] = parse_float(
                form,
                "priority_rx_threshold_dbm",
                optical.get("priority_rx_threshold_dbm", -29.0),
            )

        elif settings_tab == "classification":
            classification["issue_rx_dbm"] = parse_float(
                form, "optical_issue_rx_dbm", classification.get("issue_rx_dbm", -27.0)
            )
            classification["issue_tx_dbm"] = parse_float(
                form, "optical_issue_tx_dbm", classification.get("issue_tx_dbm", -2.0)
            )
            classification["stable_rx_dbm"] = parse_float(
                form, "optical_stable_rx_dbm", classification.get("stable_rx_dbm", -24.0)
            )
            classification["stable_tx_dbm"] = parse_float(
                form, "optical_stable_tx_dbm", classification.get("stable_tx_dbm", -1.0)
            )
            classification["chart_min_dbm"] = parse_float(
                form, "optical_chart_min_dbm", classification.get("chart_min_dbm", -35.0)
            )
            classification["chart_max_dbm"] = parse_float(
                form, "optical_chart_max_dbm", classification.get("chart_max_dbm", -10.0)
            )

        elif settings_tab == "storage":
            storage["raw_retention_days"] = parse_int(
                form, "optical_raw_retention_days", storage.get("raw_retention_days", 365)
            )

    if action == "test_genieacs":
        settings_tab = "data"
        genieacs["base_url"] = form.get("genieacs_base_url", genieacs.get("base_url", ""))
        genieacs["username"] = form.get("genieacs_username", genieacs.get("username", ""))
        genieacs["password"] = form.get("genieacs_password", genieacs.get("password", ""))
        genieacs["page_size"] = parse_int(form, "genieacs_page_size", genieacs.get("page_size", 100))

        optical["rx_paths"] = parse_lines(form.get("rx_paths", ""))
        optical["tx_paths"] = parse_lines(form.get("tx_paths", ""))
        optical["pppoe_paths"] = parse_lines(form.get("pppoe_paths", ""))
        optical["ip_paths"] = parse_lines(form.get("ip_paths", ""))

        message = ""
        try:
            base_url = (genieacs.get("base_url") or "").rstrip("/")
            if not base_url:
                raise ValueError("GenieACS Base URL is required.")
            username = genieacs.get("username") or ""
            password = genieacs.get("password") or ""
            headers = {}
            if username or password:
                token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {token}"

            params = {"query": "{}", "limit": "1", "skip": "0"}
            url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            count = len(payload) if isinstance(payload, list) else 0
            message = f"GenieACS API OK. Retrieved {count} device(s)."
        except Exception as exc:
            message = f"GenieACS test failed: {exc}"

        window_hours = 24
        optical_status = build_optical_status(settings, window_hours)
        job_status = {item["job_name"]: dict(item) for item in get_job_status()}
        optical_job = job_status.get("optical", {})
        optical_job = {
            "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
            "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
        }
        return templates.TemplateResponse(
            "settings_optical.html",
            make_context(
                request,
                {
                    "settings": settings,
                    "message": message,
                    "optical_status": optical_status,
                    "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                    "optical_job": optical_job,
                    "active_tab": "settings",
                    "settings_tab": settings_tab,
                },
            ),
        )

    save_settings("optical", settings)
    window_hours = 24
    optical_status = build_optical_status(settings, window_hours)
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "Saved.",
                "optical_status": optical_status,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "settings",
                "settings_tab": settings_tab or "general",
            },
        ),
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
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": build_optical_status(settings, 24),
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": {
                    "last_run_at_ph": None,
                    "last_success_at_ph": None,
                },
                "active_tab": "settings",
                "settings_tab": "general",
            },
        ),
    )


@app.post("/settings/optical/test_genieacs", response_class=HTMLResponse)
async def optical_settings_test_genieacs(request: Request):
    form = await request.form()
    settings = get_settings("optical", OPTICAL_DEFAULTS)

    genieacs = settings.get("genieacs") if isinstance(settings.get("genieacs"), dict) else {}
    genieacs["base_url"] = form.get("genieacs_base_url", genieacs.get("base_url", ""))
    genieacs["username"] = form.get("genieacs_username", genieacs.get("username", ""))
    genieacs["password"] = form.get("genieacs_password", genieacs.get("password", ""))
    genieacs["page_size"] = parse_int(form, "genieacs_page_size", genieacs.get("page_size", 100))
    settings["genieacs"] = genieacs

    optical = settings.get("optical") if isinstance(settings.get("optical"), dict) else {}
    optical["rx_paths"] = parse_lines(form.get("rx_paths", ""))
    optical["tx_paths"] = parse_lines(form.get("tx_paths", ""))
    optical["pppoe_paths"] = parse_lines(form.get("pppoe_paths", ""))
    optical["ip_paths"] = parse_lines(form.get("ip_paths", ""))
    settings["optical"] = optical

    message = ""
    try:
        base_url = (genieacs.get("base_url") or "").rstrip("/")
        if not base_url:
            raise ValueError("GenieACS Base URL is required.")
        username = genieacs.get("username") or ""
        password = genieacs.get("password") or ""
        headers = {}
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        params = {"query": "{}", "limit": "1", "skip": "0"}
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        count = len(payload) if isinstance(payload, list) else 0
        message = f"GenieACS API OK. Retrieved {count} device(s)."
    except Exception as exc:
        message = f"GenieACS test failed: {exc}"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": build_optical_status(settings, 24),
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "settings",
                "settings_tab": "data",
            },
        ),
    )


@app.get("/settings/optical/test_genieacs", response_class=HTMLResponse)
async def optical_settings_test_genieacs_get(request: Request):
    settings = get_settings("optical", OPTICAL_DEFAULTS)
    message = ""
    started = time.monotonic()
    try:
        genieacs = settings.get("genieacs", {}) if isinstance(settings.get("genieacs"), dict) else {}
        base_url = (genieacs.get("base_url") or "").rstrip("/")
        if not base_url:
            raise ValueError("GenieACS Base URL is required.")
        username = genieacs.get("username") or ""
        password = genieacs.get("password") or ""
        headers = {}
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        params = {"query": "{}", "limit": "1", "skip": "0"}
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        count = len(payload) if isinstance(payload, list) else 0
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS API OK ({elapsed_ms} ms). Retrieved {count} device(s)."
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS test failed ({elapsed_ms} ms): {exc}"

    window_hours = _normalize_wan_window(request.query_params.get("window"))
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    optical_job = job_status.get("optical", {})
    optical_job = {
        "last_run_at_ph": format_ts_ph(optical_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(optical_job.get("last_success_at")),
    }
    return templates.TemplateResponse(
        "settings_optical.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": build_optical_status(settings, window_hours),
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": optical_job,
                "active_tab": "settings",
                "settings_tab": "data",
            },
        ),
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
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "optical_status": build_optical_status(settings, 24),
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "optical_job": {
                    "last_run_at_ph": None,
                    "last_success_at_ph": None,
                },
                "active_tab": "settings",
                "settings_tab": "general",
            },
        ),
    )


@app.get("/optical/series", response_class=JSONResponse)
async def optical_series(device_id: str, window: int = 24):
    if not (device_id or "").strip():
        return JSONResponse({"hours": 0, "series": []}, status_code=400)
    hours = _normalize_wan_window(window)
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    rows = get_optical_results_for_device_since(device_id, since_iso)
    series = [{"ts": row.get("timestamp"), "rx": row.get("rx"), "tx": row.get("tx")} for row in rows]
    return JSONResponse({"hours": hours, "series": series})


@app.get("/settings/usage", response_class=HTMLResponse)
async def usage_settings(request: Request):
    settings = get_settings("usage", USAGE_DEFAULTS)
    active_tab = (request.query_params.get("tab") or "status").strip().lower()
    if active_tab not in ("status", "settings"):
        active_tab = "status"
    settings_tab = (request.query_params.get("settings_tab") or "general").strip().lower()
    if settings_tab not in ("general", "routers", "data", "detection", "storage", "danger"):
        settings_tab = "general"
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "",
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "usage_job": usage_job,
                "wan_settings": wan_settings,
                "usage_router_state": router_state_map,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
            },
        ),
    )


@app.post("/settings/usage", response_class=HTMLResponse)
async def usage_settings_save(request: Request):
    form = await request.form()
    settings_tab = (form.get("settings_tab") or "general").strip() or "general"
    settings = get_settings("usage", USAGE_DEFAULTS)

    settings["mikrotik"] = settings.get("mikrotik") if isinstance(settings.get("mikrotik"), dict) else {}
    settings["genieacs"] = settings.get("genieacs") if isinstance(settings.get("genieacs"), dict) else {}
    settings["source"] = settings.get("source") if isinstance(settings.get("source"), dict) else {}
    settings["device"] = settings.get("device") if isinstance(settings.get("device"), dict) else {}
    settings["detection"] = settings.get("detection") if isinstance(settings.get("detection"), dict) else {}
    settings["storage"] = settings.get("storage") if isinstance(settings.get("storage"), dict) else {}
    settings["mikrotik"]["router_enabled"] = (
        settings["mikrotik"].get("router_enabled")
        if isinstance(settings["mikrotik"].get("router_enabled"), dict)
        else {}
    )

    message = ""
    try:
        if settings_tab == "general":
            settings["enabled"] = parse_bool(form, "enabled")
            settings["mikrotik"]["poll_interval_seconds"] = parse_int(
                form,
                "poll_interval_seconds",
                int(settings["mikrotik"].get("poll_interval_seconds", USAGE_DEFAULTS["mikrotik"]["poll_interval_seconds"])),
            )
            settings["mikrotik"]["secrets_refresh_minutes"] = parse_int(
                form,
                "secrets_refresh_minutes",
                int(
                    settings["mikrotik"].get(
                        "secrets_refresh_minutes", USAGE_DEFAULTS["mikrotik"]["secrets_refresh_minutes"]
                    )
                ),
            )
            settings["mikrotik"]["timeout_seconds"] = parse_int(
                form,
                "timeout_seconds",
                int(settings["mikrotik"].get("timeout_seconds", USAGE_DEFAULTS["mikrotik"]["timeout_seconds"])),
            )
            settings["storage"]["sample_interval_seconds"] = parse_int(
                form,
                "sample_interval_seconds",
                int(settings["storage"].get("sample_interval_seconds", USAGE_DEFAULTS["storage"]["sample_interval_seconds"])),
            )
            message = "Usage settings saved."
        elif settings_tab == "routers":
            wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
            system_routers = wan_settings.get("pppoe_routers") if isinstance(wan_settings.get("pppoe_routers"), list) else []
            count = parse_int(form, "router_count", len(system_routers))
            enabled_map = {}
            for idx in range(count):
                router_id = (form.get(f"router_{idx}_id") or "").strip()
                if not router_id:
                    continue
                enabled_map[router_id] = parse_bool(form, f"router_{idx}_enabled")
            settings["mikrotik"]["router_enabled"] = enabled_map
            message = "Usage router selection saved."
        elif settings_tab == "data":
            settings["genieacs"]["base_url"] = (form.get("genieacs_base_url") or "").strip()
            settings["genieacs"]["username"] = (form.get("genieacs_username") or "").strip()
            settings["genieacs"]["password"] = (form.get("genieacs_password") or "").strip()
            settings["genieacs"]["page_size"] = parse_int(form, "genieacs_page_size", int(settings["genieacs"].get("page_size", 100) or 100))

            settings["source"]["refresh_minutes"] = parse_int(
                form,
                "genieacs_refresh_minutes",
                int(settings["source"].get("refresh_minutes", USAGE_DEFAULTS["source"]["refresh_minutes"])),
            )

            settings["device"]["pppoe_paths"] = parse_lines(form.get("pppoe_paths") or "")
            settings["device"]["host_count_paths"] = parse_lines(form.get("host_count_paths") or "")
            settings["device"]["host_name_paths"] = parse_lines(form.get("host_name_paths") or "")
            settings["device"]["host_ip_paths"] = parse_lines(form.get("host_ip_paths") or "")
            settings["device"]["host_active_paths"] = parse_lines(form.get("host_active_paths") or "")
            message = "Data Source settings saved."
        elif settings_tab == "detection":
            settings["detection"]["peak_start_ph"] = (form.get("peak_start_ph") or "").strip() or "17:30"
            settings["detection"]["peak_end_ph"] = (form.get("peak_end_ph") or "").strip() or "21:00"
            settings["detection"]["peak_enabled"] = parse_bool(form, "peak_enabled")
            settings["detection"]["min_connected_devices"] = parse_int(
                form,
                "min_connected_devices",
                int(settings["detection"].get("min_connected_devices", USAGE_DEFAULTS["detection"]["min_connected_devices"])),
            )
            default_to = settings["detection"].get("total_kbps_to")
            if default_to is None:
                default_to = settings["detection"].get("min_total_kbps", USAGE_DEFAULTS["detection"]["min_total_kbps"])
            settings["detection"]["total_kbps_from"] = parse_int(
                form,
                "total_kbps_from",
                int(settings["detection"].get("total_kbps_from", USAGE_DEFAULTS["detection"]["total_kbps_from"])),
            )
            settings["detection"]["total_kbps_to"] = parse_int(
                form,
                "total_kbps_to",
                int(default_to),
            )
            # Back-compat: keep the old single threshold in sync with the range upper bound.
            settings["detection"]["min_total_kbps"] = int(settings["detection"]["total_kbps_to"])

            settings["detection"]["anytime_enabled"] = parse_bool(form, "anytime_enabled")
            settings["detection"]["anytime_work_start_ph"] = (form.get("anytime_work_start_ph") or "").strip() or "00:00"
            settings["detection"]["anytime_work_end_ph"] = (form.get("anytime_work_end_ph") or "").strip() or "23:59"
            settings["detection"]["anytime_no_usage_minutes"] = parse_int(
                form,
                "anytime_no_usage_minutes",
                int(
                    settings["detection"].get(
                        "anytime_no_usage_minutes", USAGE_DEFAULTS["detection"]["anytime_no_usage_minutes"]
                    )
                ),
            )
            settings["detection"]["anytime_min_connected_devices"] = parse_int(
                form,
                "anytime_min_connected_devices",
                int(
                    settings["detection"].get(
                        "anytime_min_connected_devices", USAGE_DEFAULTS["detection"]["anytime_min_connected_devices"]
                    )
                ),
            )
            settings["detection"]["anytime_total_kbps_from"] = parse_int(
                form,
                "anytime_total_kbps_from",
                int(
                    settings["detection"].get(
                        "anytime_total_kbps_from", USAGE_DEFAULTS["detection"]["anytime_total_kbps_from"]
                    )
                ),
            )
            settings["detection"]["anytime_total_kbps_to"] = parse_int(
                form,
                "anytime_total_kbps_to",
                int(
                    settings["detection"].get(
                        "anytime_total_kbps_to", USAGE_DEFAULTS["detection"]["anytime_total_kbps_to"]
                    )
                ),
            )
            message = "Detection settings saved."
        elif settings_tab == "storage":
            settings["storage"]["raw_retention_days"] = parse_int(
                form,
                "raw_retention_days",
                int(settings["storage"].get("raw_retention_days", USAGE_DEFAULTS["storage"]["raw_retention_days"])),
            )
            settings["storage"]["sample_interval_seconds"] = parse_int(
                form,
                "sample_interval_seconds",
                int(settings["storage"].get("sample_interval_seconds", USAGE_DEFAULTS["storage"]["sample_interval_seconds"])),
            )
            message = "Storage settings saved."
        else:
            message = "Settings saved."

        save_settings("usage", settings)
    except Exception as exc:
        message = f"Save failed: {exc}"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": settings_tab,
                "usage_job": usage_job,
                "wan_settings": wan_settings,
                "usage_router_state": router_state_map,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
            },
        ),
    )


@app.post("/settings/usage/test_genieacs", response_class=HTMLResponse)
async def usage_test_genieacs(request: Request):
    settings = get_settings("usage", USAGE_DEFAULTS)
    message = ""
    started = time.monotonic()
    try:
        base_url = (settings.get("genieacs", {}) or {}).get("base_url", "").strip().rstrip("/")
        if not base_url:
            raise ValueError("GenieACS Base URL is required.")
        username = (settings.get("genieacs", {}) or {}).get("username") or ""
        password = (settings.get("genieacs", {}) or {}).get("password") or ""
        headers = {}
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        params = {"query": "{}", "limit": "1", "skip": "0"}
        url = f"{base_url}/devices?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        count = len(payload) if isinstance(payload, list) else 0
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS API OK ({elapsed_ms} ms). Retrieved {count} device(s)."
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        message = f"GenieACS test failed ({elapsed_ms} ms): {exc}"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": "data",
                "usage_job": usage_job,
                "wan_settings": wan_settings,
                "usage_router_state": router_state_map,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
            },
        ),
    )


@app.post("/settings/usage/routers", response_class=HTMLResponse)
async def usage_save_routers(request: Request):
    # Routers were moved from Usage settings to System Settings → Routers → Mikrotik Routers.
    form = await request.form()
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    existing = wan_settings_data.get("pppoe_routers", [])
    count = parse_int(form, "router_count", len(existing))
    routers, removed_ids = _parse_wan_pppoe_routers_from_form(form, count)
    wan_settings_data["pppoe_routers"] = routers
    if removed_ids:
        for wan in wan_settings_data.get("wans", []):
            if wan.get("pppoe_router_id") in removed_ids:
                wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(
        request,
        "Mikrotik routers saved.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/usage/routers/add", response_class=HTMLResponse)
async def usage_add_router(request: Request):
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
    return RedirectResponse(url="/settings/system?tab=routers&routers_tab=mikrotik-routers#sys-routers-mikrotik", status_code=302)


@app.post("/settings/usage/routers/test/{router_id}", response_class=HTMLResponse)
async def usage_test_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router = next((item for item in wan_settings_data.get("pppoe_routers", []) if item.get("id") == router_id), None)
    if not router:
        return render_system_settings_response(
            request,
            "Router not found.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    if router.get("use_tls"):
        return render_system_settings_response(
            request,
            "TLS test not supported yet. Disable TLS or use port 8728.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    host = (router.get("host") or "").strip()
    if not host:
        return render_system_settings_response(
            request,
            "Router host is required.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    client = RouterOSClient(
        host,
        int(router.get("port", 8728) or 8728),
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
    return render_system_settings_response(
        request,
        message,
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/usage/format", response_class=HTMLResponse)
async def usage_format(request: Request):
    form = await request.form()
    settings = get_settings("usage", USAGE_DEFAULTS)
    message = ""
    if not parse_bool(form, "confirm_format"):
        message = "Please confirm format to proceed."
    else:
        try:
            clear_pppoe_usage_samples()
            message = "Usage database formatted."
        except Exception as exc:
            message = f"Format failed: {exc}"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router_state_rows = state.get("routers") if isinstance(state.get("routers"), list) else []
    router_state_map = {
        (row.get("router_id") or "").strip(): row for row in router_state_rows if isinstance(row, dict)
    }
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": "danger",
                "usage_job": usage_job,
                "wan_settings": wan_settings,
                "usage_router_state": router_state_map,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
            },
        ),
    )


@app.get("/settings/offline", response_class=HTMLResponse)
async def offline_settings(request: Request):
    settings = get_settings("offline", OFFLINE_DEFAULTS)
    active_tab = (request.query_params.get("tab") or "status").strip().lower()
    if active_tab not in ("status", "settings"):
        active_tab = "status"
    settings_tab = (request.query_params.get("settings_tab") or "general").strip().lower()
    if settings_tab not in ("general", "routers", "radius"):
        settings_tab = "general"
    radius_tab = (request.query_params.get("radius_tab") or "settings").strip().lower()
    if radius_tab not in ("settings", "accounts"):
        radius_tab = "settings"

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    offline_job = job_status.get("offline", {})
    offline_job = {
        "last_run_at_ph": format_ts_ph(offline_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(offline_job.get("last_success_at")),
        "last_error": (offline_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(offline_job.get("last_error_at")),
    }

    state = get_state("offline_state", {})
    offline_state = {
        "last_check": format_ts_ph(state.get("last_check_at")),
        "router_errors": state.get("router_errors") if isinstance(state.get("router_errors"), list) else [],
        "radius_error": (state.get("radius_error") or "").strip(),
    }
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    return templates.TemplateResponse(
        "settings_offline.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "",
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "radius_tab": radius_tab,
                "offline_job": offline_job,
                "offline_state": offline_state,
                "wan_settings": wan_settings,
            },
        ),
    )


@app.post("/settings/offline", response_class=HTMLResponse)
async def offline_settings_save(request: Request):
    form = await request.form()
    settings_tab = (form.get("settings_tab") or "general").strip() or "general"
    radius_tab = (form.get("radius_tab") or "settings").strip().lower()
    if radius_tab not in ("settings", "accounts"):
        radius_tab = "settings"
    settings = get_settings("offline", OFFLINE_DEFAULTS)

    settings["general"] = settings.get("general") if isinstance(settings.get("general"), dict) else {}
    settings["radius"] = settings.get("radius") if isinstance(settings.get("radius"), dict) else {}
    settings["radius"]["ssh"] = (
        settings["radius"].get("ssh") if isinstance(settings["radius"].get("ssh"), dict) else {}
    )

    try:
        if settings_tab == "general":
            settings["enabled"] = parse_bool(form, "enabled")
            mode = (form.get("mode") or settings.get("mode") or "secrets").strip().lower()
            if mode not in ("secrets", "radius"):
                mode = "secrets"
            settings["mode"] = mode
            settings["general"]["poll_interval_seconds"] = parse_int(
                form,
                "poll_interval_seconds",
                int(settings["general"].get("poll_interval_seconds", OFFLINE_DEFAULTS["general"]["poll_interval_seconds"])),
            )
            min_val = parse_int(form, "min_offline_value", int(settings["general"].get("min_offline_value", 1) or 1))
            if min_val is None:
                min_val = int(settings["general"].get("min_offline_value", 1) or 1)
            min_val = max(int(min_val or 0), 0)
            min_unit = (form.get("min_offline_unit") or settings["general"].get("min_offline_unit") or "day").strip().lower()
            if min_unit not in ("hour", "day"):
                min_unit = "day"
            settings["general"]["min_offline_value"] = min_val
            settings["general"]["min_offline_unit"] = min_unit
            settings["general"]["history_retention_days"] = parse_int(
                form,
                "history_retention_days",
                int(settings["general"].get("history_retention_days", OFFLINE_DEFAULTS["general"]["history_retention_days"])),
            )
        elif settings_tab == "routers":
            pass
        elif settings_tab == "radius":
            settings["radius"]["enabled"] = parse_bool(form, "radius_enabled")
            ssh = settings["radius"]["ssh"]
            ssh["host"] = (form.get("radius_host") or "").strip()
            ssh["port"] = parse_int(form, "radius_port", int(ssh.get("port", 22) or 22))
            ssh["user"] = (form.get("radius_user") or "").strip()
            ssh["password"] = (form.get("radius_password") or "").strip()
            ssh["use_key"] = parse_bool(form, "radius_use_key")
            ssh["key_path"] = (form.get("radius_key_path") or "").strip()
            settings["radius"]["list_command"] = (form.get("radius_list_command") or "").strip()
        else:
            pass
        save_settings("offline", settings)
    except Exception:
        # avoid leaking secrets in messages; just fall through to redirect.
        save_settings("offline", settings)

    return RedirectResponse(
        url=f"/settings/offline?tab=settings&settings_tab={settings_tab}"
        + (f"&radius_tab={radius_tab}" if settings_tab == "radius" else "")
        + f"#offline-{settings_tab}",
        status_code=302,
    )


@app.post("/settings/offline/test-radius", response_class=HTMLResponse)
async def offline_test_radius(request: Request):
    settings = get_settings("offline", OFFLINE_DEFAULTS)
    message = ""
    try:
        from .notifiers import offline as offline_notifier

        accounts = offline_notifier.fetch_radius_accounts(settings.get("radius") or {})
        message = f"Radius OK: {len(accounts)} accounts returned."
    except Exception as exc:
        message = f"Radius test failed: {exc}"
    wan_settings = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    state = get_state("offline_state", {})
    offline_state = {
        "last_check": format_ts_ph(state.get("last_check_at")),
        "router_errors": state.get("router_errors") if isinstance(state.get("router_errors"), list) else [],
        "radius_error": (state.get("radius_error") or "").strip(),
    }
    return templates.TemplateResponse(
        "settings_offline.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": "radius",
                "radius_tab": "settings",
                "offline_job": {"last_run_at_ph": "n/a", "last_success_at_ph": "n/a", "last_error": "", "last_error_at_ph": ""},
                "offline_state": offline_state,
                "wan_settings": wan_settings,
            },
        ),
    )


@app.get("/profile-review/suggest", response_class=JSONResponse)
async def profile_review_suggest(q: str = "", limit: int = 12):
    query = (q or "").strip()
    limit = max(min(int(limit or 12), 25), 1)
    if len(query) < 2:
        since_iso = (datetime.utcnow() - timedelta(hours=24)).replace(microsecond=0).isoformat() + "Z"
        optical_settings = get_settings("optical", OPTICAL_DEFAULTS)
        accounts_ping_settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
        ping_state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
        devices = ping_state.get("devices") if isinstance(ping_state.get("devices"), list) else []
        state_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}

        cls = accounts_ping_settings.get("classification", {}) or {}
        issue_loss_pct = float(cls.get("issue_loss_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_loss_pct"]) or 20.0)
        issue_latency_ms = float(cls.get("issue_latency_ms", ACCOUNTS_PING_DEFAULTS["classification"]["issue_latency_ms"]) or 200.0)
        stable_fail_pct = float(cls.get("stable_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["stable_rto_pct"]) or 2.0)
        issue_fail_pct = float(cls.get("issue_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_rto_pct"]) or 5.0)

        rows = []
        account_ids = []
        for dev in devices:
            ip = (dev.get("ip") or "").strip()
            if not ip:
                continue
            pppoe = (dev.get("pppoe") or dev.get("name") or "").strip() or ip
            aid = _accounts_ping_account_id_for_pppoe(pppoe)
            if not aid:
                continue
            rows.append({"pppoe": pppoe, "ip": ip, "account_id": aid})
            account_ids.append(aid)

        stats_by_ip_map = get_accounts_ping_window_stats_by_ip(account_ids, since_iso) if account_ids else {}

        acc_items = []
        for row in rows:
            aid = row["account_id"]
            st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
            chosen_ip = (st.get("last_ip") or row.get("ip") or "").strip()
            stats = (stats_by_ip_map.get(aid) or {}).get(chosen_ip) or {}
            total = int(stats.get("total") or 0)
            failures = int(stats.get("failures") or 0)
            fail_pct = (failures / total) * 100.0 if total else 0.0
            has_recent = bool((st.get("last_check_at") or "").strip())
            last_ok = bool(st.get("last_ok")) if has_recent else True
            last_loss = st.get("last_loss")
            last_avg_ms = st.get("last_avg_ms")

            status = ""
            if not has_recent:
                status = "pending"
            elif not last_ok:
                status = "down"
            else:
                issue_hit = False
                if last_loss is not None and float(last_loss) >= issue_loss_pct:
                    issue_hit = True
                if last_avg_ms is not None and float(last_avg_ms) >= issue_latency_ms:
                    issue_hit = True
                if total and fail_pct >= issue_fail_pct:
                    issue_hit = True
                if total and fail_pct > stable_fail_pct:
                    issue_hit = True
                status = "monitor" if issue_hit else "stable"

            if status in ("down", "monitor"):
                acc_items.append(
                    {
                        "group": "ACC-Ping",
                        "name": row.get("pppoe") or chosen_ip,
                        "pppoe": row.get("pppoe") or "",
                        "ip": chosen_ip,
                        "device_id": "",
                        "sources": ["accounts_ping"],
                        "last_seen": st.get("last_check_at") or "",
                        "meta": {"status": status, "loss": last_loss, "avg_ms": last_avg_ms, "fail_pct": fail_pct},
                    }
                )

        acc_items.sort(
            key=lambda x: (
                x.get("meta", {}).get("status") != "down",
                -(float(x.get("meta", {}).get("loss") or 0.0)),
                -(float(x.get("meta", {}).get("avg_ms") or 0.0)),
                -(float(x.get("meta", {}).get("fail_pct") or 0.0)),
                str(x.get("name") or "").lower(),
            )
        )
        acc_items = acc_items[:10]

        classification = optical_settings.get("classification", {})
        issue_rx = float(classification.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]))
        issue_tx = float(classification.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]))
        stable_rx = float(classification.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]))
        stable_tx = float(classification.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]))
        rx_realistic_min = float(classification.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]))
        rx_realistic_max = float(classification.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]))
        tx_realistic_min = float(classification.get("tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"]))
        tx_realistic_max = float(classification.get("tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"]))

        candidates = get_optical_worst_candidates(since_iso, limit=300)

        def optical_score(row):
            rx = row.get("rx")
            tx = row.get("tx")
            p = 0
            if rx is None or rx < rx_realistic_min or rx > rx_realistic_max:
                p += 1000
            elif rx <= issue_rx:
                p += 600 + int(abs(issue_rx - rx) * 10)
            elif rx < stable_rx:
                p += 300 + int(abs(stable_rx - rx) * 5)
            else:
                p += 50
            if tx is None:
                p += 220
            else:
                if tx < tx_realistic_min or tx > tx_realistic_max:
                    p += 200
                if tx <= issue_tx:
                    p += 180 + int(abs(issue_tx - tx) * 10)
                elif tx < stable_tx:
                    p += 90
            if bool(row.get("priority")):
                p += 80
            return p

        candidates = sorted(candidates, key=optical_score, reverse=True)[:10]
        optical_items = []
        for row in candidates:
            ip = (row.get("ip") or "").strip()
            device_id = (row.get("device_id") or "").strip()
            rx = row.get("rx")
            tx = row.get("tx")
            rx_invalid = rx is None or rx < rx_realistic_min or rx > rx_realistic_max
            tx_missing = tx is None
            tx_unrealistic = (tx is not None) and (tx < tx_realistic_min or tx > tx_realistic_max)
            status = "stable"
            if rx_invalid:
                status = "issue"
            elif tx_missing or tx_unrealistic:
                status = "monitor"
            elif (rx is not None and rx <= issue_rx) or (tx is not None and tx <= issue_tx):
                status = "issue"
            elif not (rx is not None and rx >= stable_rx and tx is not None and tx >= stable_tx):
                status = "monitor"
            optical_items.append(
                {
                    "group": "Optical",
                    "name": (row.get("pppoe") or "").strip() or device_id,
                    "ip": ip,
                    "device_id": device_id,
                    "sources": ["optical"],
                    "last_seen": row.get("timestamp") or "",
                    "meta": {"status": status, "rx": rx, "tx": tx, "tx_missing": tx_missing, "tx_unrealistic": tx_unrealistic},
                }
            )

        return JSONResponse(
            {
                "mode": "top10",
                "header": "TOP10 - Critical Connections (Last 24h)",
                "items": acc_items + optical_items,
            }
        )
    since_iso = (datetime.utcnow() - timedelta(days=120)).replace(microsecond=0).isoformat() + "Z"

    optical_hits = search_optical_customers(query, since_iso, limit=limit)
    ping_state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
    devices = ping_state.get("devices") if isinstance(ping_state.get("devices"), list) else []
    state_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}

    merged = {}
    for row in optical_hits:
        ip = (row.get("ip") or "").strip()
        pppoe = (row.get("pppoe") or "").strip()
        key = f"ppp:{pppoe}" if pppoe else (f"ip:{ip}" if ip else f"dev:{row.get('device_id')}")
        merged.setdefault(
            key,
            {
                "name": pppoe,
                "pppoe": pppoe,
                "ip": ip,
                "device_id": row.get("device_id") or "",
                "sources": set(),
                "last_seen": row.get("timestamp") or "",
            },
        )
        merged[key]["sources"].add("optical")
        if row.get("timestamp") and row.get("timestamp") > merged[key]["last_seen"]:
            merged[key]["last_seen"] = row.get("timestamp")
        if not merged[key]["name"] and row.get("pppoe"):
            merged[key]["name"] = row.get("pppoe")

    for dev in devices:
        ip = (dev.get("ip") or "").strip()
        if not ip:
            continue
        pppoe = (dev.get("pppoe") or dev.get("name") or "").strip() or ip
        hay = f"{pppoe} {ip}".lower()
        if query.lower() not in hay:
            continue
        aid = _accounts_ping_account_id_for_pppoe(pppoe)
        st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
        last_seen = (st.get("last_check_at") or "").strip()
        key = f"ppp:{pppoe}"
        merged.setdefault(
            key,
            {
                "name": pppoe,
                "pppoe": pppoe,
                "ip": ip,
                "device_id": "",
                "sources": set(),
                "last_seen": last_seen or "",
            },
        )
        merged[key]["sources"].add("accounts_ping")
        if last_seen and last_seen > (merged[key]["last_seen"] or ""):
            merged[key]["last_seen"] = last_seen

    items = []
    for value in merged.values():
        sources = sorted(value["sources"])
        items.append(
            {
                "name": value.get("name") or value.get("ip") or value.get("device_id") or "Customer",
                "pppoe": value.get("pppoe") or "",
                "ip": value.get("ip") or "",
                "device_id": value.get("device_id") or "",
                "sources": sources,
                "last_seen": value.get("last_seen") or "",
            }
        )
    items.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
    return JSONResponse({"mode": "search", "header": "Results", "items": items[:limit]})


@app.get("/profile-review", response_class=HTMLResponse)
async def profile_review(request: Request):
    pppoe = (request.query_params.get("pppoe") or "").strip()
    ip = (request.query_params.get("ip") or "").strip()
    device_id = (request.query_params.get("device_id") or "").strip()
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    window_label = next((label for label, hours in WAN_STATUS_WINDOW_OPTIONS if hours == window_hours), "1D")

    optical_settings = get_settings("optical", OPTICAL_DEFAULTS)
    accounts_ping_settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    ping_state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
    devices = ping_state.get("devices") if isinstance(ping_state.get("devices"), list) else []
    state_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}

    if pppoe and not device_id:
        try:
            opt_map = get_latest_optical_by_pppoe([pppoe])
            hit = opt_map.get(pppoe) or {}
            if hit and not device_id:
                device_id = (hit.get("device_id") or "").strip()
            if hit and not ip:
                ip = (hit.get("ip") or "").strip()
        except Exception:
            pass

    if pppoe and not ip:
        aid = _accounts_ping_account_id_for_pppoe(pppoe)
        st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
        ip = (st.get("last_ip") or "").strip() or ip

    if ip and not device_id:
        device_id = get_latest_optical_device_for_ip(ip) or ""
    optical_ident = get_latest_optical_identity(device_id) if device_id else None
    if optical_ident and not ip:
        ip = (optical_ident.get("ip") or "").strip()
    if optical_ident:
        optical_pppoe = (optical_ident.get("pppoe") or "").strip()
        if optical_pppoe and not pppoe:
            pppoe = optical_pppoe

    if not pppoe and ip:
        for dev in devices:
            if (dev.get("ip") or "").strip() == ip:
                pppoe = (dev.get("pppoe") or dev.get("name") or "").strip() or pppoe
                break

    genie_base = ""
    try:
        genie_base = (
            (optical_settings.get("optical", {}) or {}).get("genieacs_base_url")
            or (optical_settings.get("genieacs", {}) or {}).get("base_url")
            or ""
        ).rstrip("/")
    except Exception:
        genie_base = ""

    def genie_device_url(base_url, dev_id):
        if not base_url or not dev_id:
            return ""
        try:
            parsed = urllib.parse.urlparse(base_url)
            scheme = parsed.scheme or "http"
            host = parsed.hostname or parsed.netloc or ""
            device_path = f"/devices/{urllib.parse.quote(str(dev_id))}"
            netloc = f"{host}:3000" if host else ""
            return urllib.parse.urlunparse((scheme, netloc, "/", "", "", f"/{device_path.lstrip('/')}"))
        except Exception:
            return ""

    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).replace(microsecond=0).isoformat() + "Z"

    profile = {
        "window_hours": window_hours,
        "window_label": window_label,
        "ip": ip,
        "device_id": device_id,
        "device_url": genie_device_url(genie_base, device_id) if device_id else "",
        "name": "",
        "pppoe": pppoe,
        "sources": [],
        "accounts_ping": None,
        "optical": None,
        "usage": None,
        "classification": {
            "tx_realistic_min_dbm": float(optical_settings.get("classification", {}).get("tx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_min_dbm"])),
            "tx_realistic_max_dbm": float(optical_settings.get("classification", {}).get("tx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["tx_realistic_max_dbm"])),
        },
    }

    if optical_ident:
        optical_pppoe = (optical_ident.get("pppoe") or "").strip()
        if optical_pppoe and not profile["pppoe"]:
            profile["pppoe"] = optical_pppoe
        profile["name"] = optical_pppoe or profile["name"]
        profile["sources"].append("optical")
        classification = optical_settings.get("classification", {})
        issue_rx = float(classification.get("issue_rx_dbm", OPTICAL_DEFAULTS["classification"]["issue_rx_dbm"]))
        issue_tx = float(classification.get("issue_tx_dbm", OPTICAL_DEFAULTS["classification"]["issue_tx_dbm"]))
        stable_rx = float(classification.get("stable_rx_dbm", OPTICAL_DEFAULTS["classification"]["stable_rx_dbm"]))
        stable_tx = float(classification.get("stable_tx_dbm", OPTICAL_DEFAULTS["classification"]["stable_tx_dbm"]))
        rx_realistic_min = float(classification.get("rx_realistic_min_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_min_dbm"]))
        rx_realistic_max = float(classification.get("rx_realistic_max_dbm", OPTICAL_DEFAULTS["classification"]["rx_realistic_max_dbm"]))
        tx_realistic_min = float(profile["classification"]["tx_realistic_min_dbm"])
        tx_realistic_max = float(profile["classification"]["tx_realistic_max_dbm"])

        rx = optical_ident.get("rx")
        tx = optical_ident.get("tx")
        rx_invalid = rx is None or rx < rx_realistic_min or rx > rx_realistic_max
        tx_missing = tx is None
        tx_unrealistic = (tx is not None) and (tx < tx_realistic_min or tx > tx_realistic_max)
        status = "stable"
        if rx_invalid:
            status = "issue"
        elif tx_missing or tx_unrealistic:
            status = "monitor"
        elif (rx is not None and rx <= issue_rx) or (tx is not None and tx <= issue_tx):
            status = "issue"
        elif not (rx is not None and rx >= stable_rx and tx is not None and tx >= stable_tx):
            status = "monitor"

        recent = get_recent_optical_readings(device_id, since_iso, limit=12)
        profile["optical"] = {
            "name": profile["name"],
            "ip": ip,
            "device_id": device_id,
            "last_seen": format_ts_ph(optical_ident.get("timestamp")),
            "rx": rx,
            "tx": tx,
            "rx_invalid": rx_invalid,
            "tx_missing": tx_missing,
            "tx_unrealistic": tx_unrealistic,
            "status": status,
            "samples": len(recent),
            "recent": [
                {
                    "ts": format_ts_ph(item.get("timestamp")),
                    "rx": item.get("rx"),
                    "tx": item.get("tx"),
                    "priority": bool(item.get("priority")),
                }
                for item in recent
            ],
            "chart": {
                "min_dbm": float(classification.get("chart_min_dbm", OPTICAL_DEFAULTS["classification"]["chart_min_dbm"])),
                "max_dbm": float(classification.get("chart_max_dbm", OPTICAL_DEFAULTS["classification"]["chart_max_dbm"])),
            },
        }

    if profile["pppoe"]:
        cls = accounts_ping_settings.get("classification", {}) or {}
        issue_loss_pct = float(cls.get("issue_loss_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_loss_pct"]) or 20.0)
        issue_latency_ms = float(cls.get("issue_latency_ms", ACCOUNTS_PING_DEFAULTS["classification"]["issue_latency_ms"]) or 200.0)
        stable_fail_pct = float(cls.get("stable_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["stable_rto_pct"]) or 2.0)
        issue_fail_pct = float(cls.get("issue_rto_pct", ACCOUNTS_PING_DEFAULTS["classification"]["issue_rto_pct"]) or 5.0)

        account_id = _accounts_ping_account_id_for_pppoe(profile["pppoe"])
        st = state_accounts.get(account_id) if isinstance(state_accounts.get(account_id), dict) else {}
        has_recent = bool((st.get("last_check_at") or "").strip())
        last_ok = bool(st.get("last_ok")) if has_recent else True
        last_loss = st.get("last_loss")
        last_avg_ms = st.get("last_avg_ms")
        last_seen = format_ts_ph(st.get("last_check_at")) if has_recent else "n/a"

        stats_map = get_accounts_ping_window_stats([account_id], since_iso)
        stats = stats_map.get(account_id) or {}
        total = int(stats.get("total") or 0)
        failures = int(stats.get("failures") or 0)
        fail_pct = (failures / total) * 100.0 if total else 0.0
        uptime_pct = (100.0 - fail_pct) if total else 0.0

        status = "pending"
        if has_recent:
            if not last_ok:
                status = "down"
            else:
                issue_hit = False
                if last_loss is not None and float(last_loss) >= issue_loss_pct:
                    issue_hit = True
                if last_avg_ms is not None and float(last_avg_ms) >= issue_latency_ms:
                    issue_hit = True
                if total and fail_pct >= issue_fail_pct:
                    issue_hit = True
                if total and fail_pct > stable_fail_pct:
                    issue_hit = True
                status = "monitor" if issue_hit else "stable"

        chosen_ip = (get_accounts_ping_latest_ip_since(account_id, since_iso) or "").strip()
        if not chosen_ip:
            chosen_ip = (st.get("last_ip") or profile.get("ip") or "").strip()
        if chosen_ip and not profile.get("ip"):
            profile["ip"] = chosen_ip

        recent_rows = []
        try:
            rows = get_accounts_ping_series(account_id, since_iso)
            if chosen_ip:
                rows = [row for row in rows if (row.get("ip") or "").strip() == chosen_ip]
            recent_rows = list(reversed(rows))[:12]
        except Exception:
            recent_rows = []

        profile["sources"].append("accounts_ping")
        profile["accounts_ping"] = {
            "account_id": account_id,
            "pppoe": profile["pppoe"],
            "ip": chosen_ip,
            "last_seen": last_seen,
            "status": status,
            "total": total,
            "failures": failures,
            "fail_pct": fail_pct,
            "uptime_pct": uptime_pct,
            "loss_avg": stats.get("loss_avg"),
            "avg_ms_avg": stats.get("avg_ms_avg"),
	            "recent": [
	                {
	                    "ts": format_ts_ph(item.get("timestamp")),
	                    "ok": bool(item.get("ok")),
	                    "loss": item.get("loss"),
	                    "avg_ms": item.get("avg_ms"),
	                }
	                for item in recent_rows
	            ],
		        }

    if profile["pppoe"]:
        usage_settings = get_settings("usage", USAGE_DEFAULTS)
        usage_enabled = bool(usage_settings.get("enabled"))
        usage = {
            "enabled": usage_enabled,
            "active": False,
            "router_id": "",
            "router_name": "",
            "address": "",
            "uptime": "",
            "session_id": "",
            "last_seen": "n/a",
            "dl_bps": None,
            "ul_bps": None,
            "dl_bps_fmt": "n/a",
            "ul_bps_fmt": "n/a",
            "dl_total_bytes": None,
            "ul_total_bytes": None,
            "dl_total_fmt": "n/a",
            "ul_total_fmt": "n/a",
            "devices": 0,
            "hostnames": [],
            "issue": False,
            "issue_peak": False,
            "issue_anytime": False,
            "idle_kbps_to": float((usage_settings.get("detection") or {}).get("total_kbps_to", 8) or 8),
        }
        if usage_enabled:
            try:
                state = get_state("usage_state", {})
                active_rows = state.get("active_rows") if isinstance(state.get("active_rows"), list) else []
                hosts = state.get("pppoe_hosts") if isinstance(state.get("pppoe_hosts"), dict) else {}
                anytime_issues = state.get("anytime_issues") if isinstance(state.get("anytime_issues"), dict) else {}

                pppoe_key = profile["pppoe"].strip().lower()
                row = next(
                    (
                        r
                        for r in active_rows
                        if (r.get("pppoe") or "").strip().lower() == pppoe_key
                        or (r.get("name") or "").strip().lower() == pppoe_key
                    ),
                    None,
                )
                host_info = hosts.get(profile["pppoe"]) or hosts.get(pppoe_key) or {}
                host_count = int(host_info.get("host_count") or 0)
                hostnames = host_info.get("hostnames") if isinstance(host_info.get("hostnames"), list) else []
                hostnames = [str(x).strip() for x in hostnames if str(x or "").strip()]

                usage["devices"] = host_count
                usage["hostnames"] = hostnames

                if row:
                    ul_bps = row.get("rx_bps")
                    dl_bps = row.get("tx_bps")
                    total_bps = float(ul_bps or 0.0) + float(dl_bps or 0.0)

                    detect = usage_settings.get("detection") if isinstance(usage_settings.get("detection"), dict) else {}
                    peak_enabled = bool(detect.get("peak_enabled", True))
                    min_devices = max(int(detect.get("min_connected_devices", 2) or 2), 1)
                    kbps_from = detect.get("total_kbps_from")
                    kbps_to = detect.get("total_kbps_to")
                    if kbps_from is None:
                        kbps_from = 0
                    if kbps_to is None:
                        kbps_to = detect.get("min_total_kbps", 8)
                    kbps_from = max(float(kbps_from or 0.0), 0.0)
                    kbps_to = max(float(kbps_to or 0.0), 0.0)
                    if kbps_to < kbps_from:
                        kbps_from, kbps_to = kbps_to, kbps_from
                    range_from_bps = kbps_from * 1000.0
                    range_to_bps = kbps_to * 1000.0
                    start_ph = (detect.get("peak_start_ph") or "17:30").strip()
                    end_ph = (detect.get("peak_end_ph") or "21:00").strip()
                    now_ph = datetime.now(PH_TZ)
                    in_peak = is_time_window_ph(now_ph, start_ph, end_ph)
                    peak_issue = bool(
                        peak_enabled
                        and in_peak
                        and host_count >= min_devices
                        and (range_from_bps <= total_bps <= range_to_bps)
                    )
                    router_id = (row.get("router_id") or "").strip()
                    anytime_issue = bool(anytime_issues.get(f"{router_id}|{pppoe_key}"))

                    usage.update(
                        {
                            "active": True,
                            "router_id": router_id,
                            "router_name": (row.get("router_name") or router_id or "").strip(),
                            "address": (row.get("address") or "").strip(),
                            "uptime": (row.get("uptime") or "").strip(),
                            "session_id": (row.get("session_id") or "").strip(),
                            "last_seen": format_ts_ph(row.get("timestamp")),
                            "dl_bps": dl_bps,
                            "ul_bps": ul_bps,
                            "dl_bps_fmt": format_bps(dl_bps),
                            "ul_bps_fmt": format_bps(ul_bps),
                            "dl_total_bytes": row.get("bytes_out"),
                            "ul_total_bytes": row.get("bytes_in"),
                            "dl_total_fmt": format_bytes(row.get("bytes_out")),
                            "ul_total_fmt": format_bytes(row.get("bytes_in")),
                            "issue_peak": peak_issue,
                            "issue_anytime": anytime_issue,
                            "issue": bool(peak_issue or anytime_issue),
                        }
                    )
            except Exception:
                pass

        profile["usage"] = usage
        if usage_enabled:
            profile["sources"].append("usage")

    profile["sources"] = sorted({*profile["sources"]})
    if not profile["name"]:
        profile["name"] = profile["pppoe"] or profile["ip"] or profile["device_id"] or ""
    if not profile["pppoe"]:
        # keep empty when we can't confidently identify the PPPoE username
        profile["pppoe"] = ""

    return templates.TemplateResponse(
        "profile_review.html",
        make_context(
            request,
            {
                "profile": profile,
            },
        ),
    )

@app.get("/settings/accounts-ping", response_class=HTMLResponse)
async def accounts_ping_settings(request: Request):
    settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    limit = _parse_table_limit(request.query_params.get("limit"), default=50)
    issues_page = _parse_table_page(request.query_params.get("issues_page"), default=1)
    stable_page = _parse_table_page(request.query_params.get("stable_page"), default=1)
    issues_sort = (request.query_params.get("issues_sort") or "").strip()
    issues_dir = (request.query_params.get("issues_dir") or "").strip().lower()
    stable_sort = (request.query_params.get("stable_sort") or "").strip()
    stable_dir = (request.query_params.get("stable_dir") or "").strip().lower()
    query = (request.query_params.get("q") or "").strip()
    return render_accounts_ping_response(
        request,
        settings,
        "",
        "status",
        "general",
        window_hours,
        limit=limit,
        issues_page=issues_page,
        stable_page=stable_page,
        issues_sort=issues_sort,
        issues_dir=issues_dir,
        stable_sort=stable_sort,
        stable_dir=stable_dir,
        query=query,
    )


@app.get("/accounts-ping/series", response_class=JSONResponse)
async def accounts_ping_series(account_id: str, window: int = 24):
    hours = _normalize_wan_window(window)
    since_iso = (datetime.utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    chosen_ip = (get_accounts_ping_latest_ip_since(account_id, since_iso) or "").strip()
    rows = get_accounts_ping_series(account_id, since_iso)
    if chosen_ip:
        rows = [row for row in rows if (row.get("ip") or "").strip() == chosen_ip]
    series = [
        {
            "ts": row.get("timestamp"),
            "ok": bool(row.get("ok")),
            "loss": row.get("loss"),
            "avg_ms": row.get("avg_ms"),
        }
        for row in rows
    ]
    return JSONResponse({"hours": hours, "series": series})


def _parse_iso_z(value):
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1]
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _format_duration_short(seconds):
    if seconds is None:
        return ""
    try:
        seconds = int(seconds)
    except Exception:
        return ""
    if seconds < 0:
        seconds = 0
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def build_accounts_ping_status(
    settings,
    window_hours=24,
    limit=50,
    issues_page=1,
    stable_page=1,
    issues_sort="",
    issues_dir="",
    stable_sort="",
    stable_dir="",
    query="",
):
    window_hours = max(int(window_hours or 24), 1)
    limit = _parse_table_limit(limit, default=50)
    issues_page = _parse_table_page(issues_page, default=1)
    stable_page = _parse_table_page(stable_page, default=1)
    state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
    devices = state.get("devices") if isinstance(state.get("devices"), list) else []
    account_map = {}
    for device in devices:
        ip = (device.get("ip") or "").strip()
        if not ip:
            continue
        pppoe = (device.get("pppoe") or device.get("name") or "").strip() or ip
        aid = _accounts_ping_account_id_for_pppoe(pppoe)
        if not aid:
            continue
        account_map[aid] = {"id": aid, "name": pppoe, "ip": ip}

    account_rows = list(account_map.values())
    account_ids = [row["id"] for row in account_rows]
    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).replace(microsecond=0).isoformat() + "Z"
    stats_by_ip_map = get_accounts_ping_window_stats_by_ip(account_ids, since_iso)

    state_accounts = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}

    cls = settings.get("classification", {}) or {}
    issue_loss_pct = float(cls.get("issue_loss_pct", 20.0) or 20.0)
    issue_latency_ms = float(cls.get("issue_latency_ms", 200.0) or 200.0)
    stable_rto_pct = float(cls.get("stable_rto_pct", 2.0) or 2.0)
    issue_rto_pct = float(cls.get("issue_rto_pct", 5.0) or 5.0)
    issue_streak = int(cls.get("issue_streak", 2) or 2)

    chosen_ip_map = {}
    for account in account_rows:
        aid = account["id"]
        st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
        chosen_ip_map[aid] = (st.get("last_ip") or account.get("ip") or "").strip()

    issue_rows = []
    stable_rows = []
    pending_total = 0
    for account in account_rows:
        aid = account["id"]
        st = state_accounts.get(aid) if isinstance(state_accounts.get(aid), dict) else {}
        chosen_ip = chosen_ip_map.get(aid) or (st.get("last_ip") or account.get("ip") or "").strip()
        stats = (stats_by_ip_map.get(aid) or {}).get(chosen_ip) or {}
        loss = st.get("last_loss")
        avg_ms = st.get("last_avg_ms")
        has_recent = bool(st.get("last_check_at"))
        last_ok = bool(st.get("last_ok")) if has_recent else True
        last_seen = format_ts_ph(st.get("last_check_at")) if has_recent else "n/a"
        last_seen_raw = (st.get("last_check_at") or "").strip()

        total = int(stats.get("total") or 0)
        failures = int(stats.get("failures") or 0)
        rto_pct = (failures / total) * 100.0 if total else 0.0
        uptime_pct = 100.0 - rto_pct

        streak = int(st.get("streak") or 0)
        down_since_dt = _parse_iso_z(st.get("down_since"))
        down_for = _format_duration_short((datetime.utcnow() - down_since_dt).total_seconds()) if down_since_dt else ""
        down_seconds = int((datetime.utcnow() - down_since_dt).total_seconds()) if down_since_dt else 0

        issue_hit = False
        reasons = []
        if not has_recent:
            pending_total += 1
            status = "pending"
            reasons = ["Not yet checked"]
        else:
            if not last_ok:
                issue_hit = True
                reasons.append("Currently down")
            if loss is not None and float(loss) >= issue_loss_pct:
                issue_hit = True
                reasons.append(f"Loss >= {issue_loss_pct:g}%")
            if avg_ms is not None and float(avg_ms) >= issue_latency_ms:
                issue_hit = True
                reasons.append(f"Latency >= {issue_latency_ms:g}ms")
            if total and rto_pct >= issue_rto_pct:
                issue_hit = True
                reasons.append(f"Fail % >= {issue_rto_pct:g}%")
            if streak >= issue_streak and not last_ok:
                issue_hit = True
                reasons.append(f"Streak {streak}")

            is_stable = last_ok and (not issue_hit) and ((not total) or rto_pct <= stable_rto_pct)
            status = "down" if not last_ok else ("up" if is_stable else "monitor")

            if status == "monitor" and total and rto_pct > stable_rto_pct:
                reasons.append(f"Fail % > {stable_rto_pct:g}%")

        if status not in ("pending", "down", "up", "monitor"):
            status = "pending"
            reasons = ["Not yet checked"]

        row = {
            "id": aid,
            "name": account["name"],
            "ip": chosen_ip or account["ip"],
            "status": status,
            "loss": loss,
            "avg_ms": avg_ms,
            "total": total,
            "failures": failures,
            "rto_pct": rto_pct,
            "uptime_pct": uptime_pct,
            "streak": streak,
            "down_for": down_for,
            "down_seconds": down_seconds,
            "last_check": last_seen,
            "last_check_at": last_seen_raw,
            "reasons": reasons or (["OK"] if status == "up" else ["Monitor"]),
            "spark_points_24h": "",
            "spark_points_24h_large": "",
            "pending": status == "pending",
        }
        if status in ("up", "pending"):
            stable_rows.append(row)
        else:
            issue_rows.append(row)

    def _sort_numeric(val, desc=False):
        if val is None:
            return (1, 0.0)
        try:
            num = float(val)
        except Exception:
            return (1, 0.0)
        return (0, -num if desc else num)

    def _sort_text(val, desc=False):
        text = (val or "").strip().lower()
        return (0, "".join(reversed(text)) if desc else text)

    def _sort_key_for(row, key, desc=False):
        if key in ("customer", "name"):
            return _sort_text(row.get("name"), desc=desc)
        if key in ("ip", "ipv4"):
            return _sort_text(row.get("ip"), desc=desc)
        if key == "status":
            order = {"down": 0, "monitor": 1, "up": 2, "pending": 3}
            return (0, -order.get(row.get("status"), 9) if desc else order.get(row.get("status"), 9))
        if key in ("loss", "loss_pct"):
            return _sort_numeric(row.get("loss"), desc=desc)
        if key in ("latency", "avg_ms"):
            return _sort_numeric(row.get("avg_ms"), desc=desc)
        if key in ("fail", "fail_pct", "rto_pct"):
            return _sort_numeric(row.get("rto_pct"), desc=desc)
        if key in ("uptime", "uptime_pct"):
            return _sort_numeric(row.get("uptime_pct"), desc=desc)
        if key == "streak":
            return _sort_numeric(row.get("streak"), desc=desc)
        if key in ("down_for", "down_seconds"):
            return _sort_numeric(row.get("down_seconds"), desc=desc)
        if key in ("last_check", "last_check_at"):
            return _sort_text(row.get("last_check_at"), desc=desc)
        if key == "reason":
            return _sort_text("; ".join(row.get("reasons") or []), desc=desc)
        return _sort_text(row.get("name"), desc=desc)

    q = (query or "").strip().lower()
    if q:
        def match_row(row):
            hay = " ".join(
                [
                    str(row.get("name") or ""),
                    str(row.get("ip") or ""),
                    " ".join(row.get("reasons") or []),
                ]
            ).lower()
            return q in hay

        issue_rows = [row for row in issue_rows if match_row(row)]
        stable_rows = [row for row in stable_rows if match_row(row)]
        pending_total = sum(1 for row in stable_rows if row.get("status") == "pending")

    # defaults
    default_issue = sorted(
        issue_rows,
        key=lambda x: (x["status"] != "down", -(x["loss"] or 0), -(x["avg_ms"] or 0), x["name"].lower()),
    )
    default_stable = sorted(stable_rows, key=lambda x: (x.get("pending", False), x["name"].lower()))

    issues_sort = (issues_sort or "").strip()
    stable_sort = (stable_sort or "").strip()
    issues_desc = (issues_dir or "").lower() != "asc"
    stable_desc = (stable_dir or "").lower() != "asc"

    issue_rows = (
        sorted(issue_rows, key=lambda row: _sort_key_for(row, issues_sort, desc=issues_desc))
        if issues_sort
        else default_issue
    )
    stable_rows = (
        sorted(stable_rows, key=lambda row: _sort_key_for(row, stable_sort, desc=stable_desc))
        if stable_sort
        else default_stable
    )

    stable_up_total = sum(1 for row in stable_rows if row.get("status") == "up")

    paged_issue, issue_page_meta = _paginate_items(issue_rows, issues_page, limit)
    paged_stable, stable_page_meta = _paginate_items(stable_rows, stable_page, limit)

    paged_ids = sorted({row["id"] for row in (paged_issue + paged_stable) if row.get("id")})
    spark_map = {}
    if paged_ids:
        spark_since_iso = (datetime.utcnow() - timedelta(hours=24)).replace(microsecond=0).isoformat() + "Z"
        spark_rows = get_accounts_ping_rollups_since(spark_since_iso, paged_ids)
        for row in spark_rows:
            aid = (row.get("account_id") or "").strip()
            if not aid:
                continue
            chosen_ip = chosen_ip_map.get(aid) or ""
            if chosen_ip and (row.get("ip") or "").strip() != chosen_ip:
                continue
            sample_count = int(row.get("sample_count") or 0)
            ok_count = int(row.get("ok_count") or 0)
            pct = (ok_count / sample_count) * 100.0 if sample_count > 0 else 0.0
            spark_map.setdefault(aid, []).append(pct)

    def with_spark(row):
        aid = row.get("id")
        if row.get("pending"):
            next_row = dict(row)
            next_row["spark_points_24h"] = ""
            next_row["spark_points_24h_large"] = ""
            return next_row
        spark_values = spark_map.get(aid, [])
        next_row = dict(row)
        next_row["spark_points_24h"] = _sparkline_points_fixed(spark_values or [0], 0, 100, width=140, height=28)
        next_row["spark_points_24h_large"] = _sparkline_points_fixed(spark_values or [0], 0, 100, width=640, height=200)
        return next_row

    paged_issue = [with_spark(row) for row in paged_issue]
    paged_stable = [with_spark(row) for row in paged_stable]

    window_label = next((label for label, hours in WAN_STATUS_WINDOW_OPTIONS if hours == window_hours), "1D")
    return {
        "total": len(issue_rows) + len(stable_rows),
        "issue_total": len(issue_rows),
        "stable_total": stable_up_total,
        "pending_total": pending_total,
        "issue_rows": paged_issue,
        "stable_rows": paged_stable,
        "window_hours": window_hours,
        "window_label": window_label,
        "pagination": {
            "limit": limit,
            "limit_label": "ALL" if not limit else str(limit),
            "options": TABLE_PAGE_SIZE_OPTIONS,
            "issues": issue_page_meta,
            "stable": stable_page_meta,
        },
        "sort": {
            "issues": {"key": issues_sort, "dir": "desc" if issues_desc else "asc"},
            "stable": {"key": stable_sort, "dir": "desc" if stable_desc else "asc"},
        },
        "query": query or "",
        "rules": {
            "issue_loss_pct": issue_loss_pct,
            "issue_latency_ms": issue_latency_ms,
            "stable_rto_pct": stable_rto_pct,
            "issue_rto_pct": issue_rto_pct,
            "issue_streak": issue_streak,
        },
    }


def render_accounts_ping_response(
    request,
    settings,
    message,
    active_tab,
    settings_tab,
    window_hours=24,
    limit=None,
    issues_page=None,
    stable_page=None,
    issues_sort="",
    issues_dir="",
    stable_sort="",
    stable_dir="",
    query="",
):
    status_map = {item["job_name"]: dict(item) for item in get_job_status()}
    job_status = status_map.get("accounts_ping", {})
    job_status["last_run_at_ph"] = format_ts_ph(job_status.get("last_run_at"))
    job_status["last_success_at_ph"] = format_ts_ph(job_status.get("last_success_at"))
    if limit is None:
        limit = _parse_table_limit(request.query_params.get("limit"), default=50)
    if issues_page is None:
        issues_page = _parse_table_page(request.query_params.get("issues_page"), default=1)
    if stable_page is None:
        stable_page = _parse_table_page(request.query_params.get("stable_page"), default=1)
    if not issues_sort:
        issues_sort = (request.query_params.get("issues_sort") or "").strip()
    if not issues_dir:
        issues_dir = (request.query_params.get("issues_dir") or "").strip().lower()
    if not stable_sort:
        stable_sort = (request.query_params.get("stable_sort") or "").strip()
    if not stable_dir:
        stable_dir = (request.query_params.get("stable_dir") or "").strip().lower()
    if not query:
        query = (request.query_params.get("q") or "").strip()
    status = build_accounts_ping_status(
        settings,
        window_hours,
        limit=limit,
        issues_page=issues_page,
        stable_page=stable_page,
        issues_sort=issues_sort,
        issues_dir=issues_dir,
        stable_sort=stable_sort,
        stable_dir=stable_dir,
        query=query,
    )
    return templates.TemplateResponse(
        "settings_accounts_ping.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": active_tab,
                "settings_tab": settings_tab,
                "accounts_ping_status": status,
                "accounts_ping_job": job_status,
                "accounts_ping_window_options": WAN_STATUS_WINDOW_OPTIONS,
            },
        ),
    )


def _accounts_ping_account_id_for_pppoe(pppoe):
    raw = (pppoe or "").strip().encode("utf-8")
    if not raw:
        return ""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _accounts_ping_account_id_for_ip(ip):
    # Backward-compatible wrapper (legacy callers still pass an IP string).
    return _accounts_ping_account_id_for_pppoe(ip)


@app.post("/settings/accounts-ping", response_class=HTMLResponse)
async def accounts_ping_settings_save(request: Request):
    form = await request.form()
    current = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    settings = {
        "enabled": parse_bool(form, "enabled"),
        "ssh": {
            "host": (form.get("ssh_host") or "").strip(),
            "port": parse_int(form, "ssh_port", 22),
            "user": (form.get("ssh_user") or "").strip(),
            "password": (form.get("ssh_password") or "").strip(),
            "use_key": parse_bool(form, "ssh_use_key"),
            "key_path": (form.get("ssh_key_path") or "").strip(),
            "remote_csv_path": (form.get("ssh_remote_csv_path") or "").strip() or "/opt/libreqos/src/ShapedDevices.csv",
        },
        "source": {
            "refresh_minutes": parse_int(form, "source_refresh_minutes", 15),
        },
        "general": {
            "base_interval_seconds": parse_int(form, "base_interval_seconds", 30),
            "max_parallel": parse_int(form, "max_parallel", 64),
        },
        "ping": {
            "count": parse_int(form, "ping_count", 3),
            "timeout_seconds": parse_int(form, "ping_timeout_seconds", 1),
        },
        "classification": {
            "issue_loss_pct": parse_float(form, "issue_loss_pct", 20.0),
            "issue_latency_ms": parse_float(form, "issue_latency_ms", 200.0),
            "down_loss_pct": parse_float(form, "down_loss_pct", 100.0),
            "stable_rto_pct": parse_float(form, "stable_rto_pct", 2.0),
            "issue_rto_pct": parse_float(form, "issue_rto_pct", 5.0),
            "issue_streak": parse_int(form, "issue_streak", 2),
        },
        "storage": {
            "raw_retention_days": parse_int(form, "raw_retention_days", 30),
            "rollup_retention_days": parse_int(form, "rollup_retention_days", 365),
            "bucket_seconds": parse_int(form, "bucket_seconds", 60),
        },
    }
    save_settings("accounts_ping", settings)
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    active_tab = form.get("active_tab", "settings")
    settings_tab = (form.get("settings_tab") or "general").strip().lower()
    if settings_tab not in ("general", "source", "classification", "storage", "danger"):
        settings_tab = "general"
    return render_accounts_ping_response(request, settings, "Accounts Ping settings saved.", active_tab, settings_tab, window_hours)


@app.post("/settings/accounts-ping/test", response_class=HTMLResponse)
async def accounts_ping_settings_test(request: Request):
    cfg = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    message = ""
    try:
        csv_text = rto_notifier.fetch_csv_text(cfg)
        devices = rto_notifier.parse_devices(csv_text)
        state = get_state("accounts_ping_state", {"accounts": {}, "devices": []})
        state["devices"] = [
            {
                "pppoe": (d.get("pppoe") or d.get("name") or d.get("ip") or "").strip(),
                "name": (d.get("pppoe") or d.get("name") or d.get("ip") or "").strip(),
                "ip": (d.get("ip") or "").strip(),
            }
            for d in (devices or [])
            if (d.get("ip") or "").strip()
        ]
        state["devices_refreshed_at"] = utc_now_iso()
        save_state("accounts_ping_state", state)
        message = f"SSH OK. Loaded {len(state['devices'])} accounts from CSV."
    except Exception as exc:
        message = f"SSH test failed: {exc}"
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    return render_accounts_ping_response(request, cfg, message, "settings", "general", window_hours)


@app.post("/settings/accounts-ping/format", response_class=HTMLResponse)
async def accounts_ping_settings_format(request: Request):
    form = await request.form()
    settings = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
    message = ""
    if parse_bool(form, "confirm_format"):
        clear_accounts_ping_data()
        state = get_state("accounts_ping_state", {})
        devices = state.get("devices") if isinstance(state.get("devices"), list) else []
        devices_refreshed_at = state.get("devices_refreshed_at") or ""
        save_state(
            "accounts_ping_state",
            {
                "accounts": {},
                "devices": devices,
                "devices_refreshed_at": devices_refreshed_at,
                "last_prune_at": None,
            },
        )
        message = "Accounts Ping database formatted."
    else:
        message = "Please confirm format before proceeding."
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    return render_accounts_ping_response(request, settings, message, "settings", "danger", window_hours)


@app.post("/accounts-ping/investigate", response_class=HTMLResponse)
async def accounts_ping_investigate(request: Request):
    form = await request.form()
    account_id = (form.get("account_id") or "").strip()
    minutes = parse_int(form, "minutes", 15)
    if not account_id:
        return RedirectResponse(url="/settings/accounts-ping", status_code=303)
    state = get_state("accounts_ping_state", {"accounts": {}})
    accounts = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}
    entry = accounts.get(account_id) if isinstance(accounts.get(account_id), dict) else {}
    until = (datetime.utcnow() + timedelta(minutes=max(int(minutes or 1), 1))).replace(microsecond=0).isoformat() + "Z"
    entry["investigate_until"] = until
    accounts[account_id] = entry
    state["accounts"] = accounts
    save_state("accounts_ping_state", state)
    return RedirectResponse(url="/settings/accounts-ping", status_code=303)


def normalize_surveillance_settings(raw):
    cfg = copy.deepcopy(SURVEILLANCE_DEFAULTS)
    if isinstance(raw, dict):
        cfg["enabled"] = bool(raw.get("enabled", cfg["enabled"]))
        for key in ("ping", "burst", "backoff", "stability", "auto_add"):
            if isinstance(raw.get(key), dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(raw[key])
        if isinstance(raw.get("entries"), list):
            cfg["entries"] = raw["entries"]

    normalized = []
    now_iso = utc_now_iso()
    cfg.setdefault("stability", {})
    cfg["stability"]["require_optical"] = True
    cfg.setdefault("auto_add", {})
    if not isinstance(cfg["auto_add"], dict):
        cfg["auto_add"] = copy.deepcopy(SURVEILLANCE_DEFAULTS.get("auto_add") or {})
    sources = cfg["auto_add"].get("sources")
    if not isinstance(sources, dict):
        cfg["auto_add"]["sources"] = {"accounts_ping": True}
    cfg["auto_add"]["sources"].setdefault("accounts_ping", True)
    try:
        wd = float(cfg["auto_add"].get("window_days", 3) or 3)
    except Exception:
        wd = 3.0
    if wd <= 0:
        wd = 3.0
    cfg["auto_add"]["window_days"] = wd
    try:
        mde = int(cfg["auto_add"].get("min_down_events", 5) or 5)
    except Exception:
        mde = 5
    if mde < 1:
        mde = 1
    cfg["auto_add"]["min_down_events"] = mde
    try:
        sim = int(cfg["auto_add"].get("scan_interval_minutes", 5) or 5)
    except Exception:
        sim = 5
    if sim < 1:
        sim = 1
    cfg["auto_add"]["scan_interval_minutes"] = sim
    try:
        mae = int(cfg["auto_add"].get("max_add_per_eval", 3))
    except Exception:
        mae = 3
    if mae is None:
        mae = 3
    if mae < 0:
        mae = 0
    cfg["auto_add"]["max_add_per_eval"] = mae
    for entry in cfg.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        pppoe = (entry.get("pppoe") or entry.get("name") or "").strip()
        if not pppoe:
            continue
        status = (entry.get("status") or "under").strip().lower()
        if status not in ("under", "level2"):
            status = "under"
        normalized.append(
            {
                "pppoe": pppoe,
                "name": (entry.get("name") or pppoe).strip(),
                "ip": (entry.get("ip") or "").strip(),
                "source": (entry.get("source") or "").strip(),
                "status": status,
                "added_at": (entry.get("added_at") or "").strip() or now_iso,
                "updated_at": (entry.get("updated_at") or "").strip() or now_iso,
                "level2_at": (entry.get("level2_at") or "").strip(),
                "last_fixed_at": (entry.get("last_fixed_at") or "").strip(),
                "last_fixed_reason": (entry.get("last_fixed_reason") or "").strip(),
                "last_fixed_mode": (entry.get("last_fixed_mode") or "").strip(),
                "added_mode": (entry.get("added_mode") or "").strip().lower() or "manual",
                "auto_source": (entry.get("auto_source") or "").strip(),
                "auto_reason": (entry.get("auto_reason") or "").strip(),
            }
        )
    cfg["entries"] = normalized
    return cfg


def _surveillance_entry_map(settings):
    entries = settings.get("entries") if isinstance(settings.get("entries"), list) else []
    merged = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pppoe = (entry.get("pppoe") or "").strip()
        if not pppoe:
            continue
        merged[pppoe] = entry
    settings["entries"] = list(merged.values())
    return merged


@app.get("/surveillance", response_class=HTMLResponse)
async def surveillance_page(request: Request):
    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    save_settings("surveillance", settings)

    active_tab = (request.query_params.get("tab") or "").strip().lower()
    focus = (request.query_params.get("focus") or "").strip()
    if active_tab not in ("under", "level2", "history", "settings"):
        active_tab = ""
    if focus and focus in entry_map and not active_tab:
        active_tab = "level2" if (entry_map.get(focus, {}).get("status") == "level2") else "under"
    if not active_tab:
        active_tab = "under"

    pppoes = sorted(entry_map.keys(), key=lambda x: x.lower())
    account_ids = [_accounts_ping_account_id_for_ip(pppoe) for pppoe in pppoes]

    stab_cfg = settings.get("stability", {}) or {}
    stable_window_minutes = max(int(stab_cfg.get("stable_window_minutes", 10) or 10), 1)
    stable_window_days = stable_window_minutes / 1440.0
    now = datetime.utcnow()
    since_iso = (now - timedelta(minutes=stable_window_minutes)).replace(microsecond=0).isoformat() + "Z"

    latest_map = get_latest_accounts_ping_map(account_ids)
    stats_map = get_accounts_ping_window_stats(account_ids, since_iso)
    optical_latest_map = get_latest_optical_by_pppoe(pppoes)
    ping_state = get_state("accounts_ping_state", {"accounts": {}})
    ping_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}

    def build_row(pppoe):
        entry = entry_map.get(pppoe, {})
        account_id = _accounts_ping_account_id_for_ip(pppoe)
        latest = latest_map.get(account_id) or {}
        stats = stats_map.get(account_id) or {}
        opt = optical_latest_map.get(pppoe) or {}
        st = ping_accounts.get(account_id) if isinstance(ping_accounts.get(account_id), dict) else {}

        total = int(stats.get("total") or 0)
        failures = int(stats.get("failures") or 0)
        uptime_pct = (100.0 - (failures / total) * 100.0) if total else 0.0

        down_since_dt = _parse_iso_z(st.get("down_since"))
        down_for = _format_duration_short((datetime.utcnow() - down_since_dt).total_seconds()) if down_since_dt else ""

        return {
            "pppoe": pppoe,
            "name": entry.get("name") or pppoe,
            "optical_device_id": (opt.get("device_id") or "").strip(),
            "ip": entry.get("ip") or latest.get("ip") or opt.get("ip") or "",
            "status": entry.get("status") or "under",
            "added_mode": (entry.get("added_mode") or "manual").strip().lower(),
            "auto_source": (entry.get("auto_source") or "").strip(),
            "auto_reason": (entry.get("auto_reason") or "").strip(),
            "added_at": format_ts_ph(entry.get("added_at")),
            "added_at_iso": (entry.get("added_at") or "").strip(),
            "last_check": format_ts_ph(latest.get("timestamp")),
            "loss": latest.get("loss"),
            "avg_ms": latest.get("avg_ms"),
            "mode": latest.get("mode") or "",
            "ok": bool(latest.get("ok")) if latest else False,
            "uptime_pct": uptime_pct,
            "stable_total": total,
            "stable_failures": failures,
            "stable_loss_avg": stats.get("loss_avg"),
            "stable_avg_ms_avg": stats.get("avg_ms_avg"),
            "down_for": down_for,
            "down_since_iso": (st.get("down_since") or "").strip(),
            "optical_rx": opt.get("rx"),
            "optical_tx": opt.get("tx"),
            "optical_last": format_ts_ph(opt.get("timestamp")),
            "optical_last_iso": (opt.get("timestamp") or "").strip(),
            "last_fixed_at_iso": (entry.get("last_fixed_at") or "").strip(),
            "last_fixed_at_ph": format_ts_ph(entry.get("last_fixed_at")),
            "last_fixed_reason": (entry.get("last_fixed_reason") or "").strip(),
            "last_fixed_mode": (entry.get("last_fixed_mode") or "").strip(),
        }

    under_rows = [build_row(pppoe) for pppoe in pppoes if (entry_map.get(pppoe, {}).get("status") or "under") == "under"]
    level2_rows = [build_row(pppoe) for pppoe in pppoes if (entry_map.get(pppoe, {}).get("status") or "") == "level2"]

    history_query = (request.query_params.get("q") or "").strip() if active_tab == "history" else ""
    history_page = _parse_table_page(request.query_params.get("page"), default=1) if active_tab == "history" else 1
    history = list_surveillance_history(query=history_query, page=history_page, limit=50)

    message = (request.query_params.get("msg") or "").strip()

    history_rows = []
    if history.get("rows"):
        for row in history["rows"]:
            started_iso = (row.get("started_at") or "").strip()
            ended_iso = (row.get("ended_at") or "").strip()
            history_rows.append(
                {
                    "id": row.get("id"),
                    "pppoe": row.get("pppoe") or "",
                    "source": row.get("source") or "",
                    "last_ip": row.get("last_ip") or "",
                    "last_state": row.get("last_state") or "",
                    "observed_count": int(row.get("observed_count") or 0),
                    "end_reason": (row.get("end_reason") or "").strip().lower(),
                    "end_note": (row.get("end_note") or "").strip(),
                    "started_at_iso": started_iso,
                    "ended_at_iso": ended_iso,
                    "started_at_ph": format_ts_ph(started_iso),
                    "ended_at_ph": format_ts_ph(ended_iso),
                    "active": not bool(ended_iso),
                    "currently_active": bool((row.get("pppoe") or "") in entry_map),
                }
            )

    total = int(history.get("total") or 0)
    limit = int(history.get("limit") or 50)
    page = int(history.get("page") or 1)
    pages = max((total + limit - 1) // limit, 1) if limit else 1
    history_pagination = {"page": page, "pages": pages, "total": total}

    optical_cfg = get_settings("optical", OPTICAL_DEFAULTS)
    optical_class = (optical_cfg.get("classification") or {}) if isinstance(optical_cfg.get("classification"), dict) else {}

    return templates.TemplateResponse(
        "surveillance.html",
        make_context(
            request,
            {
                "settings": settings,
                "active_tab": active_tab,
                "under_rows": under_rows,
                "level2_rows": level2_rows,
                "stable_window_minutes": stable_window_minutes,
                "stable_window_days": stable_window_days,
                "history_rows": history_rows,
                "history_query": history_query,
                "history_pagination": history_pagination,
                "message": message,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "surv_optical_chart_min_dbm": float(optical_class.get("chart_min_dbm", -35.0) or -35.0),
                "surv_optical_chart_max_dbm": float(optical_class.get("chart_max_dbm", -10.0) or -10.0),
                "surv_optical_tx_realistic_min_dbm": float(optical_class.get("tx_realistic_min_dbm", -10.0) or -10.0),
                "surv_optical_tx_realistic_max_dbm": float(optical_class.get("tx_realistic_max_dbm", 10.0) or 10.0),
            },
        ),
    )


@app.get("/surveillance/series", response_class=JSONResponse)
async def surveillance_series(pppoe: str, window: int = 24):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return JSONResponse({"hours": 0, "series": []})
    try:
        hours = int(str(window).strip())
    except Exception:
        hours = 24
    if hours not in {1, 6, 12, 24, 168}:
        hours = 24
    now = datetime.utcnow().replace(microsecond=0)
    since_iso = (now - timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"
    until_iso = now.isoformat() + "Z"
    account_id = _accounts_ping_account_id_for_pppoe(pppoe)
    rows = get_accounts_ping_series_range(account_id, since_iso, until_iso)

    def _merge_rows(rows_in):
        merged = []
        cur = None
        cur_ts = None
        for row in rows_in or []:
            ts = (row.get("timestamp") or "").strip()
            if not ts:
                continue
            ok = bool(row.get("ok"))
            loss = row.get("loss")
            avg_ms = row.get("avg_ms")
            mode = row.get("mode")
            if cur is None or ts != cur_ts:
                if cur is not None:
                    merged.append(cur)
                cur_ts = ts
                cur = {"ts": ts, "ok": ok, "loss": loss, "avg_ms": avg_ms, "mode": mode}
                continue
            cur["ok"] = bool(cur.get("ok")) or ok
            # Preserve worst-case values per second.
            for k, v in (("loss", loss), ("avg_ms", avg_ms)):
                a = cur.get(k)
                b = v
                try:
                    av = float(a) if a is not None else None
                except Exception:
                    av = None
                try:
                    bv = float(b) if b is not None else None
                except Exception:
                    bv = None
                if av is None:
                    cur[k] = b
                elif bv is None:
                    pass
                else:
                    cur[k] = b if bv > av else a
        if cur is not None:
            merged.append(cur)
        return merged

    series = _merge_rows(rows)
    return JSONResponse({"pppoe": pppoe, "hours": hours, "since": since_iso, "until": until_iso, "series": series})


def _surv_rollup_points_and_stats(rollups, bucket_seconds=60):
    points = []
    sample_total = 0
    ok_total = 0
    avg_sum_total = 0.0
    avg_count_total = 0
    loss_sum_total = 0.0
    loss_count_total = 0
    max_latency = None
    max_loss = None
    loss100_seconds = 0
    downtime_seconds = 0.0

    for row in rollups or []:
        ts = (row.get("bucket_ts") or "").strip()
        if not ts:
            continue
        sc = int(row.get("sample_count") or 0)
        oc = int(row.get("ok_count") or 0)
        sample_total += sc
        ok_total += oc

        a_sum = row.get("avg_sum")
        a_cnt = int(row.get("avg_count") or 0)
        l_sum = row.get("loss_sum")
        l_cnt = int(row.get("loss_count") or 0)

        if a_sum is not None:
            try:
                avg_sum_total += float(a_sum)
            except Exception:
                pass
        avg_count_total += a_cnt

        if l_sum is not None:
            try:
                loss_sum_total += float(l_sum)
            except Exception:
                pass
        loss_count_total += l_cnt

        avg_ms = (float(a_sum) / a_cnt) if (a_sum is not None and a_cnt) else None
        loss_pct = (float(l_sum) / l_cnt) if (l_sum is not None and l_cnt) else None
        points.append({"ts": ts, "avg_ms": avg_ms, "loss": loss_pct})

        if avg_ms is not None:
            max_latency = avg_ms if max_latency is None else max(max_latency, avg_ms)
        if loss_pct is not None:
            max_loss = loss_pct if max_loss is None else max(max_loss, loss_pct)
            # Downtime is an "equivalent downtime" derived from loss%.
            # Example: 10% loss over a 60s bucket contributes ~6 seconds of downtime.
            try:
                downtime_seconds += (float(loss_pct) / 100.0) * float(bucket_seconds)
            except Exception:
                pass
            if loss_pct >= 99.999:
                loss100_seconds += int(bucket_seconds)

    avg_latency = (avg_sum_total / avg_count_total) if avg_count_total else None
    avg_loss = (loss_sum_total / loss_count_total) if loss_count_total else None
    uptime_pct = (ok_total / sample_total * 100.0) if sample_total else 0.0
    return {
        "points": points,
        "stats": {
            "samples": sample_total,
            "uptime_pct": uptime_pct,
            "avg_latency_ms": avg_latency,
            "max_latency_ms": max_latency,
            "avg_loss_pct": avg_loss,
            "max_loss_pct": max_loss,
            "loss100_seconds": loss100_seconds,
            "downtime_seconds": int(round(downtime_seconds)),
            "bucket_seconds": int(bucket_seconds),
        },
    }


def _surv_raw_points_and_stats(rows):
    items = []
    for row in rows or []:
        ts = (row.get("timestamp") or "").strip()
        if not ts:
            continue
        dt = _parse_iso_z(ts)
        if not dt:
            continue
        items.append(
            {
                "ts": ts,
                "dt": dt,
                "ok": bool(row.get("ok")),
                "loss": row.get("loss"),
                "avg_ms": row.get("avg_ms"),
            }
        )
    items.sort(key=lambda x: x["dt"])
    if not items:
        return {"points": [], "stats": {"samples": 0, "uptime_pct": 0.0, "avg_latency_ms": None, "max_latency_ms": None, "avg_loss_pct": None, "max_loss_pct": None, "loss100_seconds": 0, "downtime_seconds": 0, "bucket_seconds": 0}}

    # Collapse duplicate timestamps (common when multiple checks happen within the same second)
    # by keeping the "worst" values for that timestamp. Without this, spike samples can be
    # de-duplicated away later and mini charts can misleadingly look "clean".
    merged = []
    cur = None
    for it in items:
        if cur is None or it["dt"] != cur["dt"]:
            if cur is not None:
                merged.append(cur)
            cur = dict(it)
            continue
        # Same timestamp: merge (worst-case).
        cur["ok"] = bool(cur.get("ok")) or bool(it.get("ok"))
        for k in ("loss", "avg_ms"):
            a = cur.get(k)
            b = it.get(k)
            try:
                av = float(a) if a is not None else None
            except Exception:
                av = None
            try:
                bv = float(b) if b is not None else None
            except Exception:
                bv = None
            if av is None:
                cur[k] = b
            elif bv is None:
                pass
            else:
                cur[k] = b if bv > av else a
    if cur is not None:
        merged.append(cur)
    items = merged

    deltas = []
    for i in range(len(items) - 1):
        d = (items[i + 1]["dt"] - items[i]["dt"]).total_seconds()
        if d <= 0:
            continue
        deltas.append(d)
    deltas_sorted = sorted(deltas)
    if deltas_sorted:
        mid = deltas_sorted[len(deltas_sorted) // 2]
        default_dt = max(1.0, min(float(mid), 300.0))
    else:
        default_dt = 60.0

    sample_total = 0
    ok_total = 0
    avg_sum_total = 0.0
    avg_count_total = 0
    loss_sum_total = 0.0
    loss_count_total = 0
    max_latency = None
    max_loss = None
    loss100_seconds = 0.0
    downtime_seconds = 0.0

    for i, it in enumerate(items):
        sample_total += 1
        if it["ok"]:
            ok_total += 1
        avg_ms = it["avg_ms"]
        if avg_ms is not None:
            try:
                v = float(avg_ms)
                avg_sum_total += v
                avg_count_total += 1
                max_latency = v if max_latency is None else max(max_latency, v)
            except Exception:
                pass
        loss = it["loss"]
        loss_pct = None
        if loss is not None:
            try:
                loss_pct = float(loss)
                loss_sum_total += loss_pct
                loss_count_total += 1
                max_loss = loss_pct if max_loss is None else max(max_loss, loss_pct)
            except Exception:
                loss_pct = None

        if i < len(items) - 1:
            duration = (items[i + 1]["dt"] - it["dt"]).total_seconds()
        else:
            duration = default_dt
        if duration <= 0:
            duration = default_dt
        duration = max(1.0, min(float(duration), 300.0))

        if loss_pct is not None:
            downtime_seconds += (loss_pct / 100.0) * duration
            if loss_pct >= 99.999:
                loss100_seconds += duration

    avg_latency = (avg_sum_total / avg_count_total) if avg_count_total else None
    avg_loss = (loss_sum_total / loss_count_total) if loss_count_total else None
    uptime_pct = (ok_total / sample_total * 100.0) if sample_total else 0.0
    points = [{"ts": it["ts"], "avg_ms": (float(it["avg_ms"]) if it["avg_ms"] is not None else None), "loss": (float(it["loss"]) if it["loss"] is not None else None)} for it in items]
    return {
        "points": points,
        "stats": {
            "samples": sample_total,
            "uptime_pct": uptime_pct,
            "avg_latency_ms": avg_latency,
            "max_latency_ms": max_latency,
            "avg_loss_pct": avg_loss,
            "max_loss_pct": max_loss,
            "loss100_seconds": int(round(loss100_seconds)),
            "downtime_seconds": int(round(downtime_seconds)),
            "bucket_seconds": int(round(default_dt)),
        },
    }


def _surv_downsample_points(points, max_points=96):
    pts = list(points or [])
    if len(pts) <= max_points:
        return pts
    # Preserve spikes by including max-loss point per chunk (plus endpoints).
    # This is important for mini charts where rare loss spikes would otherwise be skipped.
    step = max(1, int((len(pts) + max_points - 1) // max_points))
    out = []
    for i in range(0, len(pts), step):
        chunk = pts[i : i + step]
        if not chunk:
            continue
        out.append(chunk[0])

        # Add peak loss point (if any).
        best_loss = None
        for p in chunk:
            loss = p.get("loss")
            if loss is None:
                continue
            try:
                v = float(loss)
            except Exception:
                continue
            if best_loss is None or v > best_loss[0]:
                best_loss = (v, p)
        if best_loss is not None:
            out.append(best_loss[1])

        # Add peak latency point (if any).
        best_lat = None
        for p in chunk:
            avg_ms = p.get("avg_ms")
            if avg_ms is None:
                continue
            try:
                v = float(avg_ms)
            except Exception:
                continue
            if best_lat is None or v > best_lat[0]:
                best_lat = (v, p)
        if best_lat is not None:
            out.append(best_lat[1])

        out.append(chunk[-1])

    # De-duplicate by timestamp while preserving order, but keep the "worst" values
    # when duplicates exist so we don't lose spikes.
    seen = {}
    order = []
    for p in out:
        ts = (p.get("ts") or "").strip()
        if not ts:
            continue
        if ts not in seen:
            seen[ts] = dict(p)
            order.append(ts)
            continue
        existing = seen[ts]
        for k in ("loss", "avg_ms"):
            a = existing.get(k)
            b = p.get(k)
            try:
                av = float(a) if a is not None else None
            except Exception:
                av = None
            try:
                bv = float(b) if b is not None else None
            except Exception:
                bv = None
            if av is None:
                existing[k] = b
            elif bv is None:
                pass
            else:
                existing[k] = b if bv > av else a
    return [seen[ts] for ts in order]


@app.get("/surveillance/series_range", response_class=JSONResponse)
async def surveillance_series_range(pppoe: str, since: str, until: str):
    pppoe = (pppoe or "").strip()
    since = (since or "").strip()
    until = (until or "").strip()
    if not pppoe or not since or not until:
        return JSONResponse({"pppoe": pppoe, "series": []})
    account_id = _accounts_ping_account_id_for_pppoe(pppoe)
    rows = get_accounts_ping_series_range(account_id, since, until)
    # Keep the range chart consistent with the dropdown chart by using the same raw dataset.
    series = []
    cur = None
    cur_ts = None
    for row in rows or []:
        ts = (row.get("timestamp") or "").strip()
        if not ts:
            continue
        ok = bool(row.get("ok"))
        loss = row.get("loss")
        avg_ms = row.get("avg_ms")
        mode = row.get("mode")
        if cur is None or ts != cur_ts:
            if cur is not None:
                series.append(cur)
            cur_ts = ts
            cur = {"ts": ts, "ok": ok, "loss": loss, "avg_ms": avg_ms, "mode": mode}
            continue
        cur["ok"] = bool(cur.get("ok")) or ok
        for k, v in (("loss", loss), ("avg_ms", avg_ms)):
            a = cur.get(k)
            b = v
            try:
                av = float(a) if a is not None else None
            except Exception:
                av = None
            try:
                bv = float(b) if b is not None else None
            except Exception:
                bv = None
            if av is None:
                cur[k] = b
            elif bv is None:
                pass
            else:
                cur[k] = b if bv > av else a
    if cur is not None:
        series.append(cur)
    return JSONResponse({"pppoe": pppoe, "since": since, "until": until, "series": series})


@app.get("/surveillance/timeline", response_class=JSONResponse)
async def surveillance_timeline(pppoe: str, until: str = ""):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return JSONResponse({"pppoe": "", "days": [], "summary": {}, "total": {}})

    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    added_at_iso = (entry.get("added_at") or "").strip()
    added_dt = _parse_iso_z(added_at_iso) or datetime.utcnow().replace(microsecond=0)
    tz = ZoneInfo("Asia/Manila")
    added_local = added_dt.replace(tzinfo=timezone.utc).astimezone(tz)
    now_local = datetime.now(tz)

    # Day 1 is the calendar day the account was added to Surveillance (Asia/Manila).
    # Day 0 is a 7-day overview (stats + optional chart range).
    start_day = added_local.date()
    current_day_index = (now_local.date() - start_day).days + 1
    if current_day_index < 1:
        current_day_index = 1
    total_days = max(7, current_day_index + 1)

    def day_start_local(day_date):
        return datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0, tzinfo=tz)

    def to_utc_iso(dt_local):
        return dt_local.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    account_id = _accounts_ping_account_id_for_pppoe(pppoe)

    day_items = []
    # Day 0 is a rolling "Last 7d" overview. Anchor it to the same `until` the big chart uses
    # so the Day 0 tile matches the dropdown's 7d window exactly.
    anchor_until = (until or "").strip()
    anchor_dt = _parse_iso_z(anchor_until) if anchor_until else None
    now_utc = (anchor_dt or datetime.utcnow()).replace(microsecond=0)
    range7_since_utc = (now_utc - timedelta(hours=168)).replace(microsecond=0)
    range7_until_utc = now_utc
    range7_since_iso = range7_since_utc.isoformat() + "Z"
    range7_until_iso = range7_until_utc.isoformat() + "Z"
    # Use raw samples for Day 0 to match the big chart's 7d dropdown (investigation view).
    summary7_rows = get_accounts_ping_series_range(account_id, range7_since_iso, range7_until_iso)
    summary7_payload = _surv_raw_points_and_stats(summary7_rows)
    summary7 = summary7_payload["stats"]
    summary7_points = _surv_downsample_points(summary7_payload["points"], max_points=160)

    # Total since added (rounded down to minute boundary).
    added_floor = added_dt.replace(second=0, microsecond=0)
    total_rollups = get_accounts_ping_rollups_range(
        account_id,
        added_floor.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        to_utc_iso(now_local + timedelta(minutes=1)),
    )
    total_stats = _surv_rollup_points_and_stats(total_rollups, bucket_seconds=60)["stats"]

    for idx in range(1, total_days + 1):
        day_date = start_day + timedelta(days=idx - 1)
        kind = "future"
        if day_date < now_local.date():
            kind = "past"
        elif day_date == now_local.date():
            kind = "today"

        start_local = day_start_local(day_date)
        until_local = day_start_local(day_date + timedelta(days=1))
        # For today, stop at "now" for partial rendering.
        query_until_local = until_local if kind == "past" else min(until_local, now_local + timedelta(minutes=1))

        series = []
        stats = None
        if kind != "future":
            rollups = get_accounts_ping_rollups_range(account_id, to_utc_iso(start_local), to_utc_iso(query_until_local))
            payload = _surv_rollup_points_and_stats(rollups, bucket_seconds=60)
            stats = payload["stats"]
            series = _surv_downsample_points(payload["points"], max_points=96)

        hours_so_far = None
        if kind == "today":
            seconds = max(0, (now_local - start_local).total_seconds())
            hours_so_far = round(seconds / 3600.0, 1)

        day_items.append(
            {
                "index": idx,
                "date": day_date.isoformat(),
                "label": f"Day {idx}",
                "date_label": start_local.strftime("%b %d"),
                "kind": kind,
                "hours_so_far": hours_so_far,
                "start_iso": to_utc_iso(start_local),
                "until_iso": to_utc_iso(until_local),
                "series": [{"ts": p["ts"], "loss": p["loss"], "avg_ms": p["avg_ms"]} for p in series],
                "stats": stats,
            }
        )

    return JSONResponse(
        {
            "pppoe": pppoe,
            "added_at": added_at_iso,
            "start_day": start_day.isoformat(),
            "current_day_index": current_day_index,
            "total_days": total_days,
            "day0": {
                "label": "Day 0",
                "title": "Last 7d",
                "start_iso": range7_since_iso,
                "until_iso": range7_until_iso,
                "query_until_iso": range7_until_iso,
                "series": [{"ts": p["ts"], "loss": p["loss"], "avg_ms": p["avg_ms"]} for p in summary7_points],
                "stats": summary7,
            },
            "days": day_items,
            "summary7": summary7,
            "total": total_stats,
        }
    )


@app.post("/surveillance/settings", response_class=HTMLResponse)
async def surveillance_settings_save(request: Request):
    form = await request.form()
    current = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(current)

    def _float(name, default):
        try:
            return float(form.get(name, default))
        except Exception:
            return float(default)

    def _minutes_from_days(field, default_minutes, min_minutes=1):
        default_days = float(default_minutes) / 1440.0
        days = _float(field, default_days)
        if days <= 0:
            days = default_days
        minutes = int(round(days * 1440.0))
        if minutes < min_minutes:
            minutes = min_minutes
        return minutes

    settings = {
        **current,
        "enabled": parse_bool(form, "enabled"),
        "auto_add": {
            "enabled": parse_bool(form, "auto_add_enabled"),
            "window_days": _float("auto_add_window_days", (current.get("auto_add", {}) or {}).get("window_days", 3)),
            "min_down_events": parse_int(
                form,
                "auto_add_min_down_events",
                (current.get("auto_add", {}) or {}).get("min_down_events", 5),
            ),
            "scan_interval_minutes": parse_int(
                form,
                "auto_add_scan_interval_minutes",
                (current.get("auto_add", {}) or {}).get("scan_interval_minutes", 5),
            ),
            "max_add_per_eval": parse_int(
                form,
                "auto_add_max_add_per_eval",
                (current.get("auto_add", {}) or {}).get("max_add_per_eval", 3),
            ),
            "sources": {
                "accounts_ping": parse_bool(form, "auto_add_source_accounts_ping"),
            },
        },
        "ping": {
            **(current.get("ping") or {}),
            "interval_seconds": parse_int(form, "interval_seconds", current["ping"].get("interval_seconds", 1)),
            "count": parse_int(form, "ping_count", current["ping"].get("count", 1)),
            "timeout_seconds": parse_int(form, "ping_timeout_seconds", current["ping"].get("timeout_seconds", 1)),
            "burst_count": parse_int(form, "burst_count", current["ping"].get("burst_count", 1)),
            "burst_timeout_seconds": parse_int(form, "burst_timeout_seconds", current["ping"].get("burst_timeout_seconds", 1)),
            "max_parallel": parse_int(form, "max_parallel", current["ping"].get("max_parallel", 64)),
        },
        "burst": {
            **(current.get("burst") or {}),
            "enabled": parse_bool(form, "burst_enabled"),
            "burst_interval_seconds": parse_int(form, "burst_interval_seconds", current["burst"].get("burst_interval_seconds", 1)),
            "burst_duration_seconds": parse_int(form, "burst_duration_seconds", current["burst"].get("burst_duration_seconds", 120)),
            "trigger_on_issue": parse_bool(form, "trigger_on_issue"),
        },
        "backoff": {
            **(current.get("backoff") or {}),
            "long_down_seconds": parse_int(form, "long_down_seconds", current["backoff"].get("long_down_seconds", 7200)),
            "long_down_interval_seconds": parse_int(
                form, "long_down_interval_seconds", current["backoff"].get("long_down_interval_seconds", 300)
            ),
        },
        "stability": {
            **(current.get("stability") or {}),
            "stable_window_minutes": _minutes_from_days(
                "stable_window_days",
                current["stability"].get("stable_window_minutes", 10),
                min_minutes=1,
            ),
            "uptime_threshold_pct": _float("uptime_threshold_pct", current["stability"].get("uptime_threshold_pct", 95.0)),
            "latency_max_ms": _float("latency_max_ms", current["stability"].get("latency_max_ms", 15.0)),
            "loss_max_pct": _float("loss_max_pct", current["stability"].get("loss_max_pct", 100.0)),
            "optical_rx_min_dbm": _float("optical_rx_min_dbm", current["stability"].get("optical_rx_min_dbm", -24.0)),
            "require_optical": True,
            "escalate_after_minutes": _minutes_from_days(
                "escalate_after_days",
                current["stability"].get(
                    "escalate_after_minutes", current["stability"].get("stable_window_minutes", 10)
                ),
                min_minutes=1,
            ),
            "level2_autofix_after_minutes": _minutes_from_days(
                "level2_autofix_after_days",
                current["stability"].get("level2_autofix_after_minutes", 30),
                min_minutes=1,
            ),
        },
        "entries": list(entry_map.values()),
    }
    # normalize auto-add numeric bounds
    try:
        wd = float(settings["auto_add"].get("window_days", 3) or 3)
    except Exception:
        wd = 3.0
    if wd <= 0:
        wd = 3.0
    settings["auto_add"]["window_days"] = wd
    settings["auto_add"]["min_down_events"] = max(int(settings["auto_add"].get("min_down_events", 5) or 5), 1)
    settings["auto_add"]["scan_interval_minutes"] = max(int(settings["auto_add"].get("scan_interval_minutes", 5) or 5), 1)
    try:
        mae = int(settings["auto_add"].get("max_add_per_eval", 3))
    except Exception:
        mae = 3
    if mae < 0:
        mae = 0
    settings["auto_add"]["max_add_per_eval"] = mae

    save_settings("surveillance", settings)
    return RedirectResponse(url="/surveillance?tab=settings", status_code=303)


@app.post("/surveillance/add", response_class=JSONResponse)
async def surveillance_add(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    name = (form.get("name") or pppoe).strip()
    ip = (form.get("ip") or "").strip()
    source = (form.get("source") or "").strip()
    if not pppoe:
        return JSONResponse({"ok": False, "error": "Missing PPPoE"}, status_code=400)

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    now_iso = utc_now_iso()
    existing = entry_map.get(pppoe)
    if existing:
        existing["name"] = name or existing.get("name") or pppoe
        existing["ip"] = ip or existing.get("ip") or ""
        existing["updated_at"] = now_iso
        if source and not existing.get("source"):
            existing["source"] = source
        entry_map[pppoe] = existing
    else:
        entry_map[pppoe] = {
            "pppoe": pppoe,
            "name": name or pppoe,
            "ip": ip,
            "source": source,
            "status": "under",
            "added_at": now_iso,
            "updated_at": now_iso,
            "level2_at": "",
            "last_fixed_at": "",
            "last_fixed_reason": "",
            "last_fixed_mode": "",
            "added_mode": "manual",
            "auto_source": "",
            "auto_reason": "",
        }
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    try:
        ensure_surveillance_session(pppoe, started_at=now_iso, source=source, ip=ip, state="under")
    except Exception:
        pass
    return JSONResponse({"ok": True, "pppoe": pppoe})


@app.post("/surveillance/undo", response_class=JSONResponse)
async def surveillance_undo(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    if not pppoe:
        return JSONResponse({"ok": False, "error": "Missing PPPoE"}, status_code=400)
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe)
    if not entry:
        return JSONResponse({"ok": True, "pppoe": pppoe})
    added = _parse_iso_z(entry.get("added_at"))
    if not added:
        return JSONResponse({"ok": False, "error": "Cannot undo"}, status_code=400)
    if (datetime.utcnow() - added).total_seconds() > 5:
        return JSONResponse({"ok": False, "error": "Undo window expired"}, status_code=400)
    try:
        end_surveillance_session(
            pppoe,
            "removed",
            started_at=(entry.get("added_at") or "").strip(),
            source=(entry.get("source") or "").strip(),
            ip=(entry.get("ip") or "").strip(),
            state=(entry.get("status") or "under"),
        )
    except Exception:
        pass
    entry_map.pop(pppoe, None)
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    return JSONResponse({"ok": True, "pppoe": pppoe})


@app.post("/surveillance/remove", response_class=HTMLResponse)
async def surveillance_remove(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    if pppoe:
        entry = entry_map.get(pppoe) or {}
        try:
            end_surveillance_session(
                pppoe,
                "removed",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
            )
        except Exception:
            pass
        entry_map.pop(pppoe, None)
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    tab = (form.get("tab") or "under").strip() or "under"
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/remove_many", response_class=HTMLResponse)
async def surveillance_remove_many(request: Request):
    form = await request.form()
    raw_pppoes = (form.get("pppoes") or "").strip()
    tab = (form.get("tab") or "under").strip() or "under"

    pppoes: list[str] = []
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            # Fallback: comma-separated
            pppoes = [p.strip() for p in raw_pppoes.split(",") if p.strip()]

    if not pppoes:
        return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    # De-dupe while keeping order.
    seen = set()
    unique_pppoes = []
    for p in pppoes:
        if p in seen:
            continue
        seen.add(p)
        unique_pppoes.append(p)

    for pppoe in unique_pppoes:
        entry = entry_map.get(pppoe) or {}
        if not entry:
            continue
        try:
            end_surveillance_session(
                pppoe,
                "removed",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
            )
        except Exception:
            pass
        entry_map.pop(pppoe, None)

    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/fixed", response_class=HTMLResponse)
async def surveillance_fixed(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    reason = (form.get("reason") or "").strip()
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    if pppoe and pppoe in entry_map:
        old = dict(entry_map.get(pppoe) or {})
        if not reason or len(reason) < 3:
            return RedirectResponse(
                url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is required for Account Fixed.')}",
                status_code=303,
            )
        if len(reason) > 500:
            return RedirectResponse(
                url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is too long (max 500 characters).')}",
                status_code=303,
            )
        now_iso = utc_now_iso()
        try:
            end_surveillance_session(
                pppoe,
                "fixed",
                started_at=(old.get("added_at") or "").strip(),
                source=(old.get("source") or "").strip(),
                ip=(old.get("ip") or "").strip(),
                state=(old.get("status") or "level2"),
                note=reason,
            )
        except Exception:
            pass

        entry_map[pppoe]["status"] = "under"
        entry_map[pppoe]["added_at"] = now_iso
        entry_map[pppoe]["updated_at"] = now_iso
        entry_map[pppoe]["level2_at"] = ""
        entry_map[pppoe]["last_fixed_at"] = now_iso
        entry_map[pppoe]["last_fixed_reason"] = reason
        entry_map[pppoe]["last_fixed_mode"] = "manual"
        try:
            ensure_surveillance_session(
                pppoe,
                started_at=now_iso,
                source=(entry_map[pppoe].get("source") or "").strip(),
                ip=(entry_map[pppoe].get("ip") or "").strip(),
                state="under",
            )
        except Exception:
            pass
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    return RedirectResponse(url="/surveillance?tab=under", status_code=303)


@app.post("/surveillance/fixed_many", response_class=HTMLResponse)
async def surveillance_fixed_many(request: Request):
    form = await request.form()
    raw_pppoes = (form.get("pppoes") or "").strip()
    reason = (form.get("reason") or "").strip()

    pppoes: list[str] = []
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            pppoes = [p.strip() for p in raw_pppoes.split(",") if p.strip()]

    if not pppoes:
        return RedirectResponse(url="/surveillance?tab=level2", status_code=303)

    if not reason or len(reason) < 3:
        return RedirectResponse(
            url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is required for Account Fixed.')}",
            status_code=303,
        )
    if len(reason) > 500:
        return RedirectResponse(
            url=f"/surveillance?tab=level2&msg={urllib.parse.quote('Reason is too long (max 500 characters).')}",
            status_code=303,
        )

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    now_iso = utc_now_iso()

    seen = set()
    unique_pppoes: list[str] = []
    for p in pppoes:
        if p in seen:
            continue
        seen.add(p)
        unique_pppoes.append(p)

    for pppoe in unique_pppoes:
        if pppoe not in entry_map:
            continue
        old = dict(entry_map.get(pppoe) or {})
        try:
            end_surveillance_session(
                pppoe,
                "fixed",
                started_at=(old.get("added_at") or "").strip(),
                source=(old.get("source") or "").strip(),
                ip=(old.get("ip") or "").strip(),
                state=(old.get("status") or "level2"),
                note=reason,
            )
        except Exception:
            pass
        entry_map[pppoe]["status"] = "under"
        entry_map[pppoe]["added_at"] = now_iso
        entry_map[pppoe]["updated_at"] = now_iso
        entry_map[pppoe]["level2_at"] = ""
        entry_map[pppoe]["last_fixed_at"] = now_iso
        entry_map[pppoe]["last_fixed_reason"] = reason
        entry_map[pppoe]["last_fixed_mode"] = "manual"
        try:
            ensure_surveillance_session(
                pppoe,
                started_at=now_iso,
                source=(entry_map[pppoe].get("source") or "").strip(),
                ip=(entry_map[pppoe].get("ip") or "").strip(),
                state="under",
            )
        except Exception:
            pass

    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    return RedirectResponse(url="/surveillance?tab=under", status_code=303)

def render_wan_ping_response(request, pulse_settings, wan_settings, message, active_tab, wan_window_hours=24, wan_settings_tab="telegram"):
    if (active_tab or "").strip().lower() in ("add", "routers"):
        active_tab = "settings"
    active_tab = (active_tab or "status").strip().lower()
    if active_tab not in ("status", "settings", "messages"):
        active_tab = "settings"
    wan_settings_tab = (wan_settings_tab or "telegram").strip().lower()
    if wan_settings_tab not in ("telegram", "targets", "interval", "database", "danger"):
        wan_settings_tab = "telegram"
    wan_rows = build_wan_rows(pulse_settings, wan_settings)
    wan_state = get_state("wan_ping_state", {})
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=24)
    start_iso = window_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    end_iso = window_end.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    status_start = (datetime.now(timezone.utc) - timedelta(hours=max(int(wan_window_hours or 24), 1)))
    combined_start = min(window_start - timedelta(days=1), status_start)
    history_start_iso = combined_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    wan_ids = [row.get("wan_id") for row in wan_rows if row.get("wan_id")]
    history_map = fetch_wan_history_map(wan_ids, history_start_iso, end_iso)
    wan_latency_series = build_wan_latency_series(
        wan_rows,
        wan_state,
        hours=24,
        window_start=window_start,
        window_end=window_end,
        history_map=history_map,
    )
    wan_status = build_wan_status_summary(wan_rows, wan_state, history_map, window_hours=max(int(wan_window_hours or 24), 1))
    wan_targets = sorted({item.get("target") for item in wan_latency_series if item.get("target")})
    wan_refresh_seconds = int(wan_settings.get("general", {}).get("interval_seconds", 30) or 30)
    wan_target_refresh_seconds = int(
        wan_settings.get("general", {}).get("target_latency_interval_seconds", wan_refresh_seconds) or wan_refresh_seconds or 30
    )
    wan_target_rotation_raw = wan_settings.get("general", {}).get("target_rotation_enabled", False)
    if isinstance(wan_target_rotation_raw, str):
        wan_target_rotation_enabled = wan_target_rotation_raw.strip().lower() in ("1", "true", "yes", "on")
    else:
        wan_target_rotation_enabled = bool(wan_target_rotation_raw)
    wan_targets_per_wan_per_run_raw = wan_settings.get("general", {}).get("targets_per_wan_per_run", 1)
    if wan_targets_per_wan_per_run_raw in (None, ""):
        wan_targets_per_wan_per_run_raw = 1
    try:
        wan_targets_per_wan_per_run = max(int(wan_targets_per_wan_per_run_raw), 0)
    except Exception:
        wan_targets_per_wan_per_run = 1

    general_cfg = wan_settings.get("general") if isinstance(wan_settings.get("general"), dict) else {}
    enabled_targets = [
        item
        for item in (general_cfg.get("targets") or [])
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
    wan_target_default_host = (enabled_targets[0].get("host") or "").strip() if enabled_targets else ""
    wan_target_extra_targets = max(len(enabled_targets) - 1, 0)
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
                "wan_target_refresh_seconds": wan_target_refresh_seconds,
                "wan_target_rotation_enabled": wan_target_rotation_enabled,
                "wan_targets_per_wan_per_run": wan_targets_per_wan_per_run,
                "wan_status": wan_status,
                "wan_window_options": WAN_STATUS_WINDOW_OPTIONS,
                "wan_message_defaults": WAN_MESSAGE_DEFAULTS,
                "wan_summary_defaults": WAN_SUMMARY_DEFAULTS,
                "wan_target_default_host": wan_target_default_host,
                "wan_target_extra_targets": wan_target_extra_targets,
                "message": message,
                "active_tab": active_tab,
                "wan_settings_tab": wan_settings_tab,
            },
        ),
    )


@app.get("/settings/wan", response_class=HTMLResponse)
async def wan_settings(request: Request):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    window_hours = _normalize_wan_window(request.query_params.get("wan_window"))
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "", "status", window_hours)


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
        netwatch_host = (form.get(f"wan_{idx}_netwatch_host") or "").strip()
        if mode == "bridged" and not netwatch_host:
            netwatch_host = local_ip
        enabled = parse_bool(form, f"wan_{idx}_enabled")
        if not local_ip:
            enabled = False
        wans.append(
            {
                "id": wan_row_id(core_id, list_name),
                "core_id": core_id,
                "list_name": list_name,
                "identifier": (form.get(f"wan_{idx}_identifier") or "").strip(),
                "color": _sanitize_hex_color(form.get(f"wan_{idx}_color") or ""),
                "enabled": enabled,
                "mode": mode,
                "local_ip": local_ip,
                "gateway_ip": "",
                "netwatch_host": netwatch_host,
                "pppoe_router_id": (form.get(f"wan_{idx}_pppoe_router_id") or "").strip(),
            }
        )
    wan_settings_data["wans"] = wans
    save_settings("wan_ping", wan_settings_data)
    sync_errors = wan_ping_notifier.sync_netwatch(wan_settings_data, pulse_settings)
    save_settings("wan_ping", wan_settings_data)
    if sync_errors:
        message = "WAN list saved with Netwatch warnings: " + "; ".join(sync_errors)
    else:
        message = "WAN list saved and Netwatch synced."
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="isps")


@app.post("/settings/wan/routers", response_class=HTMLResponse)
async def wan_settings_save_routers(request: Request):
    form = await request.form()
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "router_count", 0)
    routers, removed_ids = _parse_wan_pppoe_routers_from_form(form, count)
    wan_settings_data["pppoe_routers"] = routers
    if removed_ids:
        for wan in wan_settings_data.get("wans", []):
            if wan.get("pppoe_router_id") in removed_ids:
                wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(request, "Mikrotik routers saved.", active_tab="routers", routers_tab="mikrotik-routers")


@app.post("/settings/wan/routers/add", response_class=HTMLResponse)
async def wan_settings_add_router(request: Request):
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
    return render_system_settings_response(request, "Mikrotik router added.", active_tab="routers", routers_tab="mikrotik-routers")


@app.post("/settings/wan/routers/remove/{router_id}", response_class=HTMLResponse)
async def wan_settings_remove_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = [router for router in wan_settings_data.get("pppoe_routers", []) if router.get("id") != router_id]
    wan_settings_data["pppoe_routers"] = routers
    for wan in wan_settings_data.get("wans", []):
        if wan.get("pppoe_router_id") == router_id:
            wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(request, "Mikrotik router removed.", active_tab="routers", routers_tab="mikrotik-routers")


@app.post("/settings/wan/routers/test/{router_id}", response_class=HTMLResponse)
async def wan_settings_test_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router = next(
        (item for item in wan_settings_data.get("pppoe_routers", []) if item.get("id") == router_id),
        None,
    )
    if not router:
        return render_system_settings_response(request, "Router not found.", active_tab="routers", routers_tab="mikrotik-routers")
    if router.get("use_tls"):
        return render_system_settings_response(
            request,
            "TLS test not supported yet. Disable TLS or use port 8728.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    host = (router.get("host") or "").strip()
    if not host:
        return render_system_settings_response(request, "Router host is required.", active_tab="routers", routers_tab="mikrotik-routers")
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
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="mikrotik-routers")


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
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Telegram settings saved.", "settings", wan_settings_tab="telegram")


@app.post("/settings/wan/targets", response_class=HTMLResponse)
async def wan_settings_save_targets(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "target_count", 0)
    raw_targets = []
    deleted_target_ids = []
    for idx in range(max(count, 0)):
        if parse_bool(form, f"target_{idx}_delete"):
            target_id = (form.get(f"target_{idx}_id") or "").strip()
            if target_id:
                deleted_target_ids.append(target_id)
            continue
        host = (form.get(f"target_{idx}_host") or "").strip()
        label = (form.get(f"target_{idx}_label") or "").strip()
        enabled = parse_bool(form, f"target_{idx}_enabled")
        if not host:
            continue
        target_id = (form.get(f"target_{idx}_id") or "").strip()
        if not target_id:
            base = re.sub(r"[^a-z0-9]+", "-", (label or host).lower()).strip("-")
            target_id = base or f"target-{idx+1}"
        raw_targets.append({"id": target_id, "label": label or host, "host": host, "enabled": enabled})

    seen = set()
    targets = []
    for item in raw_targets:
        base = item["id"]
        candidate = base
        suffix = 2
        while candidate in seen:
            candidate = f"{base}-{suffix}"
            suffix += 1
        seen.add(candidate)
        targets.append({**item, "id": candidate})

    wan_settings_data.setdefault("general", {})["targets"] = targets
    wan_settings_data.setdefault("general", {})["targets_configured"] = True
    save_settings("wan_ping", wan_settings_data)
    try:
        delete_wan_target_ping_results_for_targets(deleted_target_ids)
    except Exception:
        pass
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Targets saved.", "settings", wan_settings_tab="targets")


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
    general = wan_settings_data.setdefault("general", {})
    general["interval_seconds"] = max(interval, 5)
    target_interval = parse_int(form, "wan_target_latency_interval_seconds", general.get("interval_seconds", 30))
    general["target_latency_interval_seconds"] = max(target_interval, 1)
    general["target_rotation_enabled"] = parse_bool(form, "wan_target_rotation_enabled")
    parallel_workers = parse_int(form, "wan_target_parallel_workers", general.get("target_parallel_workers", 0))
    general["target_parallel_workers"] = max(min(parallel_workers, 64), 0)
    targets_per_wan = parse_int(form, "wan_targets_per_wan_per_run", general.get("targets_per_wan_per_run", 1))
    general["targets_per_wan_per_run"] = max(targets_per_wan, 0)
    timeout_ms = parse_int(form, "wan_target_ping_timeout_ms", general.get("target_ping_timeout_ms", 1000))
    general["target_ping_timeout_ms"] = max(min(timeout_ms, 60000), 100)
    ping_count = parse_int(form, "wan_target_ping_count", general.get("target_ping_count", 1))
    general["target_ping_count"] = max(min(ping_count, 20), 1)
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Polling settings saved.", "settings", wan_settings_tab="interval")


@app.post("/settings/wan/database", response_class=HTMLResponse)
async def wan_settings_save_database(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    retention = parse_int(form, "wan_history_retention_days", 400)
    retention = max(min(retention, 1460), 1)
    wan_settings_data.setdefault("general", {})["history_retention_days"] = retention
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Database settings saved.", "settings", wan_settings_tab="database")


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
            wan_settings_tab="danger",
        )
    save_state("wan_ping_state", {"reset_at": utc_now_iso(), "wans": {}})
    clear_wan_history()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    return render_wan_ping_response(
        request,
        pulse_settings,
        wan_settings_data,
        "WAN database cleared. WAN status history and Target Latency history removed. Settings preserved.",
        "settings",
        wan_settings_tab="danger",
    )


@app.get("/settings/pulsewatch")
async def legacy_pulsewatch_settings_redirect():
    return RedirectResponse(url="/settings/wan", status_code=302)


@app.api_route("/settings/pulsewatch/{legacy_path:path}", methods=["GET", "POST"])
async def legacy_pulsewatch_settings_path_redirect(legacy_path: str):
    return RedirectResponse(url="/settings/wan", status_code=302)


@app.api_route("/isp/pulsewatch/{legacy_path:path}", methods=["GET", "POST"])
async def legacy_pulsewatch_action_removed(legacy_path: str):
    return JSONResponse(
        {
            "ok": False,
            "message": "ISP Pulsewatch has been removed. Use WAN Ping instead.",
            "path": legacy_path,
        },
        status_code=410,
    )


@app.api_route("/pulsewatch/{legacy_path:path}", methods=["GET", "POST"])
async def legacy_pulsewatch_api_removed(legacy_path: str):
    return JSONResponse(
        {
            "ok": False,
            "message": "ISP Pulsewatch APIs were removed. Use WAN endpoints instead.",
            "path": legacy_path,
        },
        status_code=410,
    )


@app.get("/system/resources")
async def system_resources():
    mem = _memory_details_kb()
    mem_total_kb = int(mem.get("mem_total_kb") or 0)
    mem_avail_kb = int(mem.get("mem_available_kb") or 0)
    mem_free_kb = int(mem.get("mem_free_kb") or 0)
    mem_cached_kb = int(mem.get("cached_kb") or 0)
    mem_buffers_kb = int(mem.get("buffers_kb") or 0)
    return JSONResponse(
        {
            "cpu_pct": round(_cpu_percent(), 1),
            # ram_pct remains backward-compatible (pressure view, based on MemAvailable)
            "ram_pct": round(_memory_percent(), 1),
            # explicit fields:
            "ram_pressure_pct": round(_memory_percent(), 1),
            "ram_used_incl_cache_pct": round(_memory_used_including_cache_percent(), 1),
            # raw figures for debugging/UI (KB from /proc/meminfo)
            "ram_total_kb": mem_total_kb,
            "ram_available_kb": mem_avail_kb,
            "ram_free_kb": mem_free_kb,
            "ram_cached_kb": mem_cached_kb,
            "ram_buffers_kb": mem_buffers_kb,
            "disk_pct": round(_disk_percent(), 1),
            "uptime_seconds": _uptime_seconds(),
        }
    )
@app.post("/settings/system/mikrotik/test", response_class=HTMLResponse)
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


@app.get("/settings", response_class=HTMLResponse)
async def settings_root():
    return RedirectResponse(url="/settings/optical", status_code=302)

@app.get("/settings/system", response_class=HTMLResponse)
async def system_settings(request: Request):
    active_tab = (request.query_params.get("tab") or "general").strip().lower()
    if active_tab not in {"general", "routers", "backup", "danger"}:
        active_tab = "general"
    routers_tab = (request.query_params.get("routers_tab") or "cores").strip().lower()
    if routers_tab not in {"cores", "mikrotik-routers", "isps"}:
        routers_tab = "cores"
    return render_system_settings_response(request, "", active_tab=active_tab, routers_tab=routers_tab)


def render_system_settings_response(request: Request, message: str, active_tab: str = "general", routers_tab: str = "cores"):
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    # Back-compat: Usage originally had its own MikroTik router list. If System Settings is empty,
    # migrate those legacy routers into the shared list so other modules keep working.
    if not (wan_settings_data.get("pppoe_routers") or []):
        try:
            usage_settings = get_settings("usage", USAGE_DEFAULTS)
            legacy = (usage_settings.get("mikrotik") or {}).get("routers") or []
            migrated = []
            for item in legacy:
                if not isinstance(item, dict):
                    continue
                rid = (item.get("id") or "").strip()
                host = (item.get("host") or "").strip()
                if not rid or not host:
                    continue
                try:
                    port = int(item.get("port", 8728) or 8728)
                except Exception:
                    port = 8728
                migrated.append(
                    {
                        "id": rid,
                        "name": (item.get("name") or "").strip(),
                        "host": host,
                        "port": port,
                        "username": item.get("username", ""),
                        "password": item.get("password", ""),
                        "use_tls": False,
                    }
                )
            if migrated:
                wan_settings_data["pppoe_routers"] = migrated
                save_settings("wan_ping", wan_settings_data)
        except Exception:
            pass
    interfaces = get_interface_options()
    telegram_state = get_state("telegram_state", {})

    wan_rows_loaded = bool(active_tab == "routers" and routers_tab == "isps")
    wan_rows = []
    wan_autodetect_warnings = []
    if wan_rows_loaded:
        try:
            wan_rows = build_wan_rows(pulse_settings, wan_settings_data)
            detect_map, detect_warnings = detect_routed_wan_autofill(pulse_settings, wan_rows, probe_public=False)
            wan_autodetect_warnings = detect_warnings
            for row in wan_rows:
                key = ((row.get("core_id") or "").strip(), (row.get("list_name") or "").strip())
                detected = detect_map.get(key) or {}
                detected_local_ip = (detected.get("local_ip") or "").strip()
                detected_netwatch = (detected.get("netwatch_host") or "").strip()
                row["detected_local_ip"] = detected_local_ip
                row["detected_netwatch_host"] = detected_netwatch
                row["detected_interface"] = (detected.get("interface") or "").strip()
                row["detected_routing_mark"] = (detected.get("routing_mark") or "").strip()
                mode = (row.get("mode") or "routed").strip().lower()
                local_ip = (row.get("local_ip") or "").strip()
                netwatch_host = (row.get("netwatch_host") or "").strip()
                if mode == "routed":
                    local_ip = detected_local_ip
                    netwatch_host = detected_netwatch
                else:
                    if not netwatch_host:
                        netwatch_host = local_ip
                row["local_ip"] = local_ip
                row["netwatch_host"] = netwatch_host
                row["enabled"] = bool(row.get("enabled")) and bool(local_ip)
        except Exception:
            wan_rows = []
            wan_autodetect_warnings = []

    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {
                "message": message,
                "active_tab": active_tab,
                "routers_tab": routers_tab,
                "settings": pulse_settings,
                "wan_settings": wan_settings_data,
                "wan_rows": wan_rows,
                "wan_rows_loaded": wan_rows_loaded,
                "wan_autodetect_warnings": wan_autodetect_warnings,
                "interfaces": interfaces,
                "telegram_state": telegram_state,
            },
        ),
    )


def _parse_wan_pppoe_routers_from_form(form, count: int):
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
    return routers, removed_ids


def _parse_wan_list_from_form(form, count: int):
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
        netwatch_host = (form.get(f"wan_{idx}_netwatch_host") or "").strip()
        if not netwatch_host:
            netwatch_host = local_ip
        enabled = parse_bool(form, f"wan_{idx}_enabled")
        if not local_ip:
            enabled = False
        wans.append(
            {
                "id": wan_row_id(core_id, list_name),
                "core_id": core_id,
                "list_name": list_name,
                "identifier": (form.get(f"wan_{idx}_identifier") or "").strip(),
                "color": _sanitize_hex_color(form.get(f"wan_{idx}_color") or ""),
                "enabled": enabled,
                "mode": mode,
                "local_ip": local_ip,
                "gateway_ip": "",
                "netwatch_host": netwatch_host,
                "pppoe_router_id": (form.get(f"wan_{idx}_pppoe_router_id") or "").strip(),
            }
        )
    return wans


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
    message = "MikroTik settings saved."
    netplan_msg = None
    apply_msg = None
    try:
        netplan_path, netplan_msg, interface_map, route_specs = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map, route_specs)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if netplan_msg and "no router source IPs configured" not in netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg and not apply_msg.startswith("Netplan applied"):
        message = f"{message} {apply_msg}"
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="cores")


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
    message = "Telegram command settings saved."
    return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")


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
    if netplan_msg and "no router source IPs configured" not in netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg and not apply_msg.startswith("Netplan applied"):
        message = f"{message} {apply_msg}"
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="cores")


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
    if netplan_msg and "no router source IPs configured" not in netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg and not apply_msg.startswith("Netplan applied"):
        message = f"{message} {apply_msg}"
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="cores")


@app.post("/settings/system/routers/pppoe", response_class=HTMLResponse)
async def system_save_pppoe_routers(request: Request):
    form = await request.form()
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "router_count", 0)
    routers, removed_ids = _parse_wan_pppoe_routers_from_form(form, count)
    wan_settings_data["pppoe_routers"] = routers
    if removed_ids:
        for wan in wan_settings_data.get("wans", []):
            if wan.get("pppoe_router_id") in removed_ids:
                wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(
        request,
        "MikroTik routers saved.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/pppoe/add", response_class=HTMLResponse)
async def system_add_pppoe_router(request: Request):
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
    return render_system_settings_response(
        request,
        "MikroTik router added.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/pppoe/remove/{router_id}", response_class=HTMLResponse)
async def system_remove_pppoe_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    routers = [router for router in wan_settings_data.get("pppoe_routers", []) if router.get("id") != router_id]
    wan_settings_data["pppoe_routers"] = routers
    for wan in wan_settings_data.get("wans", []):
        if wan.get("pppoe_router_id") == router_id:
            wan["pppoe_router_id"] = ""
    save_settings("wan_ping", wan_settings_data)
    return render_system_settings_response(
        request,
        "MikroTik router removed.",
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/pppoe/test/{router_id}", response_class=HTMLResponse)
async def system_test_pppoe_router(request: Request, router_id: str):
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    router = next((item for item in wan_settings_data.get("pppoe_routers", []) if item.get("id") == router_id), None)
    if not router:
        return render_system_settings_response(
            request,
            "Router not found.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    if router.get("use_tls"):
        return render_system_settings_response(
            request,
            "TLS test not supported yet. Disable TLS or use port 8728.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
    host = (router.get("host") or "").strip()
    if not host:
        return render_system_settings_response(
            request,
            "Router host is required.",
            active_tab="routers",
            routers_tab="mikrotik-routers",
        )
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
    return render_system_settings_response(
        request,
        message,
        active_tab="routers",
        routers_tab="mikrotik-routers",
    )


@app.post("/settings/system/routers/isps", response_class=HTMLResponse)
async def system_save_isps(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    count = parse_int(form, "wan_count", 0)
    parsed_wans = _parse_wan_list_from_form(form, count)
    routed_detect_map, routed_detect_warnings = detect_routed_wan_autofill(pulse_settings, parsed_wans, probe_public=True)
    local_warnings = []
    for wan in parsed_wans:
        mode = (wan.get("mode") or "routed").strip().lower()
        local_ip = ""
        netwatch_host = ""
        if mode == "routed":
            key = ((wan.get("core_id") or "").strip(), (wan.get("list_name") or "").strip())
            detected = routed_detect_map.get(key) or {}
            detected_local = (detected.get("local_ip") or "").strip()
            detected_netwatch = (detected.get("netwatch_host") or "").strip()
            local_ip = detected_local
            netwatch_host = detected_netwatch
            if not local_ip:
                local_warnings.append(f"{wan.get('core_id')} {wan.get('list_name')}: no auto-detected local IP")
            if not netwatch_host:
                local_warnings.append(f"{wan.get('core_id')} {wan.get('list_name')}: no auto-detected WAN/public IP")
        else:
            local_ip = (wan.get("local_ip") or "").strip()
            netwatch_host = (wan.get("netwatch_host") or "").strip()
            if not netwatch_host:
                netwatch_host = local_ip
        wan["local_ip"] = local_ip
        wan["netwatch_host"] = netwatch_host
        if not local_ip:
            wan["enabled"] = False
    wan_settings_data["wans"] = parsed_wans
    save_settings("wan_ping", wan_settings_data)
    sync_errors = wan_ping_notifier.sync_netwatch(wan_settings_data, pulse_settings)
    save_settings("wan_ping", wan_settings_data)
    warn_parts = []
    if routed_detect_warnings:
        warn_parts.append("Auto-detect: " + "; ".join(routed_detect_warnings[:6]))
    if local_warnings:
        warn_parts.append("Routed IP checks: " + "; ".join(local_warnings[:6]))
    if sync_errors:
        warn_parts.append("Netwatch: " + "; ".join(sync_errors[:6]))
    if warn_parts:
        message = "ISP list saved with warnings: " + " | ".join(warn_parts)
    else:
        message = "ISP list saved and Netwatch synced."
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="isps")


@app.post("/settings/system/uninstall", response_class=HTMLResponse)
async def system_uninstall(request: Request):
    form = await request.form()
    confirm_text = (form.get("confirm_text") or "").strip().upper()
    message = ""
    if confirm_text != "UNINSTALL":
        message = "Confirmation text does not match. Type UNINSTALL to proceed."
        return render_system_settings_response(request, message, active_tab="danger", routers_tab="cores")

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

    return render_system_settings_response(request, message, active_tab="danger", routers_tab="cores")


@app.post("/settings/system/logo", response_class=HTMLResponse)
async def system_logo_upload(request: Request, company_logo: UploadFile = File(...)):
    message = ""

    if not company_logo or not (company_logo.filename or "").strip():
        message = "Please select an image file to upload."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    content_type = (company_logo.content_type or "").lower().strip()
    if not content_type.startswith("image/"):
        message = "Invalid file type. Please upload an image only."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    header = await company_logo.read(512)
    await company_logo.seek(0)
    kind = imghdr.what(None, header)
    allowed_kinds = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
    if kind not in allowed_kinds:
        message = "Invalid image. Please upload a PNG, JPG, WebP, or GIF."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    max_bytes = 5 * 1024 * 1024
    public_dir = DATA_DIR / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    for old in public_dir.glob("company_logo.*"):
        try:
            old.unlink()
        except OSError:
            pass
    ext = "jpg" if kind == "jpeg" else kind
    dest = public_dir / f"company_logo.{ext}"
    written = 0
    try:
        with open(dest, "wb") as handle:
            while True:
                chunk = await company_logo.read(1024 * 256)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError("File too large")
                handle.write(chunk)
    except ValueError:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = "Image too large. Max size is 5MB."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = f"Upload failed: {exc}"
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    branding = dict(system_settings.get("branding") or {})
    branding["company_logo"] = {
        "path": str(dest),
        "content_type": allowed_kinds.get(kind) or content_type,
        "updated_at": utc_now_iso(),
    }
    system_settings["branding"] = branding
    save_settings("system", system_settings)

    message = "Company logo updated."
    return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")


@app.post("/settings/system/browser-logo", response_class=HTMLResponse)
async def system_browser_logo_upload(request: Request, browser_logo: UploadFile = File(...)):
    message = ""

    if not browser_logo or not (browser_logo.filename or "").strip():
        message = "Please select an image file to upload."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    content_type = (browser_logo.content_type or "").lower().strip()
    if not content_type.startswith("image/") and content_type not in {"application/octet-stream"}:
        message = "Invalid file type. Please upload an image only."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    header = await browser_logo.read(512)
    await browser_logo.seek(0)
    kind = imghdr.what(None, header)
    is_ico = header[:4] == b"\x00\x00\x01\x00"
    allowed_kinds = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
    if kind not in allowed_kinds and not is_ico:
        message = "Invalid image. Please upload a PNG, JPG, WebP, GIF, or ICO."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    max_bytes = 2 * 1024 * 1024
    public_dir = DATA_DIR / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    for old in public_dir.glob("browser_logo.*"):
        try:
            old.unlink()
        except OSError:
            pass
    if is_ico:
        ext = "ico"
        media = "image/x-icon"
    else:
        ext = "jpg" if kind == "jpeg" else kind
        media = allowed_kinds.get(kind) or content_type or "image/png"
    dest = public_dir / f"browser_logo.{ext}"
    written = 0
    try:
        with open(dest, "wb") as handle:
            while True:
                chunk = await browser_logo.read(1024 * 256)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError("File too large")
                handle.write(chunk)
    except ValueError:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = "Image too large. Max size is 2MB."
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = f"Upload failed: {exc}"
        return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")

    system_settings = get_settings("system", SYSTEM_DEFAULTS)
    branding = dict(system_settings.get("branding") or {})
    branding["browser_logo"] = {
        "path": str(dest),
        "content_type": media,
        "updated_at": utc_now_iso(),
    }
    system_settings["branding"] = branding
    save_settings("system", system_settings)

    message = "Browser logo updated."
    return render_system_settings_response(request, message, active_tab="general", routers_tab="cores")
