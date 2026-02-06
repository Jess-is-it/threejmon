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
import urllib.parse
import urllib.request
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
    clear_pulsewatch_data,
    clear_wan_history,
    end_surveillance_session,
    ensure_surveillance_session,
    fetch_wan_history_map,
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
    get_latest_speedtest_map,
    get_optical_latest_results_since,
    get_optical_results_for_device_since,
    get_optical_rx_series_for_devices_since,
    get_optical_samples_for_devices_since,
    get_optical_worst_candidates,
    get_ping_history_map,
    get_ping_latency_trend_map,
    get_ping_latency_trend_window,
    get_ping_rollup_history_map,
    get_ping_stability_counts,
    get_offline_history_since,
    get_pppoe_usage_series_since,
    get_recent_optical_readings,
    init_db,
    list_surveillance_history,
    search_optical_customers,
    touch_surveillance_session,
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
    general.setdefault("history_retention_days", 400)
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


WAN_STATUS_WINDOW_OPTIONS = [
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


WAN_STATUS_WINDOW_OPTIONS = [
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
    pulse_rows, _ = build_pulsewatch_rows(settings)
    pulse_ids = [row.get("row_id") for row in pulse_rows if row.get("row_id")]
    speedtests = get_latest_speedtest_map(pulse_ids)
    dashboard_cfg = settings.get("pulsewatch", {}).get("dashboard", {})
    summary_target = (dashboard_cfg.get("default_target") or "all").strip() or "all"
    summary_minutes = int(dashboard_cfg.get("loss_history_minutes", 120) or 120)
    summary_since = (datetime.now(timezone.utc) - timedelta(minutes=summary_minutes)).isoformat().replace("+00:00", "Z")
    target_filter = None if summary_target == "all" else summary_target
    ping_history = get_ping_rollup_history_map(pulse_ids, summary_since, target=target_filter)
    latency_since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    latency_history = get_ping_latency_trend_map(pulse_ids, latency_since)
    pulse_dashboard_rows = build_pulsewatch_dashboard_rows(settings, state, speedtests, ping_history)
    pulse_display_rows = [row for row in pulse_dashboard_rows if (row.get("source_ip") or "").strip()]
    pulse_latency_series = build_pulsewatch_latency_series(pulse_display_rows, latency_history)
    pulse_targets = sorted({item.get("target") for item in pulse_latency_series if item.get("target")})
    pulse_enabled = bool(settings.get("pulsewatch", {}).get("enabled"))
    pulse_state = state.get("pulsewatch", {})
    pulse_last_reconcile = format_ts_ph(pulse_state.get("last_mikrotik_reconcile_at"))
    pulse_last_check = format_ts_ph(pulse_state.get("last_check_at"))
    pulse_total = len(pulse_display_rows)
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
                "pulse_latency_series": pulse_latency_series,
                "pulse_targets": pulse_targets,
                "pulse_summary_target": summary_target,
                "pulse_summary_refresh": int(dashboard_cfg.get("refresh_seconds", 2) or 2),
                "pulse_summary_loss_minutes": summary_minutes,
                "pulse_rows": pulse_display_rows,
                "pulse_last_check": pulse_last_check,
                "pulse_last_reconcile": pulse_last_reconcile,
                "pulse_total": pulse_total,
                "pulse_enabled": pulse_enabled,
                "isp_state": state,
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


@app.get("/pulsewatch/loss_series", response_class=JSONResponse)
async def pulsewatch_loss_series(row_id: str, target: str = "all", loss_minutes: int = 120):
    minutes = max(int(loss_minutes or 120), 1)
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    target_filter = None if target == "all" else target
    history_map = get_ping_rollup_history_map([row_id], since, target=target_filter)
    history = history_map.get(row_id, [])
    series = [
        {"ts": item.get("timestamp"), "value": item.get("loss")}
        for item in history
        if item.get("timestamp") and item.get("loss") is not None
    ]
    return JSONResponse({"minutes": minutes, "series": series})


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
            message = "Routers are saved in the Routers tab."
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
    form = await request.form()
    settings = get_settings("usage", USAGE_DEFAULTS)
    settings["mikrotik"] = settings.get("mikrotik") if isinstance(settings.get("mikrotik"), dict) else {}
    routers = settings["mikrotik"].get("routers") if isinstance(settings["mikrotik"].get("routers"), list) else []
    count = parse_int(form, "router_count", len(routers))
    next_routers = []
    for idx in range(count):
        router_id = (form.get(f"router_{idx}_id") or "").strip()
        if not router_id:
            continue
        if parse_bool(form, f"router_{idx}_remove"):
            continue
        next_routers.append(
            {
                "id": router_id,
                "name": (form.get(f"router_{idx}_name") or "").strip(),
                "host": (form.get(f"router_{idx}_host") or "").strip(),
                "port": parse_int(form, f"router_{idx}_port", 8728),
                "username": (form.get(f"router_{idx}_username") or "").strip(),
                "password": (form.get(f"router_{idx}_password") or "").strip(),
                "enabled": parse_bool(form, f"router_{idx}_enabled"),
            }
        )
    settings["mikrotik"]["routers"] = next_routers
    save_settings("usage", settings)
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": "Routers saved.",
                "active_tab": "settings",
                "settings_tab": "routers",
                "usage_job": usage_job,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
            },
        ),
    )


@app.post("/settings/usage/routers/add", response_class=HTMLResponse)
async def usage_add_router(request: Request):
    settings = get_settings("usage", USAGE_DEFAULTS)
    settings["mikrotik"] = settings.get("mikrotik") if isinstance(settings.get("mikrotik"), dict) else {}
    routers = settings["mikrotik"].get("routers") if isinstance(settings["mikrotik"].get("routers"), list) else []
    existing_ids = {r.get("id") for r in routers if isinstance(r, dict) and r.get("id")}
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
            "enabled": True,
        }
    )
    settings["mikrotik"]["routers"] = routers
    save_settings("usage", settings)
    return RedirectResponse(url="/settings/usage?tab=settings&settings_tab=routers#usage-routers", status_code=302)


@app.post("/settings/usage/routers/test/{router_id}", response_class=HTMLResponse)
async def usage_test_router(request: Request, router_id: str):
    settings = get_settings("usage", USAGE_DEFAULTS)
    routers = (settings.get("mikrotik") or {}).get("routers") or []
    router = next((r for r in routers if isinstance(r, dict) and (r.get("id") or "").strip() == (router_id or "").strip()), None)
    message = ""
    if not router:
        message = "Router not found."
    else:
        host = (router.get("host") or "").strip()
        if not host:
            message = "Router host is required."
        else:
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

    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    usage_job = job_status.get("usage", {})
    usage_job = {
        "last_run_at_ph": format_ts_ph(usage_job.get("last_run_at")),
        "last_success_at_ph": format_ts_ph(usage_job.get("last_success_at")),
        "last_error": (usage_job.get("last_error") or "").strip(),
        "last_error_at_ph": format_ts_ph(usage_job.get("last_error_at")),
    }
    state = get_state("usage_state", {})
    return templates.TemplateResponse(
        "settings_usage.html",
        make_context(
            request,
            {
                "settings": settings,
                "message": message,
                "active_tab": "settings",
                "settings_tab": "routers",
                "usage_job": usage_job,
                "usage_state": {
                    "last_check": format_ts_ph(state.get("last_check_at")),
                    "genieacs_last_refresh": format_ts_ph(state.get("last_genieacs_refresh_at")),
                    "genieacs_error": (state.get("genieacs_error") or "").strip(),
                },
            },
        ),
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
    usage_settings = get_settings("usage", USAGE_DEFAULTS)
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
                "usage_settings": usage_settings,
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
    usage_settings = get_settings("usage", USAGE_DEFAULTS)
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
                "usage_settings": usage_settings,
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

def render_wan_ping_response(request, pulse_settings, wan_settings, message, active_tab, wan_window_hours=24):
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
                "wan_status": wan_status,
                "wan_window_options": WAN_STATUS_WINDOW_OPTIONS,
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


@app.post("/settings/wan/database", response_class=HTMLResponse)
async def wan_settings_save_database(request: Request):
    form = await request.form()
    pulse_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    wan_settings_data = normalize_wan_ping_settings(get_settings("wan_ping", WAN_PING_DEFAULTS))
    retention = parse_int(form, "wan_history_retention_days", 400)
    retention = max(min(retention, 1460), 1)
    wan_settings_data.setdefault("general", {})["history_retention_days"] = retention
    save_settings("wan_ping", wan_settings_data)
    return render_wan_ping_response(request, pulse_settings, wan_settings_data, "Database settings saved.", "settings")


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
    clear_wan_history()
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


@app.post("/settings/system/logo", response_class=HTMLResponse)
async def system_logo_upload(request: Request, company_logo: UploadFile = File(...)):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    telegram_state = get_state("telegram_state", {})
    message = ""

    if not company_logo or not (company_logo.filename or "").strip():
        message = "Please select an image file to upload."
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

    content_type = (company_logo.content_type or "").lower().strip()
    if not content_type.startswith("image/"):
        message = "Invalid file type. Please upload an image only."
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

    header = await company_logo.read(512)
    await company_logo.seek(0)
    kind = imghdr.what(None, header)
    allowed_kinds = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
    if kind not in allowed_kinds:
        message = "Invalid image. Please upload a PNG, JPG, WebP, or GIF."
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

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
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = f"Upload failed: {exc}"
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

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
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
        ),
    )


@app.post("/settings/system/browser-logo", response_class=HTMLResponse)
async def system_browser_logo_upload(request: Request, browser_logo: UploadFile = File(...)):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    telegram_state = get_state("telegram_state", {})
    message = ""

    if not browser_logo or not (browser_logo.filename or "").strip():
        message = "Please select an image file to upload."
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

    content_type = (browser_logo.content_type or "").lower().strip()
    if not content_type.startswith("image/") and content_type not in {"application/octet-stream"}:
        message = "Invalid file type. Please upload an image only."
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

    header = await browser_logo.read(512)
    await browser_logo.seek(0)
    kind = imghdr.what(None, header)
    is_ico = header[:4] == b"\x00\x00\x01\x00"
    allowed_kinds = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
    if kind not in allowed_kinds and not is_ico:
        message = "Invalid image. Please upload a PNG, JPG, WebP, GIF, or ICO."
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

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
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        message = f"Upload failed: {exc}"
        return templates.TemplateResponse(
            "settings_system.html",
            make_context(
                request,
                {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
            ),
        )

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
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {"message": message, "settings": settings, "interfaces": interfaces, "telegram_state": telegram_state},
        ),
    )
