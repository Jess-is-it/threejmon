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
    clear_surveillance_history,
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
    get_accounts_ping_checker_stats_map,
    get_accounts_ping_window_stats,
    get_accounts_ping_window_stats_by_ip,
    get_job_status,
    get_latest_accounts_ping_map,
    get_latest_optical_by_pppoe,
    get_latest_optical_device_for_ip,
    get_latest_optical_identity,
    get_surveillance_fixed_cycles_map,
    get_surveillance_session_by_id,
    get_optical_latest_results_since,
    get_optical_results_for_device_since,
    get_optical_rx_series_for_devices_since,
    get_optical_samples_for_devices_since,
    get_optical_worst_candidates,
    get_wan_status_counts,
    increment_surveillance_observed,
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
from .feature_usage import add_feature_cpu, sample_feature_cpu_percent, register_feature
from .ai_investigator import AIInvestigatorError, generate_investigation_report
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
    },
    "ai": {
        "enabled": False,
        "provider": "chatgpt",
        "chatgpt": {
            "api_key": "",
            "model": "gpt-4o-mini",
            "timeout_seconds": 30,
            "max_tokens": 900,
        },
        "gemini": {
            "api_key": "",
            "model": "gemini-2.5-flash-preview-09-2025",
            "timeout_seconds": 30,
            "max_tokens": 900,
        },
        "report": {
            "lookback_hours": 24,
            "max_samples": 60,
        },
    },
}

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

jobs_manager = JobsManager()
_cpu_sample = {"total": None, "idle": None, "at": 0.0, "pct": 0.0}
_surv_ai_lock = threading.Lock()
_surv_ai_running = set()
_SURV_AI_MAX_PARALLEL = 1
_SURV_AI_STAGES = ("under", "level2", "observe")
_SURV_AI_STAGE_LABELS = {
    "under": "Active Monitoring",
    "level2": "Needs Manual Fix",
    "observe": "Post-Fix Observation",
}
for _feature_name in (
    "WAN Ping",
    "Accounts Ping",
    "Under Surveillance",
    "Usage",
    "Offline",
    "Optical Monitoring",
    "Telegram",
    "Dashboard/API",
):
    register_feature(_feature_name)

AI_MODEL_PRICING = {
    "chatgpt": [
        {
            "id": "gpt-4o-mini",
            "label": "gpt-4o-mini",
            "input_per_1m": 0.15,
            "output_per_1m": 0.60,
            "free_tier": False,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Balanced cost for frequent investigations.",
        },
        {
            "id": "gpt-4o",
            "label": "gpt-4o",
            "input_per_1m": 2.50,
            "output_per_1m": 10.00,
            "free_tier": False,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Higher quality, higher cost.",
        },
        {
            "id": "gpt-4.1",
            "label": "gpt-4.1",
            "input_per_1m": 2.00,
            "output_per_1m": 8.00,
            "free_tier": False,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Strong reasoning for complex diagnostics.",
        },
        {
            "id": "gpt-4.1-mini",
            "label": "gpt-4.1-mini",
            "input_per_1m": 0.40,
            "output_per_1m": 1.60,
            "free_tier": False,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Good quality with lower spend.",
        },
        {
            "id": "gpt-4.1-nano",
            "label": "gpt-4.1-nano",
            "input_per_1m": 0.10,
            "output_per_1m": 0.40,
            "free_tier": False,
            "recommended_max_tokens": 700,
            "max_tokens_hint": "Lowest cost, concise outputs.",
        },
        {
            "id": "o3",
            "label": "o3",
            "input_per_1m": 2.00,
            "output_per_1m": 8.00,
            "free_tier": False,
            "recommended_max_tokens": 1000,
            "max_tokens_hint": "Reasoning model; cost can rise with deeper analysis.",
        },
        {
            "id": "o4-mini",
            "label": "o4-mini",
            "input_per_1m": 1.10,
            "output_per_1m": 4.40,
            "free_tier": False,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Reasoning-focused and mid-cost.",
        },
    ],
    "gemini": [
        {
            "id": "gemini-2.5-flash-preview-09-2025",
            "label": "gemini-2.5-flash-preview-09-2025",
            "input_per_1m": 0.30,
            "output_per_1m": 2.50,
            "free_tier": True,
            "recommended_max_tokens": 900,
            "max_tokens_hint": "Fast and cost-effective for high-volume reports.",
        },
        {
            "id": "gemini-2.5-flash-lite-preview-09-2025",
            "label": "gemini-2.5-flash-lite-preview-09-2025",
            "input_per_1m": 0.10,
            "output_per_1m": 0.40,
            "free_tier": True,
            "recommended_max_tokens": 700,
            "max_tokens_hint": "Lowest-cost Gemini option.",
        },
        {
            "id": "gemini-2.5-pro",
            "label": "gemini-2.5-pro",
            "input_per_1m": 1.25,
            "output_per_1m": 10.00,
            "free_tier": True,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Best for deeper technical analysis.",
        },
        {
            "id": "gemini-3-flash-preview",
            "label": "gemini-3-flash-preview",
            "input_per_1m": 0.50,
            "output_per_1m": 3.00,
            "free_tier": True,
            "recommended_max_tokens": 1000,
            "max_tokens_hint": "Fast latest-generation preview model.",
        },
        {
            "id": "gemini-3-pro-preview",
            "label": "gemini-3-pro-preview",
            "input_per_1m": 2.00,
            "output_per_1m": 12.00,
            "free_tier": False,
            "recommended_max_tokens": 1200,
            "max_tokens_hint": "Highest capability, highest cost.",
        },
        {
            "id": "gemini-2.0-flash-lite",
            "label": "gemini-2.0-flash-lite",
            "input_per_1m": 0.075,
            "output_per_1m": 0.30,
            "free_tier": True,
            "recommended_max_tokens": 700,
            "max_tokens_hint": "Legacy low-cost fallback.",
        },
    ],
}


def _runtime_feature_from_path(path: str):
    value = (path or "").strip().lower()
    if not value:
        return ""
    if value.startswith("/static/") or value == "/favicon.ico":
        return ""
    if value.startswith("/surveillance"):
        return "Under Surveillance"
    if value.startswith("/accounts-ping") or value.startswith("/settings/accounts-ping"):
        return "Accounts Ping"
    if value.startswith("/settings/wan") or value.startswith("/wan"):
        return "WAN Ping"
    if value.startswith("/settings/optical") or value.startswith("/optical"):
        return "Optical Monitoring"
    if value.startswith("/usage") or value.startswith("/settings/usage"):
        return "Usage"
    if value.startswith("/offline") or value.startswith("/settings/offline"):
        return "Offline"
    return "Dashboard/API"


@app.middleware("http")
async def runtime_feature_cpu_middleware(request: Request, call_next):
    feature = _runtime_feature_from_path(request.url.path)
    start = time.thread_time() if feature else 0.0
    try:
        return await call_next(request)
    finally:
        if feature:
            add_feature_cpu(feature, max(time.thread_time() - start, 0.0))


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


def _process_proc_root():
    host_root = "/host_proc"
    try:
        if os.path.isfile(f"{host_root}/stat") and os.path.isdir(f"{host_root}/1"):
            return host_root
    except Exception:
        pass
    return "/proc"


def _read_cpu_times(proc_root: str = "/proc"):
    try:
        with open(f"{proc_root}/stat", "r", encoding="utf-8") as handle:
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
    now = time.monotonic()
    last_at = float(_cpu_sample.get("at") or 0.0)
    if last_at > 0 and (now - last_at) < 1.0:
        return float(_cpu_sample.get("pct") or 0.0)
    proc_root = _process_proc_root()
    first = _read_cpu_times(proc_root=proc_root)
    if not first:
        return float(_cpu_sample.get("pct") or 0.0)
    time.sleep(0.20)
    second = _read_cpu_times(proc_root=proc_root)
    if not second:
        return float(_cpu_sample.get("pct") or 0.0)
    total_delta = int(second[0]) - int(first[0])
    idle_delta = int(second[1]) - int(first[1])
    if total_delta <= 0:
        pct = float(_cpu_sample.get("pct") or 0.0)
    else:
        pct = max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta))
    _cpu_sample["total"] = int(second[0])
    _cpu_sample["idle"] = int(second[1])
    _cpu_sample["pct"] = pct
    _cpu_sample["at"] = now
    return pct


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


def _classify_process_feature(proc_name: str, proc_args: str):
    hay = f"{proc_name or ''} {proc_args or ''}".strip().lower()
    if proc_name == "ping" or hay.startswith("ping ") or " ping " in hay:
        return "WAN Ping Probes"
    if "uvicorn" in hay or "app.main:app" in hay or "threejnotif" in hay:
        return "ThreeJ API / Jobs"
    if "postgres" in hay:
        return "PostgreSQL"
    if "docker" in hay or "containerd" in hay:
        return "Docker Engine"
    if "sshd" in hay:
        return "SSH Sessions"
    if "python" in hay:
        return "Python Worker"
    if "nginx" in hay:
        return "Web Proxy"
    return (proc_name or "System Process").strip()


def _read_proc_snapshot(proc_root: str = "/proc"):
    snapshot = {}
    try:
        names = os.listdir(proc_root)
    except Exception:
        return snapshot
    try:
        page_size_kb = max(int(os.sysconf("SC_PAGE_SIZE")) // 1024, 1)
    except Exception:
        page_size_kb = 4
    for entry in names:
        if not entry.isdigit():
            continue
        pid = int(entry)
        base = f"{proc_root}/{entry}"
        try:
            with open(f"{base}/stat", "r", encoding="utf-8") as handle:
                stat_line = handle.read().strip()
            left = stat_line.find("(")
            right = stat_line.rfind(")")
            if left < 0 or right <= left:
                continue
            proc_name = stat_line[left + 1 : right].strip() or "n/a"
            parts = stat_line[right + 2 :].split()
            if len(parts) < 15:
                continue
            utime = int(parts[11])
            stime = int(parts[12])
            rss_kb = 0
            try:
                with open(f"{base}/statm", "r", encoding="utf-8") as handle:
                    statm = handle.read().strip().split()
                if len(statm) >= 2:
                    rss_kb = max(int(statm[1]), 0) * page_size_kb
            except Exception:
                rss_kb = 0
            snapshot[pid] = {
                "pid": pid,
                "name": proc_name,
                "args": proc_name,
                "cpu_ticks": max(utime + stime, 0),
                "rss_kb": max(rss_kb, 0),
            }
        except Exception:
            continue
    return snapshot


def _top_process_usage_from_proc(limit: int = 12, proc_root: str = "/proc"):
    return _sample_process_usage(limit=limit, sample_seconds=0.25, proc_root=proc_root).get("rows", [])


def _read_mem_total_kb(proc_root: str = "/proc"):
    try:
        with open(f"{proc_root}/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return int(_memory_details_kb().get("mem_total_kb") or 0)


def _sample_process_usage(limit: int = 12, sample_seconds: float = 0.25, proc_root: str = "/proc"):
    try:
        first = _read_proc_snapshot(proc_root=proc_root)
        if not first:
            return {"rows": [], "total_cpu_pct": 0.0, "process_count": 0}
        hz = 100
        try:
            hz = max(int(os.sysconf("SC_CLK_TCK")), 1)
        except Exception:
            hz = 100
        cpu_count = max(int(os.cpu_count() or 1), 1)
        wait_seconds = max(0.05, min(float(sample_seconds or 0.25), 1.0))
        start_ts = time.monotonic()
        time.sleep(wait_seconds)
        second = _read_proc_snapshot(proc_root=proc_root)
        elapsed = max(time.monotonic() - start_ts, 0.05)
        if not second:
            return {"rows": [], "total_cpu_pct": 0.0, "process_count": 0}
        mem_total_kb = _read_mem_total_kb(proc_root=proc_root)
        rows = []
        total_cpu_pct = 0.0
        for pid, cur in second.items():
            prev = first.get(pid)
            if prev:
                proc_delta = max(int(cur.get("cpu_ticks") or 0) - int(prev.get("cpu_ticks") or 0), 0)
                cpu_pct = (100.0 * float(proc_delta) / float(hz * cpu_count * elapsed)) if hz > 0 else 0.0
            else:
                cpu_pct = 0.0
            rss_kb = max(int(cur.get("rss_kb") or 0), 0)
            ram_pct = (100.0 * rss_kb / mem_total_kb) if mem_total_kb > 0 else 0.0
            cpu_pct = max(cpu_pct, 0.0)
            total_cpu_pct += cpu_pct
            rows.append(
                {
                    "pid": int(cur.get("pid") or pid),
                    "name": (cur.get("name") or "n/a").strip(),
                    "feature": _classify_process_feature(cur.get("name") or "", cur.get("args") or ""),
                    "cpu_pct": round(cpu_pct, 1),
                    "ram_pct": round(max(ram_pct, 0.0), 1),
                    "rss_mb": round(rss_kb / 1024.0, 1),
                }
            )
        rows.sort(key=lambda item: (item.get("cpu_pct") or 0.0, item.get("ram_pct") or 0.0), reverse=True)
        limit_value = None
        try:
            if limit is not None:
                limit_value = int(limit)
        except Exception:
            limit_value = None
        if limit_value is None or limit_value <= 0:
            top = list(rows)
        else:
            top = rows[:limit_value]
        if any((item.get("cpu_pct") or 0.0) > 0 for item in top):
            return {
                "rows": top,
                "total_cpu_pct": round(max(0.0, min(100.0, total_cpu_pct)), 1),
                "process_count": len(rows),
            }
        rows.sort(key=lambda item: (item.get("ram_pct") or 0.0, item.get("rss_mb") or 0.0), reverse=True)
        if limit_value is None or limit_value <= 0:
            top = list(rows)
        else:
            top = rows[:limit_value]
        return {
            "rows": top,
            "total_cpu_pct": round(max(0.0, min(100.0, total_cpu_pct)), 1),
            "process_count": len(rows),
        }
    except Exception:
        return {"rows": [], "total_cpu_pct": 0.0, "process_count": 0}


def _is_threej_feature(feature: str):
    item = (feature or "").strip()
    if not item:
        return False
    if item.startswith("ThreeJ "):
        return True
    return item in {
        "WAN Ping Probes",
        "Accounts Ping Probes",
        "Usage Probes",
        "Optical Monitor",
        "Offline Monitor",
        "WAN Ping",
        "Accounts Ping",
        "Under Surveillance",
        "Usage",
        "Offline",
        "Optical Monitoring",
        "Telegram",
        "Dashboard/API",
    }


def _aggregate_threej_vs_system(process_rows, limit_threej: int = 8):
    threej = {}
    system_bucket = {"cpu_pct": 0.0, "ram_pct": 0.0, "process_count": 0}
    for row in process_rows or []:
        feature = (row.get("feature") or "Unknown").strip() or "Unknown"
        cpu = float(row.get("cpu_pct") or 0.0)
        ram = float(row.get("ram_pct") or 0.0)
        if _is_threej_feature(feature):
            bucket = threej.setdefault(feature, {"cpu_pct": 0.0, "ram_pct": 0.0, "process_count": 0})
            bucket["cpu_pct"] += cpu
            bucket["ram_pct"] += ram
            bucket["process_count"] += 1
        else:
            system_bucket["cpu_pct"] += cpu
            system_bucket["ram_pct"] += ram
            system_bucket["process_count"] += 1
    rows = sorted(
        (
            {
                "name": name,
                "cpu_pct": round(values["cpu_pct"], 1),
                "ram_pct": round(values["ram_pct"], 1),
                "process_count": int(values["process_count"] or 0),
                "kind": "threej",
            }
            for name, values in threej.items()
        ),
        key=lambda item: (item.get("cpu_pct") or 0.0, item.get("ram_pct") or 0.0),
        reverse=True,
    )
    limit_value = max(int(limit_threej or 0), 1)
    rows = rows[:limit_value]
    rows.append(
        {
            "name": "System",
            "cpu_pct": round(system_bucket["cpu_pct"], 1),
            "ram_pct": round(system_bucket["ram_pct"], 1),
            "process_count": int(system_bucket["process_count"] or 0),
            "kind": "system",
        }
    )
    return rows


def _build_runtime_threej_summary(feature_cpu_rows, process_rows, host_cpu_pct: float):
    mandatory = {"Accounts Ping", "Under Surveillance"}
    rows = []
    threej_cpu_total = 0.0
    for item in feature_cpu_rows or []:
        name = (item.get("name") or "").strip()
        if not name:
            continue
        cpu = float(item.get("cpu_pct") or 0.0)
        if cpu <= 0 and name not in mandatory:
            continue
        rows.append(
            {
                "name": name,
                "cpu_pct": round(max(cpu, 0.0), 1),
                "ram_pct": None,
                "process_count": None,
                "kind": "threej",
                "source": "ThreeJ runtime",
            }
        )
        threej_cpu_total += max(cpu, 0.0)
    system_ram = 0.0
    system_count = 0
    for row in process_rows or []:
        feature = (row.get("feature") or "").strip()
        if _is_threej_feature(feature):
            continue
        system_ram += float(row.get("ram_pct") or 0.0)
        system_count += 1
    system_cpu = max(float(host_cpu_pct or 0.0) - threej_cpu_total, 0.0)
    rows.sort(key=lambda item: (item.get("cpu_pct") or 0.0, item.get("name") or ""), reverse=True)
    rows.append(
        {
            "name": "System",
            "cpu_pct": round(system_cpu, 1),
            "ram_pct": round(system_ram, 1),
            "process_count": int(system_count),
            "kind": "system",
            "source": "Host OS / other processes",
        }
    )
    return rows


def _top_process_usage(limit: int = 12):
    try:
        cmd = ["ps", "-eo", "pid=,comm=,pcpu=,pmem=,rss=,args=", "--sort=-pcpu"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0, check=False)
        lines = (out.stdout or "").splitlines()
        items = []
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            pid_raw, comm_raw, cpu_raw, mem_raw, rss_raw = parts[:5]
            args_raw = parts[5] if len(parts) > 5 else comm_raw
            try:
                pid = int(pid_raw)
                cpu_pct = max(float(cpu_raw), 0.0)
                ram_pct = max(float(mem_raw), 0.0)
                rss_kb = max(int(float(rss_raw)), 0)
            except Exception:
                continue
            feature = _classify_process_feature(comm_raw, args_raw)
            items.append(
                {
                    "pid": pid,
                    "name": (comm_raw or "").strip() or "n/a",
                    "feature": feature,
                    "cpu_pct": round(cpu_pct, 1),
                    "ram_pct": round(ram_pct, 1),
                    "rss_mb": round(rss_kb / 1024.0, 1),
                }
            )
            if len(items) >= max(int(limit or 0), 1):
                break
        if items:
            return items
        return _top_process_usage_from_proc(limit=limit)
    except Exception:
        return _top_process_usage_from_proc(limit=limit)


def _aggregate_feature_usage(process_rows, limit: int = 8):
    summary = {}
    for row in process_rows or []:
        feature = (row.get("feature") or "Unknown").strip() or "Unknown"
        bucket = summary.setdefault(feature, {"cpu_pct": 0.0, "ram_pct": 0.0, "process_count": 0})
        bucket["cpu_pct"] += float(row.get("cpu_pct") or 0.0)
        bucket["ram_pct"] += float(row.get("ram_pct") or 0.0)
        bucket["process_count"] += 1
    ranked = sorted(
        (
            {
                "feature": feature,
                "cpu_pct": round(vals["cpu_pct"], 1),
                "ram_pct": round(vals["ram_pct"], 1),
                "process_count": int(vals["process_count"] or 0),
            }
            for feature, vals in summary.items()
        ),
        key=lambda item: (item.get("cpu_pct") or 0.0, item.get("ram_pct") or 0.0),
        reverse=True,
    )
    return ranked[: max(int(limit or 0), 1)]


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


def _dashboard_job_health(enabled, status):
    if not enabled:
        return ("Disabled", "secondary")
    status = status or {}
    if status.get("last_error"):
        return ("Error", "danger")
    if status.get("last_success_at"):
        return ("OK", "success")
    if status.get("last_run_at"):
        return ("Running", "warning")
    return ("Idle", "secondary")


def _build_dashboard_kpis(job_status):
    now = datetime.utcnow()
    out = {
        "features": [],
        "surveillance": {},
        "wan": {},
        "usage": {},
        "accounts_ping": {},
        "optical": {},
        "offline": {},
        "attention": {},
    }

    try:
        surv_cfg = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entries = surv_cfg.get("entries") if isinstance(surv_cfg.get("entries"), list) else []
        under = level2 = observe = auto = manual = 0
        ai_pending = ai_error = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            status = (entry.get("status") or "under").strip().lower()
            if status == "level2":
                level2 += 1
            elif status == "observe":
                observe += 1
            else:
                under += 1
            if (entry.get("added_mode") or "manual").strip().lower() == "auto":
                auto += 1
            else:
                manual += 1
            reports = entry.get("ai_reports") if isinstance(entry.get("ai_reports"), dict) else {}
            for stage in ("under", "level2", "observe"):
                item = reports.get(stage) if isinstance(reports.get(stage), dict) else {}
                st = (item.get("status") or "").strip().lower()
                if st in ("queued", "running"):
                    ai_pending += 1
                elif st == "error":
                    ai_error += 1
        history_total = 0
        try:
            history_total = int((list_surveillance_history(page=1, limit=1) or {}).get("total") or 0)
        except Exception:
            history_total = 0
        out["surveillance"] = {
            "total": under + level2 + observe,
            "under": under,
            "level2": level2,
            "observe": observe,
            "auto": auto,
            "manual": manual,
            "history_total": history_total,
            "ai_pending": ai_pending,
            "ai_error": ai_error,
            "enabled": bool(surv_cfg.get("enabled", True)),
        }
    except Exception:
        out["surveillance"] = {
            "total": 0,
            "under": 0,
            "level2": 0,
            "observe": 0,
            "auto": 0,
            "manual": 0,
            "history_total": 0,
            "ai_pending": 0,
            "ai_error": 0,
            "enabled": False,
        }

    try:
        wan_cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
        wan_state = get_state("wan_ping_state", {})
        wans_cfg = wan_cfg.get("wans") if isinstance(wan_cfg.get("wans"), list) else []
        wan_rows = wan_state.get("wans") if isinstance(wan_state.get("wans"), dict) else {}
        up = down = unknown = 0
        latency_ready = 0
        for info in wan_rows.values():
            if not isinstance(info, dict):
                continue
            status = (info.get("status") or "").strip().lower()
            if status == "up":
                up += 1
            elif status == "down":
                down += 1
            else:
                unknown += 1
            if info.get("last_target_check"):
                latency_ready += 1
        targets = [
            item
            for item in ((wan_cfg.get("general") or {}).get("targets") or [])
            if isinstance(item, dict) and bool(item.get("enabled", True))
        ]
        out["wan"] = {
            "configured": len(wans_cfg),
            "up": up,
            "down": down,
            "unknown": unknown,
            "targets_enabled": len(targets),
            "routers": len(wan_cfg.get("pppoe_routers") or []),
            "latency_ready": latency_ready,
            "interval_seconds": int(((wan_cfg.get("general") or {}).get("interval_seconds") or 30)),
            "target_interval_seconds": int(((wan_cfg.get("general") or {}).get("target_latency_interval_seconds") or 30)),
            "enabled": bool(wan_cfg.get("enabled")),
            "last_poll_at_ph": format_ts_ph(wan_state.get("last_status_poll_at")),
        }
    except Exception:
        out["wan"] = {
            "configured": 0,
            "up": 0,
            "down": 0,
            "unknown": 0,
            "targets_enabled": 0,
            "routers": 0,
            "latency_ready": 0,
            "interval_seconds": 30,
            "target_interval_seconds": 30,
            "enabled": False,
            "last_poll_at_ph": "n/a",
        }

    try:
        usage_cfg = get_settings("usage", USAGE_DEFAULTS)
        usage_state = get_state("usage_state", {})
        active_rows = usage_state.get("active_rows") if isinstance(usage_state.get("active_rows"), list) else []
        active_accounts = {
            (row.get("pppoe") or "").strip().lower()
            for row in active_rows
            if isinstance(row, dict) and (row.get("pppoe") or "").strip()
        }
        routers = usage_state.get("routers") if isinstance(usage_state.get("routers"), list) else []
        connected_routers = sum(1 for row in routers if isinstance(row, dict) and bool(row.get("connected")))
        router_errors = sum(1 for row in routers if isinstance(row, dict) and (row.get("error") or "").strip())
        anytime_issues = usage_state.get("anytime_issues") if isinstance(usage_state.get("anytime_issues"), dict) else {}
        out["usage"] = {
            "active_sessions": len(active_rows),
            "active_accounts": len(active_accounts),
            "offline_accounts": len(usage_state.get("offline_rows") or []),
            "router_count": len(routers),
            "router_connected": connected_routers,
            "router_errors": router_errors,
            "anytime_issues": len(anytime_issues),
            "sample_interval_seconds": int(((usage_cfg.get("storage") or {}).get("sample_interval_seconds") or 60)),
            "enabled": bool(usage_cfg.get("enabled")),
            "last_check_at_ph": format_ts_ph(usage_state.get("last_check_at")),
        }
    except Exception:
        out["usage"] = {
            "active_sessions": 0,
            "active_accounts": 0,
            "offline_accounts": 0,
            "router_count": 0,
            "router_connected": 0,
            "router_errors": 0,
            "anytime_issues": 0,
            "sample_interval_seconds": 60,
            "enabled": False,
            "last_check_at_ph": "n/a",
        }

    try:
        acc_cfg = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
        acc_state = get_state("accounts_ping_state", {})
        accounts = acc_state.get("accounts") if isinstance(acc_state.get("accounts"), dict) else {}
        down = issue = up = burst = 0
        for item in accounts.values():
            if not isinstance(item, dict):
                continue
            status = (item.get("last_status") or "").strip().lower()
            if status == "down":
                down += 1
            elif status == "issue":
                issue += 1
            elif status == "up":
                up += 1
            if item.get("burst_until"):
                burst += 1
        dashboard_status = None
        try:
            dashboard_status = build_accounts_ping_status(
                acc_cfg,
                window_hours=24,
                limit=1,
                issues_page=1,
                stable_page=1,
            )
        except Exception:
            dashboard_status = None
        total_accounts = len(accounts)
        issue_total = issue
        stable_total = up
        pending_total = 0
        if isinstance(dashboard_status, dict):
            total_accounts = int(dashboard_status.get("total") or total_accounts)
            issue_total = int(dashboard_status.get("issue_total") or 0)
            stable_total = int(dashboard_status.get("stable_total") or 0)
            pending_total = int(dashboard_status.get("pending_total") or 0)
            down = int(dashboard_status.get("down_total") or 0)
        out["accounts_ping"] = {
            "accounts": total_accounts,
            "devices": len(acc_state.get("devices") or []),
            "up": stable_total,
            "down": down,
            "issue": issue_total,
            "pending": pending_total,
            "burst": burst,
            "interval_seconds": int(((acc_cfg.get("general") or {}).get("base_interval_seconds") or 30)),
            "max_parallel": int(((acc_cfg.get("general") or {}).get("max_parallel") or 16)),
            "enabled": bool(acc_cfg.get("enabled")),
            "last_refresh_at_ph": format_ts_ph(acc_state.get("devices_refreshed_at")),
        }
    except Exception:
        out["accounts_ping"] = {
            "accounts": 0,
            "devices": 0,
            "up": 0,
            "down": 0,
            "issue": 0,
            "burst": 0,
            "interval_seconds": 30,
            "max_parallel": 16,
            "enabled": False,
            "last_refresh_at_ph": "n/a",
        }

    try:
        opt_cfg = get_settings("optical", OPTICAL_DEFAULTS)
        classification = opt_cfg.get("classification") if isinstance(opt_cfg.get("classification"), dict) else {}
        issue_rx = float(classification.get("issue_rx_dbm", -27.0) or -27.0)
        issue_tx = float(classification.get("issue_tx_dbm", -2.0) or -2.0)
        tx_real_min = float(classification.get("tx_realistic_min_dbm", -10.0) or -10.0)
        tx_real_max = float(classification.get("tx_realistic_max_dbm", 10.0) or 10.0)
        since_iso = (now - timedelta(days=7)).replace(microsecond=0).isoformat() + "Z"
        latest = get_optical_latest_results_since(since_iso)
        issue_rx_count = 0
        issue_tx_count = 0
        priority_count = 0
        pppoe_set = set()
        for row in latest:
            if not isinstance(row, dict):
                continue
            pppoe = (row.get("pppoe") or "").strip().lower()
            if pppoe:
                pppoe_set.add(pppoe)
            rx = row.get("rx")
            tx = row.get("tx")
            if row.get("priority"):
                priority_count += 1
            try:
                if rx is not None and float(rx) <= issue_rx:
                    issue_rx_count += 1
            except Exception:
                pass
            try:
                if tx is not None:
                    tx_value = float(tx)
                    if tx_real_min <= tx_value <= tx_real_max and tx_value <= issue_tx:
                        issue_tx_count += 1
            except Exception:
                pass
        out["optical"] = {
            "latest_devices": len(latest),
            "latest_accounts": len(pppoe_set),
            "issue_rx": issue_rx_count,
            "issue_tx": issue_tx_count,
            "priority": priority_count,
            "enabled": bool(opt_cfg.get("enabled")),
            "threshold_rx": issue_rx,
            "threshold_tx": issue_tx,
        }
    except Exception:
        out["optical"] = {
            "latest_devices": 0,
            "latest_accounts": 0,
            "issue_rx": 0,
            "issue_tx": 0,
            "priority": 0,
            "enabled": False,
            "threshold_rx": -27.0,
            "threshold_tx": -2.0,
        }

    try:
        off_cfg = get_settings("offline", OFFLINE_DEFAULTS)
        off_state = get_state("offline_state", {})
        history_since = (now - timedelta(days=1)).replace(microsecond=0).isoformat() + "Z"
        off_hist = get_offline_history_since(history_since, limit=2000)
        out["offline"] = {
            "current": len(off_state.get("rows") or []),
            "history_24h": len(off_hist),
            "routers": len(off_state.get("routers") or []),
            "router_errors": len(off_state.get("router_errors") or []),
            "mode": (off_state.get("mode") or off_cfg.get("mode") or "secrets"),
            "threshold_minutes": int(off_state.get("min_offline_minutes") or 0),
            "enabled": bool(off_cfg.get("enabled")),
            "last_check_at_ph": format_ts_ph(off_state.get("last_check_at")),
        }
    except Exception:
        out["offline"] = {
            "current": 0,
            "history_24h": 0,
            "routers": 0,
            "router_errors": 0,
            "mode": "secrets",
            "threshold_minutes": 0,
            "enabled": False,
            "last_check_at_ph": "n/a",
        }

    try:
        accounts_issue_total = int(out["accounts_ping"].get("issue") or 0)
        optical_issue_total = int(out["optical"].get("issue_rx") or 0) + int(out["optical"].get("issue_tx") or 0)
        active_monitoring_total = int(out["surveillance"].get("under") or 0)
        needs_manual_fix_total = int(out["surveillance"].get("level2") or 0)
        wan_down_total = int(out["wan"].get("down") or 0)
        offline_total = int(out["offline"].get("current") or 0)
        cpu_pct = round(float(_cpu_percent()), 1)
        ram_pct = round(float(_memory_percent()), 1)
        attention_items = [
            {
                "label": "Accounts Ping Issues",
                "value_label": f"{accounts_issue_total} accounts",
                "active": accounts_issue_total > 0,
                "note": "Accounts currently classified as issue/down.",
            },
            {
                "label": "Optical Monitoring Issues",
                "value_label": f"{optical_issue_total} findings",
                "active": optical_issue_total > 0,
                "note": "RX/TX threshold violations from latest optical data.",
            },
            {
                "label": "Under Surveillance · Active Monitoring",
                "value_label": f"{active_monitoring_total} accounts",
                "active": active_monitoring_total > 0,
                "note": "Accounts still under active watch.",
            },
            {
                "label": "Under Surveillance · Needs Manual Fix",
                "value_label": f"{needs_manual_fix_total} accounts",
                "active": needs_manual_fix_total > 0,
                "note": "Accounts requiring manual intervention.",
            },
            {
                "label": "WAN Ping · Down ISPs",
                "value_label": f"{wan_down_total} down",
                "active": wan_down_total > 0,
                "note": "Any ISP marked down by WAN Ping/Netwatch.",
            },
            {
                "label": "Offline Accounts",
                "value_label": f"{offline_total} offline",
                "active": offline_total > 0,
                "note": "Accounts currently in Offline state.",
            },
            {
                "label": "CPU Usage",
                "value_label": f"{cpu_pct:.1f}%",
                "active": cpu_pct >= 85.0,
                "note": "Triggers attention at 85% and above.",
            },
            {
                "label": "RAM Usage",
                "value_label": f"{ram_pct:.1f}%",
                "active": ram_pct >= 85.0,
                "note": "Triggers attention at 85% and above.",
            },
        ]
        active_total = sum(1 for item in attention_items if bool(item.get("active")))
        out["attention"] = {
            "title": "Operations Attention Board",
            "active_total": active_total,
            "items": attention_items,
            "healthy": active_total == 0,
        }
    except Exception:
        out["attention"] = {
            "title": "Operations Attention Board",
            "active_total": 0,
            "items": [],
            "healthy": True,
        }

    feature_defs = [
        ("WAN Ping", "wan_ping", out["wan"].get("enabled"), f"{out['wan'].get('configured', 0)} ISPs · {out['wan'].get('targets_enabled', 0)} targets"),
        ("Accounts Ping", "accounts_ping", out["accounts_ping"].get("enabled"), f"{out['accounts_ping'].get('accounts', 0)} accounts"),
        ("Under Surveillance", "", out["surveillance"].get("enabled"), f"{out['surveillance'].get('total', 0)} active"),
        ("Usage", "usage", out["usage"].get("enabled"), f"{out['usage'].get('active_accounts', 0)} active accounts"),
        ("Offline", "offline", out["offline"].get("enabled"), f"{out['offline'].get('current', 0)} offline now"),
        ("Optical Monitoring", "optical", out["optical"].get("enabled"), f"{out['optical'].get('latest_devices', 0)} devices"),
    ]
    features = []
    for label, job_key, enabled, subtitle in feature_defs:
        status = job_status.get(job_key) if job_key else {}
        state_label, tone = _dashboard_job_health(bool(enabled), status)
        features.append(
            {
                "label": label,
                "state_label": state_label,
                "tone": tone,
                "subtitle": subtitle,
                "last_run_at_ph": format_ts_ph((status or {}).get("last_run_at")) if job_key else "n/a",
                "last_success_at_ph": format_ts_ph((status or {}).get("last_success_at")) if job_key else "n/a",
            }
        )
    out["features"] = features
    return out


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    job_status = {item["job_name"]: dict(item) for item in get_job_status()}
    for status in job_status.values():
        status["last_run_at_ph"] = format_ts_ph(status.get("last_run_at"))
        status["last_success_at_ph"] = format_ts_ph(status.get("last_success_at"))
        status["last_error_at_ph"] = format_ts_ph(status.get("last_error_at"))
    dashboard_kpis = _build_dashboard_kpis(job_status)
    return templates.TemplateResponse(
        "dashboard.html",
        make_context(request, {"job_status": job_status, "dashboard_kpis": dashboard_kpis}),
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
    return render_system_settings_response(request, message, active_tab="backup", routers_tab="cores")


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
        return render_system_settings_response(request, message, active_tab="backup", routers_tab="cores")
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
    return render_system_settings_response(request, message, active_tab="backup", routers_tab="cores")


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
    normalized_settings, tuning = _accounts_ping_tuning_context(settings)
    if tuning.get("was_clamped"):
        save_settings("accounts_ping", normalized_settings)
    settings = normalized_settings
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


def _accounts_ping_tuning_context(settings):
    normalized = copy.deepcopy(settings or {})
    general = normalized.get("general") if isinstance(normalized.get("general"), dict) else {}
    ping_cfg = normalized.get("ping") if isinstance(normalized.get("ping"), dict) else {}
    source_cfg = normalized.get("source") if isinstance(normalized.get("source"), dict) else {}
    storage_cfg = normalized.get("storage") if isinstance(normalized.get("storage"), dict) else {}

    try:
        configured_parallel = int(general.get("max_parallel", ACCOUNTS_PING_DEFAULTS["general"]["max_parallel"]) or 1)
    except Exception:
        configured_parallel = int(ACCOUNTS_PING_DEFAULTS["general"]["max_parallel"])
    configured_parallel = max(configured_parallel, 1)

    cpu_cores = max(int(os.cpu_count() or 1), 1)
    mem_total_kb = int((_memory_details_kb() or {}).get("mem_total_kb") or 0)
    ram_gb = round(mem_total_kb / (1024 * 1024), 1) if mem_total_kb > 0 else 0.0
    safe_parallel_cap = max(8, min(32, cpu_cores * 4))
    effective_parallel = min(configured_parallel, safe_parallel_cap)

    general["max_parallel"] = effective_parallel
    normalized["general"] = general
    normalized["ping"] = ping_cfg
    normalized["source"] = source_cfg
    normalized["storage"] = storage_cfg

    if cpu_cores <= 2 or ram_gb < 4:
        recommendation = {
            "tier": "Low Hardware",
            "max_parallel": min(8, safe_parallel_cap),
            "base_interval_seconds": 20,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 30,
            "raw_retention_days": 30,
            "bucket_seconds": 120,
        }
    elif cpu_cores <= 4 or ram_gb < 8:
        recommendation = {
            "tier": "Balanced Hardware",
            "max_parallel": min(12, safe_parallel_cap),
            "base_interval_seconds": 10,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 20,
            "raw_retention_days": 90,
            "bucket_seconds": 60,
        }
    elif cpu_cores <= 8 or ram_gb < 16:
        recommendation = {
            "tier": "High Hardware",
            "max_parallel": min(16, safe_parallel_cap),
            "base_interval_seconds": 5,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 15,
            "raw_retention_days": 180,
            "bucket_seconds": 60,
        }
    else:
        recommendation = {
            "tier": "Very High Hardware",
            "max_parallel": min(24, safe_parallel_cap),
            "base_interval_seconds": 3,
            "ping_count": 1,
            "ping_timeout_seconds": 1,
            "source_refresh_minutes": 10,
            "raw_retention_days": 365,
            "bucket_seconds": 30,
        }

    tiers = [
        {
            "label": "Low (2 cores / 4GB)",
            "max_parallel": "4–8",
            "base_interval_seconds": "20–30s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "30m",
            "raw_retention_days": "30d",
            "bucket_seconds": "120s",
        },
        {
            "label": "Balanced (4 cores / 8GB)",
            "max_parallel": "8–12",
            "base_interval_seconds": "10–20s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "15–20m",
            "raw_retention_days": "90d",
            "bucket_seconds": "60s",
        },
        {
            "label": "High (8 cores / 16GB)",
            "max_parallel": "12–16",
            "base_interval_seconds": "5–10s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "10–15m",
            "raw_retention_days": "180d",
            "bucket_seconds": "60s",
        },
        {
            "label": "Very High (12+ cores / 24GB+)",
            "max_parallel": "16–24",
            "base_interval_seconds": "3–5s",
            "ping_count": "1",
            "ping_timeout_seconds": "1s",
            "source_refresh_minutes": "10m",
            "raw_retention_days": "365d",
            "bucket_seconds": "30–60s",
        },
    ]

    return normalized, {
        "cpu_cores": cpu_cores,
        "ram_gb": ram_gb,
        "safe_parallel_cap": safe_parallel_cap,
        "configured_parallel": configured_parallel,
        "effective_parallel": effective_parallel,
        "was_clamped": configured_parallel != effective_parallel,
        "recommendation": recommendation,
        "tiers": tiers,
    }


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
    down_total = sum(1 for row in issue_rows if row.get("status") == "down")
    monitor_total = sum(1 for row in issue_rows if row.get("status") == "monitor")

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
        "down_total": down_total,
        "monitor_total": monitor_total,
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
    settings, tuning = _accounts_ping_tuning_context(settings)
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
                "accounts_ping_tuning": tuning,
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
            "max_parallel": parse_int(form, "max_parallel", ACCOUNTS_PING_DEFAULTS["general"]["max_parallel"]),
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
    requested_parallel = int(settings.get("general", {}).get("max_parallel") or 1)
    settings, tuning = _accounts_ping_tuning_context(settings)
    save_settings("accounts_ping", settings)
    window_hours = _normalize_wan_window(request.query_params.get("window"))
    active_tab = form.get("active_tab", "settings")
    settings_tab = (form.get("settings_tab") or "general").strip().lower()
    if settings_tab not in ("general", "source", "classification", "storage", "danger"):
        settings_tab = "general"
    message = "Accounts Ping settings saved."
    if requested_parallel > int(tuning.get("effective_parallel") or requested_parallel):
        message = (
            f"Accounts Ping settings saved. Max Parallel was capped to {tuning.get('effective_parallel')} "
            f"for this server ({tuning.get('cpu_cores')} cores / {tuning.get('ram_gb')} GB RAM)."
        )
    return render_accounts_ping_response(request, settings, message, active_tab, settings_tab, window_hours)


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


def normalize_system_settings(raw):
    cfg = copy.deepcopy(SYSTEM_DEFAULTS)
    if isinstance(raw, dict):
        branding = raw.get("branding")
        if isinstance(branding, dict):
            cfg["branding"]["company_logo"].update(branding.get("company_logo") or {})
            cfg["branding"]["browser_logo"].update(branding.get("browser_logo") or {})
        ai = raw.get("ai")
        if isinstance(ai, dict):
            cfg["ai"]["enabled"] = bool(ai.get("enabled", cfg["ai"]["enabled"]))
            provider = (ai.get("provider") or cfg["ai"]["provider"]).strip().lower()
            if provider not in ("chatgpt", "gemini"):
                provider = "chatgpt"
            cfg["ai"]["provider"] = provider
            if isinstance(ai.get("chatgpt"), dict):
                cfg["ai"]["chatgpt"].update(ai.get("chatgpt") or {})
            if isinstance(ai.get("gemini"), dict):
                cfg["ai"]["gemini"].update(ai.get("gemini") or {})
            if isinstance(ai.get("report"), dict):
                cfg["ai"]["report"].update(ai.get("report") or {})

    for provider in ("chatgpt", "gemini"):
        block = cfg["ai"].get(provider) if isinstance(cfg["ai"].get(provider), dict) else {}
        block["api_key"] = (block.get("api_key") or "").strip()
        block["model"] = (block.get("model") or "").strip() or (
            "gpt-4o-mini" if provider == "chatgpt" else "gemini-2.5-flash-preview-09-2025"
        )
        block["model"] = _normalize_provider_model_id(provider, block["model"])
        try:
            timeout_seconds = int(block.get("timeout_seconds") or 30)
        except Exception:
            timeout_seconds = 30
        try:
            max_tokens = int(block.get("max_tokens") or 900)
        except Exception:
            max_tokens = 900
        block["timeout_seconds"] = max(5, min(timeout_seconds, 180))
        block["max_tokens"] = max(200, min(max_tokens, 4000))
        cfg["ai"][provider] = block

    report = cfg["ai"].get("report") if isinstance(cfg["ai"].get("report"), dict) else {}
    try:
        lookback = int(report.get("lookback_hours") or 24)
    except Exception:
        lookback = 24
    try:
        max_samples = int(report.get("max_samples") or 60)
    except Exception:
        max_samples = 60
    report["lookback_hours"] = max(1, min(lookback, 168))
    report["max_samples"] = max(10, min(max_samples, 300))
    cfg["ai"]["report"] = report
    cfg["ai"]["enabled"] = bool(cfg["ai"].get("enabled"))
    provider = (cfg["ai"].get("provider") or "chatgpt").strip().lower()
    cfg["ai"]["provider"] = provider if provider in ("chatgpt", "gemini") else "chatgpt"
    return cfg


def _format_model_price(value):
    if value is None:
        return "n/a"
    try:
        amount = float(value)
    except Exception:
        return "n/a"
    if amount >= 1:
        return f"${amount:.2f}"
    if amount >= 0.1:
        return f"${amount:.3f}".rstrip("0").rstrip(".")
    return f"${amount:.4f}".rstrip("0").rstrip(".")


def _normalize_provider_model_id(provider, model):
    provider = (provider or "").strip().lower()
    model = (model or "").strip()
    if provider == "gemini":
        if model.startswith("models/"):
            model = model.split("/", 1)[1].strip()
    return model


def _fetch_chatgpt_model_ids(api_key, timeout_seconds=8):
    api_key = (api_key or "").strip()
    if not api_key:
        return [], ""
    try:
        req = urllib.request.Request(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=max(int(timeout_seconds or 8), 5)) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        rows = payload.get("data") if isinstance(payload, dict) else []
        out = []
        for row in rows or []:
            model_id = (row.get("id") or "").strip() if isinstance(row, dict) else ""
            if not model_id:
                continue
            low = model_id.lower()
            if low.startswith(("gpt-", "o1", "o3", "o4", "o5")):
                out.append(model_id)
        out = sorted(set(out), key=lambda x: x.lower())
        return out, ""
    except Exception:
        return [], "Unable to auto-load ChatGPT model list from API key."


def _fetch_gemini_model_ids(api_key, timeout_seconds=8):
    api_key = (api_key or "").strip()
    if not api_key:
        return [], ""
    out = set()
    next_token = ""
    pages = 0
    try:
        while pages < 5:
            pages += 1
            query = {"key": api_key, "pageSize": 1000}
            if next_token:
                query["pageToken"] = next_token
            url = "https://generativelanguage.googleapis.com/v1beta/models?" + urllib.parse.urlencode(query)
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=max(int(timeout_seconds or 8), 5)) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            rows = payload.get("models") if isinstance(payload, dict) else []
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                model_name = _normalize_provider_model_id("gemini", row.get("name") or "")
                methods = row.get("supportedGenerationMethods") if isinstance(row.get("supportedGenerationMethods"), list) else []
                if not model_name.lower().startswith("gemini-"):
                    continue
                if methods and "generateContent" not in methods:
                    continue
                out.add(model_name)
            next_token = (payload.get("nextPageToken") or "").strip() if isinstance(payload, dict) else ""
            if not next_token:
                break
        return sorted(out, key=lambda x: x.lower()), ""
    except Exception:
        return [], "Unable to auto-load Gemini model list from API key."


def _build_ai_model_options(ai_settings, active_tab):
    ai_settings = ai_settings or {}
    catalog_map = {}
    catalog_order = {}
    for provider, rows in AI_MODEL_PRICING.items():
        local_map = {}
        local_order = []
        for item in rows or []:
            model_id = _normalize_provider_model_id(provider, item.get("id") or "")
            if not model_id:
                continue
            local_map[model_id] = {
                "id": model_id,
                "label": (item.get("label") or model_id).strip(),
                "input_per_1m": item.get("input_per_1m"),
                "output_per_1m": item.get("output_per_1m"),
                "free_tier": item.get("free_tier"),
                "recommended_max_tokens": int(item.get("recommended_max_tokens") or 900),
                "max_tokens_hint": (item.get("max_tokens_hint") or "").strip(),
            }
            local_order.append(model_id)
        catalog_map[provider] = local_map
        catalog_order[provider] = local_order

    discovered = {"chatgpt": [], "gemini": []}
    fetch_errors = {"chatgpt": "", "gemini": ""}
    if active_tab == "ai":
        chatgpt_key = ((ai_settings.get("chatgpt") or {}).get("api_key") or "").strip()
        gemini_key = ((ai_settings.get("gemini") or {}).get("api_key") or "").strip()
        discovered["chatgpt"], fetch_errors["chatgpt"] = _fetch_chatgpt_model_ids(chatgpt_key)
        discovered["gemini"], fetch_errors["gemini"] = _fetch_gemini_model_ids(gemini_key)

    options = {}
    for provider in ("chatgpt", "gemini"):
        selected = _normalize_provider_model_id(provider, ((ai_settings.get(provider) or {}).get("model") or ""))
        ids = set(catalog_map.get(provider, {}).keys())
        ids.update([_normalize_provider_model_id(provider, x) for x in discovered.get(provider, []) if x])
        if selected:
            ids.add(selected)

        ordered = []
        for known in catalog_order.get(provider, []):
            if known in ids:
                ordered.append(known)
        for model_id in sorted(ids, key=lambda x: x.lower()):
            if model_id not in ordered:
                ordered.append(model_id)

        provider_options = []
        for model_id in ordered:
            cat = (catalog_map.get(provider) or {}).get(model_id) or {}
            input_cost = cat.get("input_per_1m")
            output_cost = cat.get("output_per_1m")
            free_tier = cat.get("free_tier")
            recommended = int(cat.get("recommended_max_tokens") or 900)
            hint = (cat.get("max_tokens_hint") or "").strip()
            if input_cost is not None and output_cost is not None:
                cost_text = f"In { _format_model_price(input_cost) } / Out { _format_model_price(output_cost) } per 1M tokens"
            else:
                cost_text = "Pricing n/a (check provider billing page)"
            if free_tier is True:
                free_tier_text = "Free Tier: Available"
            elif free_tier is False:
                free_tier_text = "Free Tier: Paid only"
            else:
                free_tier_text = "Free Tier: Unknown"
            provider_options.append(
                {
                    "id": model_id,
                    "label": (cat.get("label") or model_id).strip(),
                    "input_cost_text": _format_model_price(input_cost),
                    "output_cost_text": _format_model_price(output_cost),
                    "cost_text": cost_text,
                    "free_tier": free_tier,
                    "free_tier_text": free_tier_text,
                    "recommended_max_tokens": recommended,
                    "max_tokens_hint": hint or "Set lower values to control report size and cost.",
                }
            )
        options[provider] = provider_options

    return {"options": options, "errors": fetch_errors}


def _ai_report_status_badge(status: str):
    status = (status or "").strip().lower()
    if status in ("queued", "running"):
        return "Generating"
    if status in ("ready", "done"):
        return "Ready"
    if status in ("disabled",):
        return "Disabled"
    if status in ("error",):
        return "Error"
    if status in ("missing_api_key", "missing_key"):
        return "Missing API Key"
    return "n/a"


def _ai_safe_error(exc: Exception):
    text = str(exc or "").strip() or "Unknown error"
    lowered = text.lower()
    if "unauthorized" in lowered or "invalid api key" in lowered or "permission denied" in lowered:
        return "Authentication failed. Check API key and model access."
    if "http 429" in lowered:
        return "AI rate limit reached. Wait a bit, then generate again."
    if "http 503" in lowered or "http 502" in lowered or "http 504" in lowered or "http 500" in lowered:
        return "AI provider is temporarily unavailable. Retry in a few seconds."
    if len(text) > 220:
        text = text[:220].rstrip() + "…"
    return text


def _sample_rows_for_ai(rows, max_samples):
    rows = list(rows or [])
    if len(rows) <= max_samples:
        return rows
    if max_samples <= 1:
        return [rows[-1]]
    out = []
    last_idx = len(rows) - 1
    for idx in range(max_samples):
        pick = round((idx * last_idx) / (max_samples - 1))
        out.append(rows[pick])
    return out


def _normalize_ai_recommendation(value):
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "y", "recommend", "recommended"):
        return "yes"
    if text in ("0", "false", "no", "n", "not_recommended", "not-recommended"):
        return "no"
    return "unknown"


def _normalize_ai_potential_problems(value):
    if isinstance(value, str):
        rows = [line.strip("-• ").strip() for line in value.splitlines() if line.strip()]
    elif isinstance(value, list):
        rows = [str(item or "").strip() for item in value if str(item or "").strip()]
    else:
        rows = []
    return rows[:8]


def _empty_surveillance_ai_report():
    return {
        "status": "",
        "error": "",
        "generated_at": "",
        "cycle_index": 1,
        "provider": "",
        "model": "",
        "text": "",
        "recommend_needs_manual_fix": "unknown",
        "recommendation_reason": "",
        "potential_problems": [],
        "provider_override": "",
        "model_override": "",
    }


def _normalize_surveillance_ai_report(raw):
    report = _empty_surveillance_ai_report()
    if isinstance(raw, dict):
        report["status"] = (raw.get("status") or "").strip().lower()
        report["error"] = (raw.get("error") or "").strip()
        report["generated_at"] = (raw.get("generated_at") or "").strip()
        try:
            report["cycle_index"] = max(int(raw.get("cycle_index") or 1), 1)
        except Exception:
            report["cycle_index"] = 1
        report["provider"] = (raw.get("provider") or "").strip()
        report["model"] = (raw.get("model") or "").strip()
        report["text"] = (raw.get("text") or "").strip()
        report["recommend_needs_manual_fix"] = _normalize_ai_recommendation(raw.get("recommend_needs_manual_fix"))
        report["recommendation_reason"] = (raw.get("recommendation_reason") or "").strip()
        report["potential_problems"] = _normalize_ai_potential_problems(raw.get("potential_problems"))
        report["provider_override"] = (raw.get("provider_override") or "").strip().lower()
        report["model_override"] = (raw.get("model_override") or "").strip()
    if report["text"] and report["status"] in ("error", "missing_api_key", "missing_key", "disabled"):
        report["status"] = "ready"
        report["error"] = ""
    return report


def _surveillance_ai_report_has_content(report):
    report = report or {}
    return bool(
        (report.get("status") or "").strip()
        or (report.get("error") or "").strip()
        or (report.get("generated_at") or "").strip()
        or int(report.get("cycle_index") or 0) > 1
        or (report.get("provider") or "").strip()
        or (report.get("model") or "").strip()
        or (report.get("text") or "").strip()
    )


def _normalize_surveillance_ai_history(raw):
    out = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        stage = (item.get("stage") or "").strip().lower()
        if stage not in _SURV_AI_STAGES:
            continue
        generated_at = (item.get("generated_at") or "").strip()
        text = (item.get("text") or "").strip()
        if not generated_at and not text:
            continue
        try:
            cycle_index = max(int(item.get("cycle_index") or 1), 1)
        except Exception:
            cycle_index = 1
        out.append(
            {
                "stage": stage,
                "cycle_index": cycle_index,
                "generated_at": generated_at,
                "provider": (item.get("provider") or "").strip(),
                "model": (item.get("model") or "").strip(),
                "status": (item.get("status") or "").strip().lower(),
                "error": (item.get("error") or "").strip(),
                "text": text,
                "recommend_needs_manual_fix": _normalize_ai_recommendation(item.get("recommend_needs_manual_fix")),
                "recommendation_reason": (item.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(item.get("potential_problems")),
            }
        )
    if len(out) > 400:
        out = out[-400:]
    return out


def _surveillance_fixed_cycle_count(entry):
    history = _normalize_surveillance_stage_history((entry or {}).get("stage_history"))
    count = 0
    for item in history:
        action = (item.get("action") or "").strip().lower()
        from_stage = (item.get("from") or "").strip().lower()
        to_stage = (item.get("to") or "").strip().lower()
        if action == "mark_fixed" or (from_stage == "level2" and to_stage == "observe"):
            count += 1
    if count <= 0 and (entry or {}).get("last_fixed_at"):
        count = 1
    return max(count, 0)


def _surveillance_cycle_index_for_stage(entry, stage):
    stage = _resolve_surveillance_ai_stage(entry, stage)
    fixed_count = _surveillance_fixed_cycle_count(entry)
    if stage == "observe":
        return max(fixed_count, 1)
    return max(fixed_count + 1, 1)


def _legacy_surveillance_ai_report(entry):
    if not isinstance(entry, dict):
        return _empty_surveillance_ai_report()
    raw = {
        "status": (entry.get("ai_report_status") or "").strip().lower(),
        "error": (entry.get("ai_report_error") or "").strip(),
        "generated_at": (entry.get("ai_report_generated_at") or "").strip(),
        "provider": (entry.get("ai_report_provider") or "").strip(),
        "model": (entry.get("ai_report_model") or "").strip(),
        "text": (entry.get("ai_report_text") or "").strip(),
        "recommend_needs_manual_fix": entry.get("ai_recommend_needs_manual_fix"),
        "recommendation_reason": (entry.get("ai_recommendation_reason") or "").strip(),
        "potential_problems": entry.get("ai_potential_problems"),
        "provider_override": (entry.get("ai_report_provider_override") or "").strip().lower(),
        "model_override": (entry.get("ai_report_model_override") or "").strip(),
    }
    return _normalize_surveillance_ai_report(raw)


def _legacy_surveillance_ai_stage(entry, legacy_report):
    status = ((entry or {}).get("status") or "under").strip().lower()
    if status not in _SURV_AI_STAGES:
        status = "under"
    generated_at = _parse_iso_z((legacy_report or {}).get("generated_at"))
    level2_at = _parse_iso_z((entry or {}).get("level2_at"))
    fixed_at = _parse_iso_z((entry or {}).get("last_fixed_at"))
    if status == "level2":
        if generated_at and level2_at and generated_at < level2_at:
            return "under"
        return "level2"
    if status == "under" and fixed_at:
        if generated_at and generated_at >= fixed_at:
            return "observe"
        return "under"
    return "under"


def _entry_surveillance_ai_reports(entry):
    if not isinstance(entry, dict):
        return {stage: _empty_surveillance_ai_report() for stage in _SURV_AI_STAGES}
    raw_reports = entry.get("ai_reports") if isinstance(entry.get("ai_reports"), dict) else {}
    reports = {stage: _normalize_surveillance_ai_report(raw_reports.get(stage)) for stage in _SURV_AI_STAGES}
    has_stage_content = any(_surveillance_ai_report_has_content(reports.get(stage)) for stage in _SURV_AI_STAGES)
    if not has_stage_content:
        legacy = _legacy_surveillance_ai_report(entry)
        if _surveillance_ai_report_has_content(legacy):
            stage = _legacy_surveillance_ai_stage(entry, legacy)
            reports[stage] = legacy
    entry["ai_reports"] = reports
    entry["ai_report_history"] = _normalize_surveillance_ai_history(entry.get("ai_report_history"))
    pending_stage = (entry.get("ai_report_pending_stage") or "").strip().lower()
    if pending_stage not in _SURV_AI_STAGES:
        pending_stage = ""
    entry["ai_report_pending_stage"] = pending_stage
    return reports


def _resolve_surveillance_ai_stage(entry, fallback_stage=""):
    fallback_stage = (fallback_stage or "").strip().lower()
    if fallback_stage in _SURV_AI_STAGES:
        return fallback_stage
    if isinstance(entry, dict):
        pending = (entry.get("ai_report_pending_stage") or "").strip().lower()
        if pending in _SURV_AI_STAGES:
            return pending
        reports = _entry_surveillance_ai_reports(entry)
        for stage in _SURV_AI_STAGES:
            if (reports.get(stage, {}).get("status") or "").strip().lower() == "queued":
                return stage
        status = (entry.get("status") or "under").strip().lower()
        if status == "level2":
            return "level2"
        if status == "under" and (entry.get("last_fixed_at") or "").strip():
            return "observe"
    return "under"


def _queue_surveillance_ai_report(entry, stage="under", now_iso=None, reset_text=True):
    if not isinstance(entry, dict):
        return
    now_iso = (now_iso or "").strip() or utc_now_iso()
    stage = _resolve_surveillance_ai_stage(entry, stage)
    cycle_index = _surveillance_cycle_index_for_stage(entry, stage)
    reports = _entry_surveillance_ai_reports(entry)
    report = reports.get(stage) or _empty_surveillance_ai_report()
    report["status"] = "queued"
    report["error"] = ""
    report["generated_at"] = ""
    report["cycle_index"] = cycle_index
    report["provider"] = ""
    report["model"] = ""
    report["recommend_needs_manual_fix"] = "unknown"
    report["recommendation_reason"] = ""
    report["potential_problems"] = []
    report["provider_override"] = ""
    report["model_override"] = ""
    if reset_text:
        report["text"] = ""
    reports[stage] = report
    entry["ai_reports"] = reports
    entry["ai_report_pending_stage"] = stage
    entry["updated_at"] = now_iso


def _build_surveillance_ai_context(pppoe, entry, ai_cfg):
    pppoe = (pppoe or "").strip()
    entry = entry or {}
    lookback_hours = int((ai_cfg.get("report") or {}).get("lookback_hours") or 24)
    max_samples = int((ai_cfg.get("report") or {}).get("max_samples") or 60)
    now = datetime.utcnow().replace(microsecond=0)
    since = now - timedelta(hours=max(lookback_hours, 1))
    since_iso = since.isoformat() + "Z"
    until_iso = now.isoformat() + "Z"
    account_id = _accounts_ping_account_id_for_pppoe(pppoe)

    latest_map = get_latest_accounts_ping_map([account_id])
    latest = latest_map.get(account_id) if isinstance(latest_map, dict) else {}
    ping_series = get_accounts_ping_series_range(account_id, since_iso, until_iso)
    ping_series = _sample_rows_for_ai(ping_series, max_samples)
    ping_samples = []
    down_samples = 0
    for row in ping_series:
        ok = bool(row.get("ok"))
        if not ok:
            down_samples += 1
        ping_samples.append(
            {
                "ts": row.get("timestamp"),
                "ok": ok,
                "loss": row.get("loss"),
                "avg_ms": row.get("avg_ms"),
                "mode": row.get("mode"),
                "ip": row.get("ip"),
            }
        )

    ping_window_stats = get_accounts_ping_window_stats([account_id], since_iso)
    ping_window = ping_window_stats.get(account_id) if isinstance(ping_window_stats, dict) else {}

    optical_latest_map = get_latest_optical_by_pppoe([pppoe])
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_samples_raw = get_optical_results_for_device_since(device_id, since_iso) if device_id else []
    optical_samples_raw = _sample_rows_for_ai(optical_samples_raw, max_samples)
    optical_samples = [
        {"ts": row.get("timestamp"), "rx": row.get("rx"), "tx": row.get("tx")} for row in optical_samples_raw
    ]

    usage_series = get_pppoe_usage_series_since("", pppoe, since_iso)
    usage_series = _sample_rows_for_ai(usage_series, max_samples)
    usage_points = []
    usage_zero_count = 0
    usage_max_total = 0.0
    for row in usage_series:
        rx_bps = float(row.get("rx_bps") or 0.0)
        tx_bps = float(row.get("tx_bps") or 0.0)
        total_bps = max(rx_bps, 0.0) + max(tx_bps, 0.0)
        if total_bps < 1.0:
            usage_zero_count += 1
        usage_max_total = max(usage_max_total, total_bps)
        usage_points.append(
            {
                "ts": row.get("timestamp"),
                "rx_bps": rx_bps,
                "tx_bps": tx_bps,
                "total_bps": total_bps,
                "host_count": row.get("host_count"),
            }
        )

    return {
        "timeframe": {
            "from_utc": since_iso,
            "to_utc": until_iso,
            "lookback_hours": lookback_hours,
        },
        "account": {
            "pppoe": pppoe,
            "status": (entry.get("status") or "").strip(),
            "source": (entry.get("source") or "").strip(),
            "added_mode": (entry.get("added_mode") or "").strip(),
            "added_at": (entry.get("added_at") or "").strip(),
            "moved_to_needs_manual_fix_at": (entry.get("level2_at") or "").strip(),
            "needs_manual_fix_reason": (entry.get("level2_reason") or "").strip(),
            "last_ip": (entry.get("ip") or "").strip(),
        },
        "accounts_ping": {
            "latest": {
                "timestamp": latest.get("timestamp") if isinstance(latest, dict) else None,
                "ok": latest.get("ok") if isinstance(latest, dict) else None,
                "loss": latest.get("loss") if isinstance(latest, dict) else None,
                "avg_ms": latest.get("avg_ms") if isinstance(latest, dict) else None,
                "ip": latest.get("ip") if isinstance(latest, dict) else None,
                "mode": latest.get("mode") if isinstance(latest, dict) else None,
            },
            "window_summary": {
                "sample_total": int((ping_window or {}).get("total") or 0),
                "failure_total": int((ping_window or {}).get("failures") or 0),
                "loss_avg": (ping_window or {}).get("loss_avg"),
                "latency_avg_ms": (ping_window or {}).get("avg_ms_avg"),
                "down_sample_total": down_samples,
            },
            "series": ping_samples,
        },
        "optical": {
            "latest": optical_latest if isinstance(optical_latest, dict) else {},
            "series": optical_samples,
        },
        "usage": {
            "series": usage_points,
            "max_total_bps": usage_max_total,
            "zero_usage_samples": usage_zero_count,
            "total_samples": len(usage_points),
        },
    }


def _set_surveillance_ai_fields(pppoe, stage, report_fields=None, entry_fields=None, append_history=None):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return False
    stage = _resolve_surveillance_ai_stage({}, stage)
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe)
    if not isinstance(entry, dict):
        return False
    reports = _entry_surveillance_ai_reports(entry)
    report = reports.get(stage) or _empty_surveillance_ai_report()
    for key, value in (report_fields or {}).items():
        report[key] = value
    reports[stage] = _normalize_surveillance_ai_report(report)
    entry["ai_reports"] = reports
    if isinstance(append_history, dict):
        history = _normalize_surveillance_ai_history(entry.get("ai_report_history"))
        try:
            history_cycle_index = max(int(append_history.get("cycle_index") or report.get("cycle_index") or 1), 1)
        except Exception:
            history_cycle_index = 1
        item = {
            "stage": stage,
            "cycle_index": history_cycle_index,
            "generated_at": (append_history.get("generated_at") or report.get("generated_at") or "").strip(),
            "provider": (append_history.get("provider") or report.get("provider") or "").strip(),
            "model": (append_history.get("model") or report.get("model") or "").strip(),
            "status": (append_history.get("status") or report.get("status") or "").strip().lower(),
            "error": (append_history.get("error") or report.get("error") or "").strip(),
            "text": (append_history.get("text") or report.get("text") or "").strip(),
            "recommend_needs_manual_fix": _normalize_ai_recommendation(
                append_history.get("recommend_needs_manual_fix") or report.get("recommend_needs_manual_fix")
            ),
            "recommendation_reason": (append_history.get("recommendation_reason") or report.get("recommendation_reason") or "").strip(),
            "potential_problems": _normalize_ai_potential_problems(
                append_history.get("potential_problems") or report.get("potential_problems")
            ),
        }
        if item.get("generated_at") or item.get("text"):
            history.append(item)
            entry["ai_report_history"] = _normalize_surveillance_ai_history(history)
    for key, value in (entry_fields or {}).items():
        entry[key] = value
    entry["updated_at"] = utc_now_iso()
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    return True


def _run_surveillance_ai_report(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return
    stage = "under"
    try:
        system_cfg = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
        ai_cfg = system_cfg.get("ai") if isinstance(system_cfg.get("ai"), dict) else {}

        settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entry_map = _surveillance_entry_map(settings)
        entry = entry_map.get(pppoe) or {}
        stage = _resolve_surveillance_ai_stage(entry)
        cycle_index = _surveillance_cycle_index_for_stage(entry, stage)

        if not ai_cfg or not ai_cfg.get("enabled"):
            _set_surveillance_ai_fields(
                pppoe,
                stage,
                report_fields={
                    "status": "disabled",
                    "error": "AI Investigator is disabled in System Settings.",
                    "generated_at": utc_now_iso(),
                    "cycle_index": cycle_index,
                    "recommend_needs_manual_fix": "unknown",
                    "recommendation_reason": "",
                    "potential_problems": [],
                },
                entry_fields={"ai_report_pending_stage": ""},
            )
            return

        effective_ai_cfg = copy.deepcopy(ai_cfg if isinstance(ai_cfg, dict) else {})
        reports = _entry_surveillance_ai_reports(entry)
        stage_report = reports.get(stage) or _empty_surveillance_ai_report()
        override_provider = (stage_report.get("provider_override") or "").strip().lower()
        override_model = (stage_report.get("model_override") or "").strip()
        if override_provider in ("chatgpt", "gemini"):
            effective_ai_cfg["provider"] = override_provider
        provider = (effective_ai_cfg.get("provider") or "chatgpt").strip().lower()
        if provider not in ("chatgpt", "gemini"):
            provider = "chatgpt"
            effective_ai_cfg["provider"] = provider
        provider_cfg = effective_ai_cfg.get(provider) if isinstance(effective_ai_cfg.get(provider), dict) else {}
        if override_model:
            provider_cfg["model"] = _normalize_provider_model_id(provider, override_model)
            effective_ai_cfg[provider] = provider_cfg
        if not (provider_cfg.get("api_key") or "").strip():
            _set_surveillance_ai_fields(
                pppoe,
                stage,
                report_fields={
                    "status": "missing_api_key",
                    "error": f"Missing API key for {provider}.",
                    "generated_at": utc_now_iso(),
                    "cycle_index": cycle_index,
                    "recommend_needs_manual_fix": "unknown",
                    "recommendation_reason": "",
                    "potential_problems": [],
                    "provider_override": "",
                    "model_override": "",
                },
                entry_fields={"ai_report_pending_stage": ""},
            )
            return

        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "running",
                "error": "",
                "generated_at": "",
                "cycle_index": cycle_index,
                "recommend_needs_manual_fix": "unknown",
                "recommendation_reason": "",
                "potential_problems": [],
            },
        )
        settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entry_map = _surveillance_entry_map(settings)
        entry = entry_map.get(pppoe) or {}
        context = _build_surveillance_ai_context(pppoe, entry, effective_ai_cfg)
        try:
            report = generate_investigation_report(effective_ai_cfg, context)
        except AIInvestigatorError as exc:
            err_text = str(exc or "").lower()
            if "timed out" not in err_text:
                raise
            retry_ai_cfg = copy.deepcopy(effective_ai_cfg if isinstance(effective_ai_cfg, dict) else {})
            retry_report_cfg = retry_ai_cfg.get("report") if isinstance(retry_ai_cfg.get("report"), dict) else {}
            current_samples = int(retry_report_cfg.get("max_samples") or 60)
            current_hours = int(retry_report_cfg.get("lookback_hours") or 24)
            retry_report_cfg["max_samples"] = max(10, min(current_samples // 2 if current_samples > 20 else 20, 40))
            retry_report_cfg["lookback_hours"] = max(1, min(current_hours, 48))
            retry_ai_cfg["report"] = retry_report_cfg
            context = _build_surveillance_ai_context(pppoe, entry, retry_ai_cfg)
            report = generate_investigation_report(retry_ai_cfg, context)
        ready_at_iso = utc_now_iso()
        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "ready",
                "error": "",
                "generated_at": ready_at_iso,
                "cycle_index": cycle_index,
                "provider": report.get("provider") or provider,
                "model": report.get("model") or (provider_cfg.get("model") or ""),
                "text": (report.get("text") or "").strip(),
                "recommend_needs_manual_fix": _normalize_ai_recommendation(report.get("recommend_needs_manual_fix")),
                "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
                "provider_override": "",
                "model_override": "",
            },
            entry_fields={"ai_report_pending_stage": ""},
            append_history={
                "stage": stage,
                "cycle_index": cycle_index,
                "generated_at": ready_at_iso,
                "provider": report.get("provider") or provider,
                "model": report.get("model") or (provider_cfg.get("model") or ""),
                "status": "ready",
                "error": "",
                "text": (report.get("text") or "").strip(),
                "recommend_needs_manual_fix": _normalize_ai_recommendation(report.get("recommend_needs_manual_fix")),
                "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
            },
        )
    except AIInvestigatorError as exc:
        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "error",
                "error": _ai_safe_error(exc),
                "generated_at": utc_now_iso(),
                "cycle_index": cycle_index,
                "recommend_needs_manual_fix": "unknown",
                "recommendation_reason": "",
                "potential_problems": [],
                "provider_override": "",
                "model_override": "",
            },
            entry_fields={"ai_report_pending_stage": ""},
        )
    except Exception as exc:
        _set_surveillance_ai_fields(
            pppoe,
            stage,
            report_fields={
                "status": "error",
                "error": _ai_safe_error(exc),
                "generated_at": utc_now_iso(),
                "cycle_index": cycle_index,
                "recommend_needs_manual_fix": "unknown",
                "recommendation_reason": "",
                "potential_problems": [],
                "provider_override": "",
                "model_override": "",
            },
            entry_fields={"ai_report_pending_stage": ""},
        )
    finally:
        with _surv_ai_lock:
            _surv_ai_running.discard(pppoe)
        _start_next_queued_surveillance_ai_report(exclude_pppoe=pppoe)


def _start_surveillance_ai_report(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return False
    with _surv_ai_lock:
        if pppoe in _surv_ai_running:
            return False
        if len(_surv_ai_running) >= max(int(_SURV_AI_MAX_PARALLEL), 1):
            return False
        _surv_ai_running.add(pppoe)
    worker = threading.Thread(target=_run_surveillance_ai_report, args=(pppoe,), daemon=True)
    worker.start()
    return True


def _start_next_queued_surveillance_ai_report(exclude_pppoe=""):
    exclude_pppoe = (exclude_pppoe or "").strip()
    try:
        settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
        entry_map = _surveillance_entry_map(settings)
    except Exception:
        return False
    for pppoe, entry in entry_map.items():
        if not isinstance(entry, dict):
            continue
        pppoe = (pppoe or "").strip()
        if not pppoe or pppoe == exclude_pppoe:
            continue
        status = (entry.get("status") or "under").strip().lower()
        if status not in ("under", "level2"):
            continue
        reports = _entry_surveillance_ai_reports(entry)
        queued_stage = ""
        for stage in _SURV_AI_STAGES:
            if (reports.get(stage, {}).get("status") or "").strip().lower() == "queued":
                queued_stage = stage
                break
        if not queued_stage:
            continue
        entry["ai_report_pending_stage"] = queued_stage
        settings["entries"] = list(entry_map.values())
        save_settings("surveillance", settings)
        if _start_surveillance_ai_report(pppoe):
            return True
    return False


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
    try:
        fixed_minutes = int(cfg["stability"].get("fixed_observation_minutes", cfg["stability"].get("stable_window_minutes", 10)) or 10)
    except Exception:
        fixed_minutes = int(cfg["stability"].get("stable_window_minutes", 10) or 10)
    if fixed_minutes < 1:
        fixed_minutes = 1
    cfg["stability"]["fixed_observation_minutes"] = fixed_minutes
    try:
        loss_max_minutes = float(cfg["stability"].get("loss_max_minutes", 10.0) or 10.0)
    except Exception:
        loss_max_minutes = 10.0
    if loss_max_minutes < 0:
        loss_max_minutes = 0.0
    cfg["stability"]["loss_max_minutes"] = loss_max_minutes
    try:
        loss_event_max_count = int(cfg["stability"].get("loss_event_max_count", 5) or 5)
    except Exception:
        loss_event_max_count = 5
    if loss_event_max_count < 0:
        loss_event_max_count = 0
    cfg["stability"]["loss_event_max_count"] = loss_event_max_count
    cfg["stability"].pop("loss_max_pct", None)
    cfg["stability"].pop("level2_autofix_after_minutes", None)
    cfg["stability"].pop("escalate_after_minutes", None)
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
        ai_reports = _entry_surveillance_ai_reports(entry)
        pending_stage = _resolve_surveillance_ai_stage(entry, entry.get("ai_report_pending_stage") or "")
        if (ai_reports.get(pending_stage, {}).get("status") or "").strip().lower() != "queued":
            pending_stage = ""
        normalized.append(
            {
                "pppoe": pppoe,
                "name": (entry.get("name") or pppoe).strip(),
                "ip": (entry.get("ip") or "").strip(),
                "source": (entry.get("source") or "").strip(),
                "status": status,
                "added_at": (entry.get("added_at") or "").strip() or now_iso,
                "first_added_at": (entry.get("first_added_at") or entry.get("added_at") or "").strip() or now_iso,
                "updated_at": (entry.get("updated_at") or "").strip() or now_iso,
                "level2_at": (entry.get("level2_at") or "").strip(),
                "level2_reason": (entry.get("level2_reason") or "").strip(),
                "last_fixed_at": (entry.get("last_fixed_at") or "").strip(),
                "last_fixed_reason": (entry.get("last_fixed_reason") or "").strip(),
                "last_fixed_mode": (entry.get("last_fixed_mode") or "").strip(),
                "added_mode": (entry.get("added_mode") or "").strip().lower() or "manual",
                "auto_source": (entry.get("auto_source") or "").strip(),
                "auto_reason": (entry.get("auto_reason") or "").strip(),
                "stage_history": _normalize_surveillance_stage_history(entry.get("stage_history")),
                "ai_reports": ai_reports,
                "ai_report_history": _normalize_surveillance_ai_history(entry.get("ai_report_history")),
                "ai_report_pending_stage": pending_stage,
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


def _normalize_surveillance_stage_history(raw_items):
    out = []
    if not isinstance(raw_items, list):
        return out
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        ts = (item.get("ts") or item.get("at") or "").strip()
        if not ts:
            ts = utc_now_iso()
        from_stage = (item.get("from") or item.get("from_stage") or "").strip().lower()
        to_stage = (item.get("to") or item.get("to_stage") or "").strip().lower()
        reason = (item.get("reason") or item.get("note") or "").strip()
        action = (item.get("action") or "").strip().lower()
        actor = (item.get("actor") or "admin").strip().lower() or "admin"
        out.append(
            {
                "ts": ts,
                "from": from_stage,
                "to": to_stage,
                "reason": reason[:500],
                "action": action[:64],
                "actor": actor[:32],
            }
        )
    if len(out) > 250:
        out = out[-250:]
    return out


def _append_surveillance_stage_history(entry, from_stage, to_stage, reason="", action="", at_iso=""):
    if not isinstance(entry, dict):
        return
    history = _normalize_surveillance_stage_history(entry.get("stage_history"))
    history.append(
        {
            "ts": (at_iso or "").strip() or utc_now_iso(),
            "from": (from_stage or "").strip().lower(),
            "to": (to_stage or "").strip().lower(),
            "reason": (reason or "").strip()[:500],
            "action": (action or "").strip().lower()[:64],
            "actor": "admin",
        }
    )
    entry["stage_history"] = _normalize_surveillance_stage_history(history)


def _surveillance_stage_seconds(entry, ended_at=None):
    end_dt = ended_at if isinstance(ended_at, datetime) else datetime.utcnow()
    added_at = _parse_iso_z((entry or {}).get("added_at"))
    level2_at = _parse_iso_z((entry or {}).get("level2_at"))
    fixed_at = _parse_iso_z((entry or {}).get("last_fixed_at"))
    status = ((entry or {}).get("status") or "under").strip().lower()

    under_seconds = 0
    level2_seconds = 0
    observe_seconds = 0

    if not added_at:
        return under_seconds, level2_seconds, observe_seconds

    if status == "level2":
        if level2_at and level2_at > added_at:
            under_seconds = max(int((level2_at - added_at).total_seconds()), 0)
            level2_seconds = max(int((end_dt - level2_at).total_seconds()), 0)
        else:
            level2_seconds = max(int((end_dt - added_at).total_seconds()), 0)
        return under_seconds, level2_seconds, observe_seconds

    is_observation = bool(fixed_at and fixed_at >= added_at)
    if is_observation:
        observe_seconds = max(int((end_dt - fixed_at).total_seconds()), 0)
    else:
        under_seconds = max(int((end_dt - added_at).total_seconds()), 0)
    return under_seconds, level2_seconds, observe_seconds


def _normalize_surveillance_stage(stage_value):
    stage = (stage_value or "").strip().lower()
    if stage in ("under", "level2", "observe"):
        return stage
    return "under"


def _surveillance_entry_anchors(entry, stage="under", now_utc=None):
    now = now_utc if isinstance(now_utc, datetime) else datetime.utcnow().replace(microsecond=0)
    stage = _normalize_surveillance_stage(stage)
    entry = entry if isinstance(entry, dict) else {}

    added_iso = (entry.get("added_at") or "").strip()
    fixed_iso = (entry.get("last_fixed_at") or "").strip()
    first_added_iso = (entry.get("first_added_at") or "").strip() or added_iso

    added_dt = _parse_iso_z(added_iso)
    fixed_dt = _parse_iso_z(fixed_iso)
    first_added_dt = _parse_iso_z(first_added_iso)

    if not added_dt:
        added_dt = now
        added_iso = now.isoformat() + "Z"
    if not first_added_dt:
        first_added_dt = added_dt
        first_added_iso = added_iso

    checker_anchor_iso = added_iso
    checker_anchor_dt = added_dt
    checker_anchor_source = "added"
    if fixed_dt and fixed_iso and fixed_dt <= now:
        checker_anchor_iso = fixed_iso
        checker_anchor_dt = fixed_dt
        checker_anchor_source = "fixed"

    stage_anchor_iso = added_iso
    stage_anchor_dt = added_dt
    stage_anchor_source = "added"
    if stage == "observe" and fixed_dt and fixed_iso and fixed_dt <= now:
        stage_anchor_iso = fixed_iso
        stage_anchor_dt = fixed_dt
        stage_anchor_source = "fixed"

    return {
        "stage": stage,
        "added_iso": added_iso,
        "added_dt": added_dt,
        "fixed_iso": fixed_iso,
        "fixed_dt": fixed_dt,
        "first_added_iso": first_added_iso,
        "first_added_dt": first_added_dt,
        "checker_anchor_iso": checker_anchor_iso,
        "checker_anchor_dt": checker_anchor_dt,
        "checker_anchor_source": checker_anchor_source,
        "stage_anchor_iso": stage_anchor_iso,
        "stage_anchor_dt": stage_anchor_dt,
        "stage_anchor_source": stage_anchor_source,
    }


@app.get("/surveillance", response_class=HTMLResponse)
async def surveillance_page(request: Request):
    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    save_settings("surveillance", settings)

    active_tab = (request.query_params.get("tab") or "").strip().lower()
    focus = (request.query_params.get("focus") or "").strip()
    if active_tab not in ("under", "observe", "level2", "history", "settings"):
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
    fixed_observation_minutes = max(
        int(stab_cfg.get("fixed_observation_minutes", stable_window_minutes) or stable_window_minutes),
        1,
    )
    fixed_observation_days = fixed_observation_minutes / 1440.0
    now = datetime.utcnow().replace(microsecond=0)
    now_iso = now.isoformat() + "Z"

    checker_anchor_by_pppoe = {}
    checker_since_by_account = {}
    for pppoe in pppoes:
        entry = entry_map.get(pppoe) or {}
        added_iso = (entry.get("added_at") or "").strip()
        fixed_iso = (entry.get("last_fixed_at") or "").strip()
        added_dt = _parse_iso_z(added_iso)
        fixed_dt = _parse_iso_z(fixed_iso)

        anchor_iso = added_iso or now_iso
        anchor_dt = added_dt or now
        anchor_source = "added"
        if fixed_dt and fixed_iso and fixed_dt <= now:
            anchor_iso = fixed_iso
            anchor_dt = fixed_dt
            anchor_source = "fixed"

        checker_anchor_by_pppoe[pppoe] = {
            "since_iso": anchor_iso,
            "since_dt": anchor_dt,
            "source": anchor_source,
        }

        account_id = _accounts_ping_account_id_for_ip(pppoe)
        if not account_id:
            continue
        current_since = checker_since_by_account.get(account_id)
        if not current_since:
            checker_since_by_account[account_id] = anchor_iso
            continue
        current_dt = _parse_iso_z(current_since)
        if current_dt is None or anchor_dt > current_dt:
            checker_since_by_account[account_id] = anchor_iso

    latest_map = get_latest_accounts_ping_map(account_ids)
    checker_stats_map = get_accounts_ping_checker_stats_map(checker_since_by_account, now_iso)
    optical_latest_map = get_latest_optical_by_pppoe(pppoes)
    fixed_cycles_map = get_surveillance_fixed_cycles_map(pppoes, limit_per_pppoe=250)
    ping_state = get_state("accounts_ping_state", {"accounts": {}})
    ping_accounts = ping_state.get("accounts") if isinstance(ping_state.get("accounts"), dict) else {}

    def build_row(pppoe):
        entry = entry_map.get(pppoe, {})
        account_id = _accounts_ping_account_id_for_ip(pppoe)
        latest = latest_map.get(account_id) or {}
        checker_meta = checker_anchor_by_pppoe.get(pppoe) or {}
        checker_since_iso = (checker_meta.get("since_iso") or "").strip() or now_iso
        checker_since_dt = checker_meta.get("since_dt")
        if not isinstance(checker_since_dt, datetime):
            checker_since_dt = _parse_iso_z(checker_since_iso) or now
        checker_since_source = (checker_meta.get("source") or "added").strip().lower()
        stats = checker_stats_map.get(account_id) or {}
        opt = optical_latest_map.get(pppoe) or {}
        st = ping_accounts.get(account_id) if isinstance(ping_accounts.get(account_id), dict) else {}

        total = int(stats.get("total") or 0)
        failures = int(stats.get("failures") or 0)
        uptime_pct = (100.0 - (failures / total) * 100.0) if total else 0.0
        checker_downtime_seconds = int(stats.get("downtime_seconds") or 0)
        checker_loss_events = int(stats.get("loss_events") or 0)

        down_since_dt = _parse_iso_z(st.get("down_since"))
        down_for = _format_duration_short((now - down_since_dt).total_seconds()) if down_since_dt else ""
        fixed_at_iso = (entry.get("last_fixed_at") or "").strip()
        fixed_at_dt = _parse_iso_z(fixed_at_iso)
        fixed_cycles = fixed_cycles_map.get(pppoe) or []
        fixed_cycle = fixed_cycles[0] if fixed_cycles else {}
        prefixed_cycle_start_iso = (fixed_cycle.get("started_at") or "").strip()
        prefixed_cycle_end_iso = (fixed_cycle.get("ended_at") or "").strip()
        stage_history = _normalize_surveillance_stage_history(entry.get("stage_history"))
        if not stage_history:
            level2_reason = (entry.get("level2_reason") or "").strip()
            level2_at_iso = (entry.get("level2_at") or "").strip()
            if level2_reason and level2_at_iso:
                stage_history.append(
                    {
                        "ts": level2_at_iso,
                        "from": "under",
                        "to": "level2",
                        "reason": level2_reason[:500],
                        "action": "move_to_manual_fix",
                        "actor": "admin",
                    }
                )
            fixed_reason = (entry.get("last_fixed_reason") or "").strip()
            if fixed_reason and fixed_at_iso:
                stage_history.append(
                    {
                        "ts": fixed_at_iso,
                        "from": "level2",
                        "to": "observe",
                        "reason": fixed_reason[:500],
                        "action": "mark_fixed",
                        "actor": "admin",
                    }
                )
            stage_history = _normalize_surveillance_stage_history(stage_history)
        observation_due_iso = ""
        observation_due_ph = ""
        observation_seconds_left = None
        observation_left_text = ""
        if fixed_at_dt:
            due_dt = fixed_at_dt + timedelta(minutes=fixed_observation_minutes)
            observation_due_iso = due_dt.replace(microsecond=0).isoformat() + "Z"
            observation_due_ph = format_ts_ph(observation_due_iso)
            observation_seconds_left = int((due_dt - now).total_seconds())
            if observation_seconds_left > 0:
                observation_left_text = _format_duration_short(observation_seconds_left)
            else:
                observation_left_text = "Done"
        reports = _entry_surveillance_ai_reports(entry)
        ai_reports = {}
        for stage_key in _SURV_AI_STAGES:
            report = reports.get(stage_key) or _empty_surveillance_ai_report()
            ai_status = (report.get("status") or "").strip().lower()
            ai_report_text = (report.get("text") or "").strip()
            ai_report_error = (report.get("error") or "").strip()
            ai_has_report = bool(ai_report_text)
            if ai_has_report and ai_status in ("error", "missing_api_key", "missing_key", "disabled"):
                ai_status = "ready"
                ai_report_error = ""
            ai_is_generating = ai_status in ("queued", "running")
            ai_has_error = (ai_status in ("error", "missing_api_key", "missing_key") or bool(ai_report_error)) and not ai_has_report
            ai_reports[stage_key] = {
                "stage": stage_key,
                "stage_label": _SURV_AI_STAGE_LABELS.get(stage_key) or stage_key,
                "status": ai_status,
                "status_label": _ai_report_status_badge(ai_status),
                "error": ai_report_error,
                "generated_at_iso": (report.get("generated_at") or "").strip(),
                "generated_at_ph": format_ts_ph(report.get("generated_at")),
                "provider": (report.get("provider") or "").strip(),
                "model": (report.get("model") or "").strip(),
                "text": ai_report_text,
                "recommend_needs_manual_fix": _normalize_ai_recommendation(report.get("recommend_needs_manual_fix")),
                "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
                "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
                "has_report": ai_has_report,
                "is_generating": ai_is_generating,
                "has_error": ai_has_error,
            }

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
            "first_added_at_iso": (entry.get("first_added_at") or entry.get("added_at") or "").strip(),
            "first_added_at_ph": format_ts_ph(entry.get("first_added_at") or entry.get("added_at")),
            "level2_at_iso": (entry.get("level2_at") or "").strip(),
            "level2_at_ph": format_ts_ph(entry.get("level2_at")),
            "level2_reason": (entry.get("level2_reason") or "").strip(),
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
            "stable_downtime_seconds": checker_downtime_seconds,
            "stable_loss_events": checker_loss_events,
            "checker_since_iso": checker_since_iso,
            "checker_since_ph": format_ts_ph(checker_since_iso),
            "checker_since_source": checker_since_source,
            "checker_elapsed_seconds": max(int((now - checker_since_dt).total_seconds()), 0),
            "down_for": down_for,
            "down_since_iso": (st.get("down_since") or "").strip(),
            "optical_rx": opt.get("rx"),
            "optical_tx": opt.get("tx"),
            "optical_last": format_ts_ph(opt.get("timestamp")),
            "optical_last_iso": (opt.get("timestamp") or "").strip(),
            "last_fixed_at_iso": fixed_at_iso,
            "last_fixed_at_ph": format_ts_ph(fixed_at_iso),
            "last_fixed_reason": (entry.get("last_fixed_reason") or "").strip(),
            "last_fixed_mode": (entry.get("last_fixed_mode") or "").strip(),
            "stage_history": stage_history,
            "prefixed_cycle_start_iso": prefixed_cycle_start_iso,
            "prefixed_cycle_end_iso": prefixed_cycle_end_iso,
            "prefixed_cycle_start_ph": format_ts_ph(prefixed_cycle_start_iso),
            "prefixed_cycle_end_ph": format_ts_ph(prefixed_cycle_end_iso),
            "prefixed_cycles": fixed_cycles,
            "fixed_cycle_count": len(fixed_cycles),
            "ai_reports": ai_reports,
            "observation_due_iso": observation_due_iso,
            "observation_due_ph": observation_due_ph,
            "observation_seconds_left": observation_seconds_left,
            "observation_left_text": observation_left_text,
        }

    def _apply_ai_stage(row, stage_key):
        stage_key = stage_key if stage_key in _SURV_AI_STAGES else "under"
        report = ((row or {}).get("ai_reports") or {}).get(stage_key) or {}
        out = dict(row or {})
        out["ai_stage"] = stage_key
        out["ai_report_status"] = (report.get("status") or "").strip()
        out["ai_report_status_label"] = report.get("status_label") or _ai_report_status_badge(report.get("status") or "")
        out["ai_report_error"] = (report.get("error") or "").strip()
        out["ai_report_generated_at_iso"] = (report.get("generated_at_iso") or "").strip()
        out["ai_report_generated_at_ph"] = (report.get("generated_at_ph") or "").strip()
        out["ai_report_provider"] = (report.get("provider") or "").strip()
        out["ai_report_model"] = (report.get("model") or "").strip()
        out["ai_report_text"] = (report.get("text") or "").strip()
        out["ai_recommend_needs_manual_fix"] = _normalize_ai_recommendation(report.get("recommend_needs_manual_fix"))
        out["ai_recommendation_reason"] = (report.get("recommendation_reason") or "").strip()
        out["ai_potential_problems"] = _normalize_ai_potential_problems(report.get("potential_problems"))
        out["ai_has_report"] = bool(report.get("has_report"))
        out["ai_is_generating"] = bool(report.get("is_generating"))
        out["ai_has_error"] = bool(report.get("has_error"))
        return out

    all_under_rows = [build_row(pppoe) for pppoe in pppoes if (entry_map.get(pppoe, {}).get("status") or "under") == "under"]
    observation_base_rows = [
        row
        for row in all_under_rows
        if row.get("last_fixed_at_iso")
    ]
    observation_set = {row.get("pppoe") for row in observation_base_rows if row.get("pppoe")}
    under_rows = [_apply_ai_stage(row, "under") for row in all_under_rows if row.get("pppoe") not in observation_set]
    observation_rows = [_apply_ai_stage(row, "observe") for row in observation_base_rows]
    level2_rows = [
        _apply_ai_stage(build_row(pppoe), "level2")
        for pppoe in pppoes
        if (entry_map.get(pppoe, {}).get("status") or "") == "level2"
    ]

    def _ai_status_panel(rows):
        rows = list(rows or [])
        grouped = {"generating": [], "ready": [], "error": [], "missing": []}
        for row in rows:
            pppoe = (row.get("pppoe") or "").strip()
            if not pppoe:
                continue
            if bool(row.get("ai_is_generating")):
                grouped["generating"].append(pppoe)
            elif bool(row.get("ai_has_error")):
                grouped["error"].append(pppoe)
            elif bool(row.get("ai_has_report")):
                grouped["ready"].append(pppoe)
            else:
                grouped["missing"].append(pppoe)
        for key in grouped:
            grouped[key] = sorted(grouped[key], key=lambda value: value.lower())
        return {
            "generating": {"label": "Generating", "accounts": grouped["generating"], "count": len(grouped["generating"])},
            "ready": {"label": "Ready", "accounts": grouped["ready"], "count": len(grouped["ready"])},
            "error": {"label": "Error", "accounts": grouped["error"], "count": len(grouped["error"])},
            "missing": {"label": "No Report", "accounts": grouped["missing"], "count": len(grouped["missing"])},
        }

    history_query = (request.query_params.get("q") or "").strip() if active_tab == "history" else ""
    history_action = (request.query_params.get("action") or "all").strip().lower() if active_tab == "history" else "all"
    if history_action not in ("all", "false", "fixed", "recovered", "healed", "removed"):
        history_action = "all"
    history_page = _parse_table_page(request.query_params.get("page"), default=1) if active_tab == "history" else 1
    history = list_surveillance_history(
        query=history_query,
        page=history_page,
        limit=50,
        end_reason=history_action,
    )

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
                    "under_seconds": int(row.get("under_seconds") or 0),
                    "level2_seconds": int(row.get("level2_seconds") or 0),
                    "observe_seconds": int(row.get("observe_seconds") or 0),
                    "under_for_text": _format_duration_short(row.get("under_seconds") or 0) or "0m",
                    "level2_for_text": _format_duration_short(row.get("level2_seconds") or 0) or "0m",
                    "observe_for_text": _format_duration_short(row.get("observe_seconds") or 0) or "0m",
                    "started_at_iso": started_iso,
                    "ended_at_iso": ended_iso,
                    "started_at_ph": format_ts_ph(started_iso),
                    "ended_at_ph": format_ts_ph(ended_iso),
                    "active": not bool(ended_iso),
                }
            )

    total = int(history.get("total") or 0)
    limit = int(history.get("limit") or 50)
    page = int(history.get("page") or 1)
    pages = max((total + limit - 1) // limit, 1) if limit else 1
    history_pagination = {"page": page, "pages": pages, "total": total}

    optical_cfg = get_settings("optical", OPTICAL_DEFAULTS)
    optical_class = (optical_cfg.get("classification") or {}) if isinstance(optical_cfg.get("classification"), dict) else {}
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    ai_settings = system_settings.get("ai") if isinstance(system_settings.get("ai"), dict) else {}
    ai_model_options_payload = _build_ai_model_options(ai_settings, active_tab="")
    ai_model_options = ai_model_options_payload.get("options") if isinstance(ai_model_options_payload, dict) else {}
    if not isinstance(ai_model_options, dict):
        ai_model_options = {}

    return templates.TemplateResponse(
        "surveillance.html",
        make_context(
            request,
            {
                "settings": settings,
                "active_tab": active_tab,
                "under_rows": under_rows,
                "observation_rows": observation_rows,
                "level2_rows": level2_rows,
                "under_ai_panel": _ai_status_panel(under_rows),
                "level2_ai_panel": _ai_status_panel(level2_rows),
                "observe_ai_panel": _ai_status_panel(observation_rows),
                "stable_window_minutes": stable_window_minutes,
                "stable_window_days": stable_window_days,
                "fixed_observation_minutes": fixed_observation_minutes,
                "fixed_observation_days": fixed_observation_days,
                "history_rows": history_rows,
                "history_query": history_query,
                "history_action": history_action,
                "history_pagination": history_pagination,
                "message": message,
                "optical_window_options": OPTICAL_WINDOW_OPTIONS,
                "surv_optical_chart_min_dbm": float(optical_class.get("chart_min_dbm", -35.0) or -35.0),
                "surv_optical_chart_max_dbm": float(optical_class.get("chart_max_dbm", -10.0) or -10.0),
                "surv_optical_tx_realistic_min_dbm": float(optical_class.get("tx_realistic_min_dbm", -10.0) or -10.0),
                "surv_optical_tx_realistic_max_dbm": float(optical_class.get("tx_realistic_max_dbm", 10.0) or 10.0),
                "surveillance_ai_model_options": ai_model_options,
            },
        ),
    )


@app.get("/surveillance/series", response_class=JSONResponse)
async def surveillance_series(pppoe: str, window: str = "24", stage: str = "under"):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return JSONResponse({"hours": 0, "series": []})
    stage = _normalize_surveillance_stage(stage)
    raw_window = (window or "").strip().lower()
    if raw_window in ("pre7d", "baseline", "pre"):
        window_key = "pre7d"
    else:
        try:
            parsed_hours = int(raw_window)
        except Exception:
            parsed_hours = 24
        if parsed_hours not in {1, 6, 12, 24, 168}:
            parsed_hours = 24
        window_key = str(parsed_hours)

    now = datetime.utcnow().replace(microsecond=0)

    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    anchors = _surveillance_entry_anchors(entry, stage=stage, now_utc=now)

    if window_key == "pre7d":
        until_dt = min(anchors["first_added_dt"], now).replace(microsecond=0)
        since_dt = (until_dt - timedelta(hours=168)).replace(microsecond=0)
        anchor_iso = anchors["first_added_iso"]
        anchor_source = "first_added"
    else:
        hours = int(window_key)
        until_dt = now
        since_dt = max((until_dt - timedelta(hours=hours)).replace(microsecond=0), anchors["stage_anchor_dt"])
        anchor_iso = anchors["stage_anchor_iso"]
        anchor_source = anchors["stage_anchor_source"]
    if until_dt < since_dt:
        since_dt = until_dt

    until_iso = until_dt.isoformat() + "Z"
    since_iso = since_dt.isoformat() + "Z"
    if since_dt > until_dt:
        since_iso = until_iso

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
    return JSONResponse(
        {
            "pppoe": pppoe,
            "stage": stage,
            "hours": int(window_key) if window_key != "pre7d" else 168,
            "window_key": window_key,
            "since": since_iso,
            "until": until_iso,
            "anchor_since": anchor_iso,
            "anchor_source": anchor_source,
            "series": series,
        }
    )


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
    loss_events = 0
    prev_down = 0

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
            is_down = 1 if loss_pct >= 99.999 else 0
            if is_down and not prev_down:
                loss_events += 1
            prev_down = is_down
            # Downtime is an "equivalent downtime" derived from loss%.
            # Example: 10% loss over a 60s bucket contributes ~6 seconds of downtime.
            try:
                downtime_seconds += (float(loss_pct) / 100.0) * float(bucket_seconds)
            except Exception:
                pass
            if loss_pct >= 99.999:
                loss100_seconds += int(bucket_seconds)
        else:
            prev_down = 0

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
            "loss_events": int(loss_events),
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
        return {
            "points": [],
            "stats": {
                "samples": 0,
                "uptime_pct": 0.0,
                "avg_latency_ms": None,
                "max_latency_ms": None,
                "avg_loss_pct": None,
                "max_loss_pct": None,
                "loss100_seconds": 0,
                "downtime_seconds": 0,
                "loss_events": 0,
                "bucket_seconds": 0,
            },
        }

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
    loss_events = 0
    prev_down = 0

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
            is_down = 1 if loss_pct >= 99.999 else 0
            if is_down and not prev_down:
                loss_events += 1
            prev_down = is_down
            downtime_seconds += (loss_pct / 100.0) * duration
            if loss_pct >= 99.999:
                loss100_seconds += duration
        else:
            prev_down = 0

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
            "loss_events": int(loss_events),
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
async def surveillance_series_range(pppoe: str, since: str, until: str, stage: str = "under"):
    pppoe = (pppoe or "").strip()
    since = (since or "").strip()
    until = (until or "").strip()
    stage = _normalize_surveillance_stage(stage)
    if not pppoe or not since or not until:
        return JSONResponse({"pppoe": pppoe, "series": []})
    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    now_dt = datetime.utcnow().replace(microsecond=0)
    anchors = _surveillance_entry_anchors(entry, stage=stage, now_utc=now_dt)
    anchor_source = anchors["stage_anchor_source"]
    anchor_dt = anchors["stage_anchor_dt"]
    anchor_iso = anchors["stage_anchor_iso"]

    since_dt = _parse_iso_z(since)
    until_dt = _parse_iso_z(until)
    if not since_dt or not until_dt:
        return JSONResponse({"pppoe": pppoe, "series": []})
    if since_dt < anchor_dt:
        since_dt = anchor_dt
    if until_dt > now_dt:
        until_dt = now_dt
    if until_dt < since_dt:
        until_dt = since_dt
    since = since_dt.replace(microsecond=0).isoformat() + "Z"
    until = until_dt.replace(microsecond=0).isoformat() + "Z"

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
    return JSONResponse(
        {
            "pppoe": pppoe,
            "stage": stage,
            "since": since,
            "until": until,
            "anchor_since": anchor_iso,
            "anchor_source": anchor_source,
            "series": series,
        }
    )


@app.get("/surveillance/timeline", response_class=JSONResponse)
async def surveillance_timeline(pppoe: str, stage: str = "under", until: str = "", anchor: str = ""):
    pppoe = (pppoe or "").strip()
    stage = _normalize_surveillance_stage(stage)
    if not pppoe:
        return JSONResponse({"pppoe": "", "days": [], "summary": {}, "total": {}})

    raw = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
    settings = normalize_surveillance_settings(raw)
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    now_utc = datetime.utcnow().replace(microsecond=0)
    anchors = _surveillance_entry_anchors(entry, stage=stage, now_utc=now_utc)
    added_at_iso = anchors["added_iso"]
    anchor_source = anchors["stage_anchor_source"]
    anchor_iso = anchors["stage_anchor_iso"]
    anchor_dt = anchors["stage_anchor_dt"]
    anchor_override = (anchor or "").strip()
    if anchor_override:
        anchor_override_dt = _parse_iso_z(anchor_override)
        if anchor_override_dt and anchor_override_dt <= now_utc:
            anchor_dt = anchor_override_dt.replace(microsecond=0)
            anchor_iso = anchor_dt.isoformat() + "Z"
            anchor_source = "custom"

    timeline_until_dt = now_utc
    until_override = (until or "").strip()
    if until_override:
        parsed_until = _parse_iso_z(until_override)
        if parsed_until:
            timeline_until_dt = min(parsed_until.replace(microsecond=0), now_utc)
    if timeline_until_dt < anchor_dt:
        timeline_until_dt = anchor_dt

    tz = ZoneInfo("Asia/Manila")
    anchor_local = anchor_dt.replace(tzinfo=timezone.utc).astimezone(tz)
    now_local = timeline_until_dt.replace(tzinfo=timezone.utc).astimezone(tz)

    # Day 1 is the calendar day the stage anchor starts in Asia/Manila.
    start_day = anchor_local.date()
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

    # Total since stage anchor (rounded down to minute boundary).
    anchor_floor = anchor_dt.replace(second=0, microsecond=0)
    total_rollups = get_accounts_ping_rollups_range(
        account_id,
        anchor_floor.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
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
        query_start_local = start_local
        if idx == 1:
            query_start_local = max(start_local, anchor_local)

        series = []
        stats = None
        if kind != "future":
            rollups = get_accounts_ping_rollups_range(account_id, to_utc_iso(query_start_local), to_utc_iso(query_until_local))
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
                "start_iso": to_utc_iso(query_start_local),
                "until_iso": to_utc_iso(until_local),
                "series": [{"ts": p["ts"], "loss": p["loss"], "avg_ms": p["avg_ms"]} for p in series],
                "stats": stats,
            }
        )

    return JSONResponse(
        {
            "pppoe": pppoe,
            "stage": stage,
            "added_at": added_at_iso,
            "first_added_at": anchors["first_added_iso"],
            "anchor_since": anchor_iso,
            "anchor_source": anchor_source,
            "until": timeline_until_dt.isoformat() + "Z",
            "start_day": start_day.isoformat(),
            "current_day_index": current_day_index,
            "total_days": total_days,
            "days": day_items,
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
            "loss_max_minutes": max(_float("loss_max_minutes", current["stability"].get("loss_max_minutes", 10.0)), 0.0),
            "loss_event_max_count": max(
                parse_int(form, "loss_event_max_count", current["stability"].get("loss_event_max_count", 5)),
                0,
            ),
            "optical_rx_min_dbm": _float("optical_rx_min_dbm", current["stability"].get("optical_rx_min_dbm", -24.0)),
            "require_optical": True,
            "fixed_observation_minutes": _minutes_from_days(
                "fixed_observation_days",
                current["stability"].get("fixed_observation_minutes", current["stability"].get("stable_window_minutes", 10)),
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


@app.post("/surveillance/format", response_class=HTMLResponse)
async def surveillance_format(request: Request):
    form = await request.form()
    message = ""
    if not parse_bool(form, "confirm_format"):
        message = "Please confirm format to proceed."
    else:
        try:
            clear_surveillance_history()
            settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
            settings["entries"] = []
            save_settings("surveillance", settings)

            state = get_state("accounts_ping_state", {})
            if not isinstance(state, dict):
                state = {}
            state.pop("surveillance_sessions_seeded", None)
            state.pop("surveillance_autoadd_seen", None)
            state.pop("surveillance_autoadd_last_scan_at", None)
            state.pop("surveillance_last_eval_at", None)
            save_state("accounts_ping_state", state)
            message = "Under Surveillance data formatted. Settings preserved."
        except Exception as exc:
            message = f"Format failed: {exc}"
    qs = urllib.parse.urlencode({"tab": "settings", "msg": message})
    return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)


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
        if not (existing.get("first_added_at") or "").strip():
            existing["first_added_at"] = (existing.get("added_at") or now_iso).strip() or now_iso
        if source and not existing.get("source"):
            existing["source"] = source
        entry_map[pppoe] = existing
    else:
        new_entry = {
            "pppoe": pppoe,
            "name": name or pppoe,
            "ip": ip,
            "source": source,
            "status": "under",
            "added_at": now_iso,
            "first_added_at": now_iso,
            "updated_at": now_iso,
            "level2_at": "",
            "level2_reason": "",
            "last_fixed_at": "",
            "last_fixed_reason": "",
            "last_fixed_mode": "",
            "added_mode": "manual",
            "auto_source": "",
            "auto_reason": "",
            "stage_history": [
                {
                    "ts": now_iso,
                    "from": "",
                    "to": "under",
                    "reason": "Added manually by admin",
                    "action": "add_manual",
                    "actor": "admin",
                }
            ],
            "ai_reports": {stage: _empty_surveillance_ai_report() for stage in _SURV_AI_STAGES},
            "ai_report_history": [],
            "ai_report_pending_stage": "",
        }
        entry_map[pppoe] = new_entry
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
    under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
    try:
        end_surveillance_session(
            pppoe,
            "removed",
            started_at=(entry.get("added_at") or "").strip(),
            source=(entry.get("source") or "").strip(),
            ip=(entry.get("ip") or "").strip(),
            state=(entry.get("status") or "under"),
            under_seconds=under_seconds,
            level2_seconds=level2_seconds,
            observe_seconds=observe_seconds,
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
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                pppoe,
                "removed",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
            )
        except Exception:
            pass
        entry_map.pop(pppoe, None)
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    tab = (form.get("tab") or "under").strip() or "under"
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/mark_false", response_class=HTMLResponse)
async def surveillance_mark_false(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    raw_pppoes = (form.get("pppoes") or "").strip()
    tab = (form.get("tab") or "under").strip().lower()
    if tab not in ("under", "level2", "observe"):
        tab = "under"
    pppoes: list[str] = []
    if pppoe:
        pppoes.append(pppoe)
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            pppoes.extend([item.strip() for item in raw_pppoes.split(",") if item.strip()])
    seen = set()
    unique_pppoes: list[str] = []
    for item in pppoes:
        if item in seen:
            continue
        seen.add(item)
        unique_pppoes.append(item)
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    for pppoe in unique_pppoes:
        entry = entry_map.get(pppoe) or {}
        if not entry:
            continue
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                pppoe,
                "false",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                note="Marked as False by admin",
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
            )
        except Exception:
            pass
        entry_map.pop(pppoe, None)
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    return RedirectResponse(url=f"/surveillance?tab={urllib.parse.quote(tab)}", status_code=303)


@app.post("/surveillance/move_level2", response_class=HTMLResponse)
async def surveillance_move_level2(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    tab = (form.get("tab") or "under").strip().lower()
    if tab not in ("under", "level2", "observe"):
        tab = "under"
    reason = (form.get("reason") or "").strip()
    if len(reason) > 500:
        reason = reason[:500]
    if not pppoe:
        qs = urllib.parse.urlencode({"tab": tab, "msg": "Missing PPPoE account for Needs Manual Fix."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)
    if len(reason) < 3:
        qs = urllib.parse.urlencode({"tab": tab, "focus": pppoe, "msg": "Investigation report is required (minimum 3 characters)."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe) or {}
    if not entry:
        qs = urllib.parse.urlencode({"tab": tab, "msg": f"Account `{pppoe}` is no longer active."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    now_iso = utc_now_iso()
    added_at = (entry.get("added_at") or "").strip() or now_iso
    first_added_at = (entry.get("first_added_at") or added_at).strip() or added_at
    from_stage = "observe" if tab == "observe" else ((entry.get("status") or "under").strip().lower() or "under")
    if from_stage not in ("under", "level2", "observe"):
        from_stage = "under"
    _append_surveillance_stage_history(
        entry,
        from_stage=from_stage,
        to_stage="level2",
        reason=reason,
        action="move_to_manual_fix",
        at_iso=now_iso,
    )
    entry["status"] = "level2"
    entry["level2_at"] = now_iso
    entry["level2_reason"] = reason
    entry["updated_at"] = now_iso
    entry["added_at"] = added_at
    entry["first_added_at"] = first_added_at
    try:
        increment_surveillance_observed(
            pppoe,
            started_at=added_at,
            source=(entry.get("source") or "").strip(),
            ip=(entry.get("ip") or "").strip(),
        )
    except Exception:
        try:
            touch_surveillance_session(
                pppoe,
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state="level2",
            )
        except Exception:
            pass
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    qs = urllib.parse.urlencode({"tab": "level2", "focus": pppoe})
    return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)


@app.post("/surveillance/ai_regenerate", response_class=HTMLResponse)
async def surveillance_ai_regenerate(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    tab = (form.get("tab") or "under").strip().lower()
    if tab not in _SURV_AI_STAGES:
        tab = "under"
    ai_stage = (form.get("ai_stage") or tab).strip().lower()
    if ai_stage not in _SURV_AI_STAGES:
        ai_stage = tab if tab in _SURV_AI_STAGES else "under"

    if not pppoe:
        qs = urllib.parse.urlencode({"tab": tab, "msg": "Missing PPPoE for AI report generation."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe)
    if not isinstance(entry, dict):
        qs = urllib.parse.urlencode({"tab": tab, "msg": f"Account `{pppoe}` is no longer active."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    reports = _entry_surveillance_ai_reports(entry)
    stage_report = reports.get(ai_stage) or _empty_surveillance_ai_report()
    stage_text = (stage_report.get("text") or "").strip()
    stage_status = (stage_report.get("status") or "").strip().lower()
    current_cycle_index = _surveillance_cycle_index_for_stage(entry, ai_stage)
    try:
        report_cycle_index = max(int(stage_report.get("cycle_index") or 1), 1)
    except Exception:
        report_cycle_index = 1
    same_cycle_report = report_cycle_index == current_cycle_index
    if same_cycle_report and (stage_text or stage_status in ("ready", "done")):
        stage_label = _SURV_AI_STAGE_LABELS.get(ai_stage) or ai_stage
        qs = urllib.parse.urlencode({"tab": tab, "msg": f"AI report already exists for {stage_label} in this cycle."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)
    if stage_status in ("queued", "running"):
        stage_label = _SURV_AI_STAGE_LABELS.get(ai_stage) or ai_stage
        qs = urllib.parse.urlencode({"tab": tab, "msg": f"AI report generation is already running for {stage_label}."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    with _surv_ai_lock:
        already_running = pppoe in _surv_ai_running
    if already_running:
        qs = urllib.parse.urlencode({"tab": tab, "msg": "AI report generation is already running."})
        return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)

    provider_override = (form.get("ai_provider_override") or "").strip().lower()
    if provider_override not in ("chatgpt", "gemini"):
        provider_override = ""
    model_override_raw = (form.get("ai_model_override") or "").strip()
    model_override = _normalize_provider_model_id(provider_override, model_override_raw) if provider_override else ""

    now_iso = utc_now_iso()
    _queue_surveillance_ai_report(entry, stage=ai_stage, now_iso=now_iso, reset_text=True)
    if provider_override and model_override:
        reports = _entry_surveillance_ai_reports(entry)
        stage_report = reports.get(ai_stage) or _empty_surveillance_ai_report()
        stage_report["provider_override"] = provider_override
        stage_report["model_override"] = model_override
        reports[ai_stage] = stage_report
        entry["ai_reports"] = reports
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
    started = _start_surveillance_ai_report(pppoe)
    stage_label = _SURV_AI_STAGE_LABELS.get(ai_stage) or ai_stage
    if started:
        if provider_override and model_override:
            message = f"{stage_label}: AI report generation queued using {provider_override}:{model_override}."
        else:
            message = f"{stage_label}: AI report generation queued."
    else:
        message = f"{stage_label}: AI report queued. Waiting for the current AI generation to finish."
    qs = urllib.parse.urlencode({"tab": tab, "msg": message})
    return RedirectResponse(url=f"/surveillance?{qs}", status_code=303)


@app.get("/surveillance/ai_reports", response_class=JSONResponse)
async def surveillance_ai_reports(pppoe: str):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return JSONResponse({"ok": False, "error": "Missing PPPoE."}, status_code=400)
    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    entry = entry_map.get(pppoe)
    if not isinstance(entry, dict):
        return JSONResponse({"ok": False, "error": "Account not found."}, status_code=404)

    reports = _entry_surveillance_ai_reports(entry)
    ai_history = _normalize_surveillance_ai_history(entry.get("ai_report_history"))
    payload = {}
    for stage in _SURV_AI_STAGES:
        report = reports.get(stage) or _empty_surveillance_ai_report()
        status = (report.get("status") or "").strip().lower()
        text = (report.get("text") or "").strip()
        error = (report.get("error") or "").strip()
        has_report = bool(text)
        if has_report and status in ("error", "missing_api_key", "missing_key", "disabled"):
            status = "ready"
            error = ""
        is_generating = status in ("queued", "running")
        has_error = (status in ("error", "missing_api_key", "missing_key") or bool(error)) and not has_report
        recommend_raw = _normalize_ai_recommendation(report.get("recommend_needs_manual_fix"))
        if recommend_raw == "yes":
            recommend_label = "Recommend Needs Manual Fix"
        elif recommend_raw == "no":
            recommend_label = "No Manual Fix Needed"
        else:
            recommend_label = "Recommendation n/a"
        try:
            cycle_index = max(int(report.get("cycle_index") or _surveillance_cycle_index_for_stage(entry, stage)), 1)
        except Exception:
            cycle_index = 1
        current_cycle_index = _surveillance_cycle_index_for_stage(entry, stage)
        has_current_cycle_report = bool(has_report and cycle_index == current_cycle_index)
        stage_history = []
        for item in ai_history:
            if (item.get("stage") or "") != stage:
                continue
            stage_history.append(
                {
                    "stage": stage,
                    "cycle_index": max(int(item.get("cycle_index") or 1), 1),
                    "generated_at_iso": (item.get("generated_at") or "").strip(),
                    "generated_at_ph": format_ts_ph(item.get("generated_at")),
                    "provider": (item.get("provider") or "").strip(),
                    "model": (item.get("model") or "").strip(),
                    "status": (item.get("status") or "").strip().lower(),
                    "error": (item.get("error") or "").strip(),
                    "text": (item.get("text") or "").strip(),
                    "recommend_needs_manual_fix": _normalize_ai_recommendation(item.get("recommend_needs_manual_fix")),
                    "recommend_label": (
                        "Recommend Needs Manual Fix"
                        if _normalize_ai_recommendation(item.get("recommend_needs_manual_fix")) == "yes"
                        else "No Manual Fix Needed"
                        if _normalize_ai_recommendation(item.get("recommend_needs_manual_fix")) == "no"
                        else "Recommendation n/a"
                    ),
                    "recommendation_reason": (item.get("recommendation_reason") or "").strip(),
                    "potential_problems": _normalize_ai_potential_problems(item.get("potential_problems")),
                }
            )
        if not stage_history and (text or (report.get("generated_at") or "").strip()):
            stage_history.append(
                {
                    "stage": stage,
                    "cycle_index": cycle_index,
                    "generated_at_iso": (report.get("generated_at") or "").strip(),
                    "generated_at_ph": format_ts_ph(report.get("generated_at")),
                    "provider": (report.get("provider") or "").strip(),
                    "model": (report.get("model") or "").strip(),
                    "status": status,
                    "error": error,
                    "text": text,
                    "recommend_needs_manual_fix": recommend_raw,
                    "recommend_label": recommend_label,
                    "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
                    "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
                }
            )
        stage_history = sorted(
            stage_history,
            key=lambda row: _parse_iso_z(row.get("generated_at_iso") or "") or datetime.min,
            reverse=True,
        )
        payload[stage] = {
            "stage": stage,
            "stage_label": _SURV_AI_STAGE_LABELS.get(stage) or stage,
            "status": status,
            "status_label": _ai_report_status_badge(status),
            "cycle_index": cycle_index,
            "current_cycle_index": current_cycle_index,
            "has_current_cycle_report": has_current_cycle_report,
            "error": error,
            "generated_at_iso": (report.get("generated_at") or "").strip(),
            "generated_at_ph": format_ts_ph(report.get("generated_at")),
            "provider": (report.get("provider") or "").strip(),
            "model": (report.get("model") or "").strip(),
            "text": text,
            "recommend_needs_manual_fix": recommend_raw,
            "recommend_label": recommend_label,
            "recommendation_reason": (report.get("recommendation_reason") or "").strip(),
            "potential_problems": _normalize_ai_potential_problems(report.get("potential_problems")),
            "has_report": has_report,
            "is_generating": is_generating,
            "has_error": has_error,
            "history": stage_history,
        }
    return JSONResponse({"ok": True, "pppoe": pppoe, "reports": payload})


@app.get("/surveillance/history_detail", response_class=JSONResponse)
async def surveillance_history_detail(id: int):
    row = get_surveillance_session_by_id(id)
    if not isinstance(row, dict):
        return JSONResponse({"ok": False, "error": "Session not found."}, status_code=404)

    pppoe = (row.get("pppoe") or "").strip()
    started_iso = (row.get("started_at") or "").strip()
    ended_iso = (row.get("ended_at") or "").strip()
    started_dt = _parse_iso_z(started_iso)
    ended_dt = _parse_iso_z(ended_iso) if ended_iso else datetime.utcnow().replace(microsecond=0)
    if isinstance(started_dt, datetime) and isinstance(ended_dt, datetime) and ended_dt < started_dt:
        ended_dt = started_dt

    since_iso = started_iso
    until_iso = ended_iso
    if isinstance(started_dt, datetime):
        since_iso = started_dt.replace(microsecond=0).isoformat() + "Z"
    if isinstance(ended_dt, datetime):
        until_iso = ended_dt.replace(microsecond=0).isoformat() + "Z"
    if not since_iso:
        since_iso = until_iso or utc_now_iso()
    if not until_iso:
        until_iso = since_iso

    def _in_window(ts):
        dt = _parse_iso_z(ts)
        if not isinstance(dt, datetime):
            return False
        if isinstance(started_dt, datetime) and dt < started_dt:
            return False
        if isinstance(ended_dt, datetime) and dt > ended_dt:
            return False
        return True

    action = (row.get("end_reason") or "").strip().lower()
    action_label_map = {
        "healed": "Auto Healed",
        "false": "Marked False",
        "fixed": "Fixed",
        "recovered": "Fully Recovered",
        "removed": "Removed",
    }

    try:
        under_seconds = max(int(row.get("under_seconds") or 0), 0)
    except Exception:
        under_seconds = 0
    try:
        level2_seconds = max(int(row.get("level2_seconds") or 0), 0)
    except Exception:
        level2_seconds = 0
    try:
        observe_seconds = max(int(row.get("observe_seconds") or 0), 0)
    except Exception:
        observe_seconds = 0

    total_seconds = under_seconds + level2_seconds + observe_seconds
    if total_seconds <= 0 and isinstance(started_dt, datetime) and isinstance(ended_dt, datetime):
        total_seconds = max(int((ended_dt - started_dt).total_seconds()), 0)

    account_id = _accounts_ping_account_id_for_pppoe(pppoe)
    ping_series = get_accounts_ping_series_range(account_id, since_iso, until_iso) if account_id else []
    ping_samples = 0
    ping_down_samples = 0
    ping_loss_values = []
    ping_avg_values = []
    ping_loss_events = 0
    ping_last_ts = ""
    ping_recent = []
    prev_full_down = False
    for item in ping_series:
        ts = (item.get("timestamp") or "").strip()
        if not _in_window(ts):
            continue
        ping_samples += 1
        ok = bool(item.get("ok"))
        loss_val = item.get("loss")
        avg_val = item.get("avg_ms")
        if not ok:
            ping_down_samples += 1
        try:
            if loss_val is not None:
                ping_loss_values.append(float(loss_val))
        except Exception:
            pass
        try:
            if avg_val is not None:
                ping_avg_values.append(float(avg_val))
        except Exception:
            pass
        full_down = (not ok) or (
            loss_val is not None and isinstance(loss_val, (int, float)) and float(loss_val) >= 100.0
        )
        if full_down and not prev_full_down:
            ping_loss_events += 1
        prev_full_down = full_down
        ping_last_ts = ts or ping_last_ts
        ping_recent.append(
            {
                "timestamp_iso": ts,
                "timestamp_ph": format_ts_ph(ts),
                "ok": ok,
                "loss": loss_val,
                "avg_ms": avg_val,
                "ip": (item.get("ip") or "").strip(),
                "mode": (item.get("mode") or "").strip(),
            }
        )
    ping_recent = ping_recent[-20:][::-1]
    ping_uptime_pct = (100.0 - (ping_down_samples / ping_samples * 100.0)) if ping_samples else None

    optical_latest_map = get_latest_optical_by_pppoe([pppoe]) if pppoe else {}
    optical_latest = optical_latest_map.get(pppoe) if isinstance(optical_latest_map, dict) else {}
    optical_device_id = (optical_latest.get("device_id") or "").strip() if isinstance(optical_latest, dict) else ""
    optical_rows = get_optical_results_for_device_since(optical_device_id, since_iso) if optical_device_id else []
    optical_filtered = []
    for item in optical_rows:
        ts = (item.get("timestamp") or "").strip()
        if not _in_window(ts):
            continue
        optical_filtered.append(item)
    optical_sample_total = len(optical_filtered)
    optical_latest_row = optical_filtered[-1] if optical_filtered else {}
    optical_rx_values = []
    for item in optical_filtered:
        try:
            val = item.get("rx")
            if val is not None:
                optical_rx_values.append(float(val))
        except Exception:
            pass

    usage_rows = get_pppoe_usage_series_since("", pppoe, since_iso) if pppoe else []
    usage_filtered = []
    for item in usage_rows:
        ts = (item.get("timestamp") or "").strip()
        if not _in_window(ts):
            continue
        usage_filtered.append(item)
    usage_sample_total = len(usage_filtered)
    usage_rx_vals = []
    usage_tx_vals = []
    usage_total_vals = []
    usage_last_ts = ""
    usage_active_device_max = 0
    for item in usage_filtered:
        rx = float(item.get("rx_bps") or 0.0)
        tx = float(item.get("tx_bps") or 0.0)
        total = max(rx, 0.0) + max(tx, 0.0)
        usage_rx_vals.append(rx)
        usage_tx_vals.append(tx)
        usage_total_vals.append(total)
        usage_last_ts = (item.get("timestamp") or "").strip() or usage_last_ts
        try:
            usage_active_device_max = max(usage_active_device_max, int(item.get("host_count") or 0))
        except Exception:
            pass

    return JSONResponse(
        {
            "ok": True,
            "session": {
                "id": int(row.get("id") or 0),
                "pppoe": pppoe,
                "source": (row.get("source") or "").strip(),
                "last_ip": (row.get("last_ip") or "").strip(),
                "last_state": (row.get("last_state") or "").strip(),
                "observed_count": int(row.get("observed_count") or 0),
                "started_at_iso": started_iso,
                "ended_at_iso": ended_iso,
                "started_at_ph": format_ts_ph(started_iso),
                "ended_at_ph": format_ts_ph(ended_iso),
                "updated_at_iso": (row.get("updated_at") or "").strip(),
                "updated_at_ph": format_ts_ph(row.get("updated_at")),
                "end_reason": action,
                "end_reason_label": action_label_map.get(action, "Removed"),
                "end_note": (row.get("end_note") or "").strip(),
                "under_seconds": under_seconds,
                "level2_seconds": level2_seconds,
                "observe_seconds": observe_seconds,
                "under_for_text": _format_duration_short(under_seconds) or "0m",
                "level2_for_text": _format_duration_short(level2_seconds) or "0m",
                "observe_for_text": _format_duration_short(observe_seconds) or "0m",
                "total_seconds": total_seconds,
                "total_for_text": _format_duration_short(total_seconds) or "0m",
            },
            "accounts_ping": {
                "samples": ping_samples,
                "down_samples": ping_down_samples,
                "loss_events": ping_loss_events,
                "uptime_pct": ping_uptime_pct,
                "avg_loss": (sum(ping_loss_values) / len(ping_loss_values)) if ping_loss_values else None,
                "avg_ms": (sum(ping_avg_values) / len(ping_avg_values)) if ping_avg_values else None,
                "worst_ms": max(ping_avg_values) if ping_avg_values else None,
                "last_sample_at_iso": ping_last_ts,
                "last_sample_at_ph": format_ts_ph(ping_last_ts),
                "recent": ping_recent,
            },
            "optical": {
                "device_id": optical_device_id,
                "samples": optical_sample_total,
                "latest_rx": optical_latest_row.get("rx") if optical_latest_row else None,
                "latest_tx": optical_latest_row.get("tx") if optical_latest_row else None,
                "worst_rx": min(optical_rx_values) if optical_rx_values else None,
                "last_sample_at_iso": (optical_latest_row.get("timestamp") or "").strip() if optical_latest_row else "",
                "last_sample_at_ph": format_ts_ph(optical_latest_row.get("timestamp")) if optical_latest_row else "n/a",
            },
            "usage": {
                "samples": usage_sample_total,
                "avg_rx_bps": (sum(usage_rx_vals) / len(usage_rx_vals)) if usage_rx_vals else None,
                "avg_tx_bps": (sum(usage_tx_vals) / len(usage_tx_vals)) if usage_tx_vals else None,
                "peak_total_bps": max(usage_total_vals) if usage_total_vals else None,
                "active_device_max": usage_active_device_max,
                "last_sample_at_iso": usage_last_ts,
                "last_sample_at_ph": format_ts_ph(usage_last_ts),
            },
        }
    )


@app.post("/surveillance/observe_recovered", response_class=HTMLResponse)
async def surveillance_observe_recovered(request: Request):
    form = await request.form()
    pppoe = (form.get("pppoe") or "").strip()
    raw_pppoes = (form.get("pppoes") or "").strip()
    tab = (form.get("tab") or "observe").strip().lower()
    remarks = (form.get("remarks") or "").strip()
    if tab not in ("under", "level2", "observe"):
        tab = "observe"

    def _redirect_with_msg(message: str):
        params = {"tab": tab, "msg": message}
        if pppoe:
            params["focus"] = pppoe
        return RedirectResponse(url=f"/surveillance?{urllib.parse.urlencode(params)}", status_code=303)

    pppoes: list[str] = []
    if pppoe:
        pppoes.append(pppoe)
    if raw_pppoes:
        try:
            parsed = json.loads(raw_pppoes)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        pppoes.append(item.strip())
        except Exception:
            pppoes.extend([item.strip() for item in raw_pppoes.split(",") if item.strip()])
    seen = set()
    unique_pppoes: list[str] = []
    for item in pppoes:
        if item in seen:
            continue
        seen.add(item)
        unique_pppoes.append(item)

    if not unique_pppoes:
        return _redirect_with_msg("Missing PPPoE account.")
    if not remarks or len(remarks) < 3:
        return _redirect_with_msg("Recovery remarks are required (min 3 characters).")
    if len(remarks) > 500:
        return _redirect_with_msg("Recovery remarks are too long (max 500 characters).")

    settings = normalize_surveillance_settings(get_settings("surveillance", SURVEILLANCE_DEFAULTS))
    entry_map = _surveillance_entry_map(settings)
    processed = 0
    for target in unique_pppoes:
        entry = entry_map.get(target) or {}
        if not entry:
            continue
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                target,
                "recovered",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                note=f"Marked as fully recovered: {remarks}",
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
            )
        except Exception:
            pass
        entry_map.pop(target, None)
        processed += 1
    if processed <= 0:
        return _redirect_with_msg("Selected accounts are no longer active in Post-Fix Observation.")
    settings["entries"] = list(entry_map.values())
    save_settings("surveillance", settings)
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
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(entry)
        try:
            end_surveillance_session(
                pppoe,
                "removed",
                started_at=(entry.get("added_at") or "").strip(),
                source=(entry.get("source") or "").strip(),
                ip=(entry.get("ip") or "").strip(),
                state=(entry.get("status") or "under"),
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
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
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(old)
        try:
            end_surveillance_session(
                pppoe,
                "fixed",
                started_at=(old.get("added_at") or "").strip(),
                source=(old.get("source") or "").strip(),
                ip=(old.get("ip") or "").strip(),
                state=(old.get("status") or "level2"),
                note=reason,
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
            )
        except Exception:
            pass

        _append_surveillance_stage_history(
            entry_map[pppoe],
            from_stage="level2",
            to_stage="observe",
            reason=reason,
            action="mark_fixed",
            at_iso=now_iso,
        )
        entry_map[pppoe]["status"] = "under"
        entry_map[pppoe]["added_at"] = now_iso
        entry_map[pppoe]["first_added_at"] = (entry_map[pppoe].get("first_added_at") or old.get("first_added_at") or old.get("added_at") or now_iso).strip() or now_iso
        entry_map[pppoe]["updated_at"] = now_iso
        entry_map[pppoe]["level2_at"] = ""
        entry_map[pppoe]["level2_reason"] = ""
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
    return RedirectResponse(url="/surveillance?tab=observe", status_code=303)


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
        under_seconds, level2_seconds, observe_seconds = _surveillance_stage_seconds(old)
        try:
            end_surveillance_session(
                pppoe,
                "fixed",
                started_at=(old.get("added_at") or "").strip(),
                source=(old.get("source") or "").strip(),
                ip=(old.get("ip") or "").strip(),
                state=(old.get("status") or "level2"),
                note=reason,
                under_seconds=under_seconds,
                level2_seconds=level2_seconds,
                observe_seconds=observe_seconds,
            )
        except Exception:
            pass
        _append_surveillance_stage_history(
            entry_map[pppoe],
            from_stage="level2",
            to_stage="observe",
            reason=reason,
            action="mark_fixed",
            at_iso=now_iso,
        )
        entry_map[pppoe]["status"] = "under"
        entry_map[pppoe]["added_at"] = now_iso
        entry_map[pppoe]["first_added_at"] = (entry_map[pppoe].get("first_added_at") or old.get("first_added_at") or old.get("added_at") or now_iso).strip() or now_iso
        entry_map[pppoe]["updated_at"] = now_iso
        entry_map[pppoe]["level2_at"] = ""
        entry_map[pppoe]["level2_reason"] = ""
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
    return RedirectResponse(url="/surveillance?tab=observe", status_code=303)

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
async def system_resources(details: int = 0):
    mem = _memory_details_kb()
    mem_total_kb = int(mem.get("mem_total_kb") or 0)
    mem_avail_kb = int(mem.get("mem_available_kb") or 0)
    mem_free_kb = int(mem.get("mem_free_kb") or 0)
    mem_cached_kb = int(mem.get("cached_kb") or 0)
    mem_buffers_kb = int(mem.get("buffers_kb") or 0)
    payload = {
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
    include_details = False
    try:
        include_details = int(details or 0) > 0
    except Exception:
        include_details = False
    if include_details:
        proc_root = _process_proc_root()
        sampled = _sample_process_usage(limit=0, sample_seconds=0.25, proc_root=proc_root)
        all_processes = list(sampled.get("rows") or [])
        top_processes = all_processes[:12]
        tracked_cpu_pct = float(sampled.get("total_cpu_pct") or 0.0)
        tracked_count = int(sampled.get("process_count") or 0)
        if not top_processes:
            top_processes = _top_process_usage(limit=12)
            tracked_cpu_pct = round(sum(float(item.get("cpu_pct") or 0.0) for item in top_processes), 1)
            tracked_count = len(top_processes)
            all_processes = list(top_processes)
        payload["top_processes"] = top_processes
        payload["feature_usage"] = _aggregate_feature_usage(all_processes, limit=8)
        runtime_features = sample_feature_cpu_percent(cpu_count=max(int(os.cpu_count() or 1), 1))
        payload["threej_feature_cpu"] = runtime_features
        payload["threej_summary"] = _build_runtime_threej_summary(
            runtime_features,
            all_processes,
            payload.get("cpu_pct") or 0.0,
        )
        payload["cpu_tracked_pct"] = round(max(0.0, min(100.0, tracked_cpu_pct)), 1)
        payload["tracked_process_count"] = tracked_count
        payload["cpu_scope"] = "Host processes" if proc_root == "/host_proc" else "Container processes"
        payload["captured_at"] = utc_now_iso()
    return JSONResponse(payload)


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
    return render_system_settings_response(request, message, active_tab="routers", routers_tab="cores")


@app.get("/settings", response_class=HTMLResponse)
async def settings_root():
    return RedirectResponse(url="/settings/optical", status_code=302)

@app.get("/settings/system", response_class=HTMLResponse)
async def system_settings(request: Request):
    active_tab = (request.query_params.get("tab") or "general").strip().lower()
    if active_tab not in {"general", "routers", "ai", "backup", "danger"}:
        active_tab = "general"
    routers_tab = (request.query_params.get("routers_tab") or "cores").strip().lower()
    if routers_tab not in {"cores", "mikrotik-routers", "isps"}:
        routers_tab = "cores"
    return render_system_settings_response(request, "", active_tab=active_tab, routers_tab=routers_tab)


def render_system_settings_response(request: Request, message: str, active_tab: str = "general", routers_tab: str = "cores"):
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    ai_settings = system_settings.get("ai") if isinstance(system_settings.get("ai"), dict) else {}
    ai_model_data = _build_ai_model_options(ai_settings, active_tab)
    ai_meta = {
        "chatgpt_api_key_set": bool((ai_settings.get("chatgpt") or {}).get("api_key")),
        "gemini_api_key_set": bool((ai_settings.get("gemini") or {}).get("api_key")),
        "chatgpt_model_fetch_error": (ai_model_data.get("errors") or {}).get("chatgpt") or "",
        "gemini_model_fetch_error": (ai_model_data.get("errors") or {}).get("gemini") or "",
    }
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
                "system_settings": system_settings,
                "ai_settings": ai_settings,
                "ai_model_options": (ai_model_data.get("options") or {}),
                "ai_meta": ai_meta,
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


@app.post("/settings/system/ai", response_class=HTMLResponse)
async def system_ai_save(request: Request):
    form = await request.form()
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    ai_cfg = system_settings.get("ai") if isinstance(system_settings.get("ai"), dict) else {}
    chatgpt_cfg = ai_cfg.get("chatgpt") if isinstance(ai_cfg.get("chatgpt"), dict) else {}
    gemini_cfg = ai_cfg.get("gemini") if isinstance(ai_cfg.get("gemini"), dict) else {}
    report_cfg = ai_cfg.get("report") if isinstance(ai_cfg.get("report"), dict) else {}

    provider = (form.get("ai_provider") or ai_cfg.get("provider") or "chatgpt").strip().lower()
    if provider not in ("chatgpt", "gemini"):
        provider = "chatgpt"

    chatgpt_api_key = (form.get("ai_chatgpt_api_key") or "").strip()
    if parse_bool(form, "ai_chatgpt_clear_api_key"):
        chatgpt_api_key = ""
    elif not chatgpt_api_key:
        chatgpt_api_key = (chatgpt_cfg.get("api_key") or "").strip()

    gemini_api_key = (form.get("ai_gemini_api_key") or "").strip()
    if parse_bool(form, "ai_gemini_clear_api_key"):
        gemini_api_key = ""
    elif not gemini_api_key:
        gemini_api_key = (gemini_cfg.get("api_key") or "").strip()

    updated_ai = {
        "enabled": parse_bool(form, "ai_enabled"),
        "provider": provider,
        "chatgpt": {
            "api_key": chatgpt_api_key,
            "model": _normalize_provider_model_id(
                "chatgpt",
                (form.get("ai_chatgpt_model") or chatgpt_cfg.get("model") or "gpt-4o-mini").strip() or "gpt-4o-mini",
            ),
            "timeout_seconds": parse_int(
                form,
                "ai_chatgpt_timeout_seconds",
                int(chatgpt_cfg.get("timeout_seconds", 30) or 30),
            ),
            "max_tokens": parse_int(
                form,
                "ai_chatgpt_max_tokens",
                int(chatgpt_cfg.get("max_tokens", 900) or 900),
            ),
        },
        "gemini": {
            "api_key": gemini_api_key,
            "model": _normalize_provider_model_id(
                "gemini",
                (form.get("ai_gemini_model") or gemini_cfg.get("model") or "gemini-2.5-flash-preview-09-2025").strip()
                or "gemini-2.5-flash-preview-09-2025",
            ),
            "timeout_seconds": parse_int(
                form,
                "ai_gemini_timeout_seconds",
                int(gemini_cfg.get("timeout_seconds", 30) or 30),
            ),
            "max_tokens": parse_int(
                form,
                "ai_gemini_max_tokens",
                int(gemini_cfg.get("max_tokens", 900) or 900),
            ),
        },
        "report": {
            "lookback_hours": parse_int(
                form,
                "ai_report_lookback_hours",
                int(report_cfg.get("lookback_hours", 24) or 24),
            ),
            "max_samples": parse_int(
                form,
                "ai_report_max_samples",
                int(report_cfg.get("max_samples", 60) or 60),
            ),
        },
    }

    system_settings["ai"] = updated_ai
    normalized = normalize_system_settings(system_settings)
    save_settings("system", normalized)
    return render_system_settings_response(
        request,
        "AI Investigator settings saved.",
        active_tab="ai",
        routers_tab="cores",
    )


@app.post("/settings/system/ai/test/{provider}", response_class=HTMLResponse)
async def system_ai_test(request: Request, provider: str):
    provider = (provider or "").strip().lower()
    if provider not in ("chatgpt", "gemini"):
        return render_system_settings_response(
            request,
            "Invalid AI provider test request.",
            active_tab="ai",
            routers_tab="cores",
        )

    form = await request.form()
    system_settings = normalize_system_settings(get_settings("system", SYSTEM_DEFAULTS))
    ai_cfg = system_settings.get("ai") if isinstance(system_settings.get("ai"), dict) else {}
    message = ""

    if provider == "chatgpt":
        saved_cfg = ai_cfg.get("chatgpt") if isinstance(ai_cfg.get("chatgpt"), dict) else {}
        submitted_key = (form.get("ai_chatgpt_api_key") or "").strip()
        if parse_bool(form, "ai_chatgpt_clear_api_key"):
            submitted_key = ""
        api_key = submitted_key or (saved_cfg.get("api_key") or "").strip()
        model = _normalize_provider_model_id(
            "chatgpt",
            (form.get("ai_chatgpt_model") or saved_cfg.get("model") or "gpt-4o-mini").strip() or "gpt-4o-mini",
        )
        timeout_seconds = parse_int(form, "ai_chatgpt_timeout_seconds", int(saved_cfg.get("timeout_seconds", 30) or 30))
        timeout_seconds = max(5, min(int(timeout_seconds or 30), 180))
        if not api_key:
            message = "ChatGPT test failed: no API key provided. Enter a key or save one first."
        else:
            model_ids, fetch_err = _fetch_chatgpt_model_ids(api_key, timeout_seconds=timeout_seconds)
            if not model_ids:
                message = f"ChatGPT test failed: {fetch_err or 'No models returned.'}"
            else:
                source = "entered key" if submitted_key else "saved key"
                if model in model_ids:
                    message = (
                        f"ChatGPT test OK using {source}. Retrieved {len(model_ids)} models. "
                        f"Selected model `{model}` is available."
                    )
                else:
                    message = (
                        f"ChatGPT key authenticated using {source}. Retrieved {len(model_ids)} models, "
                        f"but selected model `{model}` was not listed for this key."
                    )
    else:
        saved_cfg = ai_cfg.get("gemini") if isinstance(ai_cfg.get("gemini"), dict) else {}
        submitted_key = (form.get("ai_gemini_api_key") or "").strip()
        if parse_bool(form, "ai_gemini_clear_api_key"):
            submitted_key = ""
        api_key = submitted_key or (saved_cfg.get("api_key") or "").strip()
        model = _normalize_provider_model_id(
            "gemini",
            (form.get("ai_gemini_model") or saved_cfg.get("model") or "gemini-2.5-flash-preview-09-2025").strip()
            or "gemini-2.5-flash-preview-09-2025",
        )
        timeout_seconds = parse_int(form, "ai_gemini_timeout_seconds", int(saved_cfg.get("timeout_seconds", 30) or 30))
        timeout_seconds = max(5, min(int(timeout_seconds or 30), 180))
        if not api_key:
            message = "Gemini test failed: no API key provided. Enter a key or save one first."
        else:
            model_ids, fetch_err = _fetch_gemini_model_ids(api_key, timeout_seconds=timeout_seconds)
            if not model_ids:
                message = f"Gemini test failed: {fetch_err or 'No models returned.'}"
            else:
                source = "entered key" if submitted_key else "saved key"
                if model in model_ids:
                    message = (
                        f"Gemini test OK using {source}. Retrieved {len(model_ids)} models. "
                        f"Selected model `{model}` is available."
                    )
                else:
                    message = (
                        f"Gemini key authenticated using {source}. Retrieved {len(model_ids)} models, "
                        f"but selected model `{model}` was not listed for this key."
                    )

    return render_system_settings_response(
        request,
        message,
        active_tab="ai",
        routers_tab="cores",
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
