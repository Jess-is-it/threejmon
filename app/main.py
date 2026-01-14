from pathlib import Path

import asyncio
import json
import os
import base64
import shlex
import shutil
import subprocess

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import get_job_status, get_latest_speedtest_map, init_db
from .forms import parse_bool, parse_float, parse_int, parse_int_list, parse_lines, parse_targets
from .jobs import JobsManager
from .notifiers import isp_ping as isp_ping_notifier
from .mikrotik import RouterOSClient
from .notifiers import optical as optical_notifier
from .notifiers import rto as rto_notifier
from .notifiers.telegram import TelegramError, send_telegram
from .settings_defaults import ISP_PING_DEFAULTS, OPTICAL_DEFAULTS, RTO_DEFAULTS
from .settings_store import export_settings, get_settings, get_state, import_settings, save_settings, save_state

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

jobs_manager = JobsManager()


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
        return None, "Host netplan directory is not mounted.", {}
    interface_map = compute_pulsewatch_interface_map(settings)
    path = os.path.join(host_dir, "90-threejnotif-pulsewatch.yaml")
    if not interface_map:
        if os.path.exists(path):
            os.remove(path)
            return path, "Netplan file removed (no Pulsewatch IPs configured).", interface_map
        return path, "Netplan unchanged (no Pulsewatch IPs configured).", interface_map

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
    content = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, 0o600)
    return path, "Netplan file updated.", interface_map


def apply_host_addresses(interface_map):
    if not interface_map:
        return True, "No addresses to apply."
    sock = "/var/run/docker.sock"
    if not os.path.exists(sock):
        return False, "IP apply skipped (docker socket not available)."
    if not shutil.which("curl"):
        return False, "IP apply skipped (curl not available in container)."

    lines = []
    for iface, addrs in interface_map.items():
        for addr in sorted(addrs):
            lines.append(f"ip addr add {shlex.quote(addr)} dev {shlex.quote(iface)} || true")
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


def apply_netplan(interface_map):
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
            "\"chroot /host bash -c 'chmod 600 /etc/netplan/90-threejnotif-pulsewatch.yaml && netplan apply'\""
        )
        result = run_cmd(["/bin/sh", "-c", command], timeout_seconds=60)
        if result is None:
            ip_ok, ip_msg = apply_host_addresses(interface_map)
            return ip_ok, f"Netplan apply timed out. {ip_msg}"
        if result.returncode != 0:
            stderr = (result.stderr or result.stdout or "").strip()
            return False, f"Netplan apply failed: {stderr}"
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
        ip_ok, ip_msg = apply_host_addresses(interface_map)
        return ip_ok, f"Netplan apply timed out. {ip_msg}"
    if pulled.returncode != 0:
        return False, f"Netplan apply failed: {pulled.stderr.strip() or pulled.stdout.strip()}"

    payload = {
        "Image": "ubuntu",
        "Cmd": [
            "bash",
            "-c",
            "chroot /host bash -c 'chmod 600 /etc/netplan/90-threejnotif-pulsewatch.yaml && netplan apply' 2>&1",
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
        ip_ok, ip_msg = apply_host_addresses(interface_map)
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
        ip_ok, ip_msg = apply_host_addresses(interface_map)
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
        ip_ok, ip_msg = apply_host_addresses(interface_map)
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
    return True, "Netplan applied."


def normalize_pulsewatch_settings(settings):
    pulse = settings.setdefault("pulsewatch", {})
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
        for list_name in lists:
            preset = preset_lookup.get((core_id, list_name), {}) or {}
            preset_rows.append(
                {
                    "row_id": preset_row_id(core_id, list_name),
                    "core_id": core_id,
                    "core_label": core.get("label") or core_id,
                    "list_name": list_name,
                    "address": preset.get("address", ""),
                    "latency_ms": preset.get("latency_ms", 120),
                    "loss_pct": preset.get("loss_pct", 20),
                    "breach_count": preset.get("breach_count", 3),
                    "cooldown_minutes": preset.get("cooldown_minutes", 10),
                    "ping_targets": preset.get("ping_targets", ["1.1.1.1", "8.8.8.8"]),
                }
            )
    return preset_rows


def render_pulsewatch_response(request, settings, message):
    preset_rows = build_pulsewatch_rows(settings)
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
        make_context(request, {"settings": settings, "message": message, "preset_rows": preset_rows}),
    )


def find_pulsewatch_row(settings, row_id):
    for row in build_pulsewatch_rows(settings):
        if row.get("row_id") == row_id:
            return row
    return None


def _get_first_target(ping_targets):
    if isinstance(ping_targets, str):
        targets = parse_lines(ping_targets)
    else:
        targets = ping_targets or []
    return targets[0].strip() if targets else ""


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    job_status = {item["job_name"]: item for item in get_job_status()}
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
    isps = isp_settings.get("pulsewatch", {}).get("isps", [])
    isp_ids = [isp.get("id") for isp in isps if isp.get("id")]
    speedtests = get_latest_speedtest_map(isp_ids)
    return templates.TemplateResponse(
        "dashboard.html",
        make_context(
            request,
            {
                "job_status": job_status,
                "isp_settings": isp_settings,
                "isp_state": isp_state,
                "speedtests": speedtests,
            },
        ),
    )


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
            netplan_path, netplan_msg, interface_map = build_pulsewatch_netplan(settings)
            if netplan_path:
                _, apply_msg = apply_netplan(interface_map)
        except Exception as exc:
            apply_msg = f"Netplan update failed: {exc}"
        if netplan_msg:
            message = f"{message} {netplan_msg}"
        if apply_msg:
            message = f"{message} {apply_msg}"
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
    return templates.TemplateResponse(
        "settings_rto.html",
        make_context(request, {"settings": settings, "message": ""}),
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
            "schedule_time_ph": form.get("schedule_time_ph", "07:00"),
            "timezone": form.get("timezone", "Asia/Manila"),
        },
        "history": {
            "window_size": parse_int(form, "window_size", 30),
        },
    }
    save_settings("rto", settings)
    return templates.TemplateResponse(
        "settings_rto.html",
        make_context(request, {"settings": settings, "message": "Saved."}),
    )


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
    return templates.TemplateResponse(
        "settings_rto.html",
        make_context(request, {"settings": settings, "message": message}),
    )


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
    return templates.TemplateResponse(
        "settings_rto.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.get("/settings/isp", response_class=HTMLResponse)
async def isp_settings(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    return templates.TemplateResponse(
        "settings_isp.html",
        make_context(request, {"settings": settings, "message": ""}),
    )


@app.post("/settings/isp", response_class=HTMLResponse)
async def isp_settings_save(request: Request):
    form = await request.form()
    targets = parse_targets(form.get("targets", ""))
    up_icmp_lines = parse_int(form, "up_icmp_lines", 5)
    if up_icmp_lines < 0:
        up_icmp_lines = 0
    if up_icmp_lines > 20:
        up_icmp_lines = 20
    current_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    telegram = dict(current_settings.get("telegram", ISP_PING_DEFAULTS.get("telegram", {})))
    telegram["bot_token"] = form.get("telegram_bot_token", "")
    telegram["chat_id"] = form.get("telegram_chat_id", "")
    settings = {
        "enabled": parse_bool(form, "enabled"),
        "telegram": telegram,
        "general": {
            "ping_timeout_seconds": parse_int(form, "ping_timeout_seconds", 1),
            "ping_count": parse_int(form, "ping_count", 5),
            "max_parallel_pings": parse_int(form, "max_parallel_pings", 8),
            "daemon_interval_seconds": parse_int(form, "daemon_interval_seconds", 15),
            "include_up_icmp": parse_bool(form, "include_up_icmp"),
            "up_icmp_lines": up_icmp_lines,
        },
        "report": {
            "daily_time": form.get("daily_time", "07:00"),
            "timezone": form.get("timezone", "Asia/Manila"),
        },
        "targets": targets,
        "pulsewatch": current_settings.get("pulsewatch", ISP_PING_DEFAULTS.get("pulsewatch", {})),
    }
    save_settings("isp_ping", settings)
    return templates.TemplateResponse(
        "settings_isp.html",
        make_context(request, {"settings": settings, "message": "Saved."}),
    )


@app.get("/settings/pulsewatch", response_class=HTMLResponse)
async def pulsewatch_settings(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    return render_pulsewatch_response(request, settings, "")


@app.post("/settings/pulsewatch", response_class=HTMLResponse)
async def pulsewatch_settings_save(request: Request):
    form = await request.form()
    current_settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
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
    preset_count = parse_int(form, "preset_count", 0)
    presets = []
    for idx in range(preset_count):
        core_id = (form.get(f"preset_{idx}_core_id") or "").strip()
        list_name = (form.get(f"preset_{idx}_list") or "").strip()
        address = (form.get(f"preset_{idx}_address") or "").strip()
        if core_id and list_name:
            presets.append(
                {
                    "core_id": core_id,
                    "list": list_name,
                    "address": address,
                    "latency_ms": parse_float(form, f"preset_{idx}_latency_ms", 120.0),
                    "loss_pct": parse_float(form, f"preset_{idx}_loss_pct", 20.0),
                    "breach_count": parse_int(form, f"preset_{idx}_breach_count", 3),
                    "cooldown_minutes": parse_int(form, f"preset_{idx}_cooldown_minutes", 10),
                    "ping_targets": parse_lines(form.get(f"preset_{idx}_ping_targets", "")),
                }
            )
    pulsewatch = current_settings.get("pulsewatch", {})
    pulsewatch.update(
        {
            "enabled": parse_bool(form, "pulsewatch_enabled"),
            "manage_address_lists": parse_bool(form, "pulsewatch_manage_address_lists"),
            "reconcile_interval_minutes": parse_int(form, "pulsewatch_reconcile_interval_minutes", 10),
            "store_raw_output": parse_bool(form, "pulsewatch_store_raw_output"),
            "list_presets": presets,
            "speedtest": {
                "enabled": parse_bool(form, "speedtest_enabled"),
                "min_interval_minutes": parse_int(form, "speedtest_min_interval_minutes", 60),
                "command": form.get("speedtest_command", "speedtest"),
                "args": form.get("speedtest_args", "--format=json"),
                "use_netns": parse_bool(form, "speedtest_use_netns"),
                "netns_prefix": form.get("speedtest_netns_prefix", "isp"),
            },
            "isps": pulse_isps,
        }
    )
    settings = {
        "enabled": current_settings.get("enabled", False),
        "telegram": {
            "bot_token": form.get("telegram_bot_token", ""),
            "chat_id": form.get("telegram_chat_id", ""),
            "alert_channel_id": form.get("telegram_alert_channel_id", ""),
            "allowed_user_ids": parse_int_list(form.get("telegram_allowed_user_ids", "")),
        },
        "general": current_settings.get("general", {}),
        "report": current_settings.get("report", {}),
        "targets": current_settings.get("targets", []),
        "pulsewatch": pulsewatch,
    }
    save_settings("isp_ping", settings)
    message = "Saved."
    netplan_msg = None
    apply_msg = None
    sync_msg = None
    try:
        netplan_path, netplan_msg, interface_map = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if pulsewatch.get("manage_address_lists"):
        try:
            state = {}
            isp_ping_notifier.run_pulsewatch_check(settings, state, only_isps=[])
            sync_msg = "MikroTik address-list sync completed."
        except Exception as exc:
            sync_msg = f"MikroTik sync failed: {exc}"
    if netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg:
        message = f"{message} {apply_msg}"
    if sync_msg:
        message = f"{message} {sync_msg}"
    return render_pulsewatch_response(request, settings, message)




@app.post("/settings/isp/test", response_class=HTMLResponse)
async def isp_settings_test(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        token = settings["telegram"].get("bot_token", "")
        chat_id = settings["telegram"].get("chat_id", "")
        send_telegram(token, chat_id, "ThreeJ ISP Ping test message.")
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return templates.TemplateResponse(
        "settings_isp.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/settings/pulsewatch/test", response_class=HTMLResponse)
async def pulsewatch_settings_test(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    message = ""
    try:
        token = settings["telegram"].get("bot_token", "")
        chat_id = settings["telegram"].get("chat_id", "")
        send_telegram(token, chat_id, "ThreeJ Pulsewatch test message.")
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return render_pulsewatch_response(request, settings, message)


@app.post("/settings/isp/run", response_class=HTMLResponse)
async def isp_settings_run(request: Request):
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
            },
        )
        state = isp_ping_notifier.run_check(settings, state, force_report=True)
        save_state("isp_ping_state", state)
        message = "Actual ISP ping check sent."
    except TelegramError as exc:
        message = str(exc)
    except Exception as exc:
        message = f"Run failed: {exc}"
    return templates.TemplateResponse(
        "settings_isp.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/settings/isp/mikrotik/test", response_class=HTMLResponse)
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


@app.post("/settings/isp/mikrotik/sync", response_class=HTMLResponse)
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
    rows = build_pulsewatch_rows(settings)
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
            label = f"{row.get('core_label')} {row.get('list_name')}".strip()
            source_ip = (row.get("address") or "").strip()
            target = _get_first_target(row.get("ping_targets"))
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
        for row in build_pulsewatch_rows(settings):
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
        _, messages = isp_ping_notifier.run_speedtests(settings, state)
        save_state("isp_ping_state", state)
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
        _, messages = isp_ping_notifier.run_speedtests(settings, state, only_isps=[isp_id])
        save_state("isp_ping_state", state)
        message = " ".join(messages) if messages else f"Speedtest completed for {isp_id}."
    except Exception as exc:
        message = f"Speedtest failed: {exc}"
    return render_pulsewatch_response(request, settings, message)


@app.get("/settings", response_class=HTMLResponse)
async def settings_root():
    return RedirectResponse(url="/settings/optical", status_code=302)

@app.get("/settings/system", response_class=HTMLResponse)
async def system_settings(request: Request):
    settings = normalize_pulsewatch_settings(get_settings("isp_ping", ISP_PING_DEFAULTS))
    interfaces = get_interface_options()
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": "", "settings": settings, "interfaces": interfaces}),
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
        netplan_path, netplan_msg, interface_map = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg:
        message = f"{message} {apply_msg}"
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message, "settings": settings, "interfaces": interfaces}),
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
        netplan_path, netplan_msg, interface_map = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg:
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
        netplan_path, netplan_msg, interface_map = build_pulsewatch_netplan(settings)
        if netplan_path:
            _, apply_msg = apply_netplan(interface_map)
    except Exception as exc:
        apply_msg = f"Netplan update failed: {exc}"
    if netplan_msg:
        message = f"{message} {netplan_msg}"
    if apply_msg:
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
