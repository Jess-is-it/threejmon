from pathlib import Path

import json
import os
import shlex
import subprocess
import threading

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import get_job_status, init_db
from .forms import parse_bool, parse_float, parse_int, parse_lines, parse_targets
from .jobs import JobsManager
from .notifiers import isp_ping as isp_ping_notifier
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


def _run_ota_command(command, log_path, status_path):
    try:
        with open(log_path, "a", encoding="utf-8") as log_handle:
            log_handle.write("\n--- OTA update running ---\n")
        result = subprocess.run(
            ["/bin/sh", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        with open(log_path, "a", encoding="utf-8") as log_handle:
            log_handle.write((result.stdout or "").strip() + "\n")
            log_handle.write((result.stderr or "").strip() + "\n")
        with open(status_path, "w", encoding="utf-8") as status_handle:
            status_handle.write("done" if result.returncode == 0 else "failed")
    except Exception as exc:
        with open(log_path, "a", encoding="utf-8") as log_handle:
            log_handle.write(f"\n--- OTA update failed ---\n{exc}\n")
        with open(status_path, "w", encoding="utf-8") as status_handle:
            status_handle.write("failed")


def trigger_ota_update(log_path, status_path):
    repo_path = os.environ.get("THREEJ_OTA_REPO", "/repo")
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise RuntimeError("OTA repository not mounted. Ensure /repo is a git checkout.")
    current_status = read_ota_status(status_path)
    if current_status == "running":
        raise RuntimeError("OTA update already running.")

    host_repo = os.environ.get("THREEJ_HOST_REPO", "/opt/threejnotif")
    with open(log_path, "a", encoding="utf-8") as log_handle:
        log_handle.write("\n--- OTA update started ---\n")
    with open(status_path, "w", encoding="utf-8") as status_handle:
        status_handle.write("running")

    host_repo_root = os.path.join("/host", host_repo.lstrip("/"))
    host_git = "/host/usr/bin/git"
    host_docker = "/host/usr/bin/docker"
    command = (
        f"test -x {shlex.quote(host_git)} && test -x {shlex.quote(host_docker)} || "
        f"(echo \"host git/docker not found\"; exit 1); "
        f"{shlex.quote(host_git)} -C {shlex.quote(host_repo_root)} config --global --add safe.directory {shlex.quote(host_repo_root)}; "
        f"{shlex.quote(host_git)} -C {shlex.quote(host_repo_root)} pull --rebase; "
        f"THREEJ_VERSION=$({shlex.quote(host_git)} -C {shlex.quote(host_repo_root)} rev-parse --short HEAD); "
        f"THREEJ_VERSION_DATE=$({shlex.quote(host_git)} -C {shlex.quote(host_repo_root)} log -1 --format=%cs); "
        f"printf \"%s %s\" \"$THREEJ_VERSION\" \"$THREEJ_VERSION_DATE\" > {shlex.quote(host_repo_root)}/.threej_version; "
        f"{shlex.quote(host_docker)} compose -f {shlex.quote(host_repo_root)}/docker-compose.yml up -d --build"
    )
    helper_command = f"{command} >> {shlex.quote(host_repo_root)}/.ota.log 2>&1"
    thread = threading.Thread(
        target=_run_ota_command,
        args=(helper_command, log_path, status_path),
        daemon=True,
    )
    thread.start()


def get_repo_version():
    repo_path = os.environ.get("THREEJ_OTA_REPO", "/repo")
    version_file = os.path.join(repo_path, ".threej_version")
    if not os.path.exists(os.path.join(repo_path, ".git")):
        if os.path.exists(version_file):
            try:
                with open(version_file, "r", encoding="utf-8") as handle:
                    content = (handle.read() or "").strip()
                if content:
                    parts = content.split(" ", 1)
                    version = parts[0]
                    date_value = parts[1] if len(parts) > 1 else "unknown"
                    return {"version": version, "date": date_value}
            except OSError:
                pass
        env_version = os.environ.get("THREEJ_VERSION", "unknown")
        env_date = os.environ.get("THREEJ_VERSION_DATE", "unknown")
        return {"version": env_version or "unknown", "date": env_date or "unknown"}
    try:
        version_proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        date_proc = subprocess.run(
            ["git", "log", "-1", "--format=%cs"],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        version = (version_proc.stdout or "").strip() or "unknown"
        date_value = (date_proc.stdout or "").strip() or "unknown"
        try:
            with open(version_file, "w", encoding="utf-8") as handle:
                handle.write(f"{version} {date_value}".strip())
        except OSError:
            pass
        return {"version": version, "date": date_value}
    except Exception:
        env_version = os.environ.get("THREEJ_VERSION", "unknown")
        env_date = os.environ.get("THREEJ_VERSION_DATE", "unknown")
        return {"version": env_version or "unknown", "date": env_date or "unknown"}


def get_ota_paths():
    repo_path = os.environ.get("THREEJ_OTA_REPO", "/repo")
    return {
        "repo_path": repo_path,
        "log_path": os.path.join(repo_path, ".ota.log"),
        "status_path": os.path.join(repo_path, ".ota.status"),
    }


def read_ota_status(status_path):
    if not os.path.exists(status_path):
        return "idle"
    try:
        with open(status_path, "r", encoding="utf-8") as handle:
            status = (handle.read() or "").strip()
        return status or "idle"
    except OSError:
        return "idle"


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    job_status = {item["job_name"]: item for item in get_job_status()}
    return templates.TemplateResponse(
        "dashboard.html",
        make_context(
            request,
            {
                "job_status": job_status,
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

    job_status = {item["job_name"]: item for item in get_job_status()}
    return templates.TemplateResponse(
        "dashboard.html",
        make_context(
            request,
            {
                "job_status": job_status,
                "message": message,
            },
        ),
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
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
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
    settings = {
        "enabled": parse_bool(form, "enabled"),
        "telegram": {
            "bot_token": form.get("telegram_bot_token", ""),
            "chat_id": form.get("telegram_chat_id", ""),
        },
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
    }
    save_settings("isp_ping", settings)
    return templates.TemplateResponse(
        "settings_isp.html",
        make_context(request, {"settings": settings, "message": "Saved."}),
    )


@app.post("/settings/isp/test", response_class=HTMLResponse)
async def isp_settings_test(request: Request):
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
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


@app.post("/settings/isp/run", response_class=HTMLResponse)
async def isp_settings_run(request: Request):
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
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


@app.get("/settings", response_class=HTMLResponse)
async def settings_root():
    return RedirectResponse(url="/settings/optical", status_code=302)

@app.get("/settings/system", response_class=HTMLResponse)
async def system_settings(request: Request):
    paths = get_ota_paths()
    repo_version = get_repo_version()
    log_text = ""
    if os.path.exists(paths["log_path"]):
        try:
            with open(paths["log_path"], "r", encoding="utf-8") as handle:
                log_text = handle.read()
        except OSError:
            log_text = ""
    status = read_ota_status(paths["status_path"])
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {"message": "", "repo_version": repo_version, "log_text": log_text, "ota_status": status},
        ),
    )

@app.post("/settings/system/update", response_class=HTMLResponse)
async def system_update_run(request: Request):
    paths = get_ota_paths()
    message = ""
    try:
        trigger_ota_update(paths["log_path"], paths["status_path"])
        message = "Update triggered. The service may restart in a moment."
    except Exception as exc:
        message = f"Update failed: {exc}"
    repo_version = get_repo_version()
    log_text = ""
    if os.path.exists(paths["log_path"]):
        try:
            with open(paths["log_path"], "r", encoding="utf-8") as handle:
                log_text = handle.read()
        except OSError:
            log_text = ""
    status = read_ota_status(paths["status_path"])
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {"message": message, "repo_version": repo_version, "log_text": log_text, "ota_status": status},
        ),
    )


@app.post("/settings/system/update/start")
async def system_update_start():
    paths = get_ota_paths()
    try:
        trigger_ota_update(paths["log_path"], paths["status_path"])
        return {"status": "running"}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


@app.get("/settings/system/status")
async def update_status():
    paths = get_ota_paths()
    status = read_ota_status(paths["status_path"])
    return {"status": status}


@app.get("/settings/system/log")
async def update_log():
    paths = get_ota_paths()
    log_text = ""
    if os.path.exists(paths["log_path"]):
        try:
            with open(paths["log_path"], "r", encoding="utf-8") as handle:
                log_text = handle.read()
        except OSError:
            log_text = ""
    return Response(content=log_text, media_type="text/plain")


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

    paths = get_ota_paths()
    repo_version = get_repo_version()
    log_text = ""
    if os.path.exists(paths["log_path"]):
        try:
            with open(paths["log_path"], "r", encoding="utf-8") as handle:
                log_text = handle.read()
        except OSError:
            log_text = ""
    status = read_ota_status(paths["status_path"])
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(
            request,
            {"message": message, "repo_version": repo_version, "log_text": log_text, "ota_status": status},
        ),
    )
