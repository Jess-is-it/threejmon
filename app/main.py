from pathlib import Path

import json

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
        state = isp_ping_notifier.run_check(settings, state)
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
