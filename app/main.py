from pathlib import Path

import json

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
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


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    job_status = {item["job_name"]: item for item in get_job_status()}
    isp_settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
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
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message, "settings": settings}),
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
    current_settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
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
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
        make_context(request, {"settings": settings, "message": ""}),
    )


@app.post("/settings/pulsewatch", response_class=HTMLResponse)
async def pulsewatch_settings_save(request: Request):
    form = await request.form()
    current_settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
    current_isps = {isp.get("id"): isp for isp in current_settings.get("pulsewatch", {}).get("isps", [])}
    pulse_isps = []
    for idx in range(1, 6):
        isp_id = f"isp{idx}"
        existing = current_isps.get(isp_id, {})
        core2_source_ip = (form.get(f"{isp_id}_core2_source_ip", "") or "").strip()
        core3_source_ip = (form.get(f"{isp_id}_core3_source_ip", "") or "").strip()
        if not core2_source_ip:
            core2_source_ip = (existing.get("core2_source_ip") or "").strip()
        if not core3_source_ip:
            core3_source_ip = (existing.get("core3_source_ip") or "").strip()
        legacy_source_ip = (existing.get("source_ip") or "").strip()
        if not core2_source_ip and not core3_source_ip and legacy_source_ip:
            core2_source_ip = legacy_source_ip
        ping_router = (form.get(f"{isp_id}_ping_router") or existing.get("ping_router") or "auto").strip()
        pulse_isps.append(
            {
                "id": isp_id,
                "label": form.get(f"{isp_id}_label", f"ISP {idx}"),
                "source_ip": legacy_source_ip,
                "core2_source_ip": core2_source_ip,
                "core3_source_ip": core3_source_ip,
                "router_scope": form.get(f"{isp_id}_router_scope", "both"),
                "ping_router": ping_router,
                "ping_targets": parse_lines(form.get(f"{isp_id}_ping_targets", "")),
                "thresholds": {
                    "latency_ms": parse_float(form, f"{isp_id}_latency_ms", 120.0),
                    "loss_pct": parse_float(form, f"{isp_id}_loss_pct", 20.0),
                },
                "consecutive_breach_count": parse_int(form, f"{isp_id}_breach_count", 3),
                "cooldown_minutes": parse_int(form, f"{isp_id}_cooldown_minutes", 10),
            }
        )
    pulsewatch = current_settings.get("pulsewatch", {})
    pulsewatch.update(
        {
            "enabled": parse_bool(form, "pulsewatch_enabled"),
            "manage_address_lists": parse_bool(form, "pulsewatch_manage_address_lists"),
            "reconcile_interval_minutes": parse_int(form, "pulsewatch_reconcile_interval_minutes", 10),
            "store_raw_output": parse_bool(form, "pulsewatch_store_raw_output"),
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
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
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


@app.post("/settings/pulsewatch/test", response_class=HTMLResponse)
async def pulsewatch_settings_test(request: Request):
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
    message = ""
    try:
        token = settings["telegram"].get("bot_token", "")
        chat_id = settings["telegram"].get("chat_id", "")
        send_telegram(token, chat_id, "ThreeJ Pulsewatch test message.")
        message = "Test message sent."
    except TelegramError as exc:
        message = str(exc)
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
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


@app.post("/settings/isp/mikrotik/test", response_class=HTMLResponse)
async def isp_mikrotik_test(request: Request):
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
    message = ""
    pulse_cfg = settings.get("pulsewatch", {})
    routers = pulse_cfg.get("mikrotik", {})
    results = []
    for key in ("core2", "core3"):
        router = routers.get(key, {})
        host = router.get("host", "")
        if not host:
            results.append(f"{key}: skipped (no host)")
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
            results.append(f"{key}: OK ({len(entries)} entries)")
        except Exception as exc:
            results.append(f"{key}: failed ({exc})")
        finally:
            client.close()
    message = " | ".join(results)
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/settings/isp/mikrotik/sync", response_class=HTMLResponse)
async def isp_mikrotik_sync(request: Request):
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
                "pulsewatch": {},
            },
        )
        state, _ = isp_ping_notifier.run_pulsewatch_check(settings, state, only_isps=[])
        save_state("isp_ping_state", state)
        message = "MikroTik address-list sync completed."
    except Exception as exc:
        message = f"Sync failed: {exc}"
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/isp/pulsewatch/ping", response_class=HTMLResponse)
async def isp_pulsewatch_ping_all(request: Request):
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
                "pulsewatch": {},
            },
        )
        state, _ = isp_ping_notifier.run_pulsewatch_check(settings, state)
        save_state("isp_ping_state", state)
        message = "Pulsewatch ping completed for all ISPs."
    except Exception as exc:
        message = f"Pulsewatch ping failed: {exc}"
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/isp/pulsewatch/ping/{isp_id}", response_class=HTMLResponse)
async def isp_pulsewatch_ping_one(request: Request, isp_id: str):
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
                "pulsewatch": {},
            },
        )
        state, _ = isp_ping_notifier.run_pulsewatch_check(settings, state, only_isps=[isp_id])
        save_state("isp_ping_state", state)
        message = f"Pulsewatch ping completed for {isp_id}."
    except Exception as exc:
        message = f"Pulsewatch ping failed: {exc}"
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/isp/pulsewatch/speedtest", response_class=HTMLResponse)
async def isp_pulsewatch_speedtest_all(request: Request):
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
                "pulsewatch": {},
            },
        )
        _, messages = isp_ping_notifier.run_speedtests(settings, state)
        save_state("isp_ping_state", state)
        message = " ".join(messages) if messages else "Pulsewatch speedtests completed."
    except Exception as exc:
        message = f"Speedtest failed: {exc}"
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.post("/isp/pulsewatch/speedtest/{isp_id}", response_class=HTMLResponse)
async def isp_pulsewatch_speedtest_one(request: Request, isp_id: str):
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
                "pulsewatch": {},
            },
        )
        _, messages = isp_ping_notifier.run_speedtests(settings, state, only_isps=[isp_id])
        save_state("isp_ping_state", state)
        message = " ".join(messages) if messages else f"Speedtest completed for {isp_id}."
    except Exception as exc:
        message = f"Speedtest failed: {exc}"
    return templates.TemplateResponse(
        "settings_pulsewatch.html",
        make_context(request, {"settings": settings, "message": message}),
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_root():
    return RedirectResponse(url="/settings/optical", status_code=302)

@app.get("/settings/system", response_class=HTMLResponse)
async def system_settings(request: Request):
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": "", "settings": settings}),
    )


@app.post("/settings/system/mikrotik", response_class=HTMLResponse)
async def system_mikrotik_save(request: Request):
    form = await request.form()
    settings = get_settings("isp_ping", ISP_PING_DEFAULTS)
    pulsewatch = settings.get("pulsewatch", {})
    pulsewatch["mikrotik"] = {
        "core2": {
            "host": form.get("core2_host", ""),
            "port": parse_int(form, "core2_port", 8728),
            "username": form.get("core2_username", ""),
            "password": form.get("core2_password", ""),
        },
        "core3": {
            "host": form.get("core3_host", ""),
            "port": parse_int(form, "core3_port", 8728),
            "username": form.get("core3_username", ""),
            "password": form.get("core3_password", ""),
        },
    }
    settings["pulsewatch"] = pulsewatch
    save_settings("isp_ping", settings)
    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": "MikroTik settings saved.", "settings": settings}),
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

    return templates.TemplateResponse(
        "settings_system.html",
        make_context(request, {"message": message}),
    )
