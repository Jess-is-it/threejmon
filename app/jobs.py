import threading
import time as time_module
from datetime import datetime, time, timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from .db import delete_rto_results_older_than, update_job_status, utc_now_iso
from .notifiers import optical as optical_notifier
from .notifiers import rto as rto_notifier
from .notifiers import isp_ping as isp_ping_notifier
from .notifiers import wan_ping as wan_ping_notifier
from .notifiers.telegram import TelegramError, get_updates, send_telegram
from .settings_defaults import ISP_PING_DEFAULTS, OPTICAL_DEFAULTS, RTO_DEFAULTS, WAN_PING_DEFAULTS
from .settings_store import get_settings, get_state, save_state
from .telegram_commands import handle_telegram_command


class JobsManager:
    def __init__(self):
        self.stop_event = threading.Event()
        self.threads = []

    def start(self):
        self.threads = [
            threading.Thread(target=self._optical_loop, daemon=True),
            threading.Thread(target=self._rto_loop, daemon=True),
            threading.Thread(target=self._pulsewatch_loop, daemon=True),
            threading.Thread(target=self._telegram_loop, daemon=True),
            threading.Thread(target=self._wan_ping_loop, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def stop(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=2)

    def _optical_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("optical", OPTICAL_DEFAULTS)
            if not cfg.get("enabled"):
                time_module.sleep(5)
                continue

            try:
                if should_run_daily(cfg["general"], get_state("optical_state", {"last_run_date": None})):
                    update_job_status("optical", last_run_at=utc_now_iso())
                    optical_notifier.run(cfg)
                    state = get_state("optical_state", {"last_run_date": None})
                    state["last_run_date"] = current_date(cfg["general"]).isoformat()
                    save_state("optical_state", state)
                    update_job_status("optical", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                update_job_status("optical", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("optical", last_error=str(exc), last_error_at=utc_now_iso())

            time_module.sleep(20)

    def _rto_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("rto", RTO_DEFAULTS)
            if not cfg.get("enabled"):
                time_module.sleep(5)
                continue

            try:
                state = get_state("rto_state", {"last_run_date": None})
                pause_until = state.get("pause_until")
                if pause_until:
                    pause_dt = datetime.fromisoformat(pause_until.replace("Z", ""))
                    if datetime.utcnow() < pause_dt:
                        time_module.sleep(5)
                        continue
                retention_days = int(cfg.get("storage", {}).get("raw_retention_days", 0) or 0)
                if retention_days > 0:
                    last_prune = state.get("last_prune_at")
                    if not last_prune:
                        last_prune_dt = None
                    else:
                        last_prune_dt = datetime.fromisoformat(last_prune.replace("Z", ""))
                    if not last_prune_dt or last_prune_dt + timedelta(hours=24) < datetime.utcnow():
                        cutoff = datetime.utcnow() - timedelta(days=retention_days)
                        delete_rto_results_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                        state["last_prune_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
                        save_state("rto_state", state)

                ping_interval_minutes = int(cfg.get("general", {}).get("ping_interval_minutes", 5) or 5)
                last_ping_at = state.get("last_ping_at")
                last_ping_dt = datetime.fromisoformat(last_ping_at.replace("Z", "")) if last_ping_at else None
                now = datetime.utcnow()
                ping_due = not last_ping_dt or now - last_ping_dt >= timedelta(minutes=ping_interval_minutes)
                if ping_due:
                    update_job_status("rto", last_run_at=utc_now_iso())
                    history = get_state("rto_history", {})
                    payload = rto_notifier.run_check(cfg, history)
                    history = payload["history"]
                    save_state("rto_history", history)
                    state["last_ping_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    save_state("rto_state", state)
                    update_job_status("rto", last_success_at=utc_now_iso(), last_error="", last_error_at="")

                report_date = current_date(cfg["general"]).isoformat()
                schedule_time = parse_time(cfg["general"].get("schedule_time_ph", "07:00"))
                timezone = cfg["general"].get("timezone", "Asia/Manila")
                if ZoneInfo is not None:
                    now_local = datetime.now(ZoneInfo(timezone))
                else:
                    now_local = datetime.now()
                report_due = state.get("last_report_date") != report_date and now_local.time() >= schedule_time
                if report_due:
                    history = get_state("rto_history", {})
                    results = rto_notifier.build_results_from_history(history)
                    devices = rto_notifier.build_devices_from_history(history)
                    rto_notifier.send_report(cfg, history, results, devices)
                    state["last_report_date"] = report_date
                    state["last_report_at"] = utc_now_iso()
                    save_state("rto_state", state)
            except TelegramError as exc:
                update_job_status("rto", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("rto", last_error=str(exc), last_error_at=utc_now_iso())

            time_module.sleep(20)

    def _pulsewatch_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("isp_ping", ISP_PING_DEFAULTS)
            pulse_cfg = cfg.get("pulsewatch", {})
            if not pulse_cfg.get("enabled"):
                time_module.sleep(5)
                continue

            try:
                state = get_state("isp_ping_state", {
                    "last_status": {},
                    "last_report_date": None,
                    "last_report_time": None,
                    "last_report_timezone": None,
                    "pulsewatch": {},
                })
                pause_until = state.get("pulsewatch_pause_until")
                if pause_until:
                    pause_dt = datetime.fromisoformat(pause_until.replace("Z", ""))
                    if datetime.utcnow() < pause_dt:
                        time_module.sleep(5)
                        continue
                update_job_status("pulsewatch", last_run_at=utc_now_iso())
                state, _ = isp_ping_notifier.run_pulsewatch_check(cfg, state)
                reach_last = state.get("pulsewatch_reachability_checked_at")
                reach_last_dt = datetime.fromisoformat(reach_last.replace("Z", "")) if reach_last else None
                if not reach_last_dt or datetime.utcnow() - reach_last_dt >= timedelta(minutes=10):
                    state = isp_ping_notifier.check_preset_reachability(cfg, state)
                latest = get_state("isp_ping_state", {})
                if "pulsewatch" in state:
                    latest["pulsewatch"] = state["pulsewatch"]
                if "pulsewatch_reachability" in state:
                    latest["pulsewatch_reachability"] = state["pulsewatch_reachability"]
                if "pulsewatch_reachability_checked_at" in state:
                    latest["pulsewatch_reachability_checked_at"] = state["pulsewatch_reachability_checked_at"]
                if "last_pulsewatch_prune_at" in state:
                    latest["last_pulsewatch_prune_at"] = state["last_pulsewatch_prune_at"]
                if "last_mikrotik_reconcile_at" in state:
                    latest["last_mikrotik_reconcile_at"] = state["last_mikrotik_reconcile_at"]
                save_state("isp_ping_state", latest)
                update_job_status("pulsewatch", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                update_job_status("pulsewatch", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("pulsewatch", last_error=str(exc), last_error_at=utc_now_iso())

            interval_seconds = int(pulse_cfg.get("ping", {}).get("interval_seconds", 1))
            time_module.sleep(max(interval_seconds, 1))

    def _telegram_loop(self):
        executor = ThreadPoolExecutor(max_workers=2)
        while not self.stop_event.is_set():
            cfg = get_settings("isp_ping", ISP_PING_DEFAULTS)
            telegram = cfg.get("telegram", {})
            token = telegram.get("command_bot_token") or telegram.get("bot_token", "")
            command_chat_id = (telegram.get("command_chat_id") or "").strip()
            allowed_user_ids = telegram.get("allowed_user_ids", [])
            feedback_seconds = int(telegram.get("command_feedback_seconds", 10) or 0)

            if not token:
                time_module.sleep(5)
                continue

            try:
                state = get_state("telegram_state", {"last_update_id": 0})
                if state.get("token") != token:
                    state["last_update_id"] = 0
                state["token"] = token
                last_seen = int(state.get("last_update_id") or 0)
                offset = last_seen + 1
                updates = get_updates(token, offset=offset, timeout=15)
                state["last_poll_at"] = utc_now_iso()
                for update in updates:
                    update_id = update.get("update_id")
                    if update_id is None:
                        continue
                    update_id = int(update_id)
                    if update_id <= last_seen:
                        continue
                    state["last_update_id"] = max(int(state.get("last_update_id") or 0), update_id)
                    message = update.get("message") or update.get("edited_message")
                    if not message or "text" not in message:
                        continue
                    sender = message.get("from", {})
                    if sender.get("is_bot"):
                        continue
                    chat = message.get("chat", {})
                    chat_id = chat.get("id")
                    if command_chat_id and str(chat_id) != str(command_chat_id):
                        continue
                    sender_id = sender.get("id")
                    if allowed_user_ids and sender_id not in allowed_user_ids:
                        continue
                    text = message.get("text", "")
                    state["last_command"] = text
                    state["last_command_from"] = sender_id
                    future = executor.submit(handle_telegram_command, cfg, text)
                    last_feedback = time_module.time()
                    next_feedback = feedback_seconds
                    sent_feedback = False
                    while True:
                        try:
                            reply = future.result(timeout=1)
                            break
                        except FutureTimeout:
                            if next_feedback > 0 and time_module.time() - last_feedback >= next_feedback:
                                send_telegram(token, chat_id, "Working on it, please wait...")
                                last_feedback = time_module.time()
                                next_feedback = min(next_feedback * 2, 3600)
                                sent_feedback = True
                            continue
                    if reply:
                        send_telegram(token, chat_id, reply)
                        state["last_reply"] = reply[:500]
                        state["last_error"] = ""
                    elif sent_feedback:
                        state["last_reply"] = "Working on it, please wait..."
                save_state("telegram_state", state)
            except TelegramError as exc:
                state = get_state("telegram_state", {"last_update_id": 0})
                state["last_error"] = str(exc)
                state["last_poll_at"] = utc_now_iso()
                save_state("telegram_state", state)
            except Exception as exc:
                state = get_state("telegram_state", {"last_update_id": 0})
                state["last_error"] = f"{type(exc).__name__}: {exc}"
                state["last_poll_at"] = utc_now_iso()
                save_state("telegram_state", state)

            time_module.sleep(2)

    def _wan_ping_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("wan_ping", WAN_PING_DEFAULTS)
            if not cfg.get("wans"):
                time_module.sleep(10)
                continue
            pulse_cfg = get_settings("isp_ping", ISP_PING_DEFAULTS)
            try:
                update_job_status("wan_ping", last_run_at=utc_now_iso())
                state = get_state("wan_ping_state", {})
                reset_at = state.get("reset_at")
                state = wan_ping_notifier.run_check(cfg, pulse_cfg, state)
                latest = get_state("wan_ping_state", {})
                if latest.get("reset_at") and latest.get("reset_at") != reset_at:
                    state = wan_ping_notifier.run_check(cfg, pulse_cfg, latest)
                summary_cfg = cfg.get("summary", {})
                if summary_cfg.get("enabled"):
                    summary_state = {"last_run_date": state.get("summary_last_run_date")}
                    general_cfg = {
                        "schedule_time_ph": summary_cfg.get("daily_time", "07:00"),
                        "timezone": summary_cfg.get("timezone", "Asia/Manila"),
                    }
                    if should_run_daily(general_cfg, summary_state):
                        wan_ping_notifier.send_daily_summary(cfg, pulse_cfg, state)
                        state["summary_last_run_date"] = current_date(general_cfg).isoformat()
                save_state("wan_ping_state", state)
                update_job_status("wan_ping", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                update_job_status("wan_ping", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("wan_ping", last_error=str(exc), last_error_at=utc_now_iso())
            interval_seconds = int(cfg.get("general", {}).get("interval_seconds", 30) or 30)
            time_module.sleep(max(interval_seconds, 5))


def parse_time(value):
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        raise ValueError("schedule_time_ph must be HH:MM")
    return time(hour=int(parts[0]), minute=int(parts[1]))


def current_date(general_cfg):
    timezone = general_cfg.get("timezone", "Asia/Manila")
    if ZoneInfo is not None:
        return datetime.now(ZoneInfo(timezone)).date()
    return datetime.now().date()


def should_run_daily(general_cfg, state):
    schedule_time = parse_time(general_cfg.get("schedule_time_ph", "07:00"))
    timezone = general_cfg.get("timezone", "Asia/Manila")
    if ZoneInfo is not None:
        now = datetime.now(ZoneInfo(timezone))
    else:
        now = datetime.now()
    if state.get("last_run_date") == now.date().isoformat():
        return False
    return now.time() >= schedule_time
