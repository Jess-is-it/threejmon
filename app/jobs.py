import threading
import time as time_module
from datetime import datetime, time

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from .db import update_job_status, utc_now_iso
from .notifiers import optical as optical_notifier
from .notifiers import rto as rto_notifier
from .notifiers import isp_ping as isp_ping_notifier
from .notifiers.telegram import TelegramError
from .settings_defaults import ISP_PING_DEFAULTS, OPTICAL_DEFAULTS, RTO_DEFAULTS
from .settings_store import get_settings, get_state, save_state


class JobsManager:
    def __init__(self):
        self.stop_event = threading.Event()
        self.threads = []

    def start(self):
        self.threads = [
            threading.Thread(target=self._optical_loop, daemon=True),
            threading.Thread(target=self._rto_loop, daemon=True),
            threading.Thread(target=self._isp_loop, daemon=True),
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
                if should_run_daily(cfg["general"], get_state("rto_state", {"last_run_date": None})):
                    update_job_status("rto", last_run_at=utc_now_iso())
                    history = get_state("rto_history", {})
                    history = rto_notifier.run(cfg, history)
                    save_state("rto_history", history)
                    state = get_state("rto_state", {"last_run_date": None})
                    state["last_run_date"] = current_date(cfg["general"]).isoformat()
                    save_state("rto_state", state)
                    update_job_status("rto", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                update_job_status("rto", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("rto", last_error=str(exc), last_error_at=utc_now_iso())

            time_module.sleep(20)

    def _isp_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("isp_ping", ISP_PING_DEFAULTS)
            if not cfg.get("enabled"):
                time_module.sleep(5)
                continue

            try:
                update_job_status("isp_ping", last_run_at=utc_now_iso())
                state = get_state("isp_ping_state", {
                    "last_status": {},
                    "last_report_date": None,
                    "last_report_time": None,
                    "last_report_timezone": None,
                })
                state = isp_ping_notifier.run_check(cfg, state)
                save_state("isp_ping_state", state)
                update_job_status("isp_ping", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                update_job_status("isp_ping", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("isp_ping", last_error=str(exc), last_error_at=utc_now_iso())

            interval_seconds = int(cfg["general"].get("daemon_interval_seconds", 15))
            time_module.sleep(max(interval_seconds, 1))


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
