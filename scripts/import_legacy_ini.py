#!/usr/bin/env python3
import configparser
import os

from app.settings_defaults import ISP_PING_DEFAULTS, OPTICAL_DEFAULTS, RTO_DEFAULTS
from app.settings_store import save_settings

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY_DIR = os.environ.get("THREEJ_LEGACY_DIR", os.path.join(BASE_DIR, "..", "threejnotif-extract"))


def read_ini(path):
    cfg = configparser.ConfigParser()
    with open(path, "r", encoding="utf-8") as f:
        cfg.read_file(f)
    return cfg


def to_list(value):
    lines = []
    for line in (value or "").splitlines():
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    return lines


def import_optical():
    path = os.path.join(LEGACY_DIR, "optical_app", "optical_settings.ini")
    cfg = read_ini(path)
    settings = OPTICAL_DEFAULTS.copy()
    settings["enabled"] = True
    settings["genieacs"] = {
        "base_url": cfg.get("genieacs", "base_url", fallback=""),
        "username": cfg.get("genieacs", "username", fallback=""),
        "password": cfg.get("genieacs", "password", fallback=""),
        "page_size": cfg.getint("genieacs", "page_size", fallback=100),
    }
    settings["telegram"] = {
        "bot_token": cfg.get("telegram", "bot_token", fallback="").strip(),
        "chat_id": cfg.get("telegram", "chat_id", fallback="").strip(),
    }
    settings["optical"] = {
        "rx_threshold_dbm": cfg.getfloat("optical", "rx_threshold_dbm", fallback=-26.0),
        "tx_low_threshold_dbm": cfg.getfloat("optical", "tx_low_threshold_dbm", fallback=-1.0),
        "priority_rx_threshold_dbm": cfg.getfloat("optical", "priority_rx_threshold_dbm", fallback=-29.0),
        "rx_paths": to_list(cfg.get("optical", "rx_paths", fallback="")),
        "tx_paths": to_list(cfg.get("optical", "tx_paths", fallback="")),
        "pppoe_paths": to_list(cfg.get("optical", "pppoe_paths", fallback="")),
        "ip_paths": to_list(cfg.get("optical", "ip_paths", fallback="")),
    }
    settings["general"] = {
        "message_title": cfg.get("general", "message_title", fallback="Optical Power Alert"),
        "include_header": cfg.getboolean("general", "include_header", fallback=True),
        "max_chars": cfg.getint("general", "max_chars", fallback=3800),
        "schedule_time_ph": cfg.get("general", "schedule_time_ph", fallback="07:00"),
        "timezone": cfg.get("general", "timezone", fallback="Asia/Manila"),
    }
    save_settings("optical", settings)


def import_rto():
    path = os.path.join(LEGACY_DIR, "rto_app", "rto_settings.ini")
    cfg = read_ini(path)
    settings = RTO_DEFAULTS.copy()
    settings["enabled"] = True
    settings["ssh"] = {
        "host": cfg.get("ssh", "host", fallback=""),
        "port": cfg.getint("ssh", "port", fallback=22),
        "user": cfg.get("ssh", "user", fallback=""),
        "password": cfg.get("ssh", "password", fallback=""),
        "use_key": cfg.getboolean("ssh", "use_key", fallback=False),
        "key_path": cfg.get("ssh", "key_path", fallback=""),
        "remote_csv_path": cfg.get("ssh", "remote_csv_path", fallback=""),
    }
    settings["telegram"] = {
        "bot_token": cfg.get("telegram", "bot_token", fallback="").strip(),
        "chat_id": cfg.get("telegram", "chat_id", fallback="").strip(),
    }
    settings["ping"] = {
        "count": cfg.getint("ping", "count", fallback=5),
        "per_ping_timeout_sec": cfg.getint("ping", "per_ping_timeout_sec", fallback=1),
        "max_workers": cfg.getint("ping", "max_workers", fallback=64),
    }
    settings["general"] = {
        "message_title": cfg.get("general", "message_title", fallback="RTO Customers"),
        "include_header": cfg.getboolean("general", "include_header", fallback=True),
        "output_mode": cfg.get("general", "output_mode", fallback="split"),
        "max_chars": cfg.getint("general", "max_chars", fallback=3800),
        "max_lines": cfg.getint("general", "max_lines", fallback=200),
        "top_n": cfg.getint("general", "top_n", fallback=20),
        "schedule_time_ph": cfg.get("general", "schedule_time_ph", fallback="07:00"),
        "timezone": cfg.get("general", "timezone", fallback="Asia/Manila"),
    }
    settings["history"] = {
        "window_size": cfg.getint("history", "window_size", fallback=30),
    }
    save_settings("rto", settings)


def import_isp():
    path = os.path.join(LEGACY_DIR, "isp_ping_app", "isp_ping_settings.ini")
    cfg = read_ini(path)
    settings = ISP_PING_DEFAULTS.copy()
    settings["enabled"] = True
    settings["telegram"] = {
        "bot_token": cfg.get("telegram", "bot_token", fallback="").strip(),
        "chat_id": cfg.get("telegram", "chat_id", fallback="").strip(),
    }
    settings["general"] = {
        "ping_timeout_seconds": cfg.getint("general", "ping_timeout_seconds", fallback=1),
        "ping_count": cfg.getint("general", "ping_count", fallback=5),
        "max_parallel_pings": cfg.getint("general", "max_parallel_pings", fallback=8),
        "daemon_interval_seconds": cfg.getint("general", "daemon_interval_seconds", fallback=15),
    }
    settings["report"] = {
        "daily_time": cfg.get("report", "daily_time", fallback="07:00"),
        "timezone": cfg.get("report", "timezone", fallback="Asia/Manila"),
    }

    ips = to_list(cfg.get("targets", "ips", fallback=""))
    targets = []
    for ip in ips:
        section = f"target:{ip}"
        label = cfg.get(section, "label", fallback=ip)
        down_message = cfg.get(section, "down_message", fallback=f"{label} ({ip}) is DOWN")
        up_message = cfg.get(section, "up_message", fallback=f"{label} ({ip}) is UP")
        targets.append(
            {
                "ip": ip,
                "label": label,
                "down_message": down_message,
                "up_message": up_message,
            }
        )
    settings["targets"] = targets
    save_settings("isp_ping", settings)


def main():
    import_optical()
    import_rto()
    import_isp()
    print("Imported legacy INI settings.")


if __name__ == "__main__":
    main()
