OPTICAL_DEFAULTS = {
    "enabled": False,
    "genieacs": {
        "base_url": "http://genieacs:7557",
        "username": "",
        "password": "",
        "page_size": 100,
    },
    "telegram": {
        "bot_token": "",
        "chat_id": "",
    },
    "optical": {
        "rx_threshold_dbm": -26.0,
        "tx_low_threshold_dbm": -1.0,
        "priority_rx_threshold_dbm": -29.0,
        "rx_paths": [
            "InternetGatewayDevice.WANDevice.1.X_CMCC_EponInterfaceConfig.RXPower",
            "InternetGatewayDevice.WANDevice.1.X_CMCC_GponInterfaceConfig.RXPower",
            "InternetGatewayDevice.WANDevice.1.X_FH_GponInterfaceConfig.RXPower",
            "InternetGatewayDevice.WANDevice.1.X_GponInterafceConfig.RXPower",
            "InternetGatewayDevice.WANDevice.1.X_GponInterfaceConfig.RXPower",
            "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.RXPower",
            "VirtualParameters.RXPower",
        ],
        "tx_paths": [
            "InternetGatewayDevice.WANDevice.1.X_CMCC_EponInterfaceConfig.TXPower",
            "InternetGatewayDevice.WANDevice.1.X_FH_GponInterfaceConfig.TXPower",
            "InternetGatewayDevice.WANDevice.1.X_GponInterafceConfig.TXPower",
            "InternetGatewayDevice.WANDevice.1.X_GponInterfaceConfig.TXPower",
            "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.TXPower",
            "VirtualParameters.TXPower",
        ],
        "pppoe_paths": [
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.X_BROADCOM_COM_Username",
            "VirtualParameters.pppoeUsername",
        ],
        "ip_paths": [
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
            "VirtualParameters.pppoeIP",
        ],
    },
    "general": {
        "message_title": "Optical Power Alert",
        "include_header": True,
        "max_chars": 3800,
        "check_interval_minutes": 60,
        "schedule_time_ph": "07:00",
        "timezone": "Asia/Manila",
    },
    "storage": {
        "raw_retention_days": 365,
    },
    "classification": {
        "issue_rx_dbm": -27.0,
        "issue_tx_dbm": -2.0,
        "stable_rx_dbm": -24.0,
        "stable_tx_dbm": -1.0,
        "chart_min_dbm": -35.0,
        "chart_max_dbm": -10.0,
        "rx_realistic_min_dbm": -40.0,
        "rx_realistic_max_dbm": 5.0,
        "tx_realistic_min_dbm": -10.0,
        "tx_realistic_max_dbm": 10.0,
    },
}

RTO_DEFAULTS = {
    "enabled": False,
    "ssh": {
        "host": "",
        "port": 22,
        "user": "",
        "password": "",
        "use_key": False,
        "key_path": "",
        "remote_csv_path": "/opt/libreqos/src/ShapedDevices.csv",
    },
    "telegram": {
        "bot_token": "",
        "chat_id": "",
    },
    "ping": {
        "count": 5,
        "per_ping_timeout_sec": 1,
        "max_workers": 64,
    },
    "general": {
        "message_title": "RTO Customers",
        "include_header": True,
        "output_mode": "split",
        "max_chars": 3800,
        "max_lines": 200,
        "top_n": 20,
        "ping_interval_minutes": 5,
        "schedule_time_ph": "07:00",
        "timezone": "Asia/Manila",
    },
    "history": {
        "window_size": 30,
    },
    "storage": {
        "raw_retention_days": 365,
    },
    "classification": {
        "issue_rto_pct": 5.0,
        "issue_streak": 2,
        "stable_rto_pct": 1.0,
    },
}

SURVEILLANCE_DEFAULTS = {
    "enabled": True,
    "entries": [],
    "auto_add": {
        "enabled": False,
        # Lookback window for computing criteria (days).
        "window_days": 3,
        # Intermittent (full-down flapping) criteria within the lookback window.
        # A "down event" is counted when a minute bucket has Loss% = 100% and the previous minute was not 100%.
        "min_down_events": 5,
        # How often to scan all accounts for auto-add candidates (minutes).
        "scan_interval_minutes": 5,
        # Safety limit: max accounts to auto-add per scan (0 = no limit).
        "max_add_per_eval": 3,
        # Currently supported source: accounts_ping (based on latest ping status + duration).
        "sources": {
            "accounts_ping": True,
        },
    },
    "ping": {
        "interval_seconds": 1,
        "count": 1,
        "timeout_seconds": 1,
        "burst_count": 1,
        "burst_timeout_seconds": 1,
        "max_parallel": 64,
    },
    "burst": {
        "enabled": True,
        "burst_interval_seconds": 1,
        "burst_duration_seconds": 120,
        "trigger_on_issue": True,
    },
    "backoff": {
        "long_down_seconds": 7200,
        "long_down_interval_seconds": 300,
    },
    "stability": {
        "stable_window_minutes": 10,
        "uptime_threshold_pct": 95.0,
        "latency_max_ms": 15.0,
        "loss_max_pct": 100.0,
        "optical_rx_min_dbm": -24.0,
        "require_optical": True,
        "escalate_after_minutes": 10,
        "level2_autofix_after_minutes": 30,
    },
}

ISP_PING_DEFAULTS = {
    "enabled": False,
    "telegram": {
        "bot_token": "",
        "pulsewatch_bot_token": "",
        "command_bot_token": "",
        "chat_id": "",
        "command_chat_id": "",
        "alert_channel_id": "",
        "allowed_user_ids": [],
        "command_feedback_seconds": 10,
    },
    "general": {
        "ping_timeout_seconds": 1,
        "ping_count": 5,
        "max_parallel_pings": 8,
        "daemon_interval_seconds": 15,
        "include_up_icmp": False,
        "up_icmp_lines": 5,
        "down_reminder_hours": 8,
    },
    "report": {
        "daily_time": "07:00",
        "timezone": "Asia/Manila",
    },
    "targets": [],
    "pulsewatch": {
        "enabled": False,
        "manage_address_lists": False,
        "reconcile_interval_minutes": 10,
        "store_raw_output": False,
        "retention_days": 365,
        "rollup_retention_days": 365,
        "list_presets": [],
        "mikrotik": {
            "cores": [],
        },
        "speedtest": {
            "enabled": False,
            "min_interval_minutes": 60,
            "command": "speedtest",
            "args": "--format=json",
            "use_netns": False,
            "netns_prefix": "isp",
        },
        "ping": {
            "timeout_seconds": 1,
            "count": 5,
            "max_parallel": 8,
            "interval_seconds": 1,
        },
        "dashboard": {
            "default_target": "all",
            "refresh_seconds": 2,
            "loss_history_minutes": 120,
            "pie_default_days": 7,
        },
        "stability": {
            "stable_max_ms": 80,
            "unstable_max_ms": 150,
            "down_source": "wan",
        },
        "isps": [
            {
                "id": "isp1",
                "label": "ISP 1",
                "source_ip": "",
                "core2_source_ip": "",
                "core3_source_ip": "",
                "sources": {},
                "router_scope": "both",
                "ping_router": "auto",
                "ping_core_id": "auto",
                "ping_targets": ["1.1.1.1", "8.8.8.8"],
                "thresholds": {
                    "latency_ms": 120,
                    "loss_pct": 20,
                },
                "consecutive_breach_count": 3,
                "cooldown_minutes": 10,
            },
            {
                "id": "isp2",
                "label": "ISP 2",
                "source_ip": "",
                "core2_source_ip": "",
                "core3_source_ip": "",
                "sources": {},
                "router_scope": "both",
                "ping_router": "auto",
                "ping_core_id": "auto",
                "ping_targets": ["1.1.1.1", "8.8.8.8"],
                "thresholds": {
                    "latency_ms": 120,
                    "loss_pct": 20,
                },
                "consecutive_breach_count": 3,
                "cooldown_minutes": 10,
            },
            {
                "id": "isp3",
                "label": "ISP 3",
                "source_ip": "",
                "core2_source_ip": "",
                "core3_source_ip": "",
                "sources": {},
                "router_scope": "both",
                "ping_router": "auto",
                "ping_core_id": "auto",
                "ping_targets": ["1.1.1.1", "8.8.8.8"],
                "thresholds": {
                    "latency_ms": 120,
                    "loss_pct": 20,
                },
                "consecutive_breach_count": 3,
                "cooldown_minutes": 10,
            },
            {
                "id": "isp4",
                "label": "ISP 4",
                "source_ip": "",
                "core2_source_ip": "",
                "core3_source_ip": "",
                "sources": {},
                "router_scope": "both",
                "ping_router": "auto",
                "ping_core_id": "auto",
                "ping_targets": ["1.1.1.1", "8.8.8.8"],
                "thresholds": {
                    "latency_ms": 120,
                    "loss_pct": 20,
                },
                "consecutive_breach_count": 3,
                "cooldown_minutes": 10,
            },
            {
                "id": "isp5",
                "label": "ISP 5",
                "source_ip": "",
                "core2_source_ip": "",
                "core3_source_ip": "",
                "sources": {},
                "router_scope": "both",
                "ping_router": "auto",
                "ping_core_id": "auto",
                "ping_targets": ["1.1.1.1", "8.8.8.8"],
                "thresholds": {
                    "latency_ms": 120,
                    "loss_pct": 20,
                },
                "consecutive_breach_count": 3,
                "cooldown_minutes": 10,
            },
        ],
    },
}

ACCOUNTS_PING_DEFAULTS = {
    "enabled": False,
    "ssh": {
        "host": "",
        "port": 22,
        "user": "",
        "password": "",
        "use_key": False,
        "key_path": "",
        "remote_csv_path": "/opt/libreqos/src/ShapedDevices.csv",
    },
    "source": {
        "refresh_minutes": 15,
    },
    "general": {
        "base_interval_seconds": 30,
        "max_parallel": 64,
    },
    "ping": {
        "count": 3,
        "timeout_seconds": 1,
    },
    "classification": {
        "issue_loss_pct": 20.0,
        "issue_latency_ms": 200.0,
        "down_loss_pct": 100.0,
        "stable_rto_pct": 2.0,
        "issue_rto_pct": 5.0,
        "issue_streak": 2,
    },
    "storage": {
        "raw_retention_days": 365,
        "rollup_retention_days": 365,
        "bucket_seconds": 60,
    },
}

USAGE_DEFAULTS = {
    "enabled": False,
    "mikrotik": {
        "routers": [],
        # Active PPPoE polling frequency (seconds).
        "poll_interval_seconds": 10,
        # How often to refresh /ppp/secret list for offline accounts (minutes).
        "secrets_refresh_minutes": 15,
        "timeout_seconds": 5,
    },
    "genieacs": {
        "base_url": "http://genieacs:7557",
        "username": "",
        "password": "",
        "page_size": 100,
    },
    "source": {
        # How often to refresh connected-host counts from GenieACS (minutes).
        "refresh_minutes": 15,
    },
    "device": {
        # PPPoE username mapping paths in GenieACS devices.
        "pppoe_paths": [
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.X_BROADCOM_COM_Username",
            "VirtualParameters.pppoeUsername",
        ],
        # Hostname paths example. If you provide "...Hosts.Host.1.HostName", the system will auto-enumerate all Hosts.Host.<n>.
        "host_name_paths": [
            "InternetGatewayDevice.LANDevice.1.Hosts.Host.1.HostName",
        ],
        "host_ip_paths": [
            "InternetGatewayDevice.LANDevice.1.Hosts.Host.1.IPAddress",
        ],
        # If set, only Active=true hosts will be shown in the Devices hover card.
        "host_active_paths": [
            "InternetGatewayDevice.LANDevice.1.Hosts.Host.1.Active",
        ],
        # If present, used directly as connected device count.
        "host_count_paths": [
            "InternetGatewayDevice.LANDevice.1.Hosts.HostNumberOfEntries",
        ],
    },
    "detection": {
        # Peak-hours rule (time-windowed).
        "peak_enabled": True,
        "peak_start_ph": "17:30",
        "peak_end_ph": "21:00",
        "min_connected_devices": 2,
        # Consider "no usage" when (dl+ul) is within this range (inclusive).
        "total_kbps_from": 0,
        "total_kbps_to": 8,
        # Anytime rule (duration-based).
        "anytime_enabled": False,
        "anytime_min_connected_devices": 2,
        "anytime_total_kbps_from": 0,
        "anytime_total_kbps_to": 8,
        # Only evaluate Rule 2 during these hours (Asia/Manila).
        # Set 00:00–23:59 to evaluate all day.
        "anytime_work_start_ph": "00:00",
        "anytime_work_end_ph": "23:59",
        # Consider "no usage" when the last N minutes have max total bps within the range.
        "anytime_no_usage_minutes": 120,
        # Back-compat (older configs); treated as total_kbps_to when range isn't present.
        "min_total_kbps": 8,
    },
    "storage": {
        # Persist at most one sample per account per this many seconds (collector still polls for live view).
        "sample_interval_seconds": 60,
        "raw_retention_days": 365,
    },
}

OFFLINE_DEFAULTS = {
    "enabled": False,
    # "secrets": MikroTik PPPoE secrets vs /ppp/active
    # "radius": MikroTik /ppp/active vs Radius server (SSH query)
    "mode": "secrets",
    "general": {
        "poll_interval_seconds": 15,
    },
    "radius": {
        "enabled": False,
        "ssh": {
            "host": "",
            "port": 22,
            "user": "",
            "password": "",
            "use_key": False,
            "key_path": "/data/id_rsa",
        },
        # Command must print one account per line.
        # Supported formats:
        # - username,status
        # - username|status
        # - username status
        "list_command": "",
    },
}

WAN_PING_DEFAULTS = {
    "enabled": False,
    "telegram": {
        "bot_token": "",
        "chat_id": "",
    },
    "general": {
        "interval_seconds": 30,
        "history_retention_days": 400,
    },
    "wans": [],
    "pppoe_routers": [],
    "messages": {},
}

WAN_MESSAGE_DEFAULTS = {
    "down_msg": "🔴 {label} {target} is DOWN {{datetime}} 😢😤",
    "up_msg": "🟢 {label} {target} is UP {{datetime}}\n  Target: {target}\n  Source: {local-ip}\n  {ping5}",
    "still_down_msg": "🔴 {label} {target} is still DOWN {down-sincedatetime}",
}

WAN_SUMMARY_DEFAULTS = {
    "enabled": False,
    "daily_time": "07:00",
    "all_up_msg": "All ISP UP {up}/{total}",
    "partial_msg": "Partial ISP down {up}/{total}",
    "line_template": "{label} Status {status}!",
}
