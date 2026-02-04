import threading
import time as time_module
from datetime import datetime, time, timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout, as_completed
import base64

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from .db import (
    delete_optical_results_older_than,
    delete_pppoe_usage_samples_older_than,
    get_pppoe_usage_window_stats_since,
    insert_pppoe_usage_sample,
    update_job_status,
    utc_now_iso,
    get_accounts_ping_window_stats,
    get_accounts_ping_down_events_map,
    get_latest_accounts_ping_map,
    get_latest_optical_by_pppoe,
    ensure_surveillance_session,
    touch_surveillance_session,
    increment_surveillance_observed,
    end_surveillance_session,
    has_surveillance_session,
)
from .db import delete_accounts_ping_raw_older_than, delete_accounts_ping_rollups_older_than, insert_accounts_ping_result
from .notifiers import optical as optical_notifier
from .notifiers import isp_ping as isp_ping_notifier
from .notifiers import wan_ping as wan_ping_notifier
from .notifiers import rto as rto_notifier
from .notifiers import usage as usage_notifier
from .notifiers.isp_ping import ping_with_source
from .notifiers.telegram import TelegramError, get_updates, send_telegram
from .settings_defaults import (
    ACCOUNTS_PING_DEFAULTS,
    ISP_PING_DEFAULTS,
    OPTICAL_DEFAULTS,
    SURVEILLANCE_DEFAULTS,
    USAGE_DEFAULTS,
    WAN_PING_DEFAULTS,
)
from .settings_store import get_settings, get_state, save_settings, save_state
from .telegram_commands import handle_telegram_command
from .mikrotik import RouterOSClient


class JobsManager:
    def __init__(self):
        self.stop_event = threading.Event()
        self.threads = []

    def start(self):
        self.threads = [
            threading.Thread(target=self._optical_loop, daemon=True),
            threading.Thread(target=self._pulsewatch_loop, daemon=True),
            threading.Thread(target=self._telegram_loop, daemon=True),
            threading.Thread(target=self._wan_ping_loop, daemon=True),
            threading.Thread(target=self._accounts_ping_loop, daemon=True),
            threading.Thread(target=self._usage_loop, daemon=True),
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
                state = get_state("optical_state", {"last_run_date": None, "last_run_at": None})
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
                        delete_optical_results_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                        state["last_prune_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
                        save_state("optical_state", state)
                interval_minutes = int(cfg.get("general", {}).get("check_interval_minutes", 0) or 0)
                now = datetime.utcnow()
                last_run_at = state.get("last_run_at")
                last_run_dt = datetime.fromisoformat(last_run_at.replace("Z", "")) if last_run_at else None
                due_interval = interval_minutes > 0 and (not last_run_dt or now - last_run_dt >= timedelta(minutes=interval_minutes))
                daily_cfg = dict(cfg.get("general", {}))
                daily_cfg["timezone"] = "Asia/Manila"
                due_daily = should_run_daily_on_minute(daily_cfg, state)
                if due_daily:
                    update_job_status("optical", last_run_at=utc_now_iso())
                    optical_notifier.run(cfg, send_alerts=True)
                    state["last_run_date"] = current_date(daily_cfg).isoformat()
                    state["last_run_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    save_state("optical_state", state)
                    update_job_status("optical", last_success_at=utc_now_iso(), last_error="", last_error_at="")
                elif due_interval:
                    update_job_status("optical", last_run_at=utc_now_iso())
                    optical_notifier.run(cfg, send_alerts=False)
                    state["last_run_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    save_state("optical_state", state)
                    update_job_status("optical", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                update_job_status("optical", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("optical", last_error=str(exc), last_error_at=utc_now_iso())

            time_module.sleep(20)

    def _accounts_ping_loop(self):
        while not self.stop_event.is_set():
            cfg = get_settings("accounts_ping", ACCOUNTS_PING_DEFAULTS)
            surv_cfg = get_settings("surveillance", SURVEILLANCE_DEFAULTS)
            surv_enabled = bool(surv_cfg.get("enabled", True))
            auto_add_cfg = surv_cfg.get("auto_add", {}) or {}
            auto_add_sources = auto_add_cfg.get("sources", {}) or {}
            auto_add_enabled = bool(
                surv_enabled
                and auto_add_cfg.get("enabled", False)
                and auto_add_sources.get("accounts_ping", True)
            )
            raw_entries = surv_cfg.get("entries") if isinstance(surv_cfg.get("entries"), list) else []
            surv_entries = []
            for entry in raw_entries:
                if not isinstance(entry, dict):
                    continue
                pppoe = (entry.get("pppoe") or entry.get("name") or "").strip()
                if not pppoe:
                    continue
                status = (entry.get("status") or "under").strip().lower()
                if status not in ("under", "level2"):
                    status = "under"
                surv_entries.append({**entry, "pppoe": pppoe, "status": status})
            surv_map = {entry["pppoe"]: entry for entry in surv_entries}
            has_surveillance_targets = bool(surv_enabled and surv_map)

            should_run = bool(cfg.get("enabled") or has_surveillance_targets or auto_add_enabled)
            if not should_run:
                time_module.sleep(5)
                continue

            try:
                now = datetime.utcnow()
                state = get_state("accounts_ping_state", {"accounts": {}, "last_prune_at": None})
                accounts_state = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}
                devices = state.get("devices") if isinstance(state.get("devices"), list) else []
                refreshed_at = state.get("devices_refreshed_at")
                refreshed_dt = datetime.fromisoformat(refreshed_at.replace("Z", "")) if refreshed_at else None
                refresh_minutes = int((cfg.get("source", {}) or {}).get("refresh_minutes", 15) or 15)
                if refresh_minutes < 1:
                    refresh_minutes = 1

                def account_id_for_pppoe(pppoe):
                    raw = (pppoe or "").strip().encode("utf-8")
                    if not raw:
                        return ""
                    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

                # refresh devices list from SSH CSV (same source as RTO)
                should_refresh = (not refreshed_dt) or (refreshed_dt + timedelta(minutes=refresh_minutes) < now) or not devices
                ssh_cfg = cfg.get("ssh", {}) or {}
                has_ssh = bool((ssh_cfg.get("host") or "").strip() and (ssh_cfg.get("user") or "").strip())
                if should_refresh and has_ssh:
                    try:
                        csv_text = rto_notifier.fetch_csv_text(cfg)
                        parsed = rto_notifier.parse_devices(csv_text)
                        devices = [
                            {
                                "pppoe": (d.get("pppoe") or d.get("name") or d.get("ip") or "").strip(),
                                "name": (d.get("pppoe") or d.get("name") or d.get("ip") or "").strip(),
                                "ip": (d.get("ip") or "").strip(),
                            }
                            for d in (parsed or [])
                            if (d.get("ip") or "").strip()
                        ]
                        state["devices"] = devices
                        state["devices_refreshed_at"] = now.replace(microsecond=0).isoformat() + "Z"
                        save_state("accounts_ping_state", state)
                    except Exception:
                        if cfg.get("enabled"):
                            raise

                storage = cfg.get("storage", {}) or {}
                raw_retention_days = int(storage.get("raw_retention_days", 0) or 0)
                rollup_retention_days = int(storage.get("rollup_retention_days", 0) or 0)
                bucket_seconds = int(storage.get("bucket_seconds", 60) or 60)
                last_prune = state.get("last_prune_at")
                last_prune_dt = datetime.fromisoformat(last_prune.replace("Z", "")) if last_prune else None
                if (raw_retention_days > 0 or rollup_retention_days > 0) and (
                    not last_prune_dt or last_prune_dt + timedelta(hours=24) < now
                ):
                    if raw_retention_days > 0:
                        cutoff = now - timedelta(days=raw_retention_days)
                        delete_accounts_ping_raw_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                    if rollup_retention_days > 0:
                        cutoff = now - timedelta(days=rollup_retention_days)
                        delete_accounts_ping_rollups_older_than(cutoff.replace(microsecond=0).isoformat() + "Z")
                    state["last_prune_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    save_state("accounts_ping_state", state)

                pppoe_ip_map = {}
                for device in devices:
                    pppoe = (device.get("pppoe") or device.get("name") or "").strip()
                    ip = (device.get("ip") or "").strip()
                    if not pppoe or not ip:
                        continue
                    pppoe_ip_map[pppoe] = ip

                target_map = {}
                if cfg.get("enabled"):
                    for device in devices:
                        pppoe = (device.get("pppoe") or device.get("name") or "").strip()
                        ip = (device.get("ip") or "").strip()
                        if not pppoe or not ip:
                            continue
                        account_id = account_id_for_pppoe(pppoe)
                        if not account_id:
                            continue
                        target_map[account_id] = {"id": account_id, "pppoe": pppoe, "name": pppoe, "ip": ip}

                surv_changed = False
                if has_surveillance_targets:
                    for pppoe, entry in surv_map.items():
                        ip = (entry.get("ip") or "").strip() or pppoe_ip_map.get(pppoe, "")
                        if ip and ip != (entry.get("ip") or "").strip():
                            entry["ip"] = ip
                            entry["updated_at"] = now.replace(microsecond=0).isoformat() + "Z"
                            surv_changed = True
                            try:
                                touch_surveillance_session(
                                    pppoe,
                                    source=(entry.get("source") or "").strip(),
                                    ip=ip,
                                    state=(entry.get("status") or "under"),
                                )
                            except Exception:
                                pass
                        account_id = account_id_for_pppoe(pppoe)
                        if not account_id or not ip:
                            continue
                        target_map.setdefault(account_id, {"id": account_id, "pppoe": pppoe, "name": pppoe, "ip": ip})

                targets = list(target_map.values())

                if not targets:
                    time_module.sleep(2)
                    continue

                # Seed history sessions for current surveillance entries (once per PPPoE).
                seeded = state.get("surveillance_sessions_seeded")
                if not isinstance(seeded, list):
                    seeded = []
                seeded_set = {str(x).strip() for x in seeded if str(x).strip()}
                seeded_changed = False
                if has_surveillance_targets:
                    for pppoe, entry in surv_map.items():
                        if pppoe in seeded_set:
                            continue
                        try:
                            ensure_surveillance_session(
                                pppoe,
                                started_at=(entry.get("added_at") or "").strip(),
                                source=(entry.get("source") or "").strip(),
                                ip=(entry.get("ip") or "").strip(),
                                state=(entry.get("status") or "under"),
                            )
                        except Exception:
                            pass
                        seeded_set.add(pppoe)
                        seeded_changed = True
                if seeded_changed:
                    state["surveillance_sessions_seeded"] = sorted(seeded_set, key=lambda x: x.lower())

                base_interval = max(int((cfg.get("general", {}) or {}).get("base_interval_seconds", 30) or 30), 1)
                max_parallel = max(int((cfg.get("general", {}) or {}).get("max_parallel", 64) or 64), 1)
                ping_cfg = cfg.get("ping", {}) or {}
                count = max(int(ping_cfg.get("count", 3) or 3), 1)
                timeout_seconds = max(int(ping_cfg.get("timeout_seconds", 1) or 1), 1)
                surv_ping_cfg = surv_cfg.get("ping", {}) or {}
                surv_interval = max(int(surv_ping_cfg.get("interval_seconds", 1) or 1), 1)
                burst_count = max(int(surv_ping_cfg.get("burst_count", 1) or 1), 1)
                burst_timeout_seconds = max(int(surv_ping_cfg.get("burst_timeout_seconds", 1) or 1), 1)

                cls = cfg.get("classification", {}) or {}
                issue_loss_pct = float(cls.get("issue_loss_pct", 20.0) or 20.0)
                issue_latency_ms = float(cls.get("issue_latency_ms", 200.0) or 200.0)
                down_loss_pct = float(cls.get("down_loss_pct", 100.0) or 100.0)

                burst_cfg = surv_cfg.get("burst", {}) or {}
                burst_enabled = bool(burst_cfg.get("enabled", True))
                burst_interval = max(int(burst_cfg.get("burst_interval_seconds", 1) or 1), 1)
                burst_duration = max(int(burst_cfg.get("burst_duration_seconds", 120) or 120), 5)
                trigger_on_issue = bool(burst_cfg.get("trigger_on_issue", True))

                backoff_cfg = surv_cfg.get("backoff", {}) or {}
                long_down_seconds = max(int(backoff_cfg.get("long_down_seconds", 7200) or 7200), 60)
                long_down_interval = max(int(backoff_cfg.get("long_down_interval_seconds", 300) or 300), 5)

                def parse_dt(value):
                    if not value:
                        return None
                    try:
                        return datetime.fromisoformat(str(value).replace("Z", ""))
                    except Exception:
                        return None

                due_targets = []
                for target in targets:
                    entry = accounts_state.get(target["id"], {}) if isinstance(accounts_state.get(target["id"]), dict) else {}
                    last_check_dt = parse_dt(entry.get("last_check_at"))
                    down_since_dt = parse_dt(entry.get("down_since"))
                    burst_until_dt = parse_dt(entry.get("burst_until"))

                    is_long_down = bool(down_since_dt and (now - down_since_dt).total_seconds() >= long_down_seconds)
                    if is_long_down:
                        burst_until_dt = None

                    in_burst = bool(burst_enabled and (burst_until_dt and now < burst_until_dt))
                    is_surveillance_target = target.get("pppoe") in surv_map

                    effective_interval = base_interval
                    mode = "normal"
                    if is_surveillance_target:
                        if is_long_down:
                            effective_interval = long_down_interval
                            mode = "backoff"
                        else:
                            effective_interval = surv_interval
                            mode = "surveillance"
                    elif is_long_down:
                        effective_interval = long_down_interval
                        mode = "backoff"
                    elif in_burst:
                        effective_interval = burst_interval
                        mode = "burst"

                    due = (not last_check_dt) or ((now - last_check_dt).total_seconds() >= effective_interval)
                    if due:
                        due_targets.append({**target, "_mode": mode})

                if not due_targets:
                    time_module.sleep(1)
                    continue

                update_job_status("accounts_ping", last_run_at=utc_now_iso())

                def do_ping(target_row):
                    ip = target_row["ip"]
                    mode = target_row.get("_mode") or "normal"
                    if mode in ("burst", "surveillance"):
                        res = ping_with_source(ip, "", burst_timeout_seconds, burst_count)
                    else:
                        res = ping_with_source(ip, "", timeout_seconds, count)
                    return target_row, res

                results = []
                with ThreadPoolExecutor(max_workers=min(max_parallel, max(len(due_targets), 1))) as executor:
                    future_map = {executor.submit(do_ping, target): target for target in due_targets}
                    for future in as_completed(future_map):
                        try:
                            results.append(future.result())
                        except Exception:
                            target = future_map[future]
                            results.append((target, {"loss": 100.0, "min_ms": None, "avg_ms": None, "max_ms": None, "replies": 0}))

                changed = False
                for target, res in results:
                    account_id = target["id"]
                    name = target.get("name") or ""
                    ip = target["ip"]
                    mode = target.get("_mode") or "normal"
                    loss = res.get("loss")
                    min_ms = res.get("min_ms")
                    avg_ms = res.get("avg_ms")
                    max_ms = res.get("max_ms")
                    ok = bool(loss is not None and float(loss) < down_loss_pct and int(res.get("replies") or 0) > 0)

                    is_issue = (not ok) or (loss is not None and float(loss) >= issue_loss_pct) or (
                        avg_ms is not None and float(avg_ms) >= issue_latency_ms
                    )

                    entry = accounts_state.get(account_id, {}) if isinstance(accounts_state.get(account_id), dict) else {}
                    # clear expired windows
                    burst_until_dt = parse_dt(entry.get("burst_until"))
                    if burst_until_dt and now >= burst_until_dt:
                        entry["burst_until"] = ""
                        burst_until_dt = None
                    down_since_dt = parse_dt(entry.get("down_since"))
                    if ok:
                        entry["streak"] = 0
                        entry["down_since"] = ""
                        entry["last_up_at"] = now.replace(microsecond=0).isoformat() + "Z"
                        if is_issue:
                            if not entry.get("issue_since"):
                                entry["issue_since"] = now.replace(microsecond=0).isoformat() + "Z"
                        else:
                            entry["issue_since"] = ""
                    else:
                        entry["streak"] = int(entry.get("streak", 0) or 0) + 1
                        if not down_since_dt:
                            entry["down_since"] = now.replace(microsecond=0).isoformat() + "Z"
                        entry["issue_since"] = ""

                    entry["last_check_at"] = now.replace(microsecond=0).isoformat() + "Z"
                    entry["last_status"] = "up" if ok and not is_issue else ("issue" if ok else "down")
                    entry["last_ip"] = ip
                    entry["last_ok"] = bool(ok)
                    entry["last_loss"] = loss
                    entry["last_avg_ms"] = avg_ms

                    is_long_down = False
                    down_since_dt2 = parse_dt(entry.get("down_since"))
                    if down_since_dt2 and (now - down_since_dt2).total_seconds() >= long_down_seconds:
                        is_long_down = True
                    if is_long_down:
                        entry["burst_until"] = ""
                    else:
                        if mode not in ("surveillance",) and burst_enabled and ((is_issue and trigger_on_issue) or (not ok)) and not burst_until_dt:
                            entry["burst_until"] = (now + timedelta(seconds=burst_duration)).replace(microsecond=0).isoformat() + "Z"

                    accounts_state[account_id] = entry
                    changed = True

                    insert_accounts_ping_result(
                        account_id=account_id,
                        name=name,
                        ip=ip,
                        loss=loss,
                        min_ms=min_ms,
                        avg_ms=avg_ms,
                        max_ms=max_ms,
                        ok=ok,
                        mode=mode,
                        timestamp=now.replace(microsecond=0).isoformat() + "Z",
                        bucket_seconds=bucket_seconds,
                    )

                if changed:
                    state["accounts"] = accounts_state
                    save_state("accounts_ping_state", state)

                # auto-transition surveillance entries (every ~5 seconds)
                if surv_enabled and (has_surveillance_targets or auto_add_enabled):
                    last_eval = state.get("surveillance_last_eval_at")
                    last_eval_dt = parse_dt(last_eval) if last_eval else None
                    if not last_eval_dt or (now - last_eval_dt).total_seconds() >= 5:
                        now_iso = now.replace(microsecond=0).isoformat() + "Z"
                        entries_changed = False

                        # Auto-add accounts into surveillance on a schedule (minutes).
                        scan_due = False
                        if auto_add_enabled:
                            scan_interval_minutes = max(int(auto_add_cfg.get("scan_interval_minutes", 5) or 5), 1)
                            last_scan = state.get("surveillance_autoadd_last_scan_at")
                            last_scan_dt = parse_dt(last_scan) if last_scan else None
                            scan_due = (not last_scan_dt) or (now - last_scan_dt) >= timedelta(minutes=scan_interval_minutes)

                        if auto_add_enabled and scan_due:
                            sources = auto_add_cfg.get("sources") if isinstance(auto_add_cfg.get("sources"), dict) else {}
                            if not bool(sources.get("accounts_ping", True)):
                                state["surveillance_autoadd_last_scan_at"] = now_iso
                            else:
                                try:
                                    window_days = float(auto_add_cfg.get("window_days", 3) or 3)
                                except Exception:
                                    window_days = 3.0
                                if window_days <= 0:
                                    window_days = 3.0
                                min_down_events = max(int(auto_add_cfg.get("min_down_events", 5) or 5), 1)
                                try:
                                    max_add = int(auto_add_cfg.get("max_add_per_eval", 3))
                                except Exception:
                                    max_add = 3
                                if max_add < 0:
                                    max_add = 0

                                seen_map = (
                                    state.get("surveillance_autoadd_seen")
                                    if isinstance(state.get("surveillance_autoadd_seen"), dict)
                                    else {}
                                )
                                if len(seen_map) > 50000:
                                    seen_map = {}

                                candidates = []
                                for target in targets:
                                    pppoe = (target.get("pppoe") or "").strip()
                                    if not pppoe or pppoe in surv_map:
                                        continue
                                    if pppoe in seen_map:
                                        continue
                                    candidates.append(target)

                                since_iso2 = (now - timedelta(days=window_days)).replace(microsecond=0).isoformat() + "Z"
                                until_iso2 = now.replace(microsecond=0).isoformat() + "Z"
                                down_events_map = get_accounts_ping_down_events_map(
                                    [t["id"] for t in candidates], since_iso2, until_iso2
                                )

                                added = 0
                                for target in candidates:
                                    if max_add and added >= max_add:
                                        break
                                    pppoe = (target.get("pppoe") or "").strip()
                                    if not pppoe or pppoe in surv_map:
                                        continue
                                    if pppoe in seen_map:
                                        continue

                                    # PPPoE can only ever be auto-added once. If it exists in history, skip permanently.
                                    try:
                                        if has_surveillance_session(pppoe):
                                            seen_map[pppoe] = 1
                                            continue
                                    except Exception:
                                        continue

                                    down_events = int(down_events_map.get(target["id"]) or 0)
                                    if down_events < min_down_events:
                                        continue
                                    reason = f"Intermittent: {down_events} down events / {window_days:g}d"

                                    ip = (target.get("ip") or "").strip()
                                    entry = {
                                        "pppoe": pppoe,
                                        "name": (target.get("name") or pppoe).strip(),
                                        "ip": ip,
                                        "source": "accounts_ping",
                                        "status": "under",
                                        "added_at": now_iso,
                                        "updated_at": now_iso,
                                        "level2_at": "",
                                        "last_fixed_at": "",
                                        "last_fixed_reason": "",
                                        "last_fixed_mode": "",
                                        "added_mode": "auto",
                                        "auto_source": "accounts_ping",
                                        "auto_reason": reason,
                                    }
                                    surv_map[pppoe] = entry
                                    seen_map[pppoe] = 1
                                    entries_changed = True
                                    added += 1
                                    try:
                                        ensure_surveillance_session(
                                            pppoe,
                                            started_at=now_iso,
                                            source="accounts_ping",
                                            ip=ip,
                                            state="under",
                                        )
                                    except Exception:
                                        pass

                                state["surveillance_autoadd_seen"] = seen_map
                                state["surveillance_autoadd_last_scan_at"] = now_iso

                        stab_cfg = surv_cfg.get("stability", {}) or {}
                        stable_window_minutes = max(int(stab_cfg.get("stable_window_minutes", 10) or 10), 1)
                        uptime_threshold_pct = float(stab_cfg.get("uptime_threshold_pct", 95.0) or 95.0)
                        latency_max_ms = float(stab_cfg.get("latency_max_ms", 15.0) or 15.0)
                        loss_max_pct = float(stab_cfg.get("loss_max_pct", 100.0) or 100.0)
                        optical_rx_min_dbm = float(stab_cfg.get("optical_rx_min_dbm", -24.0) or -24.0)
                        require_optical = bool(stab_cfg.get("require_optical", False))
                        escalate_after_minutes = max(int(stab_cfg.get("escalate_after_minutes", stable_window_minutes) or stable_window_minutes), 1)

                        if surv_map:
                            since_iso = (now - timedelta(minutes=stable_window_minutes)).replace(microsecond=0).isoformat() + "Z"
                            surveilled_pppoes = list(surv_map.keys())
                            surveilled_ids = [account_id_for_pppoe(p) for p in surveilled_pppoes]
                            stats_map = get_accounts_ping_window_stats(surveilled_ids, since_iso)
                            latest_map = get_latest_accounts_ping_map(surveilled_ids)
                            optical_map = get_latest_optical_by_pppoe(surveilled_pppoes)

                            for pppoe, entry in list(surv_map.items()):
                                    status = (entry.get("status") or "under").strip().lower()
                                    aid = account_id_for_pppoe(pppoe)
                                    stats = stats_map.get(aid) or {}
                                    latest = latest_map.get(aid) or {}

                                    total = int(stats.get("total") or 0)
                                    failures = int(stats.get("failures") or 0)
                                    uptime_pct = (100.0 - (failures / total) * 100.0) if total else 0.0
                                    avg_ms_avg = stats.get("avg_ms_avg")
                                    if avg_ms_avg is None:
                                        avg_ms_avg = latest.get("avg_ms")
                                    loss_avg = stats.get("loss_avg")
                                    if loss_avg is None:
                                        loss_avg = latest.get("loss")

                                    stable = bool(
                                        total > 0
                                        and uptime_pct >= uptime_threshold_pct
                                        and avg_ms_avg is not None
                                        and float(avg_ms_avg) <= latency_max_ms
                                    )
                                    if stable and loss_avg is not None:
                                        stable = bool(float(loss_avg) <= loss_max_pct)
                                    if stable and require_optical:
                                        opt = optical_map.get(pppoe) or {}
                                        rx = opt.get("rx")
                                        stable = bool(rx is not None and float(rx) >= optical_rx_min_dbm)

                                    if status == "under":
                                        added_at = parse_dt(entry.get("added_at"))
                                        has_full_window = bool(
                                            added_at
                                            and (now - added_at).total_seconds() >= float(stable_window_minutes) * 60.0
                                        )
                                        if stable and has_full_window:
                                            try:
                                                end_surveillance_session(
                                                    pppoe,
                                                    "healed",
                                                    started_at=(entry.get("added_at") or "").strip(),
                                                    source=(entry.get("source") or "").strip(),
                                                    ip=(entry.get("ip") or "").strip(),
                                                    state=(entry.get("status") or "under"),
                                                )
                                            except Exception:
                                                pass
                                            surv_map.pop(pppoe, None)
                                            entries_changed = True
                                            continue
                                        if added_at and (now - added_at).total_seconds() >= float(escalate_after_minutes) * 60.0:
                                            try:
                                                increment_surveillance_observed(
                                                    pppoe,
                                                    started_at=(entry.get("added_at") or "").strip(),
                                                    source=(entry.get("source") or "").strip(),
                                                    ip=(entry.get("ip") or "").strip(),
                                                )
                                            except Exception:
                                                pass
                                            entry["status"] = "level2"
                                            entry["level2_at"] = now_iso
                                            entry["updated_at"] = now_iso
                                            surv_map[pppoe] = entry
                                            entries_changed = True
                                    elif status == "level2":
                                        level2_autofix_minutes = max(
                                            int(stab_cfg.get("level2_autofix_after_minutes", 30) or 30),
                                            1,
                                        )
                                        level2_since = parse_dt(entry.get("level2_at")) or parse_dt(entry.get("updated_at")) or parse_dt(entry.get("added_at"))
                                        due_autofix = bool(
                                            level2_since
                                            and (now - level2_since).total_seconds() >= float(level2_autofix_minutes) * 60.0
                                        )
                                        if stable and due_autofix:
                                            try:
                                                end_surveillance_session(
                                                    pppoe,
                                                    "fixed",
                                                    started_at=(entry.get("added_at") or "").strip(),
                                                    source=(entry.get("source") or "").strip(),
                                                    ip=(entry.get("ip") or "").strip(),
                                                    state="level2",
                                                    note="Auto-fixed by system",
                                                )
                                            except Exception:
                                                pass
                                            now_iso2 = now.replace(microsecond=0).isoformat() + "Z"
                                            entry["status"] = "under"
                                            entry["added_at"] = now_iso2
                                            entry["updated_at"] = now_iso2
                                            entry["level2_at"] = ""
                                            entry["last_fixed_at"] = now_iso2
                                            entry["last_fixed_reason"] = "Auto fixed"
                                            entry["last_fixed_mode"] = "auto"
                                            surv_map[pppoe] = entry
                                            entries_changed = True
                                            try:
                                                ensure_surveillance_session(
                                                    pppoe,
                                                    started_at=now_iso2,
                                                    source=(entry.get("source") or "").strip(),
                                                    ip=(entry.get("ip") or "").strip(),
                                                    state="under",
                                                )
                                            except Exception:
                                                pass

                        if surv_changed or entries_changed:
                            surv_cfg["entries"] = list(surv_map.values())
                            save_settings("surveillance", surv_cfg)

                        state["surveillance_last_eval_at"] = now_iso
                        save_state("accounts_ping_state", state)

                update_job_status("accounts_ping", last_success_at=utc_now_iso(), last_error="", last_error_at="")
            except TelegramError as exc:
                update_job_status("accounts_ping", last_error=str(exc), last_error_at=utc_now_iso())
            except Exception as exc:
                update_job_status("accounts_ping", last_error=str(exc), last_error_at=utc_now_iso())

            time_module.sleep(1)

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
                reach_last_dt = None
                if reach_last:
                    try:
                        reach_last_dt = datetime.fromisoformat(reach_last.replace("Z", ""))
                    except Exception:
                        reach_last_dt = None
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

    def _usage_loop(self):
        clients = {}
        client_sigs = {}
        genieacs_parser_version = "3"
        usage_tz = None
        try:
            if ZoneInfo:
                usage_tz = ZoneInfo("Asia/Manila")
        except Exception:
            usage_tz = None

        def _parse_hhmm(value, default=(0, 0)):
            parts = (value or "").strip().split(":")
            if len(parts) != 2:
                return default
            try:
                return int(parts[0]), int(parts[1])
            except Exception:
                return default

        def _in_time_window(now_dt, start_hhmm, end_hhmm, start_default=(0, 0), end_default=(23, 59)):
            sh, sm = _parse_hhmm(start_hhmm, default=start_default)
            eh, em = _parse_hhmm(end_hhmm, default=end_default)
            start_t = time(hour=max(min(sh, 23), 0), minute=max(min(sm, 59), 0))
            end_t = time(hour=max(min(eh, 23), 0), minute=max(min(em, 59), 0))
            current_t = now_dt.time()
            if start_t <= end_t:
                return start_t <= current_t <= end_t
            return current_t >= start_t or current_t <= end_t

        try:
            while not self.stop_event.is_set():
                cfg = get_settings("usage", USAGE_DEFAULTS)
                if not cfg.get("enabled"):
                    time_module.sleep(5)
                    continue

                now = datetime.utcnow().replace(microsecond=0)
                now_iso = now.isoformat() + "Z"
                state = get_state(
                    "usage_state",
                    {
                        "last_check_at": None,
                        "last_prune_at": None,
                        "last_genieacs_refresh_at": None,
                        "last_db_write_at": None,
                        "secrets_refreshed_at": {},
                        "secrets_cache": {},
                        "prev_bytes": {},
                        "pppoe_hosts": {},
                        "anytime_issues": {},
                        "anytime_eval_at": None,
                    },
                )

                try:
                    retention_days = int((cfg.get("storage") or {}).get("raw_retention_days", 0) or 0)
                    if retention_days > 0:
                        last_prune = state.get("last_prune_at")
                        last_prune_dt = datetime.fromisoformat(last_prune.replace("Z", "")) if last_prune else None
                        if not last_prune_dt or last_prune_dt + timedelta(hours=24) < now:
                            cutoff = now - timedelta(days=retention_days)
                            delete_pppoe_usage_samples_older_than(cutoff.isoformat() + "Z")
                            state["last_prune_at"] = now_iso

                    refresh_minutes = int((cfg.get("source") or {}).get("refresh_minutes", 15) or 15)
                    last_genie = state.get("last_genieacs_refresh_at")
                    last_genie_dt = datetime.fromisoformat(last_genie.replace("Z", "")) if last_genie else None
                    if refresh_minutes < 1:
                        refresh_minutes = 1
                    dev_cfg = cfg.get("device") if isinstance(cfg.get("device"), dict) else {}
                    genie_cfg = cfg.get("genieacs") if isinstance(cfg.get("genieacs"), dict) else {}
                    genie_sig = {
                        "v": genieacs_parser_version,
                        "base_url": (genie_cfg.get("base_url") or "").strip().rstrip("/"),
                        "page_size": int(genie_cfg.get("page_size", 100) or 100),
                        "pppoe_paths": list(dev_cfg.get("pppoe_paths") or []),
                        "host_count_paths": list(dev_cfg.get("host_count_paths") or []),
                        "host_name_paths": list(dev_cfg.get("host_name_paths") or []),
                        "host_ip_paths": list(dev_cfg.get("host_ip_paths") or []),
                        "host_active_paths": list(dev_cfg.get("host_active_paths") or []),
                    }
                    force_refresh = state.get("genieacs_sig") != genie_sig
                    if force_refresh:
                        last_genie_dt = None
                    if not last_genie_dt or last_genie_dt + timedelta(minutes=refresh_minutes) < now:
                        try:
                            state["pppoe_hosts"] = usage_notifier.build_pppoe_host_map(cfg)
                            state["last_genieacs_refresh_at"] = now_iso
                            state["genieacs_error"] = ""
                            state["genieacs_sig"] = genie_sig
                        except Exception as exc:
                            state["genieacs_error"] = str(exc)

                    poll_seconds = int((cfg.get("mikrotik") or {}).get("poll_interval_seconds", 10) or 10)
                    poll_seconds = max(poll_seconds, 3)
                    secrets_refresh_minutes = int((cfg.get("mikrotik") or {}).get("secrets_refresh_minutes", 15) or 15)
                    if secrets_refresh_minutes < 1:
                        secrets_refresh_minutes = 1
                    timeout_seconds = int((cfg.get("mikrotik") or {}).get("timeout_seconds", 5) or 5)

                    routers = (cfg.get("mikrotik") or {}).get("routers") or []
                    enabled_router_ids = set()
                    active_rows = []
                    offline_rows = []
                    router_status = []

                    prev_bytes = state.get("prev_bytes") if isinstance(state.get("prev_bytes"), dict) else {}
                    secrets_cache = state.get("secrets_cache") if isinstance(state.get("secrets_cache"), dict) else {}
                    secrets_refreshed_at = (
                        state.get("secrets_refreshed_at") if isinstance(state.get("secrets_refreshed_at"), dict) else {}
                    )

                    update_job_status("usage", last_run_at=utc_now_iso())
                    for router in routers:
                        if not isinstance(router, dict):
                            continue
                        if not router.get("enabled", True):
                            continue
                        router_id = (router.get("id") or "").strip()
                        router_name = (router.get("name") or router_id or "router").strip()
                        host = (router.get("host") or "").strip()
                        if not router_id or not host:
                            continue
                        enabled_router_ids.add(router_id)

                        last_secret = secrets_refreshed_at.get(router_id)
                        last_secret_dt = datetime.fromisoformat(last_secret.replace("Z", "")) if last_secret else None
                        secrets_due = not last_secret_dt or last_secret_dt + timedelta(minutes=secrets_refresh_minutes) < now

                        port = int(router.get("port", 8728) or 8728)
                        username = router.get("username", "")
                        password = router.get("password", "")
                        sig = (host, port, username, password, timeout_seconds)

                        client = clients.get(router_id)
                        if client is None or client_sigs.get(router_id) != sig:
                            try:
                                if client is not None:
                                    client.close()
                            except Exception:
                                pass
                            client = RouterOSClient(host, port, username, password, timeout=timeout_seconds)
                            clients[router_id] = client
                            client_sigs[router_id] = sig

                        router_error = ""
                        router_active = []
                        router_queues = []
                        router_ifaces = []
                        connected = False
                        try:
                            # Keep a persistent API connection; reconnect on failure.
                            if client.sock is None:
                                client.connect()
                            connected = True
                            router_active = usage_notifier.fetch_pppoe_active(client)
                            router_queues = usage_notifier.fetch_simple_queues(client)
                            router_ifaces = usage_notifier.fetch_ppp_interfaces(client)
                            if secrets_due:
                                secrets_cache[router_id] = usage_notifier.fetch_pppoe_secrets(client)
                                secrets_refreshed_at[router_id] = now_iso
                        except Exception as exc:
                            router_error = str(exc)
                            try:
                                client.close()
                            except Exception:
                                pass
                            clients[router_id] = RouterOSClient(host, port, username, password, timeout=timeout_seconds)
                            client_sigs[router_id] = sig
                            # One reconnect attempt immediately (covers session expiry / dropped sockets).
                            try:
                                clients[router_id].connect()
                                connected = True
                                router_active = usage_notifier.fetch_pppoe_active(clients[router_id])
                                router_queues = usage_notifier.fetch_simple_queues(clients[router_id])
                                router_ifaces = usage_notifier.fetch_ppp_interfaces(clients[router_id])
                                if secrets_due:
                                    secrets_cache[router_id] = usage_notifier.fetch_pppoe_secrets(clients[router_id])
                                    secrets_refreshed_at[router_id] = now_iso
                                router_error = ""
                            except Exception as exc2:
                                router_error = str(exc2)
                                try:
                                    clients[router_id].close()
                                except Exception:
                                    pass
                                connected = False

                        computed = []
                        active_set = set()
                        queue_rows = router_queues if isinstance(router_queues, list) else []
                        queue_match_count = 0
                        queue_bytes_ok = 0
                        queue_rate_ok = 0
                        iface_rows = router_ifaces if isinstance(router_ifaces, list) else []
                        iface_match_count = 0
                        iface_bytes_ok = 0

                        def match_queue_for_row(pppoe, address):
                            pppoe = (pppoe or "").strip()
                            address = (address or "").strip()
                            if not queue_rows or (not pppoe and not address):
                                return None

                            def target_matches(q):
                                tgt = (q.get("target") or "").strip()
                                if not tgt or not address:
                                    return False
                                targets = [t.strip() for t in tgt.split(",") if t.strip()]
                                for t in targets:
                                    if t == address or t.startswith(address + "/"):
                                        return True
                                return False

                            candidates = []
                            for q in queue_rows:
                                name = (q.get("name") or "").strip()
                                if pppoe and (pppoe == name or pppoe in name):
                                    candidates.append(q)
                                    continue
                                low = pppoe.lower()
                                if low and low in name.lower():
                                    candidates.append(q)
                                    continue
                                if target_matches(q):
                                    candidates.append(q)

                            if not candidates:
                                return None

                            def score(q):
                                name = (q.get("name") or "").strip()
                                # Prefer exact name match, then target match, then substring match.
                                exact = 0 if pppoe and name == pppoe else 1
                                tgt = 0 if target_matches(q) else 1
                                sub = 0 if pppoe and (pppoe in name or pppoe.lower() in name.lower()) else 1
                                return (exact, tgt, sub, len(name), name)

                            return min(candidates, key=score)

                        def match_iface_for_row(pppoe, iface_hint):
                            pppoe = (pppoe or "").strip()
                            iface_hint = (iface_hint or "").strip()
                            if not iface_rows:
                                return None
                            if iface_hint:
                                for i in iface_rows:
                                    if (i.get("name") or "").strip().lower() == iface_hint.lower():
                                        return i
                            if not pppoe:
                                return None
                            candidates = [i for i in iface_rows if pppoe in ((i.get("name") or "").strip())]
                            if not candidates:
                                low = pppoe.lower()
                                candidates = [
                                    i for i in iface_rows if low and low in ((i.get("name") or "").strip().lower())
                                ]
                            if not candidates:
                                return None
                            return min(
                                candidates,
                                key=lambda i: (len((i.get("name") or "").strip()), (i.get("name") or "").strip()),
                            )

                        for row in router_active:
                            pppoe = (row.get("name") or "").strip()
                            if not pppoe:
                                continue
                            addr = (row.get("address") or "").strip()
                            iface_hint = (row.get("interface") or "").strip()
                            active_set.add(pppoe)
                            key = f"{router_id}|{pppoe}"
                            prev = prev_bytes.get(key) or {}
                            prev_ts = prev.get("ts")
                            prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "")) if prev_ts else None
                            prev_in = prev.get("bytes_in")
                            prev_out = prev.get("bytes_out")
                            # Prefer per-subscriber traffic via simple queues when available; otherwise
                            # fall back to dynamic PPP interface counters (rx-byte/tx-byte).
                            q = match_queue_for_row(pppoe, addr)
                            if q:
                                queue_match_count += 1
                            q_bytes = usage_notifier.parse_duplex_int((q or {}).get("bytes")) if q else None
                            q_rate = usage_notifier.parse_duplex_float((q or {}).get("rate")) if q else None
                            if q_bytes:
                                queue_bytes_ok += 1
                            if q_rate:
                                queue_rate_ok += 1

                            # Convention (UI): DL = router->client, UL = client->router.
                            # MikroTik queue "bytes" and "rate" are commonly formatted as "download/upload".
                            now_out = q_bytes[0] if q_bytes else None  # DL total bytes
                            now_in = q_bytes[1] if q_bytes else None  # UL total bytes

                            # Dynamic PPP interface counters: rx-byte (UL), tx-byte (DL)
                            iface = None
                            if now_in is None or now_out is None:
                                iface = match_iface_for_row(pppoe, iface_hint)
                                if iface:
                                    iface_match_count += 1
                                    rx_b = usage_notifier._parse_int((iface or {}).get("rx-byte"))
                                    tx_b = usage_notifier._parse_int((iface or {}).get("tx-byte"))
                                    if rx_b is not None and tx_b is not None:
                                        iface_bytes_ok += 1
                                    if now_in is None:
                                        now_in = rx_b
                                    if now_out is None:
                                        now_out = tx_b

                            rate_dl_bps = q_rate[0] if q_rate else None
                            rate_ul_bps = q_rate[1] if q_rate else None
                            computed_rx_bps = None
                            computed_tx_bps = None
                            # Prefer queue-reported rate; fall back to delta computation if missing.
                            if rate_ul_bps is not None:
                                computed_rx_bps = float(rate_ul_bps)
                            if rate_dl_bps is not None:
                                computed_tx_bps = float(rate_dl_bps)

                            if (computed_rx_bps is None or computed_tx_bps is None) and prev_dt and now_in is not None and now_out is not None and prev_in is not None and prev_out is not None:
                                dt = (now - prev_dt).total_seconds()
                                if dt and dt > 0:
                                    d_in = now_in - int(prev_in)
                                    d_out = now_out - int(prev_out)
                                    if computed_rx_bps is None and d_in >= 0:
                                        computed_rx_bps = (d_in * 8.0) / dt
                                    if computed_tx_bps is None and d_out >= 0:
                                        computed_tx_bps = (d_out * 8.0) / dt
                            if computed_rx_bps is None and now_in is not None and prev_in is None:
                                computed_rx_bps = 0.0
                            if computed_tx_bps is None and now_out is not None and prev_out is None:
                                computed_tx_bps = 0.0

                            if now_in is not None or now_out is not None:
                                prev_bytes[key] = {"ts": now_iso, "bytes_in": now_in, "bytes_out": now_out}

                            norm = usage_notifier.normalize_active_row(
                                row,
                                timestamp=now_iso,
                                router_id=router_id,
                                router_name=router_name,
                                computed_rx_bps=computed_rx_bps,
                                computed_tx_bps=computed_tx_bps,
                            )
                            if norm:
                                if now_in is not None:
                                    norm["bytes_in"] = now_in
                                if now_out is not None:
                                    norm["bytes_out"] = now_out
                                computed.append(norm)

                        # Offline rows from cached secrets
                        secrets = secrets_cache.get(router_id) if isinstance(secrets_cache.get(router_id), list) else []
                        for secret in secrets:
                            name = (secret.get("name") or "").strip()
                            if not name or name in active_set:
                                continue
                            offline_rows.append(
                                {
                                    "router_id": router_id,
                                    "router_name": router_name,
                                    "pppoe": name,
                                    "disabled": str(secret.get("disabled") or "").strip().lower() in ("yes", "true", "1"),
                                    "profile": (secret.get("profile") or "").strip(),
                                    "last_logged_out": (secret.get("last-logged-out") or "").strip(),
                                }
                            )

                        active_rows.extend(computed)
                        router_status.append(
                            {
                                "router_id": router_id,
                                "router_name": router_name,
                                "active_count": len(active_set),
                                "queue_count": len(queue_rows),
                                "queue_match_count": queue_match_count,
                                "queue_bytes_ok": queue_bytes_ok,
                                "queue_rate_ok": queue_rate_ok,
                                "iface_count": len(iface_rows),
                                "iface_match_count": iface_match_count,
                                "iface_bytes_ok": iface_bytes_ok,
                                "offline_count": len(
                                    [
                                        1
                                        for s in (secrets or [])
                                        if (s.get("name") or "").strip() and (s.get("name") or "").strip() not in active_set
                                    ]
                                ),
                                "error": router_error,
                                "connected": bool(connected),
                            }
                        )

                    # Close connections for routers that were removed/disabled.
                    for rid in list(clients.keys()):
                        if rid not in enabled_router_ids:
                            try:
                                clients[rid].close()
                            except Exception:
                                pass
                            clients.pop(rid, None)
                            client_sigs.pop(rid, None)

                    # Persist raw samples at a lower cadence than the live polling.
                    sample_interval = int((cfg.get("storage") or {}).get("sample_interval_seconds", 60) or 60)
                    sample_interval = max(sample_interval, 10)
                    last_db = state.get("last_db_write_at")
                    last_db_dt = datetime.fromisoformat(last_db.replace("Z", "")) if last_db else None
                    should_write = (not last_db_dt) or (now - last_db_dt >= timedelta(seconds=sample_interval))
                    if should_write and active_rows:
                        hosts = state.get("pppoe_hosts") if isinstance(state.get("pppoe_hosts"), dict) else {}
                        for row in active_rows:
                            pppoe = (row.get("pppoe") or "").strip()
                            host_info = hosts.get(pppoe) or hosts.get(pppoe.lower()) or {}
                            host_count = int(host_info.get("host_count") or 0)
                            insert_pppoe_usage_sample(
                                row.get("timestamp"),
                                row.get("router_id"),
                                row.get("router_name"),
                                row.get("pppoe"),
                                address=row.get("address"),
                                session_id=row.get("session_id"),
                                uptime=row.get("uptime"),
                                bytes_in=row.get("bytes_in"),
                                bytes_out=row.get("bytes_out"),
                                host_count=host_count,
                                rx_bps=row.get("rx_bps"),
                                tx_bps=row.get("tx_bps"),
                            )
                        state["last_db_write_at"] = now_iso

                    # Anytime no-usage detection (window-based, not peak hours).
                    detect = cfg.get("detection") if isinstance(cfg.get("detection"), dict) else {}
                    anytime_enabled = bool(detect.get("anytime_enabled", False))
                    anytime_window_min = int(detect.get("anytime_no_usage_minutes", 120) or 120)
                    anytime_window_min = max(anytime_window_min, 5)
                    anytime_min_devices = max(int(detect.get("anytime_min_connected_devices", 2) or 2), 1)
                    anytime_from_bps = max(float(detect.get("anytime_total_kbps_from", 0) or 0.0) * 1000.0, 0.0)
                    anytime_to_bps = max(float(detect.get("anytime_total_kbps_to", 8) or 8.0) * 1000.0, 0.0)
                    if anytime_to_bps < anytime_from_bps:
                        anytime_from_bps, anytime_to_bps = anytime_to_bps, anytime_from_bps
                    work_start = (detect.get("anytime_work_start_ph") or "00:00").strip()
                    work_end = (detect.get("anytime_work_end_ph") or "23:59").strip()

                    last_eval = state.get("anytime_eval_at")
                    last_eval_dt = datetime.fromisoformat(last_eval.replace("Z", "")) if last_eval else None
                    eval_due = (not last_eval_dt) or (now - last_eval_dt >= timedelta(seconds=60))
                    if not anytime_enabled:
                        state["anytime_issues"] = {}
                    elif eval_due:
                        now_ph = datetime.now(usage_tz) if usage_tz else datetime.utcnow()
                        if not _in_time_window(now_ph, work_start, work_end):
                            state["anytime_issues"] = {}
                            state["anytime_eval_at"] = now_iso
                        else:
                            since_iso = (now - timedelta(minutes=anytime_window_min)).isoformat() + "Z"
                            stats_map = get_pppoe_usage_window_stats_since(since_iso)
                            expected = int((anytime_window_min * 60) / max(sample_interval, 10))
                            min_samples = max(3, int(expected * 0.25), 10)
                            hosts = state.get("pppoe_hosts") if isinstance(state.get("pppoe_hosts"), dict) else {}
                            issues_map = {}
                            for row in active_rows:
                                pppoe = (row.get("pppoe") or "").strip()
                                if not pppoe:
                                    continue
                                router_id = (row.get("router_id") or "").strip()
                                host_info = hosts.get(pppoe) or hosts.get(pppoe.lower()) or {}
                                host_count = int(host_info.get("host_count") or 0)
                                if host_count < anytime_min_devices:
                                    continue
                                key = f"{router_id}|{pppoe.lower()}"
                                stat = stats_map.get(key)
                                if not stat:
                                    continue
                                if int(stat.get("samples") or 0) < min_samples:
                                    continue
                                max_total_bps = float(stat.get("max_total_bps") or 0.0)
                                if anytime_from_bps <= max_total_bps <= anytime_to_bps:
                                    issues_map[key] = {
                                        "samples": int(stat.get("samples") or 0),
                                        "max_total_bps": max_total_bps,
                                        "window_minutes": anytime_window_min,
                                        "min_samples": min_samples,
                                    }
                            state["anytime_issues"] = issues_map
                            state["anytime_eval_at"] = now_iso

                    state["active_rows"] = active_rows
                    state["offline_rows"] = offline_rows
                    state["routers"] = router_status
                    state["prev_bytes"] = prev_bytes
                    state["secrets_cache"] = secrets_cache
                    state["secrets_refreshed_at"] = secrets_refreshed_at
                    state["last_check_at"] = now_iso
                    save_state("usage_state", state)
                    update_job_status("usage", last_success_at=utc_now_iso(), last_error="", last_error_at="")
                except Exception as exc:
                    update_job_status("usage", last_error=str(exc), last_error_at=utc_now_iso())

                # Sleep based on configured poll interval.
                poll_seconds = int((cfg.get("mikrotik") or {}).get("poll_interval_seconds", 10) or 10)
                time_module.sleep(max(poll_seconds, 3))
        finally:
            for client in list(clients.values()):
                try:
                    client.close()
                except Exception:
                    pass


def parse_time(value):
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        return time(hour=7, minute=0)
    try:
        return time(hour=int(parts[0]), minute=int(parts[1]))
    except (TypeError, ValueError):
        return time(hour=7, minute=0)


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


def should_run_daily_on_minute(general_cfg, state):
    schedule_time = parse_time(general_cfg.get("schedule_time_ph", "07:00"))
    timezone = general_cfg.get("timezone", "Asia/Manila")
    if ZoneInfo is not None:
        now = datetime.now(ZoneInfo(timezone))
    else:
        now = datetime.now()
    if state.get("last_run_date") == now.date().isoformat():
        return False
    return now.hour == schedule_time.hour and now.minute == schedule_time.minute
