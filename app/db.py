import json
import os
import sqlite3
from datetime import datetime

DB_PATH = os.environ.get("THREEJ_DB_PATH", "/data/threejnotif.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS job_status (
                job_name TEXT PRIMARY KEY,
                last_run_at TEXT,
                last_success_at TEXT,
                last_error TEXT,
                last_error_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ping_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                isp_id TEXT NOT NULL,
                target TEXT NOT NULL,
                loss REAL,
                min_ms REAL,
                avg_ms REAL,
                max_ms REAL,
                raw_output TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS speedtest_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                isp_id TEXT NOT NULL,
                download_mbps REAL,
                upload_mbps REAL,
                latency_ms REAL,
                server_name TEXT,
                server_id TEXT,
                public_ip TEXT,
                raw_output TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                isp_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                cooldown_until TEXT
            )
            """
        )
    conn.close()


def get_json(table, key, default):
    conn = get_conn()
    try:
        row = conn.execute(
            f"SELECT value FROM {table} WHERE key = ?",
            (key,),
        ).fetchone()
        if not row:
            return default
        return json.loads(row["value"])
    finally:
        conn.close()


def set_json(table, key, value):
    payload = json.dumps(value, ensure_ascii=True)
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                f"INSERT INTO {table} (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, payload),
            )
    finally:
        conn.close()


def update_job_status(job_name, last_run_at=None, last_success_at=None, last_error=None, last_error_at=None):
    conn = get_conn()
    try:
        existing = conn.execute(
            "SELECT * FROM job_status WHERE job_name = ?",
            (job_name,),
        ).fetchone()
        payload = {
            "last_run_at": existing["last_run_at"] if existing else None,
            "last_success_at": existing["last_success_at"] if existing else None,
            "last_error": existing["last_error"] if existing else None,
            "last_error_at": existing["last_error_at"] if existing else None,
        }
        if last_run_at is not None:
            payload["last_run_at"] = last_run_at
        if last_success_at is not None:
            payload["last_success_at"] = last_success_at
        if last_error is not None:
            payload["last_error"] = last_error
        if last_error_at is not None:
            payload["last_error_at"] = last_error_at

        with conn:
            conn.execute(
                """
                INSERT INTO job_status (job_name, last_run_at, last_success_at, last_error, last_error_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(job_name) DO UPDATE SET
                    last_run_at = excluded.last_run_at,
                    last_success_at = excluded.last_success_at,
                    last_error = excluded.last_error,
                    last_error_at = excluded.last_error_at
                """,
                (
                    job_name,
                    payload["last_run_at"],
                    payload["last_success_at"],
                    payload["last_error"],
                    payload["last_error_at"],
                ),
            )
    finally:
        conn.close()


def get_job_status():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM job_status").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def fetch_all_settings():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}
    finally:
        conn.close()


def insert_ping_result(isp_id, target, loss, min_ms, avg_ms, max_ms, raw_output=None, timestamp=None):
    stamp = timestamp or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO ping_results (timestamp, isp_id, target, loss, min_ms, avg_ms, max_ms, raw_output)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (stamp, isp_id, target, loss, min_ms, avg_ms, max_ms, raw_output),
            )
    finally:
        conn.close()


def insert_speedtest_result(
    isp_id,
    download_mbps,
    upload_mbps,
    latency_ms,
    server_name,
    server_id,
    public_ip,
    raw_output=None,
    timestamp=None,
):
    stamp = timestamp or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO speedtest_results (
                    timestamp, isp_id, download_mbps, upload_mbps, latency_ms, server_name, server_id, public_ip, raw_output
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stamp,
                    isp_id,
                    download_mbps,
                    upload_mbps,
                    latency_ms,
                    server_name,
                    server_id,
                    public_ip,
                    raw_output,
                ),
            )
    finally:
        conn.close()


def insert_alert_log(isp_id, alert_type, message, cooldown_until=None, timestamp=None):
    stamp = timestamp or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO alerts_log (timestamp, isp_id, alert_type, message, cooldown_until)
                VALUES (?, ?, ?, ?, ?)
                """,
                (stamp, isp_id, alert_type, message, cooldown_until),
            )
    finally:
        conn.close()


def get_latest_speedtest_map(isp_ids):
    if not isp_ids:
        return {}
    placeholders = ",".join("?" for _ in isp_ids)
    conn = get_conn()
    try:
        rows = conn.execute(
            f"""
            SELECT s.*
            FROM speedtest_results s
            JOIN (
                SELECT isp_id, MAX(timestamp) AS max_ts
                FROM speedtest_results
                WHERE isp_id IN ({placeholders})
                GROUP BY isp_id
            ) latest
            ON s.isp_id = latest.isp_id AND s.timestamp = latest.max_ts
            """,
            isp_ids,
        ).fetchall()
        return {row["isp_id"]: dict(row) for row in rows}
    finally:
        conn.close()


def get_latest_ping_results(isp_id, limit=5):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT *
            FROM ping_results
            WHERE isp_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (isp_id, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
