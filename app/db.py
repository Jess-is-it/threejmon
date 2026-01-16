import json
import os
import sqlite3
from datetime import datetime, timezone

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
            CREATE TABLE IF NOT EXISTS ping_rollups (
                bucket_ts TEXT NOT NULL,
                isp_id TEXT NOT NULL,
                target TEXT NOT NULL,
                sample_count INTEGER NOT NULL,
                avg_sum REAL NOT NULL,
                avg_count INTEGER NOT NULL,
                loss_sum REAL NOT NULL,
                loss_count INTEGER NOT NULL,
                min_ms REAL,
                max_ms REAL,
                max_avg_ms REAL,
                PRIMARY KEY (bucket_ts, isp_id, target)
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


def _bucket_ts_iso(timestamp, bucket_seconds=60):
    raw = str(timestamp).strip()
    if raw.endswith("Z"):
        raw = raw[:-1]
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    bucket = int(dt.timestamp() // max(int(bucket_seconds), 1)) * max(int(bucket_seconds), 1)
    return datetime.fromtimestamp(bucket, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_all_settings():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}
    finally:
        conn.close()


def fetch_all_state():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT key, value FROM state").fetchall()
        return {row["key"]: row["value"] for row in rows}
    finally:
        conn.close()


def insert_ping_result(isp_id, target, loss, min_ms, avg_ms, max_ms, raw_output=None, timestamp=None):
    stamp = timestamp or utc_now_iso()
    bucket_ts = _bucket_ts_iso(stamp, bucket_seconds=60)
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
            avg_sum = float(avg_ms) if avg_ms is not None else 0.0
            avg_count = 1 if avg_ms is not None else 0
            loss_sum = float(loss) if loss is not None else 0.0
            loss_count = 1 if loss is not None else 0
            conn.execute(
                """
                INSERT INTO ping_rollups (
                    bucket_ts, isp_id, target, sample_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
                )
                VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bucket_ts, isp_id, target) DO UPDATE SET
                    sample_count = sample_count + 1,
                    avg_sum = avg_sum + excluded.avg_sum,
                    avg_count = avg_count + excluded.avg_count,
                    loss_sum = loss_sum + excluded.loss_sum,
                    loss_count = loss_count + excluded.loss_count,
                    min_ms = CASE
                        WHEN min_ms IS NULL THEN excluded.min_ms
                        WHEN excluded.min_ms IS NULL THEN min_ms
                        ELSE MIN(min_ms, excluded.min_ms)
                    END,
                    max_ms = CASE
                        WHEN max_ms IS NULL THEN excluded.max_ms
                        WHEN excluded.max_ms IS NULL THEN max_ms
                        ELSE MAX(max_ms, excluded.max_ms)
                    END,
                    max_avg_ms = CASE
                        WHEN max_avg_ms IS NULL THEN excluded.max_avg_ms
                        WHEN excluded.max_avg_ms IS NULL THEN max_avg_ms
                        ELSE MAX(max_avg_ms, excluded.max_avg_ms)
                    END
                """,
                (
                    bucket_ts,
                    isp_id,
                    target,
                    avg_sum,
                    avg_count,
                    loss_sum,
                    loss_count,
                    min_ms,
                    max_ms,
                    avg_ms,
                ),
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


def get_ping_history_map(isp_ids, limit_per_isp=30):
    if not isp_ids:
        return {}
    conn = get_conn()
    try:
        history = {}
        for isp_id in isp_ids:
            rows = conn.execute(
                """
                SELECT timestamp, target, loss, avg_ms
                FROM ping_results
                WHERE isp_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (isp_id, limit_per_isp),
            ).fetchall()
            history[isp_id] = [dict(row) for row in rows][::-1]
        return history
    finally:
        conn.close()


def get_ping_latency_trend_map(isp_ids, since_iso):
    if not isp_ids:
        return {}
    conn = get_conn()
    try:
        history = {}
        for isp_id in isp_ids:
            rows = conn.execute(
                """
                SELECT
                  target,
                  bucket_ts,
                  CASE WHEN avg_count > 0 THEN (avg_sum / avg_count) ELSE NULL END AS avg_ms,
                  CASE WHEN loss_count > 0 THEN (loss_sum / loss_count) ELSE NULL END AS loss_avg,
                  min_ms,
                  max_ms,
                  max_avg_ms
                FROM ping_rollups
                WHERE isp_id = ? AND bucket_ts >= ? AND avg_count > 0
                ORDER BY bucket_ts ASC
                """,
                (isp_id, since_iso),
            ).fetchall()
            history[isp_id] = [dict(row) for row in rows]
        return history
    finally:
        conn.close()


def get_ping_latency_trend_window(isp_ids, start_iso, end_iso):
    if not isp_ids:
        return {}
    conn = get_conn()
    try:
        history = {}
        for isp_id in isp_ids:
            rows = conn.execute(
                """
                SELECT
                  target,
                  bucket_ts,
                  CASE WHEN avg_count > 0 THEN (avg_sum / avg_count) ELSE NULL END AS avg_ms,
                  CASE WHEN loss_count > 0 THEN (loss_sum / loss_count) ELSE NULL END AS loss_avg,
                  min_ms,
                  max_ms,
                  max_avg_ms
                FROM ping_rollups
                WHERE isp_id = ? AND bucket_ts >= ? AND bucket_ts <= ? AND avg_count > 0
                ORDER BY bucket_ts ASC
                """,
                (isp_id, start_iso, end_iso),
            ).fetchall()
            history[isp_id] = [dict(row) for row in rows]
        return history
    finally:
        conn.close()


def delete_pulsewatch_raw_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM ping_results WHERE timestamp < ?", (cutoff_iso,))
            conn.execute("DELETE FROM speedtest_results WHERE timestamp < ?", (cutoff_iso,))
            conn.execute("DELETE FROM alerts_log WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def delete_pulsewatch_rollups_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM ping_rollups WHERE bucket_ts < ?", (cutoff_iso,))
    finally:
        conn.close()


def clear_pulsewatch_data():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM ping_results")
            conn.execute("DELETE FROM speedtest_results")
            conn.execute("DELETE FROM alerts_log")
            conn.execute("DELETE FROM ping_rollups")
    finally:
        conn.close()


def backfill_ping_rollups(since_iso, until_iso=None):
    conn = get_conn()
    try:
        with conn:
            if until_iso:
                conn.execute(
                    "DELETE FROM ping_rollups WHERE bucket_ts >= ? AND bucket_ts <= ?",
                    (since_iso, until_iso),
                )
            else:
                conn.execute("DELETE FROM ping_rollups WHERE bucket_ts >= ?", (since_iso,))

            where_clause = "timestamp >= ?"
            params = [since_iso]
            if until_iso:
                where_clause += " AND timestamp <= ?"
                params.append(until_iso)

            conn.execute(
                f"""
                INSERT INTO ping_rollups (
                    bucket_ts, isp_id, target, sample_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
                )
                SELECT
                    bucket_ts,
                    isp_id,
                    target,
                    COUNT(*) AS sample_count,
                    COALESCE(SUM(avg_ms), 0) AS avg_sum,
                    SUM(CASE WHEN avg_ms IS NOT NULL THEN 1 ELSE 0 END) AS avg_count,
                    COALESCE(SUM(loss), 0) AS loss_sum,
                    SUM(CASE WHEN loss IS NOT NULL THEN 1 ELSE 0 END) AS loss_count,
                    MIN(min_ms) AS min_ms,
                    MAX(max_ms) AS max_ms,
                    MAX(avg_ms) AS max_avg_ms
                FROM (
                    SELECT
                        strftime(
                            '%Y-%m-%dT%H:%M:%SZ',
                            datetime(
                                CAST(strftime('%s', replace(replace(timestamp,'T',' '),'Z','')) AS integer) / 60 * 60,
                                'unixepoch'
                            )
                        ) AS bucket_ts,
                        isp_id,
                        target,
                        loss,
                        min_ms,
                        avg_ms,
                        max_ms
                    FROM ping_results
                    WHERE {where_clause}
                ) t
                GROUP BY bucket_ts, isp_id, target
                """,
                params,
            )
    finally:
        conn.close()
