import json
import os
import sqlite3
import threading
from datetime import datetime, timezone, timedelta

DB_PATH = os.environ.get("THREEJ_DB_PATH", "/data/threejnotif.db")
DB_URL = (os.environ.get("THREEJ_DATABASE_URL") or os.environ.get("DATABASE_URL") or "").strip()

_pg_pool = None
_pg_pool_lock = threading.Lock()


def _use_postgres():
    url = (DB_URL or "").lower()
    return url.startswith("postgres://") or url.startswith("postgresql://")


def _translate_qmarks(sql):
    # sqlite uses "?" params; psycopg2 expects "%s".
    # Replace only outside single-quoted string literals.
    out = []
    in_single = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            out.append(ch)
            if in_single and i + 1 < len(sql) and sql[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            in_single = not in_single
            i += 1
            continue
        if ch == "?" and not in_single:
            out.append("%s")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


class _NoResult:
    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _PGCursorResult:
    def __init__(self, owner, cursor):
        self._owner = owner
        self._cursor = cursor

    def _close(self):
        if not self._cursor:
            return
        try:
            self._cursor.close()
        finally:
            self._owner._discard_cursor(self._cursor)
            self._cursor = None

    def fetchone(self):
        try:
            return self._cursor.fetchone()
        finally:
            self._close()

    def fetchall(self):
        try:
            return self._cursor.fetchall()
        finally:
            self._close()


class _PGConn:
    def __init__(self, pool, conn):
        self._pool = pool
        self._conn = conn
        self._open_cursors = []

    def _discard_cursor(self, cursor):
        try:
            self._open_cursors.remove(cursor)
        except ValueError:
            pass

    def __enter__(self):
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._conn.__exit__(exc_type, exc, tb)

    def execute(self, sql, params=None):
        from psycopg2.extras import RealDictCursor

        q = _translate_qmarks(str(sql))
        cur = self._conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute(q, tuple(params or ()))
            if cur.description is None:
                cur.close()
                return _NoResult()
            self._open_cursors.append(cur)
            return _PGCursorResult(self, cur)
        except Exception:
            try:
                cur.close()
            except Exception:
                pass
            raise

    def close(self):
        # Return to pool, ensuring the connection is clean.
        for cur in list(self._open_cursors):
            try:
                cur.close()
            except Exception:
                pass
        self._open_cursors.clear()
        try:
            try:
                self._conn.rollback()
            except Exception:
                pass
        finally:
            self._pool.putconn(self._conn)


def _get_pg_pool():
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    with _pg_pool_lock:
        if _pg_pool is not None:
            return _pg_pool
        from psycopg2.pool import ThreadedConnectionPool

        minconn = max(int(os.environ.get("THREEJ_PG_POOL_MIN", 1) or 1), 1)
        maxconn = max(int(os.environ.get("THREEJ_PG_POOL_MAX", 10) or 10), minconn)
        _pg_pool = ThreadedConnectionPool(minconn, maxconn, dsn=DB_URL)
        return _pg_pool


def get_conn():
    if _use_postgres():
        conn = _get_pg_pool().getconn()
        conn.autocommit = False
        return _PGConn(_get_pg_pool(), conn)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    with conn:
        if _use_postgres():
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
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    loss DOUBLE PRECISION,
                    min_ms DOUBLE PRECISION,
                    avg_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
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
                    avg_sum DOUBLE PRECISION NOT NULL,
                    avg_count INTEGER NOT NULL,
                    loss_sum DOUBLE PRECISION NOT NULL,
                    loss_count INTEGER NOT NULL,
                    min_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
                    max_avg_ms DOUBLE PRECISION,
                    PRIMARY KEY (bucket_ts, isp_id, target)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS speedtest_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    download_mbps DOUBLE PRECISION,
                    upload_mbps DOUBLE PRECISION,
                    latency_ms DOUBLE PRECISION,
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
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    isp_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    cooldown_until TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rto_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    name TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS optical_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    pppoe TEXT,
                    ip TEXT,
                    rx DOUBLE PRECISION,
                    tx DOUBLE PRECISION,
                    priority INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wan_status_history (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    wan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    up_pct DOUBLE PRECISION,
                    target TEXT,
                    core_id TEXT,
                    label TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_results (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    name TEXT,
                    ip TEXT NOT NULL,
                    loss DOUBLE PRECISION,
                    min_ms DOUBLE PRECISION,
                    avg_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
                    mode TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_rollups (
                    bucket_ts TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    ok_count INTEGER NOT NULL,
                    avg_sum DOUBLE PRECISION NOT NULL,
                    avg_count INTEGER NOT NULL,
                    loss_sum DOUBLE PRECISION NOT NULL,
                    loss_count INTEGER NOT NULL,
                    min_ms DOUBLE PRECISION,
                    max_ms DOUBLE PRECISION,
                    max_avg_ms DOUBLE PRECISION,
                    PRIMARY KEY (bucket_ts, account_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pppoe_usage_samples (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    pppoe TEXT NOT NULL,
                    address TEXT,
                    session_id TEXT,
                    uptime TEXT,
                    bytes_in BIGINT,
                    bytes_out BIGINT,
                    host_count INTEGER,
                    rx_bps DOUBLE PRECISION,
                    tx_bps DOUBLE PRECISION
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS surveillance_sessions (
                    id BIGSERIAL PRIMARY KEY,
                    pppoe TEXT NOT NULL,
                    source TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    end_reason TEXT,
                    end_note TEXT,
                    observed_count INTEGER NOT NULL DEFAULT 0,
                    last_state TEXT NOT NULL DEFAULT 'under',
                    last_ip TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_history (
                    id BIGSERIAL PRIMARY KEY,
                    pppoe TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    mode TEXT NOT NULL,
                    offline_started_at TEXT NOT NULL,
                    offline_ended_at TEXT NOT NULL,
                    duration_seconds INTEGER,
                    radius_status TEXT,
                    disabled BOOLEAN,
                    profile TEXT,
                    last_logged_out TEXT
                )
                """
            )
        else:
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rto_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    name TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS optical_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    pppoe TEXT,
                    ip TEXT,
                    rx REAL,
                    tx REAL,
                    priority INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wan_status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    wan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    up_pct REAL,
                    target TEXT,
                    core_id TEXT,
                    label TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    name TEXT,
                    ip TEXT NOT NULL,
                    loss REAL,
                    min_ms REAL,
                    avg_ms REAL,
                    max_ms REAL,
                    mode TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_ping_rollups (
                    bucket_ts TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    ok_count INTEGER NOT NULL,
                    avg_sum REAL NOT NULL,
                    avg_count INTEGER NOT NULL,
                    loss_sum REAL NOT NULL,
                    loss_count INTEGER NOT NULL,
                    min_ms REAL,
                    max_ms REAL,
                    max_avg_ms REAL,
                    PRIMARY KEY (bucket_ts, account_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pppoe_usage_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    pppoe TEXT NOT NULL,
                    address TEXT,
                    session_id TEXT,
                    uptime TEXT,
                    bytes_in INTEGER,
                    bytes_out INTEGER,
                    host_count INTEGER,
                    rx_bps REAL,
                    tx_bps REAL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS surveillance_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pppoe TEXT NOT NULL,
                    source TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    end_reason TEXT,
                    end_note TEXT,
                    observed_count INTEGER NOT NULL DEFAULT 0,
                    last_state TEXT NOT NULL DEFAULT 'under',
                    last_ip TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pppoe TEXT NOT NULL,
                    router_id TEXT,
                    router_name TEXT,
                    mode TEXT NOT NULL,
                    offline_started_at TEXT NOT NULL,
                    offline_ended_at TEXT NOT NULL,
                    duration_seconds INTEGER,
                    radius_status TEXT,
                    disabled INTEGER,
                    profile TEXT,
                    last_logged_out TEXT
                )
                """
            )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_wan_status_history_wan_ts
            ON wan_status_history (wan_id, timestamp)
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rto_results_ip_ts ON rto_results (ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_optical_results_device_ts ON optical_results (device_id, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_optical_results_ip_ts ON optical_results (ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_optical_results_pppoe_ts ON optical_results (pppoe, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ping_results_isp_ts ON ping_results (isp_id, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ping_rollups_isp_bucket ON ping_rollups (isp_id, bucket_ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_ping_results_acct_ts ON accounts_ping_results (account_id, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_ping_results_ip_ts ON accounts_ping_results (ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_ping_rollups_acct_bucket ON accounts_ping_rollups (account_id, bucket_ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pppoe_usage_samples_pppoe_ts ON pppoe_usage_samples (pppoe, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pppoe_usage_samples_router_ts ON pppoe_usage_samples (router_id, timestamp)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_surveillance_sessions_pppoe_started ON surveillance_sessions (pppoe, started_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_surveillance_sessions_active ON surveillance_sessions (ended_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_offline_history_pppoe_ended ON offline_history (pppoe, offline_ended_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_offline_history_router_ended ON offline_history (router_id, offline_ended_at)"
        )
        # Lightweight schema upgrade for existing installs.
        try:
            if _use_postgres():
                conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN IF NOT EXISTS end_note TEXT")
                conn.execute("ALTER TABLE pppoe_usage_samples ADD COLUMN IF NOT EXISTS host_count INTEGER")
            else:
                cols = []
                try:
                    info = conn.execute("PRAGMA table_info(surveillance_sessions)").fetchall()
                    cols = [row["name"] for row in info] if info else []
                except Exception:
                    cols = []
                if "end_note" not in cols:
                    conn.execute("ALTER TABLE surveillance_sessions ADD COLUMN end_note TEXT")
                try:
                    info = conn.execute("PRAGMA table_info(pppoe_usage_samples)").fetchall()
                    cols = [row["name"] for row in info] if info else []
                except Exception:
                    cols = []
                if "host_count" not in cols:
                    conn.execute("ALTER TABLE pppoe_usage_samples ADD COLUMN host_count INTEGER")
        except Exception:
            pass
    conn.close()


def insert_offline_history_event(
    pppoe,
    router_id,
    router_name,
    mode,
    offline_started_at,
    offline_ended_at,
    duration_seconds=None,
    radius_status=None,
    disabled=None,
    profile=None,
    last_logged_out=None,
):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO offline_history (
                    pppoe, router_id, router_name, mode,
                    offline_started_at, offline_ended_at, duration_seconds,
                    radius_status, disabled, profile, last_logged_out
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pppoe,
                    (router_id or "").strip(),
                    (router_name or "").strip(),
                    (mode or "").strip(),
                    (offline_started_at or "").strip(),
                    (offline_ended_at or "").strip(),
                    int(duration_seconds) if duration_seconds is not None else None,
                    (radius_status or "").strip() if radius_status is not None else None,
                    bool(disabled) if disabled is not None else None,
                    (profile or "").strip() if profile is not None else None,
                    (last_logged_out or "").strip() if last_logged_out is not None else None,
                ),
            )
    finally:
        conn.close()


def get_offline_history_since(since_iso, limit=500):
    since_iso = (since_iso or "").strip()
    limit = max(min(int(limit or 500), 2000), 1)
    if not since_iso:
        return []
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                id, pppoe, router_id, router_name, mode,
                offline_started_at, offline_ended_at, duration_seconds,
                radius_status, disabled, profile, last_logged_out
            FROM offline_history
            WHERE offline_ended_at >= ?
            ORDER BY offline_ended_at DESC
            LIMIT ?
            """,
            (since_iso, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def delete_offline_history_older_than(cutoff_iso):
    cutoff_iso = (cutoff_iso or "").strip()
    if not cutoff_iso:
        return
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM offline_history WHERE offline_ended_at < ?", (cutoff_iso,))
    finally:
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


def _get_active_surveillance_session(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT id, pppoe, source, started_at, ended_at, end_reason, observed_count, last_state, last_ip, updated_at
            FROM surveillance_sessions
            WHERE pppoe = ? AND ended_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (pppoe,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _get_surveillance_observed_total(pppoe):
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return 0
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(observed_count), 0) AS c FROM surveillance_sessions WHERE pppoe = ?",
            (pppoe,),
        ).fetchone()
        if isinstance(row, dict):
            return int(row.get("c") or 0)
        return int(row["c"] or 0)
    except Exception:
        return 0
    finally:
        conn.close()


def ensure_surveillance_session(pppoe, started_at=None, source="", ip="", state="under"):
    """
    Ensures there is an active (non-ended) session for this PPPoE.
    Returns the active session row as a dict.
    """
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return None
    existing = _get_active_surveillance_session(pppoe)
    if existing:
        return existing
    now_iso = utc_now_iso()
    started_at = (started_at or "").strip() or now_iso
    state = (state or "under").strip().lower() or "under"
    if state not in ("under", "level2"):
        state = "under"
    observed_total = _get_surveillance_observed_total(pppoe)
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO surveillance_sessions (
                    pppoe, source, started_at, ended_at, end_reason, observed_count, last_state, last_ip, updated_at
                )
                VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?)
                """,
                (
                    pppoe,
                    (source or "").strip(),
                    started_at,
                    observed_total,
                    state,
                    (ip or "").strip(),
                    now_iso,
                ),
            )
    finally:
        conn.close()
    return _get_active_surveillance_session(pppoe)


def touch_surveillance_session(pppoe, source="", ip="", state=None):
    """
    Updates the active session's last_state/last_ip/source/updated_at.
    If no active session exists, it is created using now as started_at.
    """
    session = ensure_surveillance_session(pppoe, source=source, ip=ip, state=state or "under")
    if not session:
        return None
    session_id = session.get("id")
    if not session_id:
        return session
    now_iso = utc_now_iso()
    state = (state or session.get("last_state") or "under").strip().lower() or "under"
    if state not in ("under", "level2"):
        state = "under"
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE surveillance_sessions
                SET source = ?,
                    last_state = ?,
                    last_ip = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    (source or session.get("source") or "").strip(),
                    state,
                    (ip or session.get("last_ip") or "").strip(),
                    now_iso,
                    session_id,
                ),
            )
    finally:
        conn.close()
    return _get_active_surveillance_session(pppoe)


def increment_surveillance_observed(pppoe, started_at=None, source="", ip=""):
    """
    Increments observed_count for the active session and sets last_state to level2.
    If no active session exists, it is created using started_at (or now).
    """
    session = ensure_surveillance_session(pppoe, started_at=started_at, source=source, ip=ip, state="under")
    if not session:
        return None
    session_id = session.get("id")
    if not session_id:
        return session
    now_iso = utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE surveillance_sessions
                SET observed_count = COALESCE(observed_count, 0) + 1,
                    source = ?,
                    last_state = 'level2',
                    last_ip = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    (source or session.get("source") or "").strip(),
                    (ip or session.get("last_ip") or "").strip(),
                    now_iso,
                    session_id,
                ),
            )
    finally:
        conn.close()
    return _get_active_surveillance_session(pppoe)


def end_surveillance_session(pppoe, end_reason, started_at=None, source="", ip="", state=None, note=""):
    """
    Ends the active session, setting ended_at + end_reason.
    If no active session exists, it is created first (using started_at or now) then ended.
    """
    end_reason = (end_reason or "").strip().lower()
    if end_reason not in ("healed", "removed", "fixed"):
        end_reason = "removed"
    session = ensure_surveillance_session(pppoe, started_at=started_at, source=source, ip=ip, state="under")
    if not session:
        return None
    session_id = session.get("id")
    if not session_id:
        return session
    now_iso = utc_now_iso()
    state = (state or session.get("last_state") or "under").strip().lower() or "under"
    if state not in ("under", "level2"):
        state = session.get("last_state") or "under"
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                UPDATE surveillance_sessions
                SET ended_at = ?,
                    end_reason = ?,
                    last_state = ?,
                    last_ip = ?,
                    source = ?,
                    end_note = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    now_iso,
                    end_reason,
                    state,
                    (ip or session.get("last_ip") or "").strip(),
                    (source or session.get("source") or "").strip(),
                    (note or "").strip(),
                    now_iso,
                    session_id,
                ),
            )
    finally:
        conn.close()
    return None


def list_surveillance_sessions(query="", page=1, limit=50):
    try:
        page = int(page or 1)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    try:
        limit = int(limit or 50)
    except Exception:
        limit = 50
    if limit < 1:
        limit = 50
    if limit > 500:
        limit = 500
    query = (query or "").strip().lower()
    params = []
    where = ""
    if query:
        where = "WHERE lower(pppoe) LIKE ?"
        params.append(f"%{query}%")
    offset = (page - 1) * limit
    conn = get_conn()
    try:
        count_row = conn.execute(
            f"SELECT COUNT(*) AS c FROM surveillance_sessions {where}",
            tuple(params),
        ).fetchone()
        if isinstance(count_row, dict):
            total = int(count_row.get("c") or 0)
        else:
            total = int(count_row["c"] or 0)
        rows = conn.execute(
            f"""
            SELECT id, pppoe, source, started_at, ended_at, end_reason, observed_count, last_state, last_ip, updated_at
            FROM surveillance_sessions
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit, offset]),
        ).fetchall()
        out = [dict(row) for row in rows] if rows else []
        return {"rows": out, "total": total, "page": page, "limit": limit}
    finally:
        conn.close()


def list_surveillance_history(query="", page=1, limit=50):
    """
    History is only sessions that have ended (removed/healed/fixed).
    """
    try:
        page = int(page or 1)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    try:
        limit = int(limit or 50)
    except Exception:
        limit = 50
    if limit < 1:
        limit = 50
    if limit > 500:
        limit = 500
    query = (query or "").strip().lower()
    params = []
    where_parts = ["ended_at IS NOT NULL"]
    if query:
        where_parts.append("lower(pppoe) LIKE ?")
        params.append(f"%{query}%")
    where = "WHERE " + " AND ".join(where_parts)
    offset = (page - 1) * limit
    conn = get_conn()
    try:
        count_row = conn.execute(
            f"SELECT COUNT(*) AS c FROM surveillance_sessions {where}",
            tuple(params),
        ).fetchone()
        if isinstance(count_row, dict):
            total = int(count_row.get("c") or 0)
        else:
            total = int(count_row["c"] or 0)
        rows = conn.execute(
            f"""
            SELECT id, pppoe, source, started_at, ended_at, end_reason, end_note, observed_count, last_state, last_ip, updated_at
            FROM surveillance_sessions
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit, offset]),
        ).fetchall()
        out = [dict(row) for row in rows] if rows else []
        return {"rows": out, "total": total, "page": page, "limit": limit}
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
            if _use_postgres():
                conn.execute(
                    """
                    INSERT INTO ping_rollups (
                        bucket_ts, isp_id, target, sample_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket_ts, isp_id, target) DO UPDATE SET
                        sample_count = ping_rollups.sample_count + 1,
                        avg_sum = ping_rollups.avg_sum + excluded.avg_sum,
                        avg_count = ping_rollups.avg_count + excluded.avg_count,
                        loss_sum = ping_rollups.loss_sum + excluded.loss_sum,
                        loss_count = ping_rollups.loss_count + excluded.loss_count,
                        min_ms = CASE
                            WHEN ping_rollups.min_ms IS NULL THEN excluded.min_ms
                            WHEN excluded.min_ms IS NULL THEN ping_rollups.min_ms
                            ELSE LEAST(ping_rollups.min_ms, excluded.min_ms)
                        END,
                        max_ms = CASE
                            WHEN ping_rollups.max_ms IS NULL THEN excluded.max_ms
                            WHEN excluded.max_ms IS NULL THEN ping_rollups.max_ms
                            ELSE GREATEST(ping_rollups.max_ms, excluded.max_ms)
                        END,
                        max_avg_ms = CASE
                            WHEN ping_rollups.max_avg_ms IS NULL THEN excluded.max_avg_ms
                            WHEN excluded.max_avg_ms IS NULL THEN ping_rollups.max_avg_ms
                            ELSE GREATEST(ping_rollups.max_avg_ms, excluded.max_avg_ms)
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
            else:
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


def insert_accounts_ping_result(
    account_id,
    name,
    ip,
    loss,
    min_ms,
    avg_ms,
    max_ms,
    ok,
    mode="normal",
    timestamp=None,
    bucket_seconds=60,
):
    stamp = timestamp or utc_now_iso()
    bucket_ts = _bucket_ts_iso(stamp, bucket_seconds=bucket_seconds)
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO accounts_ping_results (timestamp, account_id, name, ip, loss, min_ms, avg_ms, max_ms, mode, ok)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (stamp, account_id, name, ip, loss, min_ms, avg_ms, max_ms, mode, 1 if ok else 0),
            )
            avg_sum = float(avg_ms) if avg_ms is not None else 0.0
            avg_count = 1 if avg_ms is not None else 0
            loss_sum = float(loss) if loss is not None else 0.0
            loss_count = 1 if loss is not None else 0
            ok_count = 1 if ok else 0
            if _use_postgres():
                conn.execute(
                    """
                    INSERT INTO accounts_ping_rollups (
                        bucket_ts, account_id, ip, sample_count, ok_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket_ts, account_id) DO UPDATE SET
                        ip = excluded.ip,
                        sample_count = accounts_ping_rollups.sample_count + 1,
                        ok_count = accounts_ping_rollups.ok_count + excluded.ok_count,
                        avg_sum = accounts_ping_rollups.avg_sum + excluded.avg_sum,
                        avg_count = accounts_ping_rollups.avg_count + excluded.avg_count,
                        loss_sum = accounts_ping_rollups.loss_sum + excluded.loss_sum,
                        loss_count = accounts_ping_rollups.loss_count + excluded.loss_count,
                        min_ms = CASE
                            WHEN accounts_ping_rollups.min_ms IS NULL THEN excluded.min_ms
                            WHEN excluded.min_ms IS NULL THEN accounts_ping_rollups.min_ms
                            ELSE LEAST(accounts_ping_rollups.min_ms, excluded.min_ms)
                        END,
                        max_ms = CASE
                            WHEN accounts_ping_rollups.max_ms IS NULL THEN excluded.max_ms
                            WHEN excluded.max_ms IS NULL THEN accounts_ping_rollups.max_ms
                            ELSE GREATEST(accounts_ping_rollups.max_ms, excluded.max_ms)
                        END,
                        max_avg_ms = CASE
                            WHEN accounts_ping_rollups.max_avg_ms IS NULL THEN excluded.max_avg_ms
                            WHEN excluded.max_avg_ms IS NULL THEN accounts_ping_rollups.max_avg_ms
                            ELSE GREATEST(accounts_ping_rollups.max_avg_ms, excluded.max_avg_ms)
                        END
                    """,
                    (
                        bucket_ts,
                        account_id,
                        ip,
                        ok_count,
                        avg_sum,
                        avg_count,
                        loss_sum,
                        loss_count,
                        min_ms,
                        max_ms,
                        avg_ms,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO accounts_ping_rollups (
                        bucket_ts, account_id, ip, sample_count, ok_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket_ts, account_id) DO UPDATE SET
                        sample_count = sample_count + 1,
                        ok_count = ok_count + excluded.ok_count,
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
                        account_id,
                        ip,
                        ok_count,
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


def delete_accounts_ping_raw_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM accounts_ping_results WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def delete_accounts_ping_rollups_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM accounts_ping_rollups WHERE bucket_ts < ?", (cutoff_iso,))
    finally:
        conn.close()


def get_accounts_ping_series(account_id, since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, ip, loss, min_ms, avg_ms, max_ms, ok, mode
            FROM accounts_ping_results
            WHERE account_id = ? AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (account_id, since_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_series_range(account_id, since_iso, until_iso):
    if not account_id:
        return []
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, ip, loss, min_ms, avg_ms, max_ms, ok, mode
            FROM accounts_ping_results
            WHERE account_id = ? AND timestamp >= ? AND timestamp < ?
            ORDER BY timestamp ASC
            """,
            (account_id, since_iso, until_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_latest_ip_since(account_id, since_iso):
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT ip
            FROM accounts_ping_results
            WHERE account_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (account_id, since_iso),
        ).fetchone()
        return row["ip"] if row and row.get("ip") else ""
    finally:
        conn.close()


def get_accounts_ping_results_since(since_iso, account_ids=None):
    conn = get_conn()
    try:
        params = [since_iso]
        account_clause = ""
        if account_ids:
            placeholders = ",".join("?" for _ in account_ids)
            account_clause = f"AND account_id IN ({placeholders})"
            params.extend(list(account_ids))
        rows = conn.execute(
            f"""
            SELECT timestamp, account_id, ip, ok
            FROM accounts_ping_results
            WHERE timestamp >= ? {account_clause}
            ORDER BY timestamp ASC
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_rollups_since(since_iso, account_ids=None):
    conn = get_conn()
    try:
        params = [since_iso]
        account_clause = ""
        if account_ids:
            if _use_postgres():
                rows = conn.execute(
                    """
                    SELECT bucket_ts, account_id, ip, sample_count, ok_count
                    FROM accounts_ping_rollups
                    WHERE bucket_ts >= ? AND account_id = ANY(?)
                    ORDER BY bucket_ts ASC
                    """,
                    (since_iso, list(account_ids)),
                ).fetchall()
                return [dict(row) for row in rows]
            placeholders = ",".join("?" for _ in account_ids)
            account_clause = f"AND account_id IN ({placeholders})"
            params.extend(list(account_ids))
        rows = conn.execute(
            f"""
            SELECT bucket_ts, account_id, ip, sample_count, ok_count
            FROM accounts_ping_rollups
            WHERE bucket_ts >= ? {account_clause}
            ORDER BY bucket_ts ASC
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_rollups_range(account_id, since_iso, until_iso):
    if not account_id:
        return []
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT bucket_ts, account_id, ip, sample_count, ok_count, avg_sum, avg_count, loss_sum, loss_count, min_ms, max_ms, max_avg_ms
            FROM accounts_ping_rollups
            WHERE account_id = ? AND bucket_ts >= ? AND bucket_ts < ?
            ORDER BY bucket_ts ASC
            """,
            (account_id, since_iso, until_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_accounts_ping_downtime_minutes_map(account_ids, since_iso, until_iso):
    """
    Returns a map of account_id -> downtime_minutes within the given window.

    Downtime minutes are counted from minute rollups where Loss% is 100%.
    (loss_pct = loss_sum / loss_count >= 99.999)
    """
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            SELECT
                account_id,
                SUM(CASE
                    WHEN loss_count > 0 AND (loss_sum / loss_count) >= 99.999 THEN 1
                    ELSE 0
                END) AS downtime_minutes
            FROM accounts_ping_rollups
            WHERE bucket_ts >= ? AND bucket_ts < ? AND account_id IN ({placeholders})
            GROUP BY account_id
            """,
            tuple([since_iso, until_iso] + list(account_ids)),
        ).fetchall()
        out = {}
        for row in rows or []:
            d = dict(row) if not isinstance(row, dict) else row
            aid = (d.get("account_id") or "").strip()
            if not aid:
                continue
            try:
                out[aid] = int(d.get("downtime_minutes") or 0)
            except Exception:
                out[aid] = 0
        return out
    finally:
        conn.close()


def get_accounts_ping_down_events_map(account_ids, since_iso, until_iso):
    """
    Returns a map of account_id -> down_events within the given window.

    A down event is counted at the start of a contiguous down streak:
    - current minute bucket has Loss% = 100% (>= 99.999)
    - previous minute bucket was not 100% (or does not exist)
    """
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            WITH w AS (
              SELECT
                account_id,
                bucket_ts,
                CASE
                  WHEN loss_count > 0 AND (loss_sum / loss_count) >= 99.999 THEN 1
                  ELSE 0
                END AS is_down,
                LAG(
                  CASE
                    WHEN loss_count > 0 AND (loss_sum / loss_count) >= 99.999 THEN 1
                    ELSE 0
                  END
                ) OVER (PARTITION BY account_id ORDER BY bucket_ts) AS prev_down
              FROM accounts_ping_rollups
              WHERE bucket_ts >= ? AND bucket_ts < ? AND account_id IN ({placeholders})
            )
            SELECT
              account_id,
              SUM(CASE WHEN is_down = 1 AND COALESCE(prev_down, 0) = 0 THEN 1 ELSE 0 END) AS down_events
            FROM w
            GROUP BY account_id
            """,
            tuple([since_iso, until_iso] + list(account_ids)),
        ).fetchall()
        out = {}
        for row in rows or []:
            d = dict(row) if not isinstance(row, dict) else row
            aid = (d.get("account_id") or "").strip()
            if not aid:
                continue
            try:
                out[aid] = int(d.get("down_events") or 0)
            except Exception:
                out[aid] = 0
        return out
    finally:
        conn.close()


def get_latest_accounts_ping_map(account_ids):
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            placeholders = ",".join("?" for _ in account_ids)
            rows = conn.execute(
                f"""
                SELECT DISTINCT ON (account_id)
                    account_id, timestamp, name, ip, loss, min_ms, avg_ms, max_ms, mode, ok
                FROM accounts_ping_results
                WHERE account_id IN ({placeholders})
                ORDER BY account_id, timestamp DESC
                """,
                list(account_ids),
            ).fetchall()
            return {row["account_id"]: dict(row) for row in rows}

        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            SELECT r.*
            FROM accounts_ping_results r
            JOIN (
                SELECT account_id, MAX(timestamp) AS max_ts
                FROM accounts_ping_results
                WHERE account_id IN ({placeholders})
                GROUP BY account_id
            ) latest
              ON r.account_id = latest.account_id AND r.timestamp = latest.max_ts
            """,
            list(account_ids),
        ).fetchall()
        return {row["account_id"]: dict(row) for row in rows}
    finally:
        conn.close()


def has_surveillance_session(pppoe: str) -> bool:
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return False
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT 1 AS ok FROM surveillance_sessions WHERE pppoe = ? LIMIT 1",
            (pppoe,),
        ).fetchone()
        if isinstance(row, dict):
            return bool(row.get("ok"))
        return bool(row)
    finally:
        conn.close()


def get_accounts_ping_window_stats(account_ids, since_iso):
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT
                  account_id,
                  SUM(sample_count) AS total,
                  SUM(sample_count - ok_count) AS failures,
                  CASE
                    WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                    ELSE NULL
                  END AS loss_avg,
                  CASE
                    WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                    ELSE NULL
                  END AS avg_ms_avg
                FROM accounts_ping_rollups
                WHERE bucket_ts >= ? AND account_id = ANY(?)
                GROUP BY account_id
                """,
                (since_iso, list(account_ids)),
            ).fetchall()
            return {row["account_id"]: dict(row) for row in rows}

        placeholders = ",".join("?" for _ in account_ids)
        rows = conn.execute(
            f"""
            SELECT
              account_id,
              SUM(sample_count) AS total,
              SUM(sample_count - ok_count) AS failures,
              CASE
                WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                ELSE NULL
              END AS loss_avg,
              CASE
                WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                ELSE NULL
              END AS avg_ms_avg
            FROM accounts_ping_rollups
            WHERE bucket_ts >= ? AND account_id IN ({placeholders})
            GROUP BY account_id
            """,
            [since_iso] + list(account_ids),
        ).fetchall()
        return {row["account_id"]: dict(row) for row in rows}
    finally:
        conn.close()


def get_accounts_ping_window_stats_by_ip(account_ids, since_iso):
    if not account_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT
                  account_id,
                  ip,
                  SUM(sample_count) AS total,
                  SUM(sample_count - ok_count) AS failures,
                  CASE
                    WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                    ELSE NULL
                  END AS loss_avg,
                  CASE
                    WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                    ELSE NULL
                  END AS avg_ms_avg
                FROM accounts_ping_rollups
                WHERE bucket_ts >= ? AND account_id = ANY(?)
                GROUP BY account_id, ip
                """,
                (since_iso, list(account_ids)),
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in account_ids)
            rows = conn.execute(
                f"""
                SELECT
                  account_id,
                  ip,
                  SUM(sample_count) AS total,
                  SUM(sample_count - ok_count) AS failures,
                  CASE
                    WHEN SUM(loss_count) > 0 THEN SUM(loss_sum) / SUM(loss_count)
                    ELSE NULL
                  END AS loss_avg,
                  CASE
                    WHEN SUM(avg_count) > 0 THEN SUM(avg_sum) / SUM(avg_count)
                    ELSE NULL
                  END AS avg_ms_avg
                FROM accounts_ping_rollups
                WHERE bucket_ts >= ? AND account_id IN ({placeholders})
                GROUP BY account_id, ip
                """,
                [since_iso] + list(account_ids),
            ).fetchall()
        out = {}
        for row in rows:
            acct = row["account_id"]
            ip = row["ip"]
            out.setdefault(acct, {})[ip] = dict(row)
        return out
    finally:
        conn.close()


def get_optical_latest_results_since(since_iso):
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT DISTINCT ON (device_id)
                  timestamp, device_id, pppoe, ip, rx, tx, priority
                FROM optical_results
                WHERE timestamp >= ?
                ORDER BY device_id, timestamp DESC
                """,
                (since_iso,),
            ).fetchall()
            return [dict(row) for row in rows]

        rows = conn.execute(
            """
            SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
            FROM optical_results o
            JOIN (
              SELECT device_id, MAX(timestamp) AS max_ts
              FROM optical_results
              WHERE timestamp >= ?
              GROUP BY device_id
            ) latest
              ON o.device_id = latest.device_id AND o.timestamp = latest.max_ts
            """,
            (since_iso,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_optical_samples_for_devices_since(device_ids, since_iso):
    if not device_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT device_id, COUNT(*) AS samples
                FROM optical_results
                WHERE timestamp >= ? AND device_id = ANY(?)
                GROUP BY device_id
                """,
                (since_iso, list(device_ids)),
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in device_ids)
            rows = conn.execute(
                f"""
                SELECT device_id, COUNT(*) AS samples
                FROM optical_results
                WHERE timestamp >= ? AND device_id IN ({placeholders})
                GROUP BY device_id
                """,
                [since_iso] + list(device_ids),
            ).fetchall()
        return {row["device_id"]: int(row["samples"] or 0) for row in rows}
    finally:
        conn.close()


def get_optical_rx_series_for_devices_since(device_ids, since_iso):
    if not device_ids:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            rows = conn.execute(
                """
                SELECT device_id, rx
                FROM optical_results
                WHERE timestamp >= ? AND device_id = ANY(?)
                ORDER BY device_id ASC, timestamp ASC
                """,
                (since_iso, list(device_ids)),
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in device_ids)
            rows = conn.execute(
                f"""
                SELECT device_id, rx
                FROM optical_results
                WHERE timestamp >= ? AND device_id IN ({placeholders})
                ORDER BY device_id ASC, timestamp ASC
                """,
                [since_iso] + list(device_ids),
            ).fetchall()
        out = {}
        for row in rows:
            if not isinstance(row, dict):
                row = dict(row)
            dev = row.get("device_id")
            if not dev:
                continue
            rx = row.get("rx")
            if rx is None:
                continue
            out.setdefault(dev, []).append(rx)
        return out
    finally:
        conn.close()


def insert_wan_history_row(
    wan_id,
    status,
    timestamp=None,
    target=None,
    core_id=None,
    label=None,
    up_pct=None,
    retention_days=400,
):
    stamp = timestamp or utc_now_iso()
    cutoff = (datetime.utcnow() - timedelta(days=max(int(retention_days or 1), 1))).replace(microsecond=0).isoformat() + "Z"
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO wan_status_history (timestamp, wan_id, status, up_pct, target, core_id, label)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (stamp, wan_id, status, up_pct, target, core_id, label),
            )
            conn.execute(
                """
                DELETE FROM wan_status_history
                WHERE timestamp < ?
                """
                ,
                (cutoff,),
            )
    finally:
        conn.close()


def fetch_wan_history_map(wan_ids, start_iso, end_iso):
    if not wan_ids:
        return {}
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in wan_ids)
        params = [start_iso, end_iso] + list(wan_ids)
        rows = conn.execute(
            f"""
            SELECT wan_id, timestamp, status
            FROM wan_status_history
            WHERE timestamp BETWEEN ? AND ?
              AND wan_id IN ({placeholders})
            ORDER BY timestamp ASC
            """,
            params,
        ).fetchall()
        history = {}
        for row in rows:
            history.setdefault(row["wan_id"], []).append(
                {"ts": row["timestamp"], "status": row["status"]}
            )
        return history
    finally:
        conn.close()


def clear_wan_history():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM wan_status_history")
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


def insert_rto_result(ip, name, ok, timestamp=None):
    stamp = timestamp or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO rto_results (timestamp, ip, name, ok)
                VALUES (?, ?, ?, ?)
                """,
                (stamp, ip, name, 1 if ok else 0),
            )
    finally:
        conn.close()


def insert_optical_result(device_id, pppoe, ip, rx, tx, priority, timestamp=None):
    stamp = timestamp or utc_now_iso()
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO optical_results (timestamp, device_id, pppoe, ip, rx, tx, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stamp,
                    device_id,
                    pppoe,
                    ip,
                    rx,
                    tx,
                    1 if priority else 0,
                ),
            )
    finally:
        conn.close()


def delete_rto_results_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM rto_results WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def delete_optical_results_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM optical_results WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def clear_rto_results():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM rto_results")
    finally:
        conn.close()


def clear_optical_results():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM optical_results")
    finally:
        conn.close()


def insert_pppoe_usage_sample(
    timestamp,
    router_id,
    router_name,
    pppoe,
    address=None,
    session_id=None,
    uptime=None,
    bytes_in=None,
    bytes_out=None,
    host_count=None,
    rx_bps=None,
    tx_bps=None,
):
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO pppoe_usage_samples
                    (timestamp, router_id, router_name, pppoe, address, session_id, uptime, bytes_in, bytes_out, host_count, rx_bps, tx_bps)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    router_id,
                    router_name,
                    pppoe,
                    address,
                    session_id,
                    uptime,
                    bytes_in,
                    bytes_out,
                    host_count,
                    rx_bps,
                    tx_bps,
                ),
            )
    finally:
        conn.close()


def delete_pppoe_usage_samples_older_than(cutoff_iso):
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM pppoe_usage_samples WHERE timestamp < ?", (cutoff_iso,))
    finally:
        conn.close()


def clear_pppoe_usage_samples():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM pppoe_usage_samples")
    finally:
        conn.close()


def get_pppoe_usage_window_stats_since(since_iso):
    """
    Returns a dict keyed by "<router_id>|<pppoe_lower>" with:
      - samples
      - max_total_bps (max(rx_bps + tx_bps) in window)
      - first_ts, last_ts
    """
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                router_id,
                pppoe,
                COUNT(*) AS samples,
                MAX(COALESCE(rx_bps, 0) + COALESCE(tx_bps, 0)) AS max_total_bps,
                MIN(timestamp) AS first_ts,
                MAX(timestamp) AS last_ts
            FROM pppoe_usage_samples
            WHERE timestamp >= ?
            GROUP BY router_id, pppoe
            """,
            (since_iso,),
        ).fetchall()
        out = {}
        for row in rows:
            router_id = (row["router_id"] or "").strip()
            pppoe = (row["pppoe"] or "").strip()
            if not pppoe:
                continue
            key = f"{router_id}|{pppoe.lower()}"
            out[key] = {
                "router_id": router_id,
                "pppoe": pppoe,
                "samples": int(row["samples"] or 0),
                "max_total_bps": float(row["max_total_bps"] or 0.0),
                "first_ts": row["first_ts"],
                "last_ts": row["last_ts"],
            }
        return out
    finally:
        conn.close()


def get_pppoe_usage_series_since(router_id, pppoe, since_iso):
    router_id = (router_id or "").strip()
    pppoe = (pppoe or "").strip()
    if not pppoe:
        return []
    conn = get_conn()
    try:
        if router_id:
            rows = conn.execute(
                """
                SELECT timestamp, rx_bps, tx_bps, bytes_in, bytes_out, host_count
                FROM pppoe_usage_samples
                WHERE router_id = ? AND pppoe = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (router_id, pppoe, since_iso),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT timestamp, rx_bps, tx_bps, bytes_in, bytes_out, host_count
                FROM pppoe_usage_samples
                WHERE pppoe = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (pppoe, since_iso),
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_rto_results_since(since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT timestamp, ip, name, ok FROM rto_results WHERE timestamp >= ? ORDER BY timestamp ASC",
            (since_iso,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_optical_results_since(since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, device_id, pppoe, ip, rx, tx, priority
            FROM optical_results
            WHERE timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (since_iso,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_rto_results_for_ip_since(ip, since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT timestamp, ok FROM rto_results WHERE ip = ? AND timestamp >= ? ORDER BY timestamp ASC",
            (ip, since_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_optical_results_for_device_since(device_id, since_iso):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, rx, tx
            FROM optical_results
            WHERE device_id = ? AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (device_id, since_iso),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_latest_optical_identity(device_id):
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT timestamp, device_id, pppoe, ip, rx, tx, priority
            FROM optical_results
            WHERE device_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_latest_optical_device_for_ip(ip):
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT device_id
            FROM optical_results
            WHERE ip = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()
        return row["device_id"] if row else None
    finally:
        conn.close()


def get_latest_optical_by_pppoe(pppoe_list):
    pppoe_list = [str(item).strip() for item in (pppoe_list or []) if str(item).strip()]
    if not pppoe_list:
        return {}
    conn = get_conn()
    try:
        if _use_postgres():
            placeholders = ",".join("?" for _ in pppoe_list)
            rows = conn.execute(
                f"""
                SELECT DISTINCT ON (pppoe)
                    timestamp, device_id, pppoe, ip, rx, tx, priority
                FROM optical_results
                WHERE pppoe IN ({placeholders})
                ORDER BY pppoe, timestamp DESC
                """,
                list(pppoe_list),
            ).fetchall()
            return {row["pppoe"]: dict(row) for row in rows if row.get("pppoe")}

        placeholders = ",".join("?" for _ in pppoe_list)
        rows = conn.execute(
            f"""
            SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
            FROM optical_results o
            JOIN (
                SELECT pppoe, MAX(timestamp) AS max_ts
                FROM optical_results
                WHERE pppoe IN ({placeholders})
                GROUP BY pppoe
            ) latest
            ON o.pppoe = latest.pppoe AND o.timestamp = latest.max_ts
            """,
            list(pppoe_list),
        ).fetchall()
        return {row["pppoe"]: dict(row) for row in rows if row.get("pppoe")}
    finally:
        conn.close()


def search_optical_customers(query, since_iso, limit=20):
    raw = (query or "").strip()
    if not raw:
        return []
    pattern = f"%{raw}%"
    limit = max(int(limit or 20), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
            FROM optical_results o
            JOIN (
                SELECT device_id, MAX(timestamp) AS max_ts
                FROM optical_results
                WHERE timestamp >= ?
                GROUP BY device_id
            ) latest
            ON o.device_id = latest.device_id AND o.timestamp = latest.max_ts
            WHERE o.timestamp >= ?
              AND (
                o.pppoe LIKE ?
                OR o.ip LIKE ?
                OR o.device_id LIKE ?
              )
            ORDER BY o.timestamp DESC
            LIMIT ?
            """,
            (since_iso, since_iso, pattern, pattern, pattern, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_latest_rto_identity(ip):
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT timestamp, ip, name, ok
            FROM rto_results
            WHERE ip = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_recent_rto_results(ip, since_iso, limit=50):
    limit = max(int(limit or 50), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, ok
            FROM rto_results
            WHERE ip = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (ip, since_iso, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_recent_optical_readings(device_id, since_iso, limit=50):
    limit = max(int(limit or 50), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT timestamp, rx, tx, priority
            FROM optical_results
            WHERE device_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (device_id, since_iso, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def search_rto_customers(query, since_iso, limit=20):
    raw = (query or "").strip()
    if not raw:
        return []
    pattern = f"%{raw}%"
    limit = max(int(limit or 20), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT r.timestamp, r.ip, r.name, r.ok
            FROM rto_results r
            JOIN (
                SELECT ip, MAX(timestamp) AS max_ts
                FROM rto_results
                WHERE timestamp >= ?
                GROUP BY ip
            ) latest
            ON r.ip = latest.ip AND r.timestamp = latest.max_ts
            WHERE r.timestamp >= ?
              AND (
                r.name LIKE ?
                OR r.ip LIKE ?
              )
            ORDER BY r.timestamp DESC
            LIMIT ?
            """,
            (since_iso, since_iso, pattern, pattern, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_rto_worst_summary(since_iso, limit=10):
    limit = max(int(limit or 10), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            WITH agg AS (
                SELECT ip,
                       COUNT(*) AS total,
                       SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END) AS failures,
                       MAX(timestamp) AS last_ts
                FROM rto_results
                WHERE timestamp >= ?
                GROUP BY ip
            )
            SELECT a.ip,
                   r.name,
                   a.total,
                   a.failures,
                   CASE WHEN a.total > 0 THEN (a.failures * 100.0 / a.total) ELSE 0.0 END AS rto_pct,
                   a.last_ts AS timestamp,
                   r.ok AS last_ok
            FROM agg a
            JOIN rto_results r
              ON r.ip = a.ip AND r.timestamp = a.last_ts
            ORDER BY rto_pct DESC, a.failures DESC, a.total DESC, a.last_ts DESC
            LIMIT ?
            """,
            (since_iso, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_optical_worst_candidates(since_iso, limit=200):
    limit = max(int(limit or 200), 1)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT o.timestamp, o.device_id, o.pppoe, o.ip, o.rx, o.tx, o.priority
            FROM optical_results o
            JOIN (
                SELECT device_id, MAX(timestamp) AS max_ts
                FROM optical_results
                WHERE timestamp >= ?
                GROUP BY device_id
            ) latest
            ON o.device_id = latest.device_id AND o.timestamp = latest.max_ts
            WHERE o.timestamp >= ?
            ORDER BY (o.rx IS NULL) DESC,
                     (o.tx IS NULL) DESC,
                     o.rx ASC,
                     o.timestamp DESC
            LIMIT ?
            """,
            (since_iso, since_iso, limit),
        ).fetchall()
        return [dict(row) for row in rows]
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


def get_ping_rollup_history_map(isp_ids, since_iso, target=None):
    if not isp_ids:
        return {}
    conn = get_conn()
    try:
        history = {}
        for isp_id in isp_ids:
            params = [isp_id, since_iso]
            target_clause = ""
            if target:
                target_clause = "AND target = ?"
                params.append(target)
            rows = conn.execute(
                f"""
                SELECT
                  bucket_ts AS timestamp,
                  target,
                  CASE WHEN avg_count > 0 THEN (avg_sum / avg_count) ELSE NULL END AS avg_ms,
                  CASE WHEN loss_count > 0 THEN (loss_sum / loss_count) ELSE NULL END AS loss
                FROM ping_rollups
                WHERE isp_id = ? AND bucket_ts >= ? {target_clause}
                ORDER BY bucket_ts ASC
                """,
                params,
            ).fetchall()
            history[isp_id] = [dict(row) for row in rows]
        return history
    finally:
        conn.close()


def get_ping_stability_counts(isp_ids, since_iso, stable_max_ms=80, unstable_max_ms=150):
    if not isp_ids:
        return {}
    stable_max_ms = int(stable_max_ms)
    unstable_max_ms = int(unstable_max_ms)
    placeholders = ",".join("?" for _ in isp_ids)
    params = [stable_max_ms, stable_max_ms + 1, unstable_max_ms, unstable_max_ms] + list(isp_ids) + [since_iso]
    conn = get_conn()
    try:
        rows = conn.execute(
            f"""
            SELECT
              isp_id,
              SUM(CASE WHEN loss >= 100 OR avg_ms IS NULL THEN 1 ELSE 0 END) AS outage,
              SUM(CASE WHEN loss < 100 AND avg_ms IS NOT NULL AND avg_ms <= ? THEN 1 ELSE 0 END) AS healthy,
              SUM(CASE WHEN loss < 100 AND avg_ms IS NOT NULL AND avg_ms BETWEEN ? AND ? THEN 1 ELSE 0 END) AS degraded,
              SUM(CASE WHEN loss < 100 AND avg_ms IS NOT NULL AND avg_ms > ? THEN 1 ELSE 0 END) AS poor,
              COUNT(*) AS total
            FROM ping_results
            WHERE isp_id IN ({placeholders}) AND timestamp >= ?
            GROUP BY isp_id
            """,
            params,
        ).fetchall()
        return {row["isp_id"]: dict(row) for row in rows}
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


def clear_accounts_ping_data():
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM accounts_ping_results")
            conn.execute("DELETE FROM accounts_ping_rollups")
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

            if _use_postgres():
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
                            to_char(date_trunc('minute', (timestamp::timestamptz AT TIME ZONE 'UTC')),
                                    'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS bucket_ts,
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
            else:
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
