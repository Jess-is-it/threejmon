import argparse
import os
import sqlite3
import sys
import time

import psycopg2
from psycopg2.extras import execute_values

from .db import init_db


TABLE_SPECS = [
    ("settings", ["key", "value"], None),
    ("state", ["key", "value"], None),
    ("job_status", ["job_name", "last_run_at", "last_success_at", "last_error", "last_error_at"], None),
    ("ping_results", ["id", "timestamp", "isp_id", "target", "loss", "min_ms", "avg_ms", "max_ms", "raw_output"], "id"),
    ("ping_rollups", ["bucket_ts", "isp_id", "target", "sample_count", "avg_sum", "avg_count", "loss_sum", "loss_count", "min_ms", "max_ms", "max_avg_ms"], None),
    ("speedtest_results", ["id", "timestamp", "isp_id", "download_mbps", "upload_mbps", "latency_ms", "server_name", "server_id", "public_ip", "raw_output"], "id"),
    ("alerts_log", ["id", "timestamp", "isp_id", "alert_type", "message", "cooldown_until"], "id"),
    ("rto_results", ["id", "timestamp", "ip", "name", "ok"], "id"),
    ("optical_results", ["id", "timestamp", "device_id", "pppoe", "ip", "rx", "tx", "priority"], "id"),
    ("wan_status_history", ["id", "timestamp", "wan_id", "status", "up_pct", "target", "core_id", "label"], "id"),
]


def _env(name, default=""):
    return (os.environ.get(name) or default or "").strip()


def _connect_sqlite(path):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def _connect_postgres(dsn):
    con = psycopg2.connect(dsn)
    con.autocommit = False
    return con


def _pg_truncate_all(pg_con):
    with pg_con.cursor() as cur:
        cur.execute(
            """
            TRUNCATE TABLE
              settings,
              state,
              job_status,
              ping_results,
              ping_rollups,
              speedtest_results,
              alerts_log,
              rto_results,
              optical_results,
              wan_status_history
            RESTART IDENTITY
            """
        )
    pg_con.commit()


def _count_sqlite(sqlite_con, table):
    cur = sqlite_con.execute(f"SELECT COUNT(1) AS n FROM {table}")
    row = cur.fetchone()
    return int(row["n"] or 0)


def _copy_table(sqlite_con, pg_con, table, cols, id_col=None, batch_size=5000, verbose=False):
    col_sql = ", ".join(cols)
    placeholders = "(" + ", ".join(["%s"] * len(cols)) + ")"
    insert_sql = f"INSERT INTO {table} ({col_sql}) VALUES %s"

    total_src = _count_sqlite(sqlite_con, table)
    if verbose:
        print(f"[{table}] source rows: {total_src}")

    scur = sqlite_con.execute(f"SELECT {col_sql} FROM {table}")
    inserted = 0
    last_print = 0
    t0 = time.time()

    with pg_con.cursor() as pcur:
        # Faster for large imports.
        pcur.execute("SET LOCAL synchronous_commit TO OFF")
        while True:
            rows = scur.fetchmany(batch_size)
            if not rows:
                break
            values = [tuple(row[c] for c in cols) for row in rows]
            execute_values(pcur, insert_sql, values, page_size=batch_size, template=placeholders)
            inserted += len(values)
            if verbose:
                now = time.time()
                if (inserted - last_print) >= batch_size * 10 or (now - t0) > 3:
                    last_print = inserted
                    pct = (inserted / total_src * 100.0) if total_src else 100.0
                    print(f"[{table}] {inserted}/{total_src} ({pct:.1f}%)")

    pg_con.commit()

    if id_col:
        with pg_con.cursor() as cur:
            cur.execute(f"SELECT COALESCE(MAX({id_col}), 0) FROM {table}")
            max_id = int(cur.fetchone()[0] or 0)
            cur.execute(
                "SELECT setval(pg_get_serial_sequence(%s, %s), %s, %s)",
                (table, id_col, max_id, True),
            )
        pg_con.commit()

    if verbose:
        dt = time.time() - t0
        rate = int(inserted / dt) if dt > 0 else inserted
        print(f"[{table}] done: {inserted} rows in {dt:.1f}s ({rate}/s)")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Migrate ThreeJ Notifier data from SQLite to Postgres.")
    parser.add_argument("--sqlite-path", default=_env("THREEJ_DB_PATH", "/data/threejnotif.db"))
    parser.add_argument("--postgres-dsn", default=_env("THREEJ_DATABASE_URL", ""))
    parser.add_argument("--batch-size", type=int, default=int(_env("THREEJ_MIGRATE_BATCH", "5000") or 5000))
    parser.add_argument("--no-truncate", action="store_true", help="Do not truncate Postgres tables before import.")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if not args.postgres_dsn:
        print("ERROR: THREEJ_DATABASE_URL is not set.", file=sys.stderr)
        return 2
    if not os.path.exists(args.sqlite_path):
        print(f"ERROR: SQLite db not found at {args.sqlite_path}", file=sys.stderr)
        return 2

    # Ensure Postgres schema exists (uses app/db.py init_db()).
    init_db()

    sqlite_con = _connect_sqlite(args.sqlite_path)
    pg_con = _connect_postgres(args.postgres_dsn)
    try:
        if not args.no_truncate:
            _pg_truncate_all(pg_con)
        for table, cols, id_col in TABLE_SPECS:
            _copy_table(
                sqlite_con,
                pg_con,
                table,
                cols,
                id_col=id_col,
                batch_size=max(args.batch_size, 100),
                verbose=args.verbose,
            )
    finally:
        try:
            sqlite_con.close()
        except Exception:
            pass
        try:
            pg_con.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

