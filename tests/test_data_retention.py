import tempfile
import unittest
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from app import db
from app import data_retention


class DataRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db.DB_URL = ""
        db.DB_PATH = str(Path(self.temp_dir.name) / "retention.db")
        db.init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scheduled_delete_is_counted_and_tracked(self):
        conn = db.get_conn()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO auth_audit_logs
                        (timestamp, user_id, username, action, resource, details, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("2020-01-01T00:00:00Z", None, "tester", "test.event", "/test", "", ""),
                )
        finally:
            conn.close()

        DiskUsage = namedtuple("DiskUsage", "total used free")
        with mock.patch.object(
            db.shutil,
            "disk_usage",
            side_effect=(DiskUsage(1000, 810, 190), DiskUsage(1000, 790, 210)),
        ):
            deleted = db.delete_data_retention_dataset_before("auth_audit", "2021-01-01T00:00:00Z")

        self.assertEqual(deleted, 1)
        history = db.list_data_retention_history(limit=25)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["trigger_type"], "scheduled")
        self.assertEqual(history[0]["rows_deleted"], 1)
        self.assertEqual(history[0]["disk_percent_before"], 81.0)
        self.assertEqual(history[0]["disk_percent_after"], 79.0)

    def test_emergency_delete_is_bounded_and_preserves_recent_rows(self):
        conn = db.get_conn()
        try:
            with conn:
                for stamp in (
                    "2020-01-01T00:00:00Z",
                    "2020-01-02T00:00:00Z",
                    "2020-01-03T00:00:00Z",
                    "2030-01-01T00:00:00Z",
                ):
                    conn.execute(
                        """
                        INSERT INTO optical_results (timestamp, device_id, pppoe, ip, rx, tx, priority)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (stamp, stamp, "account", "192.0.2.1", -20.0, -1.0, 0),
                    )
        finally:
            conn.close()

        deleted = db.delete_data_retention_dataset_oldest(
            "optical_results",
            "2025-01-01T00:00:00Z",
            target_rows=2,
        )

        self.assertEqual(deleted, 2)
        conn = db.get_conn()
        try:
            rows = conn.execute("SELECT timestamp FROM optical_results ORDER BY id").fetchall()
        finally:
            conn.close()
        self.assertEqual(
            [row["timestamp"] for row in rows],
            ["2020-01-03T00:00:00Z", "2030-01-01T00:00:00Z"],
        )

    def test_settings_are_clamped_to_safe_ranges(self):
        settings = data_retention.normalize_data_retention_settings(
            {
                "guardian": {
                    "trigger_percent": 100,
                    "recovery_percent": 99,
                    "cooldown_hours": 0,
                    "max_rows_per_dataset": 99_000_000,
                },
                "features": {
                    "usage": {
                        "delete_percent": 90,
                        "min_keep_days": 0,
                        "scheduled_cleanup_interval_days": 999,
                    },
                },
            }
        )
        self.assertEqual(settings["guardian"]["trigger_percent"], 98)
        self.assertEqual(settings["guardian"]["recovery_percent"], 97)
        self.assertEqual(settings["guardian"]["cooldown_hours"], 1)
        self.assertEqual(settings["guardian"]["max_rows_per_dataset"], 1_000_000)
        self.assertEqual(settings["features"]["usage"]["delete_percent"], 50)
        self.assertEqual(settings["features"]["usage"]["min_keep_days"], 1)
        self.assertEqual(settings["features"]["usage"]["scheduled_cleanup_interval_days"], 365)
        self.assertEqual(settings["features"]["optical"]["scheduled_cleanup_interval_days"], 30)

    def test_scheduled_retention_waits_for_batch_interval_then_returns_to_window(self):
        conn = db.get_conn()
        try:
            with conn:
                for stamp in ("2026-01-15T00:00:00Z", "2026-02-02T00:00:00Z"):
                    conn.execute(
                        """
                        INSERT INTO auth_audit_logs
                            (timestamp, user_id, username, action, resource, details, ip_address)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (stamp, None, "tester", "test.event", "/test", "", ""),
                    )
        finally:
            conn.close()

        deleted = db.delete_data_retention_dataset_before(
            "auth_audit",
            "2026-02-01T00:00:00Z",
            scheduled_cleanup_interval_days=30,
        )
        self.assertEqual(deleted, 0)
        self.assertEqual(db.count_data_retention_history(), 0)

        conn = db.get_conn()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO auth_audit_logs
                        (timestamp, user_id, username, action, resource, details, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("2026-01-01T00:00:00Z", None, "tester", "test.event", "/test", "", ""),
                )
        finally:
            conn.close()

        deleted = db.delete_data_retention_dataset_before(
            "auth_audit",
            "2026-02-01T00:00:00Z",
            scheduled_cleanup_interval_days=30,
        )
        self.assertEqual(deleted, 2)
        self.assertEqual(db.count_data_retention_history(), 1)
        conn = db.get_conn()
        try:
            remaining = conn.execute("SELECT timestamp FROM auth_audit_logs ORDER BY timestamp").fetchall()
        finally:
            conn.close()
        self.assertEqual([row["timestamp"] for row in remaining], ["2026-02-02T00:00:00Z"])

    def test_isp_status_insert_uses_batched_scheduled_retention(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)

        def stamp(days_ago):
            return (now - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")

        db._retention_prune_last.clear()
        with mock.patch.dict(db.os.environ, {"THREEJ_ISP_STATUS_PRUNE_INTERVAL_SECONDS": "0"}):
            db.insert_isp_status_sample(
                "wan-1",
                timestamp=stamp(31),
                retention_days=30,
                scheduled_cleanup_interval_days=30,
            )
            db.insert_isp_status_sample(
                "wan-1",
                timestamp=stamp(0),
                retention_days=30,
                scheduled_cleanup_interval_days=30,
            )
            self.assertEqual(db.count_data_retention_history(), 0)

            db.insert_isp_status_sample(
                "wan-1",
                timestamp=stamp(61),
                retention_days=30,
                scheduled_cleanup_interval_days=30,
            )

        history = db.list_data_retention_history(limit=25)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["feature_key"], "isp_status")
        self.assertEqual(history[0]["rows_deleted"], 2)
        conn = db.get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) AS row_count FROM isp_status_samples").fetchone()
        finally:
            conn.close()
        self.assertEqual(int(row["row_count"]), 1)

    def test_guardian_does_not_delete_below_threshold(self):
        DiskUsage = namedtuple("DiskUsage", "total used free")
        with mock.patch.object(data_retention.shutil, "disk_usage", return_value=DiskUsage(1000, 840, 160)):
            result = data_retention.run_data_retention_guardian_cycle()
        self.assertEqual(result["status"], "below_threshold")
        self.assertEqual(db.count_data_retention_history(), 0)

    def test_guardian_runs_once_then_observes_cooldown(self):
        conn = db.get_conn()
        try:
            with conn:
                for index in range(20):
                    conn.execute(
                        """
                        INSERT INTO optical_results (timestamp, device_id, pppoe, ip, rx, tx, priority)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        ("2020-01-01T00:00:00Z", f"device-{index}", "account", "192.0.2.1", -20.0, -1.0, 0),
                    )
        finally:
            conn.close()
        settings = data_retention.get_data_retention_settings()
        for feature in settings["features"].values():
            feature["delete_percent"] = 0
        settings["features"]["optical"]["delete_percent"] = 10
        settings["guardian"]["vacuum_after_cleanup"] = False
        data_retention.save_data_retention_settings(settings)

        DiskUsage = namedtuple("DiskUsage", "total used free")
        with mock.patch.object(data_retention.shutil, "disk_usage", return_value=DiskUsage(1000, 900, 100)):
            first = data_retention.run_data_retention_guardian_cycle()
            second = data_retention.run_data_retention_guardian_cycle()

        self.assertEqual(first["status"], "completed")
        self.assertEqual(first["rows_deleted"], 2)
        self.assertEqual(second["status"], "cooldown")
        history = db.list_data_retention_history(limit=25)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["trigger_type"], "emergency")
        self.assertEqual(history[0]["rows_deleted"], 2)

    def test_central_normal_retention_values_update_feature_settings(self):
        values = data_retention.normal_retention_values()
        values.update(
            {
                "accounts_ping_raw_days": 30,
                "accounts_ping_rollup_days": 90,
                "usage_raw_days": 45,
                "mikrotik_logs_days": 14,
                "auth_audit_days": 365,
            }
        )
        saved = data_retention.save_normal_retention_values(values)
        self.assertEqual(saved["accounts_ping_raw_days"], 30)
        self.assertEqual(saved["accounts_ping_rollup_days"], 90)
        self.assertEqual(saved["usage_raw_days"], 45)
        self.assertEqual(saved["mikrotik_logs_days"], 14)
        self.assertEqual(saved["auth_audit_days"], 365)

    def test_normal_retention_fields_are_mapped_to_each_feature(self):
        values = {
            "accounts_ping_raw_days": 31,
            "accounts_ping_rollup_days": 92,
        }
        fields = data_retention.data_retention_normal_fields_for_feature("accounts_ping", values)

        self.assertEqual(
            fields,
            [
                {"name": "accounts_ping_raw_days", "label": "Raw samples", "value": 31},
                {"name": "accounts_ping_rollup_days", "label": "Minute rollups", "value": 92},
            ],
        )
        with self.assertRaises(ValueError):
            data_retention.data_retention_normal_fields_for_feature("unknown", values)


if __name__ == "__main__":
    unittest.main()
