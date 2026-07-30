import asyncio
import unittest
from pathlib import Path
from unittest import mock

from app import jobs, main


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "app" / "templates" / "settings_isp_status.html"


def _samples(points):
    return [
        {"ts": timestamp, "peak_mbps": peak_mbps}
        for timestamp, peak_mbps in points
    ]


class IspStatusCapacityTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {
            "hundred_mbps_min": 90.0,
            "hundred_mbps_max": 105.0,
            "window_minutes": 10,
            "poll_interval_seconds": 10,
            "average_detection_enabled": False,
            "average_window_hours": 4,
            "non_peak_exclusion_enabled": False,
            "non_peak_start_time": "00:00",
            "non_peak_end_time": "06:00",
        }

    def test_sustained_in_range_window_is_100m(self):
        status, reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T02:00:00Z", 94.0),
                    ("2026-07-29T02:05:00Z", 98.0),
                    ("2026-07-29T02:10:00Z", 101.0),
                ]
            ),
            self.cfg,
        )

        self.assertEqual(status, "100m")
        self.assertIn("stayed within", reason)

    def test_single_in_range_spike_does_not_make_low_window_100m(self):
        status, reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T02:00:00Z", 95.0),
                    ("2026-07-29T02:05:00Z", 30.0),
                    ("2026-07-29T02:10:00Z", 25.0),
                ]
            ),
            self.cfg,
        )

        self.assertEqual(status, "observing")
        self.assertIn("below the 90.0 Mbps evidence floor", reason)

    def test_partial_in_range_window_waits_for_configured_duration(self):
        status, reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T02:00:00Z", 95.0),
                    ("2026-07-29T02:03:30Z", 98.0),
                    ("2026-07-29T02:07:00Z", 101.0),
                ]
            ),
            self.cfg,
        )

        self.assertEqual(status, "observing")
        self.assertIn("waiting for a full 10m window", reason)

    def test_average_rule_cannot_tag_100m_when_latest_is_below_floor(self):
        cfg = {
            **self.cfg,
            "average_detection_enabled": True,
            "average_window_hours": 1,
        }
        points = [
            (f"2026-07-29T02:{minute:02d}:00Z", 100.0)
            for minute in range(0, 60, 5)
        ]
        points.append(("2026-07-29T03:00:00Z", 20.0))

        status, reason = jobs._classify_isp_capacity(_samples(points), cfg)

        self.assertEqual(status, "observing")
        self.assertIn("below the 90.0 Mbps evidence floor", reason)

    def test_average_rule_cannot_override_a_recent_below_floor_reading(self):
        cfg = {
            **self.cfg,
            "average_detection_enabled": True,
            "average_window_hours": 1,
        }
        points = [
            (f"2026-07-29T02:{minute:02d}:00Z", 100.0)
            for minute in range(0, 55, 5)
        ]
        points.extend(
            [
                ("2026-07-29T02:55:00Z", 20.0),
                ("2026-07-29T03:00:00Z", 95.0),
            ]
        )

        status, reason = jobs._classify_isp_capacity(_samples(points), cfg)

        self.assertEqual(status, "observing")
        self.assertIn("contains readings below", reason)

    def test_above_ceiling_is_1g(self):
        status, reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T02:00:00Z", 98.0),
                    ("2026-07-29T02:05:00Z", 110.0),
                ]
            ),
            self.cfg,
        )

        self.assertEqual(status, "1g")
        self.assertIn("above the 105.0 Mbps", reason)

    def test_overnight_non_peak_window_pauses_100m_tagging(self):
        cfg = {
            **self.cfg,
            "non_peak_exclusion_enabled": True,
            "non_peak_start_time": "22:00",
            "non_peak_end_time": "06:00",
        }
        status, reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T16:50:00Z", 95.0),
                    ("2026-07-29T16:55:00Z", 98.0),
                    ("2026-07-29T17:00:00Z", 100.0),
                ]
            ),
            cfg,
        )

        self.assertEqual(status, "observing")
        self.assertIn("non-peak window", reason)
        self.assertIn("Asia/Manila", reason)

    def test_non_peak_window_does_not_hide_above_ceiling_evidence(self):
        cfg = {
            **self.cfg,
            "non_peak_exclusion_enabled": True,
            "non_peak_start_time": "22:00",
            "non_peak_end_time": "06:00",
        }
        status, _reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T16:55:00Z", 95.0),
                    ("2026-07-29T17:00:00Z", 110.0),
                ]
            ),
            cfg,
        )

        self.assertEqual(status, "1g")

    def test_daytime_samples_still_classify_when_exclusion_is_enabled(self):
        cfg = {
            **self.cfg,
            "non_peak_exclusion_enabled": True,
            "non_peak_start_time": "22:00",
            "non_peak_end_time": "06:00",
        }
        status, _reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T04:00:00Z", 95.0),
                    ("2026-07-29T04:05:00Z", 97.0),
                    ("2026-07-29T04:10:00Z", 99.0),
                ]
            ),
            cfg,
        )

        self.assertEqual(status, "100m")

    def test_peak_hour_evidence_restarts_after_non_peak_window(self):
        cfg = {
            **self.cfg,
            "non_peak_exclusion_enabled": True,
            "non_peak_start_time": "22:00",
            "non_peak_end_time": "06:00",
        }
        status, reason = jobs._classify_isp_capacity(
            _samples(
                [
                    ("2026-07-29T13:50:00Z", 95.0),
                    ("2026-07-29T13:55:00Z", 98.0),
                    ("2026-07-29T14:00:00Z", 99.0),
                    ("2026-07-29T21:55:00Z", 97.0),
                    ("2026-07-29T22:00:00Z", 96.0),
                    ("2026-07-29T22:05:00Z", 95.0),
                ]
            ),
            cfg,
        )

        self.assertEqual(status, "observing")
        self.assertIn("waiting for a full 10m window", reason)

    def test_settings_normalize_non_peak_controls(self):
        settings = main.normalize_isp_status_settings(
            {
                "capacity": {
                    "non_peak_exclusion_enabled": True,
                    "non_peak_start_time": "7:05",
                    "non_peak_end_time": "25:90",
                }
            }
        )

        self.assertTrue(settings["capacity"]["non_peak_exclusion_enabled"])
        self.assertEqual(settings["capacity"]["non_peak_start_time"], "07:05")
        self.assertEqual(settings["capacity"]["non_peak_end_time"], "06:00")

    def test_capacity_form_saves_non_peak_controls(self):
        class FakeRequest:
            async def form(self):
                return {
                    "settings_tab": "capacity",
                    "hundred_mbps_min": "90",
                    "hundred_mbps_max": "105",
                    "window_minutes": "15",
                    "average_detection_enabled": "on",
                    "average_window_hours": "10",
                    "non_peak_exclusion_enabled": "on",
                    "non_peak_start_time": "23:00",
                    "non_peak_end_time": "05:30",
                }

        with (
            mock.patch.object(main, "get_settings", return_value={}),
            mock.patch.object(main, "save_settings") as save_settings,
            mock.patch.object(main, "_render_isp_status_response", return_value="saved"),
        ):
            response = asyncio.run(main.isp_status_settings_save(FakeRequest()))

        self.assertEqual(response, "saved")
        saved = save_settings.call_args.args[1]
        self.assertTrue(saved["capacity"]["non_peak_exclusion_enabled"])
        self.assertEqual(saved["capacity"]["non_peak_start_time"], "23:00")
        self.assertEqual(saved["capacity"]["non_peak_end_time"], "05:30")

    def test_capacity_settings_explain_evidence_floor_and_schedule(self):
        source = TEMPLATE_PATH.read_text(encoding="utf-8")

        self.assertIn("low utilization cannot determine", source.lower())
        self.assertIn('name="non_peak_exclusion_enabled"', source)
        self.assertIn('name="non_peak_start_time"', source)
        self.assertIn('name="non_peak_end_time"', source)
        self.assertIn("Asia/Manila", source)


if __name__ == "__main__":
    unittest.main()
