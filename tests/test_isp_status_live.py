import asyncio
import json
import unittest
from pathlib import Path
from unittest import mock

from app import db
from app import main
from app.mikrotik import RouterOSClient


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "app" / "templates" / "settings_isp_status.html"


class IspStatusLiveTests(unittest.TestCase):
    def test_live_window_is_default_and_bounded(self):
        default_window = main._normalize_isp_status_series_window("", 15)
        self.assertEqual(default_window["key"], "live")
        self.assertEqual(default_window["mode"], "live")
        self.assertEqual(default_window["minutes"], 15)
        self.assertEqual(default_window["bucket_seconds"], 30)

        minimum_window = main._normalize_isp_status_series_window("live", 1)
        maximum_window = main._normalize_isp_status_series_window("live", 500)
        self.assertEqual(minimum_window["minutes"], 5)
        self.assertEqual(maximum_window["minutes"], 60)

    def test_historical_windows_remain_available(self):
        one_hour = main._normalize_isp_status_series_window("1", 15)
        thirty_days = main._normalize_isp_status_series_window("30D", 15)

        self.assertEqual(one_hour["mode"], "history")
        self.assertEqual(one_hour["hours"], 1)
        self.assertEqual(one_hour["bucket_seconds"], 300)
        self.assertEqual(thirty_days["hours"], 720)
        self.assertEqual(thirty_days["bucket_seconds"], 7200)

    def test_current_state_avoids_historical_latest_query(self):
        wan_rows = [
            {"wan_id": "wan-1", "traffic_interface": "ether1"},
            {"wan_id": "wan-2", "traffic_interface": "ether2"},
        ]
        state = {
            "latest": {
                "wan-1": {"rx_bps": 1_000_000, "timestamp": "2026-07-29T00:00:00Z"},
                "wan-2": {"rx_bps": 2_000_000, "timestamp": "2026-07-29T00:00:00Z"},
            }
        }

        with (
            mock.patch.object(main, "build_wan_rows", return_value=wan_rows),
            mock.patch.object(main, "fetch_isp_status_latest_map") as fetch_latest,
        ):
            rows = main._build_isp_status_rows({}, {}, state=state)

        fetch_latest.assert_not_called()
        self.assertEqual([row["rx_mbps"] for row in rows], [1.0, 2.0])

    def test_only_missing_state_rows_use_historical_latest_query(self):
        wan_rows = [
            {"wan_id": "wan-1", "traffic_interface": "ether1"},
            {"wan_id": "wan-2", "traffic_interface": "ether2"},
        ]
        state = {
            "latest": {
                "wan-1": {"rx_bps": 1_000_000, "timestamp": "2026-07-29T00:00:00Z"},
            }
        }

        with (
            mock.patch.object(main, "build_wan_rows", return_value=wan_rows),
            mock.patch.object(
                main,
                "fetch_isp_status_latest_map",
                return_value={
                    "wan-2": {
                        "rx_bps": 2_000_000,
                        "timestamp": "2026-07-29T00:00:00Z",
                    }
                },
            ) as fetch_latest,
        ):
            rows = main._build_isp_status_rows({}, {}, state=state)

        fetch_latest.assert_called_once_with(["wan-2"])
        self.assertEqual([row["rx_mbps"] for row in rows], [1.0, 2.0])

    def test_series_endpoint_defaults_to_small_live_payload(self):
        settings_by_key = {
            "isp_status": {
                "enabled": True,
                "general": {
                    "poll_interval_seconds": 30,
                    "history_retention_days": 400,
                    "live_window_minutes": 15,
                },
            },
            "isp_ping": {},
            "wan_ping": {},
        }
        series_payload = {
            "series": {
                "wan-1": [
                    {
                        "timestamp": "2026-07-29T00:00:00Z",
                        "total_mbps": 10.0,
                    }
                ]
            },
            "total": [
                {
                    "timestamp": "2026-07-29T00:00:00Z",
                    "total_mbps": 10.0,
                }
            ],
        }

        with (
            mock.patch.object(
                main,
                "get_settings",
                side_effect=lambda key, _default: settings_by_key[key],
            ),
            mock.patch.object(main, "normalize_pulsewatch_settings", return_value={}),
            mock.patch.object(main, "normalize_wan_ping_settings", return_value={}),
            mock.patch.object(
                main,
                "build_wan_rows",
                return_value=[
                    {
                        "wan_id": "wan-1",
                        "identifier": "ISP One",
                        "traffic_interface": "ether1",
                    }
                ],
            ),
            mock.patch.object(
                main,
                "fetch_isp_status_series_map",
                return_value=series_payload,
            ) as fetch_series,
        ):
            response = asyncio.run(main.isp_status_series())

        payload = json.loads(response.body)
        self.assertEqual(payload["window"]["mode"], "live")
        self.assertEqual(payload["window"]["minutes"], 15)
        self.assertEqual(payload["hours"], 0)
        self.assertEqual(payload["point_count"], 2)
        self.assertEqual(payload["refresh_seconds"], 1)
        self.assertEqual(payload["background_poll_seconds"], 30)
        self.assertIn("no-store", response.headers["cache-control"])
        self.assertEqual(fetch_series.call_args.kwargs["bucket_seconds"], 30)

    def test_live_snapshot_batches_interfaces_and_marks_partial_totals(self):
        pulse_settings = {
            "pulsewatch": {
                "mikrotik": {
                    "cores": [
                        {
                            "id": "core-1",
                            "label": "Core One",
                            "host": "router.invalid",
                            "port": 8728,
                            "username": "api",
                            "password": "secret",
                        }
                    ]
                }
            }
        }
        wan_settings = {
            "wans": [
                {
                    "id": "wan-1",
                    "core_id": "core-1",
                    "list_name": "TO-ISP-1",
                    "identifier": "ISP One",
                    "traffic_interface": "ether1",
                    "enabled": True,
                },
                {
                    "id": "wan-2",
                    "core_id": "core-1",
                    "list_name": "TO-ISP-2",
                    "identifier": "ISP Two",
                    "traffic_interface": "ether2",
                    "enabled": True,
                },
                {
                    "id": "wan-disabled",
                    "core_id": "core-1",
                    "list_name": "TO-ISP-3",
                    "traffic_interface": "ether3",
                    "enabled": False,
                },
            ]
        }

        def sample_group(_core, targets):
            return {
                target["id"]: (
                    {"ok": True, "rx_bps": 2_000_000, "tx_bps": 1_000_000}
                    if target["id"] == "wan-1"
                    else {"ok": False}
                )
                for target in targets
            }

        with mock.patch.object(main, "_sample_isp_status_live_group", side_effect=sample_group) as sample:
            payload = main._collect_isp_status_live_snapshot(pulse_settings, wan_settings)

        sample.assert_called_once()
        self.assertEqual(payload["target_count"], 2)
        self.assertEqual(payload["sampled_count"], 1)
        self.assertEqual(payload["error_count"], 1)
        self.assertFalse(payload["complete"])
        self.assertIsNone(payload["series"][0]["point"]["y"])
        self.assertEqual(payload["series"][1]["point"]["y"], 3.0)
        self.assertIsNone(payload["series"][2]["point"]["y"])

    def test_live_group_falls_back_to_isolate_an_invalid_interface(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            def monitor_interfaces_traffic(self, names):
                self.calls.append(list(names))
                if len(names) > 1 or names == ["ether2"]:
                    raise RuntimeError("sample failed")
                return [
                    {
                        "name": "ether1",
                        "rx-bits-per-second": "2Mbps",
                        "tx-bits-per-second": "1Mbps",
                    }
                ]

        class FakeLease:
            def __init__(self, client):
                self.client = client

            def __enter__(self):
                return self.client

            def __exit__(self, _exc_type, _exc, _tb):
                return False

        client = FakeClient()
        core = {
            "host": "router.invalid",
            "port": 8728,
            "username": "api",
            "password": "secret",
        }
        targets = [
            {"id": "wan-1", "interface_name": "ether1"},
            {"id": "wan-2", "interface_name": "ether2"},
        ]
        with mock.patch.object(
            main,
            "borrow_routeros_client",
            return_value=FakeLease(client),
        ):
            sampled = main._sample_isp_status_live_group(core, targets)

        self.assertEqual(client.calls, [["ether1", "ether2"], ["ether1"], ["ether2"]])
        self.assertTrue(sampled["wan-1"]["ok"])
        self.assertEqual(sampled["wan-1"]["rx_bps"], 2_000_000)
        self.assertFalse(sampled["wan-2"]["ok"])

    def test_live_endpoint_runs_sampler_off_the_event_loop(self):
        settings_by_key = {
            "isp_status": {
                "enabled": True,
                "general": {
                    "poll_interval_seconds": 90,
                    "history_retention_days": 400,
                    "live_window_minutes": 15,
                },
            },
            "isp_ping": {"pulsewatch": {"mikrotik": {"cores": []}}},
            "wan_ping": {"wans": []},
        }
        snapshot = {
            "collector_enabled": True,
            "sampled_at": "2026-07-29T00:00:00.000Z",
            "poll_seconds": 1,
            "target_count": 0,
            "sampled_count": 0,
            "error_count": 0,
            "complete": False,
            "sample_duration_ms": 1,
            "series": [],
        }
        with (
            mock.patch.object(
                main,
                "get_settings",
                side_effect=lambda key, _default: settings_by_key[key],
            ),
            mock.patch.object(
                main,
                "normalize_pulsewatch_settings",
                side_effect=lambda value: value,
            ),
            mock.patch.object(
                main,
                "normalize_wan_ping_settings",
                side_effect=lambda value: value,
            ),
            mock.patch.object(
                main,
                "_get_cached_isp_status_live_snapshot",
                return_value=snapshot,
            ) as sampler,
        ):
            response = asyncio.run(main.isp_status_live())

        payload = json.loads(response.body)
        self.assertEqual(payload["poll_seconds"], 1)
        self.assertIn("no-store", response.headers["cache-control"])
        sampler.assert_called_once()

    def test_live_endpoint_inherits_isp_status_view_permission(self):
        self.assertEqual(
            main._auth_permission_for_route("/isp-status/live", "GET"),
            "VIEW_IspStatus",
        )

    def test_live_snapshot_cache_coalesces_same_configuration(self):
        pulse_settings = {"pulsewatch": {"mikrotik": {"cores": []}}}
        wan_settings = {"wans": []}
        snapshot = {
            "collector_enabled": True,
            "sampled_at": "2026-07-29T00:00:00.000Z",
            "series": [],
        }
        empty_cache = {
            "configuration_key": "",
            "sample_started_at": 0.0,
            "payload": None,
        }
        with (
            mock.patch.dict(main._ISP_STATUS_LIVE_SAMPLE_CACHE, empty_cache, clear=True),
            mock.patch.object(
                main,
                "_collect_isp_status_live_snapshot",
                return_value=snapshot,
            ) as collector,
        ):
            first = main._get_cached_isp_status_live_snapshot(pulse_settings, wan_settings)
            second = main._get_cached_isp_status_live_snapshot(pulse_settings, wan_settings)

        collector.assert_called_once()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_routeros_multi_interface_monitor_uses_one_command(self):
        client = RouterOSClient("router.invalid", 8728, "api", "secret")
        client.talk = mock.Mock(
            return_value=[
                [
                    "!re",
                    "=name=ether1",
                    "=rx-bits-per-second=1000000",
                    "=tx-bits-per-second=2000000",
                ],
                [
                    "!re",
                    "=name=ether2",
                    "=rx-bits-per-second=3000000",
                    "=tx-bits-per-second=4000000",
                ],
                ["!done"],
            ]
        )

        rows = client.monitor_interfaces_traffic(["ether1", "ether2", "ether1"])

        client.talk.assert_called_once_with(
            ["/interface/monitor-traffic", "=interface=ether1,ether2", "=once="]
        )
        self.assertEqual([row["name"] for row in rows], ["ether1", "ether2"])

    def test_postgres_latest_lookup_uses_per_isp_index_probe(self):
        class FakeResult:
            def fetchall(self):
                return [
                    {
                        "wan_id": "wan-1",
                        "timestamp": "2026-07-29T00:00:00Z",
                    }
                ]

        class FakeConnection:
            def __init__(self):
                self.query = ""
                self.params = []

            def execute(self, query, params):
                self.query = query
                self.params = params
                return FakeResult()

            def close(self):
                return None

        connection = FakeConnection()
        with (
            mock.patch.object(db, "get_conn", return_value=connection),
            mock.patch.object(db, "_use_postgres", return_value=True),
        ):
            result = db.fetch_isp_status_latest_map(["wan-1", "wan-2"])

        self.assertIn("CROSS JOIN LATERAL", connection.query)
        self.assertIn("FROM (VALUES (?),(?))", connection.query)
        self.assertEqual(connection.params, ["wan-1", "wan-2"])
        self.assertEqual(result["wan-1"]["timestamp"], "2026-07-29T00:00:00Z")

    def test_template_opens_live_and_keeps_history_filters(self):
        source = TEMPLATE_PATH.read_text(encoding="utf-8")
        self.assertIn('let activeWindow = "live";', source)
        self.assertIn('data-window="{{ window }}"', source)
        self.assertIn("/isp-status/series?window=", source)
        self.assertIn('fetch("/isp-status/live"', source)
        self.assertIn("const livePollMs = 1000;", source)
        self.assertIn('activeWindow === "live"', source)
        self.assertIn("!document.hidden", source)
        self.assertIn('"IntersectionObserver" in window', source)
        self.assertIn("statusTabIsActive()", source)
        self.assertIn("stopLivePolling();", source)
        self.assertIn('id="isp-status-chart-inspection"', source)
        self.assertIn('chartEl.addEventListener("pointerenter"', source)
        self.assertIn('chartEl.addEventListener("pointerleave"', source)
        self.assertIn('chartEl.matches(":hover")', source)
        self.assertIn("if (chartInteractionHeld && chart)", source)
        self.assertIn("liveRenderPending = true;", source)
        self.assertIn("updateChartSeries(liveSeriesPayload())", source)
        self.assertIn("await chart.updateOptions({ series, colors }", source)
        self.assertNotIn("await chart.updateOptions({ colors }", source)
        self.assertNotIn("const chartRefreshMs", source)
        self.assertIn("Live Chart Window (minutes)", source)
        self.assertNotIn("settings.general.chart_window_hours", source)


if __name__ == "__main__":
    unittest.main()
