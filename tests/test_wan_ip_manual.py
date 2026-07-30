import sys
import types
import unittest
from pathlib import Path
from unittest import mock

import app
from app.notifiers import wan_ping


ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = ROOT / "app" / "main.py"
JOBS_PATH = ROOT / "app" / "jobs.py"
TEMPLATE_PATH = ROOT / "app" / "templates" / "settings_system.html"


def _settings(address="8.8.8.8"):
    return {
        "general": {"interval_seconds": 30},
        "wans": [
            {
                "id": "wan-1",
                "core_id": "core1",
                "list_name": "TO-ISP1",
                "identifier": "ISP One",
                "enabled": True,
                "mode": "routed",
                "local_ip": "10.0.0.2",
                "netwatch_host": address,
            }
        ],
    }


class ManualWanIpTests(unittest.TestCase):
    def _patch_detector(self, result):
        fake_main = types.SimpleNamespace(
            detect_routed_wan_autofill=mock.Mock(return_value=result)
        )
        return (
            mock.patch.dict(sys.modules, {"app.main": fake_main}),
            mock.patch.object(app, "main", fake_main, create=True),
            fake_main,
        )

    def test_routed_target_is_the_operator_saved_wan_ip(self):
        wan = _settings()["wans"][0]
        self.assertEqual(wan_ping._resolve_target(wan, {}), "8.8.8.8")

    def test_routed_target_never_falls_back_to_local_source_ip(self):
        wan = _settings(address="")["wans"][0]
        self.assertIsNone(wan_ping._resolve_target(wan, {}))

    def test_bridged_target_falls_back_to_local_source_ip(self):
        wan = {
            "mode": "bridged",
            "local_ip": "192.0.2.10",
            "netwatch_host": "",
        }
        self.assertEqual(wan_ping._resolve_target(wan, {}), "192.0.2.10")

    def test_local_route_refresh_preserves_manual_wan_ip(self):
        settings = _settings()
        detector_result = (
            {
                ("core1", "TO-ISP1"): {
                    "local_ip": "10.0.0.3",
                    # Even a stale/custom detector cannot replace the manual
                    # WAN IP; only local route metadata is consumed.
                    "netwatch_host": "9.9.9.9",
                    "interface": "ether1",
                    "routing_mark": "via-ISP1",
                }
            },
            [],
        )
        patches = self._patch_detector(detector_result)
        with patches[0], patches[1]:
            warnings = wan_ping._refresh_routed_wan_hosts(settings, {})

        self.assertEqual(warnings, [])
        self.assertEqual(settings["wans"][0]["local_ip"], "10.0.0.3")
        self.assertEqual(settings["wans"][0]["netwatch_host"], "8.8.8.8")
        patches[2].detect_routed_wan_autofill.assert_called_once_with(
            {},
            mock.ANY,
        )

    def test_add_isp_template_has_one_manual_wan_ip_field(self):
        source = TEMPLATE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'name="wan_{{ loop.index0 }}_netwatch_host"',
            source,
        )
        self.assertIn("Enter the public WAN IPv4 address manually", source)
        self.assertNotIn("wan_ip_mode", source)
        self.assertNotIn("manual_wan_ip", source)
        self.assertNotIn("Verify now", source)
        self.assertNotIn("wan_ip_refresh_interval_minutes", source)

    def test_runtime_has_no_public_wan_probe_or_refresh_job(self):
        main_source = MAIN_PATH.read_text(encoding="utf-8")
        jobs_source = JOBS_PATH.read_text(encoding="utf-8")
        notifier_source = Path(wan_ping.__file__).read_text(encoding="utf-8")

        self.assertNotIn("/settings/system/routers/isps/refresh", main_source)
        self.assertNotIn("WAN_IP_PROBE_PROVIDERS", main_source)
        self.assertNotIn("refresh_routed_wan_public_ips", jobs_source)
        self.assertNotIn("next_due_wan_ip_refresh_id", jobs_source)
        self.assertNotIn("refresh_routed_wan_public_ips", notifier_source)
        self.assertNotIn("wan_ip_detection", notifier_source)

    def test_netwatch_update_is_read_back_and_verified(self):
        class FakeClient:
            def __init__(self, persist=True):
                self.persist = persist
                self.entries = [
                    {
                        ".id": "*1",
                        "comment": "threejnotif_wan:wan-1",
                        "host": "8.8.8.8",
                        "interval": "30s",
                        "timeout": "1s",
                    }
                ]

            def list_netwatch(self):
                return [dict(item) for item in self.entries]

            def set_netwatch(self, entry_id, host, interval, timeout, comment):
                if self.persist:
                    self.entries[0].update(
                        {
                            "host": host,
                            "interval": interval,
                            "timeout": timeout,
                            "comment": comment,
                        }
                    )

        updated = wan_ping._ensure_netwatch(
            FakeClient(),
            "wan-1",
            "9.9.9.9",
            30,
        )
        self.assertEqual(updated["host"], "9.9.9.9")

        with self.assertRaisesRegex(RuntimeError, "did not persist"):
            wan_ping._ensure_netwatch(
                FakeClient(persist=False),
                "wan-1",
                "9.9.9.9",
                30,
            )


if __name__ == "__main__":
    unittest.main()
