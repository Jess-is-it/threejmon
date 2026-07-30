import unittest
from html.parser import HTMLParser
from pathlib import Path

from jinja2 import Environment


TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "app" / "templates" / "settings_system.html"


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._current = {"attrs": dict(attrs), "text": []}

    def handle_data(self, data):
        if self._current is not None:
            self._current["text"].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current is not None:
            self._current["text"] = " ".join("".join(self._current["text"]).split())
            self.links.append(self._current)
            self._current = None


class SystemSettingsNavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = TEMPLATE_PATH.read_text(encoding="utf-8")
        cls.env = Environment(autoescape=True)
        nav_start = cls.source.index(
            '<ul class="nav nav-tabs mb-3" id="system-settings-tabs"'
        )
        nav_end = cls.source.index("</ul>", nav_start) + len("</ul>")
        cls.nav_template = cls.env.from_string(cls.source[nav_start:nav_end])

        panes_start = cls.source.index(
            "{% if can_manage_import_export and active_tab == 'backup' %}"
        )
        modal_marker = (
            "\n{% if can_view_danger_tab and active_tab == 'danger' %}\n"
            '  <div class="modal'
        )
        panes_end = cls.source.index(modal_marker, panes_start)
        cls.backup_danger_template = cls.env.from_string(
            cls.source[panes_start:panes_end]
        )

    @staticmethod
    def _navigation_context(active_tab):
        return {
            "active_tab": active_tab,
            "can_view_general_tab": True,
            "can_view_telegram_tab": True,
            "can_view_routers_tab": True,
            "can_view_access_tab": True,
            "can_view_update_tab": True,
            "can_view_data_retention_tab": True,
            "can_view_graphify_tab": True,
            "can_manage_import_export": True,
            "can_view_danger_tab": True,
        }

    def test_top_level_tabs_use_stable_server_urls(self):
        expected = [
            ("General", "/settings/system?tab=general"),
            ("Telegram Commands", "/settings/system?tab=telegram"),
            ("Routers", "/settings/system?tab=routers"),
            ("Access", "/settings/system?tab=access"),
            ("System Update", "/settings/system?tab=update"),
            ("Data Retention", "/settings/system?tab=data-retention"),
            ("Graphify", "/settings/system?tab=graphify"),
            ("Backup", "/settings/system?tab=backup"),
            ("Danger", "/settings/system?tab=danger"),
        ]

        for active_tab in (
            "general",
            "telegram",
            "routers",
            "access",
            "update",
            "data-retention",
            "graphify",
            "backup",
            "danger",
        ):
            with self.subTest(active_tab=active_tab):
                parser = _LinkParser()
                parser.feed(
                    self.nav_template.render(
                        **self._navigation_context(active_tab)
                    )
                )
                self.assertEqual(
                    [(link["text"], link["attrs"].get("href")) for link in parser.links],
                    expected,
                )
                self.assertTrue(
                    all("data-bs-toggle" not in link["attrs"] for link in parser.links)
                )
                active_links = [
                    link
                    for link in parser.links
                    if "active" in (link["attrs"].get("class") or "").split()
                ]
                self.assertEqual(len(active_links), 1)
                self.assertEqual(
                    active_links[0]["attrs"].get("href"),
                    f"/settings/system?tab={active_tab}",
                )
                self.assertEqual(active_links[0]["attrs"].get("aria-current"), "page")

    def test_backup_and_danger_content_are_mutually_exclusive(self):
        common = {
            "can_manage_import_export": True,
            "can_view_danger_tab": True,
            "danger_groups": [],
            "danger_bulk_actions": [],
            "danger_system_actions": [],
        }

        backup_html = self.backup_danger_template.render(
            active_tab="backup", **common
        )
        self.assertIn("Backup & Restore", backup_html)
        self.assertNotIn("Centralized destructive actions", backup_html)

        danger_html = self.backup_danger_template.render(
            active_tab="danger", **common
        )
        self.assertIn("Centralized destructive actions", danger_html)
        self.assertNotIn("Backup & Restore", danger_html)

    def test_data_retention_and_other_panes_share_one_top_level_container(self):
        retention_start = self.source.index('id="sys-data-retention"')
        general_start = self.source.index('id="sys-general"')
        boundary = self.source[retention_start:general_start]
        self.assertNotIn(
            '</div>\n\n<div class="tab-content">',
            boundary,
        )


if __name__ == "__main__":
    unittest.main()
