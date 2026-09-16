"""Tests for Flask route wiring."""

from __future__ import annotations

import unittest

from web.app import app


class WebRouteRegistrationTests(unittest.TestCase):
    def test_chat_and_webhook_routes_are_registered(self):
        routes = {rule.rule for rule in app.url_map.iter_rules()}
        self.assertIn("/api/chat/<int:case_id>", routes)
        self.assertIn("/api/webhooks/test", routes)
        self.assertIn("/api/webhooks/wazuh", routes)
        self.assertIn("/api/learning/suggestions", routes)
        self.assertIn("/api/cases/<int:case_id>/export/stix", routes)
        self.assertIn("/api/cases/<int:case_id>/responders", routes)
        self.assertIn("/api/service-clients", routes)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
