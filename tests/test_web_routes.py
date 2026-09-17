"""Tests for Flask route wiring."""

from __future__ import annotations

import unittest
import os
import subprocess
import sys
from pathlib import Path

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
        self.assertIn("/api/capabilities/proposals", routes)
        self.assertIn("/api/notifications", routes)
        self.assertIn("/health/live", routes)
        self.assertIn("/health/ready", routes)

    def test_proxy_fix_is_enabled_only_by_deployment_flag(self):
        environment = os.environ.copy()
        environment["AI_SOC_BEHIND_PROXY"] = "1"
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from flask import request; from werkzeug.middleware.proxy_fix import ProxyFix; "
                "from web.app import app; assert isinstance(app.wsgi_app, ProxyFix); "
                "app.add_url_rule('/_proxy-probe', '_proxy_probe', lambda: {'secure': request.is_secure, 'host': request.host}); "
                "response=app.test_client().get('/_proxy-probe', headers={'X-Forwarded-Proto':'https','X-Forwarded-Host':'soc-console.local'}); "
                "assert response.json == {'secure': True, 'host': 'soc-console.local'}",
            ],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
