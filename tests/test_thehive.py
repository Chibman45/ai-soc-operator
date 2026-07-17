"""Tests for TheHive client."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.soc_client.thehive import TheHiveClient


class TheHiveClientTests(TestCase):
    def setUp(self):
        self.client = TheHiveClient(
            "https://thehive.example.com",
            "test-api-key-12345",
        )

    def test_create_case_body(self):
        with patch.object(self.client, "_request") as mock_req:
            mock_req.return_value = {"id": "case-123", "title": "Test"}
            result = self.client.create_case(
                title="Test Case",
                description="Automated triage",
                severity=3,
                tags=["test", "automated"],
            )
            mock_req.assert_called_once()
            call_args = mock_req.call_args
            self.assertEqual(call_args[0][0], "POST")
            self.assertEqual(call_args[0][1], "/api/v1/case")
            body = call_args[1]["body"]
            self.assertEqual(body["title"], "Test Case")
            self.assertEqual(body["severity"], 3)
            self.assertIn("test", body["tags"])

    def test_add_comment_body(self):
        with patch.object(self.client, "_request") as mock_req:
            mock_req.return_value = {"id": "comment-1"}
            self.client.add_comment("case-123", "Analyst note here")
            call_args = mock_req.call_args
            self.assertEqual(call_args[0][0], "POST")
            self.assertEqual(call_args[0][1], "/api/v1/case/case-123/comment")
            self.assertEqual(call_args[1]["body"]["message"], "Analyst note here")

    def test_add_observable_body(self):
        with patch.object(self.client, "_request") as mock_req:
            mock_req.return_value = {"id": "obs-1"}
            self.client.add_observable(
                case_id="case-123",
                data_type="ip",
                data="203.0.113.42",
                message="Source IP from brute-force",
                tags=["ioc", "brute-force"],
            )
            call_args = mock_req.call_args
            body = call_args[1]["body"]
            self.assertEqual(body["dataType"], "ip")
            self.assertEqual(body["data"], "203.0.113.42")
            self.assertIn("ioc", body["tags"])

    def test_handle_alert_body(self):
        with patch.object(self.client, "_request") as mock_req:
            mock_req.return_value = {"status": "ok"}
            self.client.handle_alert("alert-1", case_id="case-123")
            call_args = mock_req.call_args
            body = call_args[1]["body"]
            self.assertEqual(body["importToCase"]["caseId"], "case-123")
            self.assertFalse(body["importToCase"]["mergeInCase"])

    def test_list_alerts_query(self):
        with patch.object(self.client, "_request") as mock_req:
            mock_req.return_value = []
            self.client.list_alerts(limit=10)
            call_args = mock_req.call_args
            body = call_args[1]["body"]
            self.assertEqual(body["range"], "0-10")

    def test_authorization_header(self):
        headers = self.client._build_headers()
        self.assertEqual(headers["Authorization"], "Bearer test-api-key-12345")

    def test_update_case_body(self):
        with patch.object(self.client, "_request") as mock_req:
            mock_req.return_value = {"id": "case-123"}
            self.client.update_case("case-123", severity=4, status="Resolved")
            call_args = mock_req.call_args
            self.assertEqual(call_args[0][0], "PATCH")
            body = call_args[1]["body"]
            self.assertEqual(body["severity"], 4)

    def test_create_alert_body(self):
        with patch.object(self.client, "_request") as mock_req:
            mock_req.return_value = {"id": "alert-new"}
            self.client.create_alert(
                title="New Alert",
                description="Test",
                severity=2,
                source="ai-soc-operator",
                tags=["test"],
            )
            call_args = mock_req.call_args
            body = call_args[1]["body"]
            self.assertEqual(body["title"], "New Alert")
            self.assertEqual(body["source"], "ai-soc-operator")


if __name__ == "__main__":
    import unittest
    unittest.main()
