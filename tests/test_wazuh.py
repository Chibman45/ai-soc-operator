"""Tests for Wazuh API clients."""

from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts.soc_client.wazuh import WazuhManagerClient, WazuhIndexerClient


class WazuhManagerClientTests(unittest.TestCase):
    """Test Wazuh Manager client request construction."""

    def _make_client(self) -> WazuhManagerClient:
        return WazuhManagerClient("https://wazuh.example.com:55000", "test-token")

    def test_authorization_header(self):
        client = self._make_client()
        headers = client._build_headers()
        self.assertEqual(headers["Authorization"], "Bearer test-token")

    def test_get_manager_info(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"affected_items": [{"version": "4.7.0"}]}}
            result = client.get_manager_info()
            mock_req.assert_called_once_with("GET", "/manager/info")

    def test_get_rules(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {
                "data": {
                    "affected_items": [
                        {"id": "1001", "description": "SSH brute force"},
                        {"id": "1002", "description": "Port scan"},
                    ]
                }
            }
            result = client.get_rules()
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["id"], "1001")

    def test_get_rules_with_limit(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"affected_items": []}}
            client.get_rules(limit=50)
            mock_req.assert_called_once_with("GET", "/rules", query={"limit": "50"})

    def test_get_rules_handles_empty_response(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {}}
            result = client.get_rules()
            self.assertEqual(result, [])

    def test_get_agent_summary(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"total": 10, "active": 8}}
            result = client.get_agent_summary()
            mock_req.assert_called_once_with("GET", "/agents/summary")

    def test_search_agent_alerts(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {
                "data": {
                    "affected_items": [
                        {"rule": {"id": "1001"}, "timestamp": "2026-01-01T00:00:00Z"}
                    ]
                }
            }
            result = client.search_agent_alerts("001", rule_id="1001", limit=10)
            mock_req.assert_called_once_with(
                "GET", "/alerts/agents/001", query={"limit": "10", "rule_id": "1001"}
            )
            self.assertEqual(len(result), 1)


class WazuhIndexerClientTests(unittest.TestCase):
    """Test Wazuh Indexer client request construction."""

    def _make_client(self) -> WazuhIndexerClient:
        return WazuhIndexerClient(
            "https://wazuh-indexer.example.com:9200",
            "admin",
            "secret",
        )

    def test_authorization_header_is_basic_auth(self):
        client = self._make_client()
        headers = client._build_headers()
        expected = base64.b64encode(b"admin:secret").decode()
        self.assertEqual(headers["Authorization"], f"Basic {expected}")

    def test_search_alerts_body(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {
                "hits": {"hits": [{"_source": {"rule": {"id": "1001"}}}]}
            }
            result = client.search_alerts(size=50)
            mock_req.assert_called_once()
            call_args = mock_req.call_args
            self.assertEqual(call_args[0][0], "POST")
            self.assertIn("wazuh-alerts-*/_search", call_args[0][1])
            body = call_args[1]["body"]
            self.assertEqual(body["size"], 50)
            self.assertEqual(body["query"], {"match_all": {}})

    def test_search_alerts_by_rule(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"hits": {"hits": []}}
            client.search_alerts_by_rule("1001")
            call_args = mock_req.call_args
            body = call_args[1]["body"]
            self.assertEqual(body["query"], {"term": {"rule.id": "1001"}})

    def test_search_alerts_by_agent(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"hits": {"hits": []}}
            client.search_alerts_by_agent("001")
            body = mock_req.call_args[1]["body"]
            self.assertEqual(body["query"], {"term": {"agent.id": "001"}})

    def test_search_alerts_by_level(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"hits": {"hits": []}}
            client.search_alerts_by_level(min_level=10)
            body = mock_req.call_args[1]["body"]
            self.assertEqual(
                body["query"], {"range": {"rule.level": {"gte": 10}}}
            )

    def test_custom_index(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"hits": {"hits": []}}
            client.search_alerts(index="wazuh-alerts-2026.01.*")
            call_args = mock_req.call_args
            self.assertIn("wazuh-alerts-2026.01.*/_search", call_args[0][1])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
