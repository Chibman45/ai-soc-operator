"""Tests for Cortex, Wazuh, and enrichment clients."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.soc_client.cortex import CortexClient
from scripts.soc_client.wazuh import WazuhManagerClient, WazuhIndexerClient
from scripts.soc_client.enrichment import (
    EnrichmentClient,
    VirusTotalClient,
    AbuseIPDBClient,
    ShodanClient,
)


class CortexClientTests(unittest.TestCase):
    def setUp(self):
        self.client = CortexClient("https://cortex.example.com", "test-key")

    def test_authorization_header(self):
        headers = self.client._build_headers()
        self.assertEqual(headers["Authorization"], "Bearer test-key")

    def test_list_analyzers_sends_get(self):
        with patch.object(self.client, "_request", return_value=[]) as mock:
            self.client.list_analyzers()
            mock.assert_called_once()
            args = mock.call_args
            self.assertEqual(args[0][0], "GET")
            self.assertEqual(args[0][1], "/api/analyzer")

    def test_list_analyzers_by_data_type(self):
        with patch.object(self.client, "_request", return_value=[]) as mock:
            self.client.list_analyzers(data_type="ip")
            args = mock.call_args
            self.assertEqual(args[1]["query"], {"dataType": "ip"})

    def test_run_analyzer_body(self):
        with patch.object(self.client, "_request", return_value={"id": "job-1"}) as mock:
            self.client.run_analyzer(
                analyzer_id="ana-1",
                data_type="ip",
                data="192.168.1.1",
                tlp=2,
                message="test",
            )
            args = mock.call_args
            body = args[1]["body"]
            self.assertEqual(body["dataType"], "ip")
            self.assertEqual(body["data"], "192.168.1.1")
            self.assertEqual(body["tlp"], 2)

    def test_get_job(self):
        with patch.object(self.client, "_request", return_value={"id": "j1"}) as mock:
            self.client.get_job("j1")
            args = mock.call_args
            self.assertEqual(args[0][1], "/api/job/j1")

    def test_list_responders(self):
        with patch.object(self.client, "_request", return_value=[]) as mock:
            self.client.list_responders(entity_type="case_artifact")
            args = mock.call_args
            self.assertEqual(args[1]["query"], {"entity_type": "case_artifact"})


class WazuhManagerTests(unittest.TestCase):
    def setUp(self):
        self.client = WazuhManagerClient("https://wazuh.example.com:55000", "test-token")

    def test_authorization_header(self):
        headers = self.client._build_headers()
        self.assertEqual(headers["Authorization"], "Bearer test-token")

    def test_get_manager_info(self):
        with patch.object(self.client, "_request", return_value={"data": {}}) as mock:
            self.client.get_manager_info()
            args = mock.call_args
            self.assertEqual(args[0][1], "/manager/info")

    def test_get_rules(self):
        response = {"data": {"affected_items": [{"id": 1}, {"id": 2}]}}
        with patch.object(self.client, "_request", return_value=response):
            rules = self.client.get_rules()
            self.assertEqual(len(rules), 2)

    def test_search_agent_alerts(self):
        with patch.object(self.client, "_request", return_value={"data": {"affected_items": []}}) as mock:
            self.client.search_agent_alerts("001", rule_id="1001")
            args = mock.call_args
            self.assertEqual(args[0][1], "/alerts/agents/001")
            self.assertEqual(args[1]["query"]["rule_id"], "1001")


class WazuhIndexerTests(unittest.TestCase):
    def setUp(self):
        self.client = WazuhIndexerClient(
            "https://indexer.example.com:9200", "admin", "secret"
        )

    def test_basic_auth_header(self):
        import base64
        headers = self.client._build_headers()
        expected = base64.b64encode(b"admin:secret").decode()
        self.assertEqual(headers["Authorization"], f"Basic {expected}")

    def test_search_alerts_body(self):
        with patch.object(self.client, "_request", return_value={"hits": {"hits": []}}) as mock:
            self.client.search_alerts(size=50)
            args = mock.call_args
            body = args[1]["body"]
            self.assertEqual(body["size"], 50)
            self.assertEqual(body["query"], {"match_all": {}})

    def test_search_by_rule(self):
        with patch.object(self.client, "_request", return_value={}) as mock:
            self.client.search_alerts_by_rule("1001")
            args = mock.call_args
            body = args[1]["body"]
            self.assertEqual(body["query"], {"term": {"rule.id": "1001"}})

    def test_search_by_level(self):
        with patch.object(self.client, "_request", return_value={}) as mock:
            self.client.search_alerts_by_level(min_level=12)
            args = mock.call_args
            body = args[1]["body"]
            self.assertEqual(body["query"], {"range": {"rule.level": {"gte": 12}}})


class EnrichmentClientTests(unittest.TestCase):
    def test_enrich_ip_calls_vt_and_abuseipdb(self):
        config = {
            "platforms": {
                "virustotal": {"enabled": True, "credential_env": "VT_KEY"},
                "abuseipdb": {"enabled": True, "credential_env": "AB_KEY"},
            }
        }
        with patch.dict("os.environ", {"VT_KEY": "vt-123", "AB_KEY": "ab-456"}):
            client = EnrichmentClient(config)
            self.assertIn("virustotal", client._clients)
            self.assertIn("abuseipdb", client._clients)

    def test_enrich_returns_results_per_platform(self):
        config = {
            "platforms": {
                "virustotal": {"enabled": True, "credential_env": "VT_KEY"},
            }
        }
        with patch.dict("os.environ", {"VT_KEY": "vt-123"}):
            client = EnrichmentClient(config)
            with patch.object(
                client._clients["virustotal"], "lookup_ip",
                return_value={"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}},
            ):
                result = client.enrich("ip", "8.8.8.8")
                self.assertIn("virustotal", result)

    def test_enrich_unsupported_type(self):
        config = {"platforms": {}}
        client = EnrichmentClient(config)
        result = client.enrich("unsupported", "value")
        self.assertIn("error", result)

    def test_no_clients_configured(self):
        config = {"platforms": {}}
        client = EnrichmentClient(config)
        self.assertEqual(len(client._clients), 0)


if __name__ == "__main__":
    unittest.main()
