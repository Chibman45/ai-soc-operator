"""Tests for Cortex API client."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from scripts.soc_client.cortex import CortexClient


class CortexClientTests(unittest.TestCase):
    """Test Cortex client request construction."""

    def _make_client(self) -> CortexClient:
        return CortexClient("https://cortex.example.com", "test-api-key")

    def test_authorization_header(self):
        client = self._make_client()
        headers = client._build_headers()
        self.assertEqual(headers["Authorization"], "Bearer test-api-key")
        self.assertIn("User-Agent", headers)

    def test_list_analyzers_request(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = [
                {"id": "VirusTotal_ObservedURLs_3_0", "name": "VirusTotal"},
                {"id": "MaxMind_GeoIP_2_0", "name": "MaxMind GeoIP"},
            ]
            result = client.list_analyzers()
            mock_req.assert_called_once_with("GET", "/api/analyzer", query={})
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["id"], "VirusTotal_ObservedURLs_3_0")

    def test_list_analyzers_filters_by_data_type(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = [{"id": " analyzer1"}]
            client.list_analyzers(data_type="ip")
            mock_req.assert_called_once_with(
                "GET", "/api/analyzer", query={"dataType": "ip"}
            )

    def test_list_analyzers_unwraps_data(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": [{"id": "a1"}, {"id": "a2"}]}
            result = client.list_analyzers()
            self.assertEqual(len(result), 2)

    def test_get_analyzer(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"id": "VirusTotal_3_0", "name": "VT"}
            result = client.get_analyzer("VirusTotal_3_0")
            mock_req.assert_called_once_with("GET", "/api/analyzer/VirusTotal_3_0")

    def test_run_analyzer_body(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"id": "job-123", "status": "InProgress"}
            result = client.run_analyzer(
                analyzer_id="VirusTotal_3_0",
                data_type="ip",
                data="203.0.113.42",
                tlp=2,
                message="Test enrichment",
            )
            mock_req.assert_called_once()
            call_args = mock_req.call_args
            self.assertEqual(call_args[0][0], "POST")
            self.assertEqual(call_args[0][1], "/api/analyzer/VirusTotal_3_0/run")
            body = call_args[1]["body"]
            self.assertEqual(body["dataType"], "ip")
            self.assertEqual(body["data"], "203.0.113.42")
            self.assertEqual(body["tlp"], 2)

    def test_run_analyzer_with_parameters(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"id": "job-456"}
            client.run_analyzer(
                analyzer_id="Analyzer1",
                data_type="file",
                data="abc123hash",
                parameters={"timeout": 300},
            )
            body = mock_req.call_args[1]["body"]
            self.assertEqual(body["parameters"], {"timeout": 300})

    def test_get_job(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"id": "job-123", "status": "Success"}
            result = client.get_job("job-123")
            mock_req.assert_called_once_with("GET", "/api/job/job-123")

    def test_get_job_report(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"summary": {"taxonomies": []}}
            result = client.get_job_report("job-123", "report-abc")
            mock_req.assert_called_once_with(
                "GET", "/api/job/job-123/report/report-abc"
            )

    def test_list_responders(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = [{"id": "responder1"}]
            result = client.list_responders()
            mock_req.assert_called_once_with("GET", "/api/responder", query={})

    def test_run_responder_body(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"id": "job-789"}
            client.run_responder(
                responder_id="MISP_Import_File",
                entity_type="case_artifact",
                entity_id="obs-123",
            )
            body = mock_req.call_args[1]["body"]
            self.assertEqual(body["entity_type"], "case_artifact")
            self.assertEqual(body["entity_id"], "obs-123")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
