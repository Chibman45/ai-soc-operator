"""Tests for threat intelligence enrichment clients."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch, MagicMock

from scripts.soc_client.enrichment import (
    EnrichmentClient,
    VirusTotalClient,
    AbuseIPDBClient,
    ShodanClient,
)


class VirusTotalClientTests(unittest.TestCase):
    """Test VirusTotal client request construction."""

    def _make_client(self) -> VirusTotalClient:
        return VirusTotalClient("vt-api-key-123")

    def test_apikey_header(self):
        client = self._make_client()
        headers = client._build_headers()
        self.assertEqual(headers["x-apikey"], "vt-api-key-123")

    def test_lookup_ip(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"attributes": {"last_analysis_stats": {}}}}
            client.lookup_ip("203.0.113.42")
            mock_req.assert_called_once_with("GET", "/api/v3/ip_addresses/203.0.113.42")

    def test_lookup_domain(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"id": "example.com"}}
            client.lookup_domain("example.com")
            mock_req.assert_called_once_with("GET", "/api/v3/domains/example.com")

    def test_lookup_file(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"id": "abc123"}}
            client.lookup_file("abc123")
            mock_req.assert_called_once_with("GET", "/api/v3/files/abc123")

    def test_lookup_url_encodes(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"id": "url-id"}}
            client.lookup_url("https://example.com/path?q=1")
            # URL should be base64url-encoded
            call_path = mock_req.call_args[0][1]
            self.assertIn("/api/v3/urls/", call_path)


class AbuseIPDBClientTests(unittest.TestCase):
    """Test AbuseIPDB client request construction."""

    def _make_client(self) -> AbuseIPDBClient:
        return AbuseIPDBClient("abuse-key-123")

    def test_key_header(self):
        client = self._make_client()
        headers = client._build_headers()
        self.assertEqual(headers["Key"], "abuse-key-123")

    def test_check_ip(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"data": {"abuseConfidenceScore": 85}}
            client.check_ip("198.51.100.20")
            mock_req.assert_called_once_with(
                "GET",
                "/api/v2/check",
                query={
                    "ipAddress": "198.51.100.20",
                    "maxAgeInDays": "90",
                    "verbose": "true",
                },
            )


class ShodanClientTests(unittest.TestCase):
    """Test Shodan client request construction."""

    def _make_client(self) -> ShodanClient:
        return ShodanClient("shodan-key-123")

    def test_host_lookup(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"ip_str": "203.0.113.42", "ports": [22, 80]}
            client.host_lookup("203.0.113.42")
            mock_req.assert_called_once_with(
                "GET",
                "/shodan/host/203.0.113.42",
                query={"key": "shodan-key-123", "minify": "true"},
            )

    def test_search(self):
        client = self._make_client()
        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = {"matches": []}
            client.search("apache", limit=10)
            mock_req.assert_called_once_with(
                "GET",
                "/shodan/host/search",
                query={"key": "shodan-key-123", "query": "apache", "limit": "10"},
            )


class EnrichmentClientTests(unittest.TestCase):
    """Test the unified enrichment client."""

    def test_enrich_ip_calls_platforms(self):
        config = {
            "platforms": {
                "virustotal": {"enabled": True, "credential_env": "VT_KEY"},
                "abuseipdb": {"enabled": True, "credential_env": "AB_KEY"},
            }
        }
        with patch("scripts.soc_client.enrichment.os.environ", {"VT_KEY": "vt", "AB_KEY": "ab"}):
            client = EnrichmentClient(config)
            self.assertIn("virustotal", client._clients)
            self.assertIn("abuseipdb", client._clients)

    def test_enrich_ip_dispatches(self):
        config = {
            "platforms": {
                "virustotal": {"enabled": True, "credential_env": "VT_KEY"},
            }
        }
        with patch("scripts.soc_client.enrichment.os.environ", {"VT_KEY": "vt"}):
            client = EnrichmentClient(config)
            with patch.object(client._clients["virustotal"], "lookup_ip") as mock_lookup:
                mock_lookup.return_value = {"data": {}}
                result = client.enrich_ip("203.0.113.42")
                mock_lookup.assert_called_once_with("203.0.113.42")
                self.assertIn("virustotal", result)

    def test_enrich_unsupported_type(self):
        config = {"platforms": {}}
        client = EnrichmentClient(config)
        result = client.enrich("unsupported", "value")
        self.assertIn("error", result)

    def test_enrich_hash_calls_vt_and_ha(self):
        config = {
            "platforms": {
                "virustotal": {"enabled": True, "credential_env": "VT_KEY"},
                "hybrid_analysis": {"enabled": True, "credential_env": "HA_KEY"},
            }
        }
        with patch("scripts.soc_client.enrichment.os.environ", {"VT_KEY": "vt", "HA_KEY": "ha"}):
            client = EnrichmentClient(config)
            with patch.object(client._clients["virustotal"], "lookup_file") as mock_vt:
                with patch.object(client._clients["hybrid-analysis"], "hash_search") as mock_ha:
                    mock_vt.return_value = {"data": {}}
                    mock_ha.return_value = {"result": {}}
                    result = client.enrich_hash("abc123")
                    self.assertIn("virustotal", result)
                    self.assertIn("hybrid-analysis", result)

    def test_enrich_handles_client_error(self):
        config = {
            "platforms": {
                "virustotal": {"enabled": True, "credential_env": "VT_KEY"},
            }
        }
        with patch("scripts.soc_client.enrichment.os.environ", {"VT_KEY": "vt"}):
            client = EnrichmentClient(config)
            with patch.object(client._clients["virustotal"], "lookup_ip") as mock_lookup:
                mock_lookup.side_effect = RuntimeError("Connection refused")
                result = client.enrich_ip("203.0.113.42")
                self.assertIn("virustotal", result)
                self.assertIn("error", result["virustotal"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
