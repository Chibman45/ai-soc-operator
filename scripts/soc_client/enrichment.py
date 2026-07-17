"""Threat intelligence enrichment client.

Aggregates lookups across multiple platforms:
- VirusTotal (file, URL, domain, IP)
- AbuseIPDB (IP reputation)
- Shodan (host info, search)
- urlscan.io (search, results)
- PhishTank (URL check)
- Hybrid Analysis (hash search, report)
- MISP (attribute/event search)

All lookups are third-party disclosures. Approval required.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from typing import Any

try:
    from .base import PlatformClient
    from ..common import audit
except ImportError:
    from soc_client.base import PlatformClient
    from common import audit


class VirusTotalClient(PlatformClient):
    def __init__(self, api_key: str, ca_file: str | None = None):
        super().__init__("https://www.virustotal.com", "virustotal", ca_file=ca_file)
        self._api_key = api_key

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        headers["x-apikey"] = self._api_key
        return headers

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        return self.get(f"/api/v3/ip_addresses/{ip}")

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        return self.get(f"/api/v3/domains/{domain}")

    def lookup_file(self, hash_value: str) -> dict[str, Any]:
        return self.get(f"/api/v3/files/{hash_value}")

    def lookup_url(self, url: str) -> dict[str, Any]:
        import base64
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        return self.get(f"/api/v3/urls/{encoded}")


class AbuseIPDBClient(PlatformClient):
    def __init__(self, api_key: str, ca_file: str | None = None):
        super().__init__("https://api.abuseipdb.com", "abuseipdb", ca_file=ca_file)
        self._api_key = api_key

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        headers["Key"] = self._api_key
        return headers

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict[str, Any]:
        return self.get(
            "/api/v2/check",
            query={
                "ipAddress": ip,
                "maxAgeInDays": str(max_age_days),
                "verbose": "true",
            },
        )


class ShodanClient(PlatformClient):
    def __init__(self, api_key: str, ca_file: str | None = None):
        super().__init__("https://api.shodan.io", "shodan", ca_file=ca_file)
        self._api_key = api_key

    def host_lookup(self, ip: str) -> dict[str, Any]:
        return self.get(
            f"/shodan/host/{ip}",
            query={"key": self._api_key, "minify": "true"},
        )

    def search(self, query: str, limit: int = 20) -> dict[str, Any]:
        return self.get(
            "/shodan/host/search",
            query={"key": self._api_key, "query": query, "limit": str(limit)},
        )


class URLScanClient(PlatformClient):
    def __init__(self, api_key: str | None = None, ca_file: str | None = None):
        super().__init__("https://urlscan.io", "urlscan", ca_file=ca_file)
        self._api_key = api_key

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        if self._api_key:
            headers["API-Key"] = self._api_key
        return headers

    def search(self, query: str, size: int = 20) -> dict[str, Any]:
        return self.get("/api/v1/search/", query={"q": query, "size": str(size)})

    def get_result(self, result_id: str) -> dict[str, Any]:
        return self.get(f"/api/v1/result/{result_id}/")


class PhishTankClient(PlatformClient):
    def __init__(self, app_key: str | None = None, ca_file: str | None = None):
        super().__init__("https://checkurl.phishtank.com", "phishtank", ca_file=ca_file)
        self._app_key = app_key

    def check_url(self, url: str) -> dict[str, Any]:
        query: dict[str, str] = {"url": url, "format": "json"}
        if self._app_key:
            query["app_key"] = self._app_key
        return self.post(
            "/checkurl/",
            body=query,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )


class HybridAnalysisClient(PlatformClient):
    def __init__(self, api_key: str, ca_file: str | None = None):
        super().__init__(
            "https://www.hybrid-analysis.com", "hybrid-analysis", ca_file=ca_file
        )
        self._api_key = api_key

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        headers["api-key"] = self._api_key
        return headers

    def hash_search(self, hash_value: str) -> dict[str, Any]:
        return self.get("/api/v2/search/hash", query={"hash": hash_value})

    def report_summary(self, sha256: str) -> dict[str, Any]:
        return self.get(f"/api/v2/report/{sha256}/summary")


class MISPClient(PlatformClient):
    def __init__(self, base_url: str, api_key: str, ca_file: str | None = None):
        super().__init__(base_url, "misp", ca_file=ca_file)
        self._api_key = api_key

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        headers["Authorization"] = self._api_key
        return headers

    def attribute_search(self, body: dict[str, Any]) -> dict[str, Any]:
        return self.post("/attributes/restSearch", body=body)

    def event_search(self, body: dict[str, Any]) -> dict[str, Any]:
        return self.post("/events/restSearch", body=body)


class EnrichmentClient:
    """Unified enrichment interface across all threat intel platforms."""

    def __init__(self, config: dict[str, Any]):
        self._clients: dict[str, Any] = {}
        self._init_clients(config)

    def _init_clients(self, config: dict[str, Any]) -> None:
        platforms = config.get("platforms", {})

        if platforms.get("virustotal", {}).get("enabled"):
            key = os.environ.get(
                platforms["virustotal"].get("credential_env", ""), ""
            )
            if key:
                self._clients["virustotal"] = VirusTotalClient(key)

        if platforms.get("abuseipdb", {}).get("enabled"):
            key = os.environ.get(
                platforms["abuseipdb"].get("credential_env", ""), ""
            )
            if key:
                self._clients["abuseipdb"] = AbuseIPDBClient(key)

        if platforms.get("shodan", {}).get("enabled"):
            key = os.environ.get(
                platforms["shodan"].get("credential_env", ""), ""
            )
            if key:
                self._clients["shodan"] = ShodanClient(key)

        if platforms.get("urlscan", {}).get("enabled"):
            key = os.environ.get(
                platforms["urlscan"].get("credential_env", ""), ""
            )
            self._clients["urlscan"] = URLScanClient(key or None)

        if platforms.get("hybrid_analysis", {}).get("enabled"):
            key = os.environ.get(
                platforms["hybrid_analysis"].get("credential_env", ""), ""
            )
            if key:
                self._clients["hybrid-analysis"] = HybridAnalysisClient(key)

    def enrich_ip(self, ip: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if "virustotal" in self._clients:
            try:
                results["virustotal"] = self._clients["virustotal"].lookup_ip(ip)
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        if "abuseipdb" in self._clients:
            try:
                results["abuseipdb"] = self._clients["abuseipdb"].check_ip(ip)
            except Exception as e:
                results["abuseipdb"] = {"error": str(e)}
        if "shodan" in self._clients:
            try:
                results["shodan"] = self._clients["shodan"].host_lookup(ip)
            except Exception as e:
                results["shodan"] = {"error": str(e)}
        audit("enrichment_ip", ip=ip, platforms=list(results.keys()))
        return results

    def enrich_domain(self, domain: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if "virustotal" in self._clients:
            try:
                results["virustotal"] = self._clients["virustotal"].lookup_domain(domain)
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        audit("enrichment_domain", domain=domain, platforms=list(results.keys()))
        return results

    def enrich_hash(self, hash_value: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if "virustotal" in self._clients:
            try:
                results["virustotal"] = self._clients["virustotal"].lookup_file(hash_value)
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        if "hybrid-analysis" in self._clients:
            try:
                results["hybrid-analysis"] = self._clients["hybrid-analysis"].hash_search(hash_value)
            except Exception as e:
                results["hybrid-analysis"] = {"error": str(e)}
        audit("enrichment_hash", hash_value=hash_value, platforms=list(results.keys()))
        return results

    def enrich_url(self, url: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if "virustotal" in self._clients:
            try:
                results["virustotal"] = self._clients["virustotal"].lookup_url(url)
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        audit("enrichment_url", url=url, platforms=list(results.keys()))
        return results

    def enrich(self, ioc_type: str, value: str) -> dict[str, Any]:
        enrichers = {
            "ip": self.enrich_ip,
            "domain": self.enrich_domain,
            "hash": self.enrich_hash,
            "sha256": self.enrich_hash,
            "md5": self.enrich_hash,
            "url": self.enrich_url,
        }
        enricher = enrichers.get(ioc_type)
        if not enricher:
            return {"error": f"Unsupported IOC type: {ioc_type}"}
        return enricher(value)
