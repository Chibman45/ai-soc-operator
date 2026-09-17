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

    def create_event(self, info: str) -> dict[str, Any]:
        """Create a private MISP event for an explicitly approved export."""
        return self.post(
            "/events/add",
            body={"Event": {"info": info, "distribution": 0, "threat_level_id": 2, "analysis": 1}},
        )

    def add_attribute(self, event_id: str, attribute_type: str, value: str) -> dict[str, Any]:
        return self.post(
            f"/attributes/add/{event_id}",
            body={
                "Attribute": {
                    "type": attribute_type,
                    "category": "Network activity" if attribute_type in {"ip-src", "ip-dst", "domain", "url"} else "Payload delivery",
                    "value": value,
                    "to_ids": True,
                    "distribution": 0,
                }
            },
        )


class EnrichmentClient:
    """Unified enrichment interface across all threat intel platforms."""

    def __init__(self, config: dict[str, Any], credentials: dict[str, str] | None = None):
        self._clients: dict[str, Any] = {}
        self._credentials = credentials or {}
        self._init_clients(config)

    def _secret(self, name: str) -> str:
        return self._credentials.get(name, "") or os.environ.get(name, "")

    def _init_clients(self, config: dict[str, Any]) -> None:
        platforms = config.get("platforms", {})

        if platforms.get("virustotal", {}).get("enabled"):
            key = self._secret(platforms["virustotal"].get("credential_env", ""))
            if key:
                self._clients["virustotal"] = VirusTotalClient(key)

        if platforms.get("abuseipdb", {}).get("enabled"):
            key = self._secret(platforms["abuseipdb"].get("credential_env", ""))
            if key:
                self._clients["abuseipdb"] = AbuseIPDBClient(key)

        if platforms.get("shodan", {}).get("enabled"):
            key = self._secret(platforms["shodan"].get("credential_env", ""))
            if key:
                self._clients["shodan"] = ShodanClient(key)

        if platforms.get("urlscan", {}).get("enabled"):
            key = self._secret(platforms["urlscan"].get("credential_env", ""))
            self._clients["urlscan"] = URLScanClient(key or None)

        if platforms.get("hybrid_analysis", {}).get("enabled"):
            key = self._secret(platforms["hybrid_analysis"].get("credential_env", ""))
            if key:
                self._clients["hybrid-analysis"] = HybridAnalysisClient(key)

        if platforms.get("phishtank", {}).get("enabled"):
            key = self._secret(platforms["phishtank"].get("credential_env", ""))
            self._clients["phishtank"] = PhishTankClient(key or None)

        if platforms.get("cortex", {}).get("enabled"):
            key = self._secret(platforms["cortex"].get("credential_env", ""))
            base_url = platforms["cortex"].get("base_url", "")
            if key and base_url:
                from .cortex import CortexClient
                self._clients["cortex"] = CortexClient(base_url, key)

        if platforms.get("misp", {}).get("enabled"):
            key = self._secret(platforms["misp"].get("credential_env", ""))
            base_url = platforms["misp"].get("base_url", "")
            if key and base_url:
                self._clients["misp"] = MISPClient(base_url, key)

    def _misp_lookup(self, value: str) -> dict[str, Any] | None:
        """Search MISP for a raw IOC value across all attribute types."""
        client = self._clients.get("misp")
        if not client:
            return None
        try:
            return client.attribute_search({"value": value, "limit": 25})
        except Exception as e:
            return {"error": str(e)}

    def _phishtank_lookup(self, url: str) -> dict[str, Any] | None:
        """Check a URL against PhishTank's phishing database."""
        client = self._clients.get("phishtank")
        if not client:
            return None
        try:
            return client.check_url(url)
        except Exception as e:
            return {"error": str(e)[:200]}

    def _cortex_enrich(self, data_type: str, value: str) -> dict[str, Any] | None:
        """Run Cortex analyzers for an observable and collect their reports.

        Bounded by CORTEX_MAX_ANALYZERS (default 3) analyzers and a
        CORTEX_POLL_TIMEOUT (default 25s) total wait budget so a slow analyzer
        can't stall enrichment. Analyzers still running when the budget expires
        are returned with their job id and status 'running'.
        """
        client = self._clients.get("cortex")
        if not client:
            return None
        import time as _time

        try:
            max_analyzers = int(os.environ.get("CORTEX_MAX_ANALYZERS", "3") or "3")
        except ValueError:
            max_analyzers = 3
        try:
            poll_budget = float(os.environ.get("CORTEX_POLL_TIMEOUT", "25") or "25")
        except ValueError:
            poll_budget = 25.0

        try:
            analyzers = client.list_analyzers(data_type=data_type)
        except Exception as e:
            return {"error": f"list_analyzers failed: {str(e)[:150]}"}
        if not analyzers:
            return {
                "analyzers": [],
                "note": f"No Cortex analyzers available for dataType '{data_type}'",
            }

        reports: dict[str, Any] = {}
        pending: dict[str, str] = {}
        for a in analyzers[:max_analyzers]:
            analyzer_id = a.get("id") or a.get("_id") or a.get("name")
            name = a.get("name", analyzer_id)
            if not analyzer_id:
                continue
            try:
                job = client.run_analyzer(analyzer_id, data_type, value)
                jid = job.get("id") or job.get("_id")
                if jid:
                    pending[name] = jid
            except Exception as e:
                reports[name] = {"error": str(e)[:150]}

        deadline = _time.time() + poll_budget
        while pending and _time.time() < deadline:
            for name, jid in list(pending.items()):
                try:
                    job = client.get_job(jid)
                except Exception as e:
                    reports[name] = {"error": str(e)[:150]}
                    pending.pop(name, None)
                    continue
                status = (job.get("status") or "").lower()
                if status in ("success", "failure"):
                    reports[name] = {"status": status, "report": job.get("report", {})}
                    pending.pop(name, None)
            if pending:
                _time.sleep(2)
        for name, jid in pending.items():
            reports[name] = {"status": "running", "job_id": jid}
        return {"analyzers_run": list(reports.keys()), "reports": reports}

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
        cortex = self._cortex_enrich("ip", ip)
        if cortex is not None:
            results["cortex"] = cortex
        misp = self._misp_lookup(ip)
        if misp is not None:
            results["misp"] = misp
        audit("enrichment_ip", ip=ip, platforms=list(results.keys()))
        return results

    def enrich_domain(self, domain: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if "virustotal" in self._clients:
            try:
                results["virustotal"] = self._clients["virustotal"].lookup_domain(domain)
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        cortex = self._cortex_enrich("domain", domain)
        if cortex is not None:
            results["cortex"] = cortex
        misp = self._misp_lookup(domain)
        if misp is not None:
            results["misp"] = misp
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
        cortex = self._cortex_enrich("hash", hash_value)
        if cortex is not None:
            results["cortex"] = cortex
        misp = self._misp_lookup(hash_value)
        if misp is not None:
            results["misp"] = misp
        audit("enrichment_hash", hash_value=hash_value, platforms=list(results.keys()))
        return results

    def enrich_url(self, url: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if "virustotal" in self._clients:
            try:
                results["virustotal"] = self._clients["virustotal"].lookup_url(url)
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        phishtank = self._phishtank_lookup(url)
        if phishtank is not None:
            results["phishtank"] = phishtank
        cortex = self._cortex_enrich("url", url)
        if cortex is not None:
            results["cortex"] = cortex
        misp = self._misp_lookup(url)
        if misp is not None:
            results["misp"] = misp
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
