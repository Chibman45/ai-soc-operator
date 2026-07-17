"""Cortex API client for analyzer and responder operations.

Supports:
- List available analyzers and responders
- Run analyzers against observables (requires elevated approval)
- Get job results and reports

Remote actions (run-analyzer) require scope, snapshot, and explicit approval.
"""

from __future__ import annotations

from typing import Any

try:
    from .base import PlatformClient
    from ..common import audit
except ImportError:
    from soc_client.base import PlatformClient
    from common import audit


class CortexClient(PlatformClient):
    """Cortex API client with safety controls for analyzer execution."""

    def __init__(self, base_url: str, api_key: str, ca_file: str | None = None):
        super().__init__(base_url, "cortex", ca_file=ca_file)
        self._api_key = api_key

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def list_analyzers(
        self,
        data_type: str | None = None,
    ) -> list[dict[str, Any]]:
        query: dict[str, str] = {}
        if data_type:
            query["dataType"] = data_type
        result = self.get("/api/analyzer", query=query)
        if isinstance(result, list):
            return result
        return result.get("data", [])

    def get_analyzer(self, analyzer_id: str) -> dict[str, Any]:
        return self.get(f"/api/analyzer/{analyzer_id}")

    def run_analyzer(
        self,
        analyzer_id: str,
        data_type: str,
        data: str,
        tlp: int = 2,
        message: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "dataType": data_type,
            "data": data,
            "tlp": tlp,
            "message": message,
        }
        if parameters:
            body["parameters"] = parameters
        result = self.post(f"/api/analyzer/{analyzer_id}/run", body=body)
        audit(
            "cortex_analyzer_run",
            analyzer_id=analyzer_id,
            data_type=data_type,
            data=data[:100],
            job_id=result.get("id"),
        )
        return result

    def get_job(self, job_id: str) -> dict[str, Any]:
        return self.get(f"/api/job/{job_id}")

    def get_job_report(self, job_id: str, report_id: str) -> dict[str, Any]:
        return self.get(f"/api/job/{job_id}/report/{report_id}")

    def list_responders(
        self,
        entity_type: str | None = None,
    ) -> list[dict[str, Any]]:
        query: dict[str, str] = {}
        if entity_type:
            query["entity_type"] = entity_type
        result = self.get("/api/responder", query=query)
        if isinstance(result, list):
            return result
        return result.get("data", [])

    def run_responder(
        self,
        responder_id: str,
        entity_type: str,
        entity_id: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "entity_type": entity_type,
            "entity_id": entity_id,
        }
        if parameters:
            body["parameters"] = parameters
        result = self.post(f"/api/responder/{responder_id}/run", body=body)
        audit(
            "cortex_responder_run",
            responder_id=responder_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )
        return result

    def list_organization_analyzers(self) -> list[dict[str, Any]]:
        result = self.get("/api/org/analyzer")
        if isinstance(result, list):
            return result
        return result.get("data", [])

    def list_organization_responders(self) -> list[dict[str, Any]]:
        result = self.get("/api/org/responder")
        if isinstance(result, list):
            return result
        return result.get("data", [])
