"""Wazuh API client for alert search and manager operations.

Supports:
- Wazuh Manager: server info, rules, decoders, stats
- Wazuh Indexer: alert search (Elasticsearch-compatible queries)

Read-only by default. Configuration changes require separate approval.
"""

from __future__ import annotations

import json
from typing import Any

try:
    from .base import PlatformClient
    from ..common import audit
except ImportError:
    from soc_client.base import PlatformClient
    from common import audit


class WazuhManagerClient(PlatformClient):
    """Wazuh Manager API client."""

    def __init__(self, base_url: str, api_token: str, ca_file: str | None = None):
        super().__init__(base_url, "wazuh-manager", ca_file=ca_file)
        self._api_token = api_token

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        headers["Authorization"] = f"Bearer {self._api_token}"
        return headers

    def get_manager_info(self) -> dict[str, Any]:
        return self.get("/manager/info")

    def get_rules(self, limit: int = 100) -> list[dict[str, Any]]:
        result = self.get("/rules", query={"limit": str(limit)})
        if isinstance(result, dict):
            return result.get("data", {}).get("affected_items", [])
        return []

    def get_rules_files(self) -> list[dict[str, Any]]:
        result = self.get("/rules/files")
        if isinstance(result, dict):
            return result.get("data", {}).get("affected_items", [])
        return []

    def get_decoders(self, limit: int = 100) -> list[dict[str, Any]]:
        result = self.get("/decoders", query={"limit": str(limit)})
        if isinstance(result, dict):
            return result.get("data", {}).get("affected_items", [])
        return []

    def get_stats(self) -> dict[str, Any]:
        return self.get("/stats/analysisd")

    def search_agent_alerts(
        self,
        agent_id: str,
        rule_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query: dict[str, str] = {"limit": str(limit)}
        if rule_id:
            query["rule_id"] = rule_id
        result = self.get(f"/alerts/agents/{agent_id}", query=query)
        if isinstance(result, dict):
            return result.get("data", {}).get("affected_items", [])
        return []

    def get_agent_summary(self) -> dict[str, Any]:
        return self.get("/agents/summary")


class WazuhIndexerClient(PlatformClient):
    """Wazuh Indexer (Elasticsearch-compatible) client for alert search."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        ca_file: str | None = None,
    ):
        super().__init__(base_url, "wazuh-indexer", ca_file=ca_file)
        self._username = username
        self._password = password

    def _build_headers(self, **extra: str) -> dict[str, str]:
        import base64
        credentials = base64.b64encode(
            f"{self._username}:{self._password}".encode()
        ).decode()
        headers = super()._build_headers(**extra)
        headers["Authorization"] = f"Basic {credentials}"
        return headers

    def search_alerts(
        self,
        query: dict[str, Any] | None = None,
        sort: list[dict[str, Any]] | None = None,
        size: int = 100,
        index: str = "wazuh-alerts-*",
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "query": query or {"match_all": {}},
            "size": size,
        }
        if sort:
            body["sort"] = sort
        result = self.post(f"/{index}/_search", body=body)
        audit("wazuh_indexer_search", index=index, size=size)
        return result

    def search_alerts_by_rule(
        self,
        rule_id: str,
        size: int = 100,
        index: str = "wazuh-alerts-*",
    ) -> dict[str, Any]:
        return self.search_alerts(
            query={"term": {"rule.id": rule_id}},
            sort=[{"timestamp": {"order": "desc"}}],
            size=size,
            index=index,
        )

    def search_alerts_by_agent(
        self,
        agent_id: str,
        size: int = 100,
        index: str = "wazuh-alerts-*",
    ) -> dict[str, Any]:
        return self.search_alerts(
            query={"term": {"agent.id": agent_id}},
            sort=[{"timestamp": {"order": "desc"}}],
            size=size,
            index=index,
        )

    def search_alerts_by_level(
        self,
        min_level: int = 10,
        size: int = 100,
        index: str = "wazuh-alerts-*",
    ) -> dict[str, Any]:
        return self.search_alerts(
            query={"range": {"rule.level": {"gte": min_level}}},
            sort=[{"timestamp": {"order": "desc"}}],
            size=size,
            index=index,
        )
