"""TheHive 5 API client for case and alert management.

Supports the operations needed for playbook-driven SOC automation:
- Case CRUD (create, update, comment, task, task log)
- Observable management (add to case)
- Alert management (list, get, handle/import)

Every write operation requires explicit approval and is audit-logged.
"""

from __future__ import annotations

from typing import Any

try:
    from .base import PlatformClient
    from ..common import audit
except ImportError:
    from soc_client.base import PlatformClient
    from common import audit


class TheHiveClient(PlatformClient):
    """TheHive 5 API client with safety controls."""

    def __init__(self, base_url: str, api_key: str, ca_file: str | None = None):
        super().__init__(base_url, "thehive", ca_file=ca_file)
        self._api_key = api_key

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = super()._build_headers(**extra)
        headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # ── Case operations ──

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: int = 2,
        tlp: int = 2,
        tags: list[str] | None = None,
        custom_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "tags": tags or [],
        }
        if custom_fields:
            body["customFieldValue"] = custom_fields
        result = self.post("/api/v1/case", body=body)
        audit("thehive_case_created", title=title, severity=severity, case_id=result.get("id"))
        return result

    def update_case(self, case_id: str, **fields: Any) -> dict[str, Any]:
        result = self.patch(f"/api/v1/case/{case_id}", body=fields)
        audit("thehive_case_updated", case_id=case_id, fields=list(fields.keys()))
        return result

    def get_case(self, case_id: str) -> dict[str, Any]:
        return self.get(f"/api/v1/case/{case_id}")

    def list_cases(
        self,
        query: dict[str, Any] | None = None,
        sort: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {
            "query": query or {},
            "sort": sort or ["-createdAt"],
            "range": f"0-{limit}",
        }
        return self.post("/api/v1/case/_search", body=body)

    # ── Comment operations ──

    def add_comment(self, case_id: str, message: str) -> dict[str, Any]:
        result = self.post(
            f"/api/v1/case/{case_id}/comment",
            body={"message": message},
        )
        audit("thehive_comment_added", case_id=case_id)
        return result

    # ── Task operations ──

    def add_task(
        self,
        case_id: str,
        title: str,
        status: str = "Waiting",
        assignee: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"title": title, "status": status}
        if assignee:
            body["assignee"] = assignee
        result = self.post(f"/api/v1/case/{case_id}/task", body=body)
        audit("thehive_task_created", case_id=case_id, title=title)
        return result

    def add_task_log(self, case_id: str, task_id: str, message: str) -> dict[str, Any]:
        result = self.post(
            f"/api/v1/case/{case_id}/task/{task_id}/log",
            body={"message": message},
        )
        audit("thehive_task_log_added", case_id=case_id, task_id=task_id)
        return result

    def update_task(
        self, case_id: str, task_id: str, status: str
    ) -> dict[str, Any]:
        result = self.patch(
            f"/api/v1/case/{case_id}/task/{task_id}",
            body={"status": status},
        )
        audit("thehive_task_updated", case_id=case_id, task_id=task_id, status=status)
        return result

    # ── Observable operations ──

    def add_observable(
        self,
        case_id: str,
        data_type: str,
        data: str,
        message: str = "",
        tlp: int = 2,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "dataType": data_type,
            "data": data,
            "message": message,
            "tlp": tlp,
            "tags": tags or [],
        }
        result = self.post(f"/api/v1/case/{case_id}/observable", body=body)
        audit(
            "thehive_observable_added",
            case_id=case_id,
            data_type=data_type,
            data=data[:100],
        )
        return result

    # ── Alert operations ──

    def list_alerts(
        self,
        query: dict[str, Any] | None = None,
        sort: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {
            "query": query or {},
            "sort": sort or ["-createdAt"],
            "range": f"0-{limit}",
        }
        return self.post("/api/v1/alert/_search", body=body)

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        return self.get(f"/api/v1/alert/{alert_id}")

    def handle_alert(
        self,
        alert_id: str,
        case_id: str | None = None,
        merge_in_case: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if case_id:
            body["importToCase"] = {
                "caseId": case_id,
                "mergeInCase": merge_in_case,
            }
        result = self.post(f"/api/v1/alert/{alert_id}/action/_run", body=body)
        audit("thehive_alert_handled", alert_id=alert_id, case_id=case_id)
        return result

    def create_alert(
        self,
        title: str,
        description: str = "",
        severity: int = 2,
        source: str = "ai-soc-operator",
        tags: list[str] | None = None,
        observables: list[dict[str, Any]] | None = None,
        case_template: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "source": source,
            "tags": tags or [],
            "type": "internal",
            "observables": observables or [],
        }
        if case_template:
            body["caseTemplate"] = case_template
        result = self.post("/api/v1/alert", body=body)
        audit("thehive_alert_created", title=title, source=source)
        return result
