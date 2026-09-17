"""Idempotent synchronization between local records and SOC platforms."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from scripts.common import audit


def record_external_object(
    conn,
    *,
    org_id: int,
    platform: str,
    object_type: str,
    external_id: str,
    local_case_id: int | None = None,
    local_alert_id: int | None = None,
    external_updated_at: str | None = None,
    payload: Any = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    canonical = json.dumps(payload, sort_keys=True, default=str) if payload is not None else ""
    payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest() if canonical else None
    conn.execute(
        """
        INSERT INTO external_objects
            (org_id, platform, object_type, external_id, local_case_id, local_alert_id,
             external_updated_at, payload_hash, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(org_id, platform, object_type, external_id) DO UPDATE SET
            local_case_id = COALESCE(excluded.local_case_id, external_objects.local_case_id),
            local_alert_id = COALESCE(excluded.local_alert_id, external_objects.local_alert_id),
            external_updated_at = COALESCE(excluded.external_updated_at, external_objects.external_updated_at),
            payload_hash = COALESCE(excluded.payload_hash, external_objects.payload_hash),
            metadata_json = excluded.metadata_json,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            org_id,
            platform,
            object_type,
            str(external_id),
            local_case_id,
            local_alert_id,
            external_updated_at,
            payload_hash,
            json.dumps(metadata or {}, sort_keys=True),
        ),
    )


def external_id_for_case(conn, *, org_id: int, platform: str, local_case_id: int, object_type: str) -> str | None:
    row = conn.execute(
        """
        SELECT external_id FROM external_objects
        WHERE org_id = ? AND platform = ? AND object_type = ? AND local_case_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (org_id, platform, object_type, local_case_id),
    ).fetchone()
    return str(row["external_id"]) if row else None


def sync_thehive_cases(conn, *, org_id: int, client: Any, limit: int = 5000) -> dict[str, Any]:
    _mark_sync_started(conn, org_id, "thehive", "case")
    try:
        records = _paged_thehive_cases(client, max(1, limit))
        seen = changed = 0
        for payload in records:
            external_id = _external_id(payload)
            if not external_id:
                continue
            seen += 1
            canonical = json.dumps(payload, sort_keys=True, default=str)
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            existing = conn.execute(
                """
                SELECT id, local_case_id, payload_hash FROM external_objects
                WHERE org_id = ? AND platform = 'thehive' AND object_type = 'case' AND external_id = ?
                """,
                (org_id, external_id),
            ).fetchone()
            if not existing:
                legacy_case = conn.execute(
                    "SELECT id FROM cases WHERE org_id = ? AND case_id = ? ORDER BY id LIMIT 1",
                    (org_id, external_id),
                ).fetchone()
                if legacy_case:
                    existing = {"id": None, "local_case_id": legacy_case["id"], "payload_hash": None}
            if existing and existing["payload_hash"] == digest:
                continue
            title = str(payload.get("title") or payload.get("name") or f"TheHive case {external_id}")[:300]
            summary = str(payload.get("description") or payload.get("summary") or "")[:5000]
            severity = _thehive_severity(payload.get("severity"))
            status = _thehive_status(payload.get("status"))
            source_updated_at = _timestamp(payload.get("updatedAt") or payload.get("updated_at"))
            opened_at = _timestamp(payload.get("createdAt") or payload.get("created_at"))
            if existing and existing["local_case_id"]:
                local_case_id = int(existing["local_case_id"])
                conn.execute(
                    """
                    UPDATE cases SET title = ?, summary = ?, severity = ?, status = ?,
                        case_id = ?, source_platform = 'thehive', source_updated_at = ?,
                        closed_at = CASE WHEN ? = 'closed' THEN COALESCE(closed_at, ?) ELSE closed_at END,
                        row_version = COALESCE(row_version, 0) + 1
                    WHERE id = ? AND org_id = ?
                    """,
                    (title, summary, severity, status, external_id, source_updated_at, status, source_updated_at, local_case_id, org_id),
                )
            else:
                local_case_id = int(
                    conn.execute(
                        """
                        INSERT INTO cases
                            (org_id, case_id, title, severity, status, summary, opened_at,
                             source_platform, source_updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), 'thehive', ?)
                        """,
                        (org_id, external_id, title, severity, status, summary, opened_at, source_updated_at),
                    ).lastrowid
                )
            record_external_object(
                conn,
                org_id=org_id,
                platform="thehive",
                object_type="case",
                external_id=external_id,
                local_case_id=local_case_id,
                external_updated_at=source_updated_at,
                payload=payload,
            )
            changed += 1
        _mark_sync_completed(conn, org_id, "thehive", "case", seen, changed)
        audit("thehive_cases_synchronized", org_id=org_id, seen=seen, changed=changed)
        return {"platform": "thehive", "object_type": "case", "seen": seen, "changed": changed}
    except Exception as exc:
        _mark_sync_failed(conn, org_id, "thehive", "case", exc)
        raise


def sync_misp_events(conn, *, org_id: int, client: Any, limit: int = 5000) -> dict[str, Any]:
    _mark_sync_started(conn, org_id, "misp", "event")
    try:
        records = _paged_misp_events(client, max(1, limit))
        seen = changed = 0
        for wrapper in records:
            payload = wrapper.get("Event", wrapper) if isinstance(wrapper, dict) else {}
            if not isinstance(payload, dict):
                continue
            external_id = _external_id(payload)
            if not external_id:
                continue
            seen += 1
            canonical = json.dumps(payload, sort_keys=True, default=str)
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            current = conn.execute(
                "SELECT payload_hash FROM external_objects WHERE org_id = ? AND platform = 'misp' AND object_type = 'event' AND external_id = ?",
                (org_id, external_id),
            ).fetchone()
            if current and current["payload_hash"] == digest:
                continue
            attributes = payload.get("Attribute") or payload.get("attributes") or []
            tags = payload.get("Tag") or payload.get("tags") or []
            source_updated_at = _timestamp(payload.get("timestamp") or payload.get("publish_timestamp"))
            conn.execute(
                """
                INSERT INTO intel_events
                    (org_id, platform, external_id, title, threat_level, analysis_status,
                     published, event_date, tags_json, attributes_json, raw_payload,
                     source_updated_at)
                VALUES (?, 'misp', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id, platform, external_id) DO UPDATE SET
                    title = excluded.title,
                    threat_level = excluded.threat_level,
                    analysis_status = excluded.analysis_status,
                    published = excluded.published,
                    event_date = excluded.event_date,
                    tags_json = excluded.tags_json,
                    attributes_json = excluded.attributes_json,
                    raw_payload = excluded.raw_payload,
                    source_updated_at = excluded.source_updated_at,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    org_id,
                    external_id,
                    str(payload.get("info") or f"MISP event {external_id}")[:500],
                    str(payload.get("threat_level_id") or ""),
                    str(payload.get("analysis") or ""),
                    1 if str(payload.get("published", "0")).lower() in {"1", "true"} else 0,
                    str(payload.get("date") or "")[:32],
                    json.dumps(tags, sort_keys=True, default=str),
                    json.dumps(attributes, sort_keys=True, default=str),
                    canonical,
                    source_updated_at,
                ),
            )
            record_external_object(
                conn,
                org_id=org_id,
                platform="misp",
                object_type="event",
                external_id=external_id,
                external_updated_at=source_updated_at,
                payload=payload,
            )
            changed += 1
        _mark_sync_completed(conn, org_id, "misp", "event", seen, changed)
        audit("misp_events_synchronized", org_id=org_id, seen=seen, changed=changed)
        return {"platform": "misp", "object_type": "event", "seen": seen, "changed": changed}
    except Exception as exc:
        _mark_sync_failed(conn, org_id, "misp", "event", exc)
        raise


def _mark_sync_started(conn, org_id: int, platform: str, object_type: str) -> None:
    conn.execute(
        """
        INSERT INTO integration_sync_state (org_id, platform, object_type, last_started_at, last_error)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, NULL)
        ON CONFLICT(org_id, platform, object_type) DO UPDATE SET
            last_started_at = CURRENT_TIMESTAMP, last_error = NULL
        """,
        (org_id, platform, object_type),
    )


def _mark_sync_completed(conn, org_id: int, platform: str, object_type: str, seen: int, changed: int) -> None:
    conn.execute(
        """
        UPDATE integration_sync_state SET last_completed_at = CURRENT_TIMESTAMP,
            last_error = NULL, records_seen = ?, records_changed = ?
        WHERE org_id = ? AND platform = ? AND object_type = ?
        """,
        (seen, changed, org_id, platform, object_type),
    )


def _mark_sync_failed(conn, org_id: int, platform: str, object_type: str, exc: Exception) -> None:
    conn.execute(
        """
        INSERT INTO integration_sync_state (org_id, platform, object_type, last_started_at, last_error)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
        ON CONFLICT(org_id, platform, object_type) DO UPDATE SET last_error = excluded.last_error
        """,
        (org_id, platform, object_type, str(exc)[:500]),
    )


def _as_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("cases", "data", "results"):
            if isinstance(value.get(key), list):
                return [item for item in value[key] if isinstance(item, dict)]
    return []


def _paged_thehive_cases(client: Any, limit: int) -> list[dict[str, Any]]:
    page_size = min(200, limit)
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for start in range(0, limit, page_size):
        try:
            page = _as_records(client.list_cases(limit=min(page_size, limit - start), start=start))
        except TypeError:  # Compatibility with an older custom client adapter.
            page = _as_records(client.list_cases(limit=min(page_size, limit - start)))
        novel = [item for item in page if _external_id(item) not in identifiers]
        if not novel:
            break
        records.extend(novel)
        identifiers.update(_external_id(item) for item in novel)
        if len(page) < page_size:
            break
    return records


def _paged_misp_events(client: Any, limit: int) -> list[dict[str, Any]]:
    page_size = min(200, limit)
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for page_number in range(1, (limit + page_size - 1) // page_size + 1):
        response = client.event_search(
            {"returnFormat": "json", "limit": min(page_size, limit - len(records)), "page": page_number}
        )
        page = _as_misp_events(response)
        novel = []
        for wrapper in page:
            payload = wrapper.get("Event", wrapper)
            external_id = _external_id(payload) if isinstance(payload, dict) else ""
            if external_id and external_id not in identifiers:
                identifiers.add(external_id)
                novel.append(wrapper)
        if not novel:
            break
        records.extend(novel)
        if len(page) < page_size or len(records) >= limit:
            break
    return records[:limit]


def _as_misp_events(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("response", "Event", "events"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return [item for item in candidate if isinstance(item, dict)]
            if isinstance(candidate, dict):
                return [{"Event": candidate}]
    return []


def _external_id(payload: dict[str, Any]) -> str:
    return str(payload.get("_id") or payload.get("id") or payload.get("uuid") or "").strip()


def _thehive_severity(value: Any) -> str:
    try:
        return {1: "low", 2: "medium", 3: "high", 4: "critical"}.get(int(value), "medium")
    except (TypeError, ValueError):
        text = str(value or "medium").lower()
        return text if text in {"info", "low", "medium", "high", "critical"} else "medium"


def _thehive_status(value: Any) -> str:
    text = str(value or "open").lower()
    return "closed" if text in {"resolved", "closed", "deleted"} else "open"


def _timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000 if float(value) > 10_000_000_000 else float(value)
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
    return str(value)[:64]
