"""Alert normalization, IOC extraction, and ingestion helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scripts.common import ROOT, audit
from scripts.learning import learn_alert
from scripts.orchestrator import auto_select_playbook, extract_iocs


SUPPORTED_SOURCES = {"generic", "manual", "wazuh", "elastic", "elasticsearch"}


def normalize_alert(source: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize SIEM-specific payloads into the internal alert shape."""
    source_key = (source or "generic").lower()
    if source_key == "wazuh":
        return _normalize_wazuh(payload)
    if source_key in {"elastic", "elasticsearch"}:
        return _normalize_elastic(payload)
    return _normalize_generic(payload)


def observables_from_alert(
    normalized: dict[str, Any],
    supplied: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Merge supplied observables with extracted IOCs."""
    merged: list[dict[str, str]] = []
    seen = set()
    for item in [*(supplied or []), *extract_iocs(normalized), *_regex_iocs(normalized)]:
        ioc_type = str(item.get("type", "")).strip().lower()
        value = str(item.get("value", "")).strip()
        if not ioc_type or not value:
            continue
        key = (ioc_type, value.lower())
        if key in seen:
            continue
        seen.add(key)
        merged.append({"type": ioc_type, "value": value})
    return merged


def ingest_alert_record(
    conn,
    *,
    source: str,
    source_alert_id: str | None,
    payload: dict[str, Any],
    supplied_observables: list[dict[str, str]] | None = None,
    org_id: int | None = None,
) -> dict[str, Any]:
    """Store an alert, correlate IOCs, select playbook, and optionally queue it."""
    from web.app import job_queue, load_config_for_web, _execute_run_job

    normalized = normalize_alert(source, payload)
    observables = observables_from_alert(normalized, supplied_observables)
    playbook_path = auto_select_playbook(normalized, ROOT / "playbooks")
    selected_playbook = playbook_path.name if playbook_path else None

    linked_case_id = find_correlated_case(conn, observables, org_id=org_id)
    status = "linked" if linked_case_id else ("queued" if playbook_path else "new")
    cursor = conn.execute(
        """
        INSERT INTO alerts
            (org_id, source, source_alert_id, case_id, title, severity, raw_payload,
             normalized_payload, status, selected_playbook, queued_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            org_id,
            source,
            source_alert_id,
            linked_case_id,
            normalized.get("title", "Untitled alert"),
            normalized.get("severity", "medium"),
            json.dumps(payload, sort_keys=True),
            json.dumps(normalized, sort_keys=True),
            status,
            selected_playbook,
        ),
    )
    alert_id = int(cursor.lastrowid)
    for obs in observables:
        upsert_observable(
            conn,
            obs_type=obs["type"],
            value=obs["value"],
            source=source,
            alert_id=alert_id,
            case_id=linked_case_id,
            org_id=org_id,
        )
    # Commit the alert + observables now so the background worker (which opens
    # its own DB connection) can see these rows, and so we don't hold a write
    # lock on the shared SQLite file while the playbook job runs.
    conn.commit()

    job_id = None
    if playbook_path and not linked_case_id:
        config = load_config_for_web()
        job_id = job_queue.create_job(
            run_id=0,
            playbook_path=str(playbook_path),
            alert=normalized,
            config=config,
        )
        conn.execute(
            "UPDATE alerts SET job_id = ?, status = 'queued' WHERE id = ?",
            (job_id, alert_id),
        )
        conn.commit()

        def execute(alert_data: dict, progress_cb):
            # Runs in a background worker thread. sqlite3 connections are bound
            # to the thread that created them, so open a fresh connection here
            # rather than reusing the request-thread `conn`.
            from web.app import get_db

            wconn = get_db()
            try:
                run_id = _create_run_for_ingested_alert(
                    wconn,
                    selected_playbook or playbook_path.name,
                    alert_id,
                    source,
                )
                wconn.execute("UPDATE jobs SET run_id = ? WHERE id = ?", (run_id, job_id))
                wconn.execute("UPDATE alerts SET status = 'running' WHERE id = ?", (alert_id,))
                wconn.commit()
                try:
                    result = _execute_run_job(run_id, playbook_path, alert_data, config, progress_cb)
                    case = wconn.execute(
                        "SELECT id FROM cases WHERE run_id = ? ORDER BY id DESC LIMIT 1",
                        (run_id,),
                    ).fetchone()
                    case_id = case["id"] if case else None
                    wconn.execute(
                        """
                        UPDATE alerts
                        SET status = 'case_created', case_id = ?, first_response_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (case_id, alert_id),
                    )
                    if case_id:
                        wconn.execute(
                            "UPDATE observables SET case_id = ? WHERE alert_id = ? AND case_id IS NULL",
                            (case_id, alert_id),
                        )
                    wconn.commit()
                    return result
                except Exception:
                    wconn.execute("UPDATE alerts SET status = 'failed' WHERE id = ?", (alert_id,))
                    wconn.commit()
                    raise
            finally:
                wconn.close()

        job_queue.execute_job(job_id, execute)

    learn_alert(normalized, source=source, playbook=selected_playbook)
    audit(
        "alert_ingested",
        source=source,
        alert_id=alert_id,
        playbook=selected_playbook,
        status=status,
        case_id=linked_case_id,
        job_id=job_id,
    )
    return {
        "alert_id": alert_id,
        "case_id": linked_case_id,
        "job_id": job_id,
        "status": "linked" if linked_case_id else ("queued" if job_id else "new"),
        "playbook": selected_playbook,
        "normalized": normalized,
        "observables": observables,
    }


def find_correlated_case(
    conn,
    observables: list[dict[str, str]],
    org_id: int | None = None,
) -> int | None:
    for obs in observables:
        query = "SELECT case_id FROM observables WHERE type = ? AND value = ? AND case_id IS NOT NULL"
        params: list[Any] = [obs.get("type", ""), obs.get("value", "")]
        if org_id is not None:
            query += " AND (org_id = ? OR org_id IS NULL)"
            params.append(org_id)
        query += " ORDER BY last_seen DESC LIMIT 1"
        row = conn.execute(query, params).fetchone()
        if row:
            return int(row["case_id"])
    return None


def upsert_observable(
    conn,
    *,
    obs_type: str,
    value: str,
    source: str,
    alert_id: int | None = None,
    case_id: int | None = None,
    org_id: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    existing = conn.execute(
        """
        SELECT id FROM observables
        WHERE type = ? AND value = ? AND IFNULL(case_id, 0) = IFNULL(?, 0)
          AND IFNULL(alert_id, 0) = IFNULL(?, 0)
        LIMIT 1
        """,
        (obs_type, value, case_id, alert_id),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE observables SET last_seen = CURRENT_TIMESTAMP WHERE id = ?",
            (existing["id"],),
        )
        return
    conn.execute(
        """
        INSERT INTO observables
            (org_id, alert_id, case_id, type, value, source, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (org_id, alert_id, case_id, obs_type, value, source, json.dumps(metadata or {})),
    )


def _create_run_for_ingested_alert(conn, playbook: str, alert_id: int, source: str) -> int:
    cursor = conn.execute(
        "INSERT INTO runs (playbook, alert_file, status) VALUES (?, ?, 'running')",
        (playbook, f"ingested-alert:{alert_id}"),
    )
    run_id = int(cursor.lastrowid)
    conn.execute(
        "INSERT INTO activity_log (run_id, step, status, detail) VALUES (?, 'ingest', 'running', ?)",
        (run_id, f"Queued from {source} alert {alert_id}"),
    )
    return run_id


def _normalize_generic(payload: dict[str, Any]) -> dict[str, Any]:
    alert = payload.get("payload") if "payload" in payload and isinstance(payload.get("payload"), dict) else payload
    title = alert.get("title") or alert.get("name") or alert.get("message") or "Generic Alert"
    normalized = {
        "title": title,
        "description": alert.get("description", alert.get("message", "")),
        "severity": _normalize_severity(alert.get("severity", alert.get("level", "medium"))),
        "rule": alert.get("rule", {"name": title}),
        "agent": alert.get("agent", {}),
        "source": alert.get("source", {}),
        "destination": alert.get("destination", {}),
        "data": alert.get("data", {}),
        "tags": alert.get("tags", []),
        "timestamp": alert.get("timestamp"),
        "mitre": alert.get("mitre", {}),
    }
    for key in ("src_ip", "dst_ip", "domain", "hostname", "md5", "sha1", "sha256", "user"):
        if key in alert:
            normalized[key] = alert[key]
    return normalized


def _normalize_wazuh(payload: dict[str, Any]) -> dict[str, Any]:
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else payload
    data = alert.get("data", {}) or {}
    rule = alert.get("rule", {}) or {}
    normalized = _normalize_generic(
        {
            "title": rule.get("description") or rule.get("name") or alert.get("description") or "Wazuh Alert",
            "description": alert.get("full_log") or alert.get("description", ""),
            "severity": _wazuh_level_to_severity(rule.get("level", alert.get("level", 3))),
            "rule": {"id": str(rule.get("id", "")), "name": rule.get("description") or rule.get("name", "Wazuh Alert"), "level": rule.get("level", alert.get("level"))},
            "agent": alert.get("agent", {}),
            "data": data,
            "tags": [*rule.get("groups", []), "wazuh"],
            "timestamp": alert.get("timestamp"),
            "mitre": rule.get("mitre", alert.get("mitre", {})),
        }
    )
    if data.get("srcip") or data.get("src_ip"):
        normalized["source"] = {"ip": data.get("srcip") or data.get("src_ip")}
    if data.get("dstip") or data.get("dst_ip"):
        normalized["destination"] = {"ip": data.get("dstip") or data.get("dst_ip")}
    if data.get("user") or data.get("dstuser"):
        normalized["user"] = {"name": data.get("user") or data.get("dstuser")}
    return normalized


def _normalize_elastic(payload: dict[str, Any]) -> dict[str, Any]:
    alert = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
    rule = alert.get("kibana", {}).get("alert", {}).get("rule", {}) or alert.get("rule", {})
    event = alert.get("event", {})
    host = alert.get("host", {})
    source = alert.get("source", {})
    destination = alert.get("destination", {})
    title = rule.get("name") or alert.get("message") or event.get("action") or "Elastic Alert"
    return _normalize_generic(
        {
            "title": title,
            "description": alert.get("message", ""),
            "severity": _normalize_severity(rule.get("severity", alert.get("severity", "medium"))),
            "rule": {"id": str(rule.get("uuid", rule.get("id", ""))), "name": title},
            "agent": {"name": host.get("name", ""), "id": host.get("id", "")},
            "source": {"ip": source.get("ip")} if source.get("ip") else {},
            "destination": {"ip": destination.get("ip")} if destination.get("ip") else {},
            "data": alert,
            "tags": alert.get("tags", ["elastic"]),
            "timestamp": alert.get("@timestamp") or alert.get("timestamp"),
        }
    )


def _regex_iocs(alert: dict[str, Any]) -> list[dict[str, str]]:
    text = json.dumps(alert, sort_keys=True)
    results = []
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        results.append({"type": "ip", "value": ip})
    for hash_value in re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text):
        results.append({"type": "hash", "value": hash_value})
    return results


def _normalize_severity(value: Any) -> str:
    if isinstance(value, (int, float)):
        if value >= 12:
            return "critical"
        if value >= 9:
            return "high"
        if value >= 6:
            return "medium"
        if value >= 3:
            return "low"
        return "info"
    text = str(value or "medium").lower()
    if text in {"critical", "high", "medium", "low", "info"}:
        return text
    if text in {"severe", "fatal"}:
        return "critical"
    if text in {"warning", "warn"}:
        return "medium"
    return "medium"


def _wazuh_level_to_severity(level: Any) -> str:
    try:
        return _normalize_severity(int(level))
    except (TypeError, ValueError):
        return "medium"
