"""Threat-intel export helpers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


def stix_bundle_for_case(case: dict[str, Any], observables: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects: list[dict[str, Any]] = [
        {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": case.get("title") or f"Case {case.get('id')}",
            "published": now,
            "report_types": ["threat-report"],
            "object_refs": [],
        }
    ]
    report = objects[0]
    for obs in observables:
        indicator = _indicator_for_observable(obs, now)
        if indicator:
            objects.append(indicator)
            report["object_refs"].append(indicator["id"])
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def stix_json_for_case(case: dict[str, Any], observables: list[dict[str, Any]]) -> str:
    return json.dumps(stix_bundle_for_case(case, observables), indent=2, sort_keys=True)


def _indicator_for_observable(obs: dict[str, Any], now: str) -> dict[str, Any] | None:
    obs_type = str(obs.get("type", "")).lower()
    value = str(obs.get("value", ""))
    if not value:
        return None
    pattern = None
    if obs_type == "ip":
        pattern = f"[ipv4-addr:value = '{value}']"
    elif obs_type in {"domain", "hostname"}:
        pattern = f"[domain-name:value = '{value}']"
    elif obs_type in {"hash", "sha256"}:
        pattern = f"[file:hashes.'SHA-256' = '{value}']"
    elif obs_type == "md5":
        pattern = f"[file:hashes.MD5 = '{value}']"
    elif obs_type == "url":
        pattern = f"[url:value = '{value}']"
    if not pattern:
        return None
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": f"{obs_type}: {value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
    }
