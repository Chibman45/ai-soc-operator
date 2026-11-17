"""Run operational readiness drills and emit verifiable evidence manifests.

The built-in adapter is deliberately side-effect free. Deployments can inject
an adapter that performs approved platform checks, while this module retains
responsibility for redaction, evidence chaining, and manifest signing.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Protocol

DRILL_NAMES = (
    "backup_restore_verification",
    "credential_rotation_readiness",
    "worker_recovery",
    "notification_dead_letter",
    "responder_rollback_readiness",
    "tenant_isolation",
    "https_validation",
    "load_soak",
    "previous_release_rollback",
)
_SENSITIVE_MARKERS = ("secret", "password", "token", "api_key", "apikey", "credential", "private_key")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _is_sensitive(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return any(marker in normalized for marker in _SENSITIVE_MARKERS)


def redact(value: Any, *, known_secrets: tuple[str, ...] = ()) -> Any:
    """Return evidence-safe data without mutating the caller's value."""
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _is_sensitive(str(key)) else redact(item, known_secrets=known_secrets)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [redact(item, known_secrets=known_secrets) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        safe = value
        for secret in known_secrets:
            if secret:
                safe = safe.replace(secret, "[REDACTED]")
        return safe
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _collect_secrets(value: Any, parent_key: str = "") -> tuple[str, ...]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _is_sensitive(str(key)) and isinstance(item, str):
                found.append(item)
            found.extend(_collect_secrets(item, str(key)))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_collect_secrets(item, parent_key))
    elif _is_sensitive(parent_key) and isinstance(value, str):
        found.append(value)
    return tuple(dict.fromkeys(found))


@dataclass(frozen=True)
class DrillOutcome:
    status: str
    details: dict[str, Any]


class OperationalDrillAdapter(Protocol):
    """Boundary implemented by deterministic fakes or approved live checks."""

    def run(self, name: str, context: Mapping[str, Any]) -> DrillOutcome:
        ...


class DeterministicDrillAdapter:
    """Secret-free readiness simulator used by tests and local dry runs."""

    is_test_adapter = True

    _CHECKS: ClassVar[dict[str, tuple[str, ...]]] = {
        "backup_restore_verification": ("backup_hash_valid", "restore_integrity_valid"),
        "credential_rotation_readiness": ("versioned_secret_supported", "revocation_plan_present"),
        "worker_recovery": ("lease_expiry_detected", "replacement_worker_claimed"),
        "notification_dead_letter": ("retry_budget_enforced", "dead_letter_preserved"),
        "responder_rollback_readiness": ("rollback_plan_present", "approval_required"),
        "tenant_isolation": ("cross_org_read_denied", "cross_org_write_denied"),
        "https_validation": ("certificate_valid", "http_redirects_to_https"),
        "load_soak": ("error_budget_met", "queue_drained"),
        "previous_release_rollback": ("previous_artifact_available", "rollback_healthcheck_passed"),
    }

    def __init__(self, failures: Mapping[str, str] | None = None):
        self.failures = dict(failures or {})

    def run(self, name: str, context: Mapping[str, Any]) -> DrillOutcome:
        if name not in self._CHECKS:
            raise ValueError(f"unknown operational drill: {name}")
        if name in self.failures:
            return DrillOutcome("failed", {"error": self.failures[name]})
        return DrillOutcome(
            "passed",
            {"mode": "deterministic", "checks": {check: True for check in self._CHECKS[name]}},
        )


class EvidenceSigner:
    """HMAC signer; only the key identifier and signature enter evidence."""

    algorithm = "HMAC-SHA256"

    def __init__(self, key: bytes, *, key_id: str):
        if len(key) < 16:
            raise ValueError("evidence signing key must be at least 16 bytes")
        if not key_id.strip():
            raise ValueError("evidence signing key id is required")
        self._key = bytes(key)
        self.key_id = key_id

    @classmethod
    def from_environment(cls) -> EvidenceSigner:
        key = os.environ.get("AI_SOC_EVIDENCE_SIGNING_KEY", "")
        key_id = os.environ.get("AI_SOC_EVIDENCE_SIGNING_KEY_ID", "")
        if not key or not key_id:
            raise RuntimeError("AI_SOC_EVIDENCE_SIGNING_KEY and AI_SOC_EVIDENCE_SIGNING_KEY_ID are required")
        return cls(key.encode("utf-8"), key_id=key_id)

    def sign(self, payload: Mapping[str, Any]) -> str:
        return hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()

    def verify(self, payload: Mapping[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class OperationalDrillRunner:
    def __init__(self, adapter: OperationalDrillAdapter, signer: EvidenceSigner, evidence_dir: Path):
        self.adapter = adapter
        self.signer = signer
        self.evidence_dir = Path(evidence_dir)

    def run_all(self, context: Mapping[str, Any] | None = None) -> Path:
        raw_context = dict(context or {})
        known_secrets = _collect_secrets(raw_context)
        run_id = str(uuid.uuid4())
        started_at = _utc_now()
        previous_hash = "0" * 64
        events: list[dict[str, Any]] = []
        drills: list[dict[str, Any]] = []

        for sequence, name in enumerate(DRILL_NAMES, start=1):
            try:
                outcome = self.adapter.run(name, raw_context)
            except Exception as exc:  # noqa: BLE001 - one failed drill must not hide later evidence.
                outcome = DrillOutcome("failed", {"error": str(exc)})
            status = outcome.status if outcome.status in {"passed", "failed"} else "failed"
            details = redact(outcome.details, known_secrets=known_secrets)
            drill = {"name": name, "status": status, "details": details}
            drills.append(drill)
            event_body = {
                "sequence": sequence,
                "recorded_at": _utc_now(),
                "name": name,
                "status": status,
                "details": details,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(_canonical(event_body)).hexdigest()
            events.append({**event_body, "event_hash": event_hash})
            previous_hash = event_hash

        passed = sum(item["status"] == "passed" for item in drills)
        unsigned = {
            "schema": "ai-soc-operational-evidence/v1",
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": _utc_now(),
            "context": redact(raw_context, known_secrets=known_secrets),
            "drills": drills,
            "events": events,
            "chain_head": previous_hash,
            "summary": {"passed": passed, "failed": len(drills) - passed},
        }
        manifest = {
            **unsigned,
            "signing": {
                "algorithm": self.signer.algorithm,
                "key_id": self.signer.key_id,
                "signature": self.signer.sign(unsigned),
            },
        }
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        path = self.evidence_dir / f"operational-drills-{run_id}.json"
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return path


def verify_evidence_manifest(path: Path, signer: EvidenceSigner) -> bool:
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        signing = manifest.pop("signing")
        if signing.get("algorithm") != signer.algorithm or signing.get("key_id") != signer.key_id:
            return False
        previous_hash = "0" * 64
        for event in manifest.get("events", []):
            event_copy = dict(event)
            event_hash = event_copy.pop("event_hash", "")
            if event_copy.get("previous_hash") != previous_hash:
                return False
            if not hmac.compare_digest(hashlib.sha256(_canonical(event_copy)).hexdigest(), event_hash):
                return False
            previous_hash = event_hash
        if manifest.get("chain_head") != previous_hash:
            return False
        return signer.verify(manifest, str(signing.get("signature", "")))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def load_drill_adapter(spec: str, context: Mapping[str, Any]) -> OperationalDrillAdapter:
    if ":" not in spec:
        raise ValueError("adapter must use module:function syntax")
    module_name, function_name = spec.split(":", 1)
    return getattr(importlib.import_module(module_name), function_name)(context)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=Path("evidence") / "operational-drills")
    parser.add_argument("--mode", choices=("deterministic", "live"), default="deterministic")
    parser.add_argument("--adapter", help="Live drill adapter factory in module:function form")
    parser.add_argument("--context", type=Path, help="JSON deployment context supplied to the adapter")
    args = parser.parse_args()
    context = json.loads(args.context.read_text(encoding="utf-8")) if args.context else {"profile": args.mode}
    if args.mode == "live":
        if not args.adapter:
            parser.error("--adapter is required in live mode")
        adapter = load_drill_adapter(args.adapter, context)
        if getattr(adapter, "is_test_adapter", False):
            parser.error("live mode rejects deterministic test adapters")
    else:
        adapter = DeterministicDrillAdapter()
    path = OperationalDrillRunner(
        adapter, EvidenceSigner.from_environment(), args.evidence_dir
    ).run_all(context)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
