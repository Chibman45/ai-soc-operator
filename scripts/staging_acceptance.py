"""Deterministic staging acceptance orchestrator with injectable adapters."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 support.
    import tomli as tomllib  # type: ignore[no-redef]

from scripts.operational_drills import redact

STAGES = (
    "wazuh",
    "normalize",
    "ioc",
    "playbook",
    "enrichment",
    "approval",
    "thehive",
    "cortex",
    "misp",
    "report",
    "slack",
    "smtp",
)
_ALLOWED_ENV = {
    "AI_SOC_WAZUH_API_KEY",
    "AI_SOC_THEHIVE_API_KEY",
    "AI_SOC_CORTEX_API_KEY",
    "AI_SOC_MISP_API_KEY",
    "AI_SOC_SLACK_WEBHOOK_URL",
    "AI_SOC_SMTP_PASSWORD",
}
_ALLOWED_CONFIG_SECTIONS = {"wazuh", "thehive", "cortex", "misp", "slack", "smtp"}
_ALLOWED_CONFIG_KEYS = {"base_url", "api_key", "webhook_url", "host", "port", "username", "password"}


class SecretValue:
    """A value that can be revealed to an adapter but not accidentally rendered."""

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretValue('[REDACTED]')"

    __str__ = __repr__


class SecretSettings:
    def __init__(self, values: Mapping[str, SecretValue] | None = None):
        self._values = dict(values or {})

    @classmethod
    def load(cls, config_path: Path | None = None) -> SecretSettings:
        values = {name: SecretValue(os.environ[name]) for name in _ALLOWED_ENV if os.environ.get(name)}
        if config_path and Path(config_path).is_file():
            with Path(config_path).open("rb") as handle:
                document = tomllib.load(handle)
            for section, fields in document.items():
                if section not in _ALLOWED_CONFIG_SECTIONS or not isinstance(fields, Mapping):
                    continue
                for key, value in fields.items():
                    if key in _ALLOWED_CONFIG_KEYS and isinstance(value, (str, int)):
                        values[f"{section}.{key}"] = SecretValue(str(value))
        return cls(values)

    def get(self, name: str) -> SecretValue:
        if name not in self._values:
            raise KeyError(name)
        return self._values[name]

    def __repr__(self) -> str:
        return f"SecretSettings({{{', '.join(f'{name!r}: [REDACTED]' for name in sorted(self._values))}}})"


class StageAdapter(Protocol):
    def execute(
        self,
        stage: str,
        payload: Mapping[str, Any],
        settings: SecretSettings,
    ) -> dict[str, Any]:
        ...


class DeterministicAdapter:
    """Pure fake that models contracts without network calls or credentials."""

    is_test_adapter = True

    def __init__(self):
        self.calls: list[str] = []

    def execute(self, stage: str, payload: Mapping[str, Any], settings: SecretSettings) -> dict[str, Any]:
        self.calls.append(stage)
        current = dict(payload)
        if stage == "wazuh":
            return {"source": "wazuh", "source_alert_id": str(current.get("id", "deterministic-alert"))}
        if stage == "normalize":
            return {**current, "normalized": True, "severity": "high"}
        if stage == "ioc":
            return {**current, "observables": [{"type": "ip", "value": "203.0.113.9"}]}
        if stage == "playbook":
            return {**current, "playbook": "identity-compromise.yaml"}
        if stage == "enrichment":
            return {**current, "enrichment": {"reputation": "suspicious", "source": "fake"}}
        if stage == "approval":
            return {**current, "approval": {"status": "approved", "actor": "staging-fixture"}}
        if stage == "thehive":
            return {**current, "thehive_case_id": "TH-FAKE-1"}
        if stage == "cortex":
            return {**current, "cortex_job_id": "CX-FAKE-1"}
        if stage == "misp":
            return {**current, "misp_event_id": "MISP-FAKE-1"}
        if stage == "report":
            return {**current, "report_id": "REPORT-FAKE-1"}
        if stage in {"slack", "smtp"}:
            notifications = list(current.get("notifications", []))
            notifications.append(stage)
            return {**current, "notifications": notifications}
        raise ValueError(f"unsupported stage: {stage}")


class AdapterRegistry:
    def __init__(self, adapters: Mapping[str, StageAdapter]):
        missing = [stage for stage in STAGES if stage not in adapters]
        if missing:
            raise ValueError(f"missing staging adapters: {', '.join(missing)}")
        self._adapters = dict(adapters)

    @classmethod
    def uniform(cls, adapter: StageAdapter) -> AdapterRegistry:
        return cls({stage: adapter for stage in STAGES})

    def get(self, stage: str) -> StageAdapter:
        return self._adapters[stage]

    def contains_test_adapters(self) -> bool:
        return any(getattr(adapter, "is_test_adapter", False) for adapter in self._adapters.values())


@dataclass
class FaultInjection:
    stage: str
    kind: str
    occurrences: int = 1
    _used: int = field(default=0, init=False, repr=False)

    def consume(self) -> str | None:
        if self._used >= self.occurrences:
            return None
        self._used += 1
        return self.kind


@dataclass(frozen=True)
class StageResult:
    stage: str
    outcome: str
    attempts: int
    evidence_hash: str


@dataclass(frozen=True)
class AcceptanceResult:
    status: str
    steps: list[StageResult]
    output: dict[str, Any]
    chain_head: str


class _TransientFault(RuntimeError):
    pass


class StagingAcceptanceOrchestrator:
    def __init__(
        self,
        adapters: AdapterRegistry,
        *,
        mode: str = "deterministic",
        settings: SecretSettings | None = None,
        faults: list[FaultInjection] | None = None,
        max_retries: int = 2,
    ):
        if mode not in {"deterministic", "live"}:
            raise ValueError("mode must be deterministic or live")
        if mode == "live" and adapters.contains_test_adapters():
            raise ValueError("live mode requires explicit non-test adapters")
        self.adapters = adapters
        self.mode = mode
        self.settings = settings or SecretSettings()
        self.faults = list(faults or [])
        self.max_retries = max(0, max_retries)

    def _fault_for(self, stage: str) -> str | None:
        for fault in self.faults:
            if fault.stage == stage:
                consumed = fault.consume()
                if consumed:
                    return consumed
        return None

    @staticmethod
    def _evidence_hash(previous_hash: str, stage: str, outcome: str, attempts: int) -> str:
        record = {"previous_hash": previous_hash, "stage": stage, "outcome": outcome, "attempts": attempts}
        return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def run(self, alert: Mapping[str, Any]) -> AcceptanceResult:
        payload: dict[str, Any] = redact(dict(alert))
        steps: list[StageResult] = []
        previous_hash = "0" * 64

        for stage in STAGES:
            attempts = 0
            outcome = "passed"
            while True:
                attempts += 1
                fault = self._fault_for(stage)
                try:
                    if fault == "retry":
                        raise _TransientFault("injected retry")
                    if fault == "duplicate":
                        outcome = "duplicate_suppressed"
                        break
                    if fault in {"timeout", "permission_denied", "unavailable"}:
                        outcome = fault
                        break
                    payload = redact(self.adapters.get(stage).execute(stage, payload, self.settings))
                    break
                except _TransientFault:
                    if attempts > self.max_retries:
                        outcome = "retry_exhausted"
                        break
            evidence_hash = self._evidence_hash(previous_hash, stage, outcome, attempts)
            steps.append(StageResult(stage, outcome, attempts, evidence_hash))
            previous_hash = evidence_hash
            if outcome in {"timeout", "permission_denied", "unavailable", "retry_exhausted"}:
                return AcceptanceResult("failed", steps, payload, previous_hash)

        return AcceptanceResult("passed", steps, payload, previous_hash)


def write_acceptance_evidence(result: AcceptanceResult, output_dir: Path, *, signing_key: str, key_id: str) -> Path:
    """Persist signed, redacted evidence without serializing adapter credentials."""
    if len(signing_key) < 16 or not key_id.strip():
        raise ValueError("acceptance evidence requires a signing key and key id")
    unsigned = {
        "schema": "ai-soc-staging-acceptance/v1",
        "status": result.status,
        "steps": [vars(step) for step in result.steps],
        "output": redact(result.output),
        "chain_head": result.chain_head,
    }
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    document = {**unsigned, "signing": {"algorithm": "HMAC-SHA256", "key_id": key_id, "signature": signature}}
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"staging-acceptance-{result.chain_head[:16]}.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_adapter_factory(spec: str, settings: SecretSettings) -> AdapterRegistry:
    """Load an operator-controlled live adapter factory from module:function."""
    if ":" not in spec:
        raise ValueError("adapter must use module:function syntax")
    module_name, function_name = spec.split(":", 1)
    factory = getattr(importlib.import_module(module_name), function_name)
    adapter = factory(settings)
    return adapter if isinstance(adapter, AdapterRegistry) else AdapterRegistry.uniform(adapter)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alert", type=Path, required=True)
    parser.add_argument("--mode", choices=("deterministic", "live"), default="deterministic")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--adapter", help="Live adapter factory in module:function form")
    parser.add_argument("--evidence-dir", type=Path, default=Path("evidence") / "staging-acceptance")
    args = parser.parse_args()
    alert = json.loads(args.alert.read_text(encoding="utf-8"))
    settings = SecretSettings.load(args.config)
    if args.mode == "live":
        if not args.adapter:
            parser.error("--adapter is required in live mode")
        adapters = load_adapter_factory(args.adapter, settings)
    else:
        adapters = AdapterRegistry.uniform(DeterministicAdapter())
    result = StagingAcceptanceOrchestrator(adapters, mode=args.mode, settings=settings).run(alert)
    path = write_acceptance_evidence(
        result,
        args.evidence_dir,
        signing_key=os.environ.get("AI_SOC_EVIDENCE_SIGNING_KEY", "deterministic-evidence-key" if args.mode == "deterministic" else ""),
        key_id=os.environ.get("AI_SOC_EVIDENCE_SIGNING_KEY_ID", "deterministic" if args.mode == "deterministic" else ""),
    )
    print(json.dumps({"status": result.status, "chain_head": result.chain_head, "evidence": str(path)}, sort_keys=True))
    return 0 if result.status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
