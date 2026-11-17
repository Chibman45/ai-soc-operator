"""Acceptance tests for the deterministic staging orchestration pipeline."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.staging_acceptance import (
    STAGES,
    AdapterRegistry,
    DeterministicAdapter,
    FaultInjection,
    SecretSettings,
    StagingAcceptanceOrchestrator,
    write_acceptance_evidence,
)


class StagingAcceptanceTests(unittest.TestCase):
    def _orchestrator(self, **kwargs):
        adapter = DeterministicAdapter()
        return StagingAcceptanceOrchestrator(
            AdapterRegistry.uniform(adapter),
            max_retries=2,
            **kwargs,
        ), adapter

    def test_complete_alert_to_notification_chain_runs_in_order(self):
        orchestrator, adapter = self._orchestrator()
        result = orchestrator.run({"id": "wazuh-1", "source_ip": "203.0.113.9"})
        self.assertEqual(result.status, "passed")
        self.assertEqual([step.stage for step in result.steps], list(STAGES))
        self.assertEqual(adapter.calls, list(STAGES))
        self.assertEqual(result.output["notifications"], ["slack", "smtp"])

    def test_transient_retry_recovers_deterministically(self):
        orchestrator, _ = self._orchestrator(
            faults=[FaultInjection(stage="enrichment", kind="retry", occurrences=1)]
        )
        result = orchestrator.run({"id": "wazuh-2"})
        step = next(item for item in result.steps if item.stage == "enrichment")
        self.assertEqual(result.status, "passed")
        self.assertEqual(step.attempts, 2)

    def test_duplicate_is_idempotent_and_does_not_repeat_side_effects(self):
        orchestrator, _ = self._orchestrator(
            faults=[FaultInjection(stage="normalize", kind="duplicate")]
        )
        result = orchestrator.run({"id": "wazuh-duplicate"})
        self.assertEqual(result.status, "passed")
        normalize = next(item for item in result.steps if item.stage == "normalize")
        self.assertEqual(normalize.outcome, "duplicate_suppressed")

    def test_terminal_faults_fail_closed_and_stop_pipeline(self):
        for kind in ("timeout", "permission_denied", "unavailable"):
            with self.subTest(kind=kind):
                orchestrator, _ = self._orchestrator(
                    faults=[FaultInjection(stage="thehive", kind=kind)]
                )
                result = orchestrator.run({"id": f"wazuh-{kind}"})
                self.assertEqual(result.status, "failed")
                self.assertEqual(result.steps[-1].stage, "thehive")
                self.assertEqual(result.steps[-1].outcome, kind)
                self.assertNotIn("cortex", [step.stage for step in result.steps])

    def test_live_settings_load_only_allowlisted_sources_and_redact_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "platforms.toml"
            config.write_text(
                '[thehive]\nbase_url = "https://thehive.local"\napi_key = "config-secret"\n',
                encoding="utf-8",
            )
            with patch.dict(
                "os.environ",
                {"AI_SOC_WAZUH_API_KEY": "env-secret", "UNRELATED_SECRET": "ignore-me"},
                clear=True,
            ):
                settings = SecretSettings.load(config)

        self.assertEqual(settings.get("AI_SOC_WAZUH_API_KEY").reveal(), "env-secret")
        self.assertEqual(settings.get("thehive.api_key").reveal(), "config-secret")
        rendered = repr(settings)
        self.assertNotIn("env-secret", rendered)
        self.assertNotIn("config-secret", rendered)
        self.assertNotIn("ignore-me", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_live_mode_requires_explicit_non_fake_adapters(self):
        with self.assertRaises(ValueError):
            StagingAcceptanceOrchestrator(
                AdapterRegistry.uniform(DeterministicAdapter()),
                mode="live",
            )

    def test_signed_evidence_contains_no_secret(self):
        result = StagingAcceptanceOrchestrator(AdapterRegistry.uniform(DeterministicAdapter())).run(
            {"id": "alert-1", "api_key": "do-not-store"}
        )
        with tempfile.TemporaryDirectory() as directory:
            path = write_acceptance_evidence(
                result,
                Path(directory),
                signing_key="a-long-evidence-key",
                key_id="test",
            )
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("do-not-store", content)
            self.assertIn('"signature"', content)


if __name__ == "__main__":
    unittest.main()
