"""Acceptance tests for auditable operational drills."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.operational_drills import (
    DRILL_NAMES,
    DeterministicDrillAdapter,
    EvidenceSigner,
    OperationalDrillRunner,
    verify_evidence_manifest,
)


class OperationalDrillTests(unittest.TestCase):
    def setUp(self):
        self.signer = EvidenceSigner(b"test-only-signing-key", key_id="test-key")

    def test_all_required_drills_produce_a_signed_hash_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = OperationalDrillRunner(
                DeterministicDrillAdapter(), self.signer, Path(tmp)
            ).run_all()

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual([item["name"] for item in manifest["drills"]], list(DRILL_NAMES))
            self.assertEqual(manifest["summary"], {"passed": len(DRILL_NAMES), "failed": 0})
            self.assertNotIn("test-only-signing-key", manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(verify_evidence_manifest(manifest_path, self.signer))

            previous = "0" * 64
            for event in manifest["events"]:
                self.assertEqual(event["previous_hash"], previous)
                previous = event["event_hash"]
            self.assertEqual(manifest["chain_head"], previous)

    def test_manifest_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = OperationalDrillRunner(
                DeterministicDrillAdapter(), self.signer, Path(tmp)
            ).run_all()
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["drills"][0]["status"] = "failed"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertFalse(verify_evidence_manifest(path, self.signer))

    def test_failed_drill_is_recorded_without_stopping_remaining_drills(self):
        adapter = DeterministicDrillAdapter(failures={"https_validation": "TLS probe failed"})
        with tempfile.TemporaryDirectory() as tmp:
            path = OperationalDrillRunner(adapter, self.signer, Path(tmp)).run_all()
            manifest = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["summary"], {"passed": len(DRILL_NAMES) - 1, "failed": 1})
        failed = next(item for item in manifest["drills"] if item["name"] == "https_validation")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["details"]["error"], "TLS probe failed")

    def test_context_secrets_are_redacted_from_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = OperationalDrillRunner(
                DeterministicDrillAdapter(), self.signer, Path(tmp)
            ).run_all({"api_key": "super-secret", "target": "staging"})
            serialized = path.read_text(encoding="utf-8")
        self.assertNotIn("super-secret", serialized)
        self.assertIn("[REDACTED]", serialized)


if __name__ == "__main__":
    unittest.main()
