"""End-to-end integration test: playbook execution pipeline."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.playbook_engine import PlaybookRunner, load_playbook, render, evaluate_condition
from scripts.orchestrator import extract_iocs, auto_select_playbook


IDENTITY_COMPROMISE_ALERT = {
    "rule": {"name": "Brute Force Detection", "level": 12},
    "agent": {"name": "web-server-01"},
    "source": {"ip": "203.0.113.42"},
    "user": {"name": "admin@corp.com"},
    "tags": ["identity", "brute-force"],
    "timestamp": "2026-07-17T10:00:00Z",
}

PHISHING_ALERT = {
    "rule": {"name": "Phishing Email Detected", "level": 8},
    "agent": {"name": "mail-gateway"},
    "source": {"ip": "198.51.100.50"},
    "domain": "evil-phish.com",
    "tags": ["phishing", "email"],
    "timestamp": "2026-07-17T10:00:00Z",
}


class FullPipelineTests(unittest.TestCase):
    def setUp(self):
        self.playbooks_dir = Path(__file__).resolve().parents[1] / "playbooks"

    def test_ioc_extraction_from_identity_compromise(self):
        iocs = extract_iocs(IDENTITY_COMPROMISE_ALERT)
        types = {ioc["type"] for ioc in iocs}
        self.assertIn("ip", types)
        self.assertIn("user", types)

    def test_ioc_extraction_from_phishing(self):
        iocs = extract_iocs(PHISHING_ALERT)
        types = {ioc["type"] for ioc in iocs}
        self.assertIn("ip", types)
        self.assertIn("domain", types)

    def test_auto_select_identity_compromise(self):
        path = auto_select_playbook(IDENTITY_COMPROMISE_ALERT, self.playbooks_dir)
        self.assertIsNotNone(path)
        self.assertIn("identity", path.name.lower())

    def test_auto_select_phishing(self):
        path = auto_select_playbook(PHISHING_ALERT, self.playbooks_dir)
        self.assertIsNotNone(path)
        self.assertIn("phishing", path.name.lower())

    def test_full_pipeline_identity_compromise(self):
        """Run the identity compromise playbook with mock alert — no API calls."""
        playbook = load_playbook(self.playbooks_dir / "identity-compromise.yaml")
        iocs = extract_iocs(IDENTITY_COMPROMISE_ALERT)
        context = {
            "alert": IDENTITY_COMPROMISE_ALERT,
            "observables": iocs,
            "iocs": iocs,
            "session": {"id": "test-session", "mode": "SOC_ANALYST", "target": "web-server-01"},
        }

        runner = PlaybookRunner(playbook, context)
        result = runner.run()

        # Verify execution completed
        self.assertIn("steps", result)
        self.assertIn("execution_log", result)
        self.assertGreater(len(result["execution_log"]), 0)

        # Verify steps executed
        steps = result["steps"]
        self.assertIn("classify", steps)
        self.assertIn("enrich", steps)
        self.assertIn("map_mitre", steps)
        self.assertIn("decide", steps)
        self.assertIn("write_case", steps)

        # Verify the skip_to branch was NOT taken (fp_prob not set)
        # Skipped steps are still in the execution log, so check status
        step_statuses = {
            e["step_id"]: e["status"] for e in result["execution_log"]
        }
        self.assertIn("check_false_positive", step_statuses)
        self.assertEqual(step_statuses["check_false_positive"], "skipped")

    def test_pipeline_with_false_positive_branch(self):
        """Run with high false positive probability — should skip enrichment."""
        playbook = load_playbook(self.playbooks_dir / "identity-compromise.yaml")
        context = {
            "alert": IDENTITY_COMPROMISE_ALERT,
            "observables": [],
            "iocs": [],
            "classify": {"false_positive_probability": 0.9},
            "session": {"id": "test-session", "mode": "SOC_ANALYST", "target": "web-server-01"},
        }

        runner = PlaybookRunner(playbook, context)
        result = runner.run()

        # The check_false_positive rule should have triggered skip_to
        log = result["execution_log"]
        skip_entries = [e for e in log if e["status"] == "skipped_by_branch"]
        self.assertGreater(len(skip_entries), 0, "Expected at least one skipped-by-branch entry")

    def test_render_resolves_step_results(self):
        """Variable resolution works across steps via the 'steps' namespace."""
        context = {
            "alert": {"rule": {"name": "Test Rule"}},
            "steps": {
                "classify": {"confidence": "high", "incident_type": "brute-force"},
            },
        }
        self.assertEqual(
            render("{classify.confidence}", context), "high"
        )
        self.assertEqual(
            render("{classify.incident_type} - {alert.rule.name}", context),
            "brute-force - Test Rule",
        )

    def test_evaluate_condition_with_step_results(self):
        context = {
            "steps": {
                "classify": {"fp_prob": 0.85},
            },
        }
        self.assertTrue(evaluate_condition("classify.fp_prob > 0.7", context))
        self.assertFalse(evaluate_condition("classify.fp_prob < 0.5", context))


if __name__ == "__main__":
    unittest.main()
