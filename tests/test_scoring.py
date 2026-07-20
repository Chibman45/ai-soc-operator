"""Tests for the deterministic scoring engine."""

from __future__ import annotations

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.soc_client.scoring import (
    WEIGHTS,
    normalize_features,
    score_to_tier,
    should_trigger_llm_review,
    apply_llm_adjustment,
    triage,
)


class FeatureExtractionTests(unittest.TestCase):
    def test_auth_risk_brute_force(self):
        alert = {"tags": ["brute-force"], "rule": {"name": "Brute Force Detection"}}
        features = normalize_features(alert)
        self.assertGreater(features["auth_risk"], 0.0)

    def test_auth_risk_impossible_travel(self):
        alert = {"tags": ["impossible-travel"], "rule": {"name": "Impossible Travel Detected"}}
        features = normalize_features(alert)
        self.assertGreater(features["auth_risk"], 0.3)

    def test_auth_risk_clean_alert(self):
        alert = {"rule": {"name": "Normal Event"}}
        features = normalize_features(alert)
        self.assertEqual(features["auth_risk"], 0.0)

    def test_observables_risk_no_enrichment(self):
        features = normalize_features({}, None)
        self.assertEqual(features["observables_risk"], 0.3)

    def test_observables_risk_vt_malicious(self):
        enrichment = {"ip": {"virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 15, "suspicious": 3, "harmless": 2, "undetected": 30}}}}}}
        features = normalize_features({}, enrichment)
        self.assertGreater(features["observables_risk"], 0.5)

    def test_observables_risk_vt_clean(self):
        enrichment = {"ip": {"virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 0}}}}}}
        features = normalize_features({}, enrichment)
        self.assertLess(features["observables_risk"], 0.1)

    def test_observables_risk_abuseipdb(self):
        enrichment = {"ip": {"abuseipdb": {"data": {"abuseConfidenceScore": 85}}}}
        features = normalize_features({}, enrichment)
        self.assertGreater(features["observables_risk"], 0.8)

    def test_behavior_risk_powershell(self):
        alert = {"tags": ["suspicious-process"], "data": {"powershell_cmdline": "IEX (...)"}}
        features = normalize_features(alert)
        self.assertGreater(features["behavior_risk"], 0.2)

    def test_behavior_risk_clean(self):
        features = normalize_features({"rule": {"name": "Normal"}})
        self.assertEqual(features["behavior_risk"], 0.0)

    def test_asset_risk_domain_controller(self):
        alert = {"agent": {"name": "dc-01"}, "user": {"name": "admin"}}
        features = normalize_features(alert)
        self.assertGreaterEqual(features["asset_risk"], 0.9)

    def test_asset_risk_dev_box(self):
        alert = {"agent": {"name": "dev-laptop-42"}, "user": {"name": "alice"}}
        features = normalize_features(alert)
        self.assertLess(features["asset_risk"], 0.5)

    def test_severity_risk_critical(self):
        alert = {"severity": "critical"}
        features = normalize_features(alert)
        self.assertEqual(features["severity_risk"], 1.0)

    def test_severity_rule_severity(self):
        alert = {"rule": {"severity": "high"}}
        features = normalize_features(alert)
        self.assertEqual(features["severity_risk"], 0.8)

    def test_correlation_risk_two_moderate(self):
        alert = {"tags": ["impossible-travel", "brute-force", "suspicious-process"], "rule": {"name": "Multiple Failed Logins — Impossible Travel"}}
        features = normalize_features(alert)
        self.assertGreaterEqual(features["correlation_risk"], 0.4)

    def test_no_correlation_for_single_signal(self):
        alert = {"rule": {"name": "Single Event"}}
        features = normalize_features(alert)
        self.assertEqual(features["correlation_risk"], 0.0)


class ScoreToTierTests(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(score_to_tier(0.85), "critical")
    def test_high(self):
        self.assertEqual(score_to_tier(0.70), "high")
    def test_medium(self):
        self.assertEqual(score_to_tier(0.45), "medium")
    def test_low(self):
        self.assertEqual(score_to_tier(0.15), "low")
    def test_boundary_high_critical(self):
        self.assertEqual(score_to_tier(0.80), "critical")
        self.assertEqual(score_to_tier(0.79), "high")
    def test_boundary_medium_high(self):
        self.assertEqual(score_to_tier(0.60), "high")
        self.assertEqual(score_to_tier(0.59), "medium")


class GreyZoneDetectionTests(unittest.TestCase):
    def test_narrow_ci_no_overlap(self):
        self.assertFalse(should_trigger_llm_review(0.72, 0.05))
    def test_ci_overlaps_above_tier(self):
        self.assertTrue(should_trigger_llm_review(0.55, 0.12))
    def test_ci_overlaps_below_tier(self):
        self.assertTrue(should_trigger_llm_review(0.32, 0.20))
    def test_low_score_no_overlap(self):
        self.assertFalse(should_trigger_llm_review(0.10, 0.05))
    def test_critical_no_above(self):
        self.assertFalse(should_trigger_llm_review(0.95, 0.05))


class LLMAdjustmentTests(unittest.TestCase):
    def test_no_override_returns_score(self):
        final, reason = apply_llm_adjustment(0.65, None)
        self.assertEqual(final, 0.65)
        self.assertIsNone(reason)
    def test_empty_dict_returns_score(self):
        final, reason = apply_llm_adjustment(0.65, {})
        self.assertEqual(final, 0.65)
    def test_valid_override(self):
        llm = {"adjusted_score": 0.92, "adjustment_reason": "Kill-chain completeness"}
        final, reason = apply_llm_adjustment(0.45, llm)
        self.assertEqual(final, 0.92)
        self.assertEqual(reason, "Kill-chain completeness")
    def test_override_out_of_range(self):
        llm = {"adjusted_score": 1.5}
        final, reason = apply_llm_adjustment(0.45, llm)
        self.assertEqual(final, 0.45)
    def test_override_negative(self):
        llm = {"adjusted_score": -0.1}
        final, reason = apply_llm_adjustment(0.45, llm)
        self.assertEqual(final, 0.45)


class TriagePipelineTests(unittest.TestCase):
    def test_triage_basic_alert(self):
        alert = {"rule": {"name": "Brute Force Detection", "severity": "medium"}, "tags": ["brute-force", "identity"]}
        result = triage(alert)
        self.assertIn("score", result)
        self.assertIn("tier", result)
        self.assertIn("confidence_interval", result)
        self.assertIn("features", result)
        self.assertIn("breakdown", result)
        self.assertIn("should_trigger_llm", result)
        self.assertIn("summary", result)
        self.assertGreaterEqual(result["score"], 0.0)
        self.assertLessEqual(result["score"], 1.0)

    def test_triage_high_severity_alert(self):
        alert = {"rule": {"name": "Impossible Travel — Admin Account", "severity": "high"}, "tags": ["impossible-travel", "geo-anomaly", "auth-anomaly"], "agent": {"name": "dc-01"}, "user": {"name": "admin"}}
        result = triage(alert)
        self.assertGreater(result["score"], 0.4)

    def test_triage_with_enrichment(self):
        alert = {"rule": {"name": "Malware Detected", "severity": "high"}, "tags": ["malware"]}
        enrichment = {"hash": {"virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 30, "suspicious": 5, "harmless": 1, "undetected": 10}}}}}}
        result = triage(alert, enrichment)
        self.assertGreater(result["features"]["observables_risk"], 0.5)

    def test_triage_with_llm_override(self):
        alert = {"rule": {"name": "Brute Force Detection", "severity": "medium"}, "tags": ["brute-force"]}
        llm = {"adjusted_score": 0.85, "adjustment_reason": "Multiple correlated auth failures"}
        result = triage(alert, llm_override=llm)
        self.assertEqual(result["score"], 0.85)
        self.assertTrue(result["llm_adjusted"])

    def test_triage_empty_alert(self):
        result = triage({})
        self.assertIsInstance(result["score"], float)
        self.assertEqual(result["tier"], "low")

    def test_breakdown_sums_to_score(self):
        alert = {"rule": {"name": "Test", "severity": "high"}, "tags": ["brute-force"]}
        result = triage(alert)
        total = sum(item["contribution"] for item in result["breakdown"])
        self.assertAlmostEqual(total, result["deterministic_score"], places=4)

    def test_breakdown_has_label_for_each_feature(self):
        result = triage({"rule": {"name": "Test"}})
        for item in result["breakdown"]:
            self.assertIn("label", item)
            self.assertGreater(len(item["label"]), 0)

    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(WEIGHTS.values()), 1.0, places=6)

    def test_should_trigger_llm_flag(self):
        alert = {"rule": {"name": "Unknown", "severity": "info"}}
        result = triage(alert)
        self.assertIn("should_trigger_llm", result)
        self.assertIsInstance(result["should_trigger_llm"], bool)


class EdgeCaseTests(unittest.TestCase):
    def test_null_fields(self):
        result = triage({"severity": None, "rule": None, "tags": None, "data": None})
        self.assertIsInstance(result["score"], float)

    def test_missing_nested_keys(self):
        result = triage({"rule": {"name": "Test"}})
        self.assertIsInstance(result["score"], float)

    def test_vt_response_missing_data_key(self):
        enrichment = {"ip": {"virustotal": {"error": "Quota exceeded"}}}
        features = normalize_features({}, enrichment)
        self.assertEqual(features["observables_risk"], 0.3)

    def test_alert_with_high_failed_logins(self):
        alert = {"rule": {"name": "Multiple Failed Logins"}, "tags": ["brute-force"], "failed_logins": 50}
        features = normalize_features(alert)
        self.assertGreater(features["auth_risk"], 0.3)

    def test_contradictory_signals(self):
        alert = {"severity": "critical", "rule": {"name": "Test"}}
        enrichment = {"ip": {"virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 0}}}}}}
        result = triage(alert, enrichment)
        self.assertGreater(result["score"], 0.05)
        self.assertLess(result["score"], 0.8)


if __name__ == "__main__":
    unittest.main()
