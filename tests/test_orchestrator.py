"""Tests for the orchestrator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import TestCase

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.orchestrator import (
    auto_select_playbook,
    extract_iocs,
    load_config,
)


class ExtractIOCsTests(TestCase):
    def test_extract_ip_from_source(self):
        alert = {"source": {"ip": "192.168.1.100"}}
        iocs = extract_iocs(alert)
        ips = [i for i in iocs if i["type"] == "ip"]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0]["value"], "192.168.1.100")

    def test_extract_legacy_ip_fields(self):
        alert = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
        iocs = extract_iocs(alert)
        ips = [i for i in iocs if i["type"] == "ip"]
        self.assertEqual(len(ips), 2)

    def test_extract_hash(self):
        alert = {"data": {"sha256": "abc123def456"}}
        iocs = extract_iocs(alert)
        hashes = [i for i in iocs if i["type"] == "hash"]
        self.assertEqual(len(hashes), 1)

    def test_extract_domain(self):
        alert = {"hostname": "evil.example.com"}
        iocs = extract_iocs(alert)
        domains = [i for i in iocs if i["type"] == "domain"]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["value"], "evil.example.com")

    def test_extract_user(self):
        alert = {"user": {"name": "admin"}}
        iocs = extract_iocs(alert)
        users = [i for i in iocs if i["type"] == "user"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["value"], "admin")

    def test_empty_alert(self):
        iocs = extract_iocs({})
        self.assertEqual(iocs, [])


class AutoSelectPlaybookTests(TestCase):
    def setUp(self):
        self.playbook_dir = Path(tempfile.mkdtemp())
        # Create a test playbook
        playbook = {
            "id": "identity-compromise-v1",
            "name": "Identity Compromise",
            "triggers": [
                {"alert_rule": "Brute Force Detection"},
                {"mitre_technique": "T1078"},
                {"tags": ["identity", "brute-force"]},
            ],
            "inputs": [{"name": "alert"}],
            "steps": [],
        }
        (self.playbook_dir / "identity-compromise.yaml").write_text(
            json.dumps(playbook)
        )

    def test_match_by_rule_name(self):
        alert = {"rule": {"name": "Brute Force Detection"}, "tags": []}
        result = auto_select_playbook(alert, self.playbook_dir)
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "identity-compromise.yaml")

    def test_match_by_mitre_technique(self):
        alert = {
            "rule": {"name": "Unknown Alert"},
            "tags": [],
            "mitre": {"techniques": ["T1078"]},
        }
        result = auto_select_playbook(alert, self.playbook_dir)
        self.assertIsNotNone(result)

    def test_match_by_tags(self):
        alert = {"rule": {"name": "Something"}, "tags": ["identity", "brute-force"]}
        result = auto_select_playbook(alert, self.playbook_dir)
        self.assertIsNotNone(result)

    def test_no_match(self):
        alert = {"rule": {"name": "Unrelated Alert"}, "tags": ["network"]}
        result = auto_select_playbook(alert, self.playbook_dir)
        self.assertIsNone(result)

    def test_nonexistent_dir(self):
        result = auto_select_playbook({}, Path("/nonexistent"))
        self.assertIsNone(result)


class LoadConfigTests(TestCase):
    def test_missing_config(self):
        config = load_config()
        # Should return empty dict if no config exists
        self.assertIsInstance(config, dict)


if __name__ == "__main__":
    import unittest
    unittest.main()
