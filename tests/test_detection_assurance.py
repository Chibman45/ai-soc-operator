"""Detection assurance, architecture, and platform validation tests."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web.app import app, hash_password, init_db
from web.services.detection_assurance import (
    active_architecture,
    approve_architecture_draft,
    assurance_metrics,
    classify_detection,
    create_architecture_draft,
    generate_rule_recommendations,
    record_ground_truth_event,
    record_verdict,
    store_and_validate_configuration,
)
from web.services.schema_features import init_feature_db


def assurance_connection() -> tuple[sqlite3.Connection, int]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
        CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
        CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
        CREATE TABLE runs (id INTEGER PRIMARY KEY);
        CREATE TABLE cases (id INTEGER PRIMARY KEY, title TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
        INSERT INTO users VALUES (1, 'analyst', 'x');
        INSERT INTO users VALUES (2, 'reviewer', 'x');
        """
    )
    init_feature_db(conn)
    org_id = int(conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()[0])
    conn.execute("INSERT INTO cases (id, org_id, title) VALUES (10, ?, 'Assurance case')", (org_id,))
    conn.execute(
        """
        INSERT INTO alerts
            (id, org_id, source, source_alert_id, case_id, title, severity, raw_payload, normalized_payload)
        VALUES (20, ?, 'wazuh', 'alert-20', 10, 'Suspicious login', 'high', '{}', ?)
        """,
        (org_id, json.dumps({"rule": {"id": "5710", "name": "Suspicious login", "version": "4.9"}})),
    )
    conn.commit()
    return conn, org_id


class ClassificationTests(unittest.TestCase):
    def test_truth_matrix(self):
        self.assertEqual(classify_detection(detection_occurred=True, ground_truth="malicious"), "true_positive")
        self.assertEqual(classify_detection(detection_occurred=True, ground_truth="benign"), "false_positive")
        self.assertEqual(classify_detection(detection_occurred=False, ground_truth="malicious"), "false_negative")
        self.assertEqual(classify_detection(detection_occurred=False, ground_truth="benign"), "true_negative")
        self.assertEqual(classify_detection(detection_occurred=True, ground_truth="unknown"), "needs_review")

    def test_alert_and_ground_truth_metrics(self):
        conn, org_id = assurance_connection()
        record_verdict(
            conn,
            org_id=org_id,
            decided_by=1,
            detection_occurred=True,
            ground_truth="malicious",
            confidence=0.95,
            rationale="The endpoint owner confirmed credential misuse.",
            alert_id=20,
        )
        record_ground_truth_event(
            conn,
            org_id=org_id,
            created_by=1,
            title="Approved attack simulation",
            ground_truth="malicious",
            detection_occurred=False,
            source="purple-team",
            event_time="2026-09-18 10:00:00",
            rule_id="5710",
            rule_name="Suspicious login",
        )
        metrics = assurance_metrics(conn, org_id)
        self.assertEqual(metrics["counts"]["true_positive"], 1)
        self.assertEqual(metrics["counts"]["false_negative"], 1)
        self.assertEqual(metrics["recall"], 0.5)


class ArchitectureTests(unittest.TestCase):
    def test_structured_profile_requires_approval_before_activation(self):
        conn, org_id = assurance_connection()
        with tempfile.TemporaryDirectory() as tmp, patch("web.services.detection_assurance.ROOT", Path(tmp)):
            source = Path(tmp) / "architecture.yaml"
            source.write_text(
                """
architecture_profile:
  organization_name: Example SOC
  assets:
    - id: dc-01
      name: Domain Controller
      type: server
      criticality: critical
      owners: [identity-team]
      trust_zone: server
      addresses: [10.0.0.10]
      log_sources: [wazuh]
  networks: []
  identity_domains: [example.local]
  trust_zones: [server]
  data_flows: []
  security_tools:
    - platform: wazuh
      purpose: endpoint monitoring
      owners: [soc]
      connected_sources: [dc-01]
  expected_behaviors: []
  compliance_requirements: []
""",
                encoding="utf-8",
            )
            draft = create_architecture_draft(
                conn,
                org_id=org_id,
                source_path=source,
                source_name=source.name,
                created_by=1,
                llm_callback=None,
            )
            self.assertEqual(active_architecture(conn, org_id), (None, None))
            approved = approve_architecture_draft(conn, draft["id"], org_id=org_id, approved_by=2)
        profile_id, profile = active_architecture(conn, org_id)
        self.assertEqual(profile_id, approved["id"])
        self.assertEqual(profile["assets"][0]["criticality"], "critical")


class ValidationAndRecommendationTests(unittest.TestCase):
    def test_configuration_snapshot_redacts_secrets_and_creates_findings(self):
        conn, org_id = assurance_connection()
        result = store_and_validate_configuration(
            conn,
            org_id=org_id,
            platform="wazuh",
            configuration={
                "base_url": "http://wazuh.example.test",
                "api_token": "do-not-store",
                "rules": [{"id": "100", "description": "one"}, {"id": "100", "description": "duplicate"}],
                "decoders": [],
            },
            source="test",
            collected_by=1,
        )
        snapshot = conn.execute("SELECT configuration_json FROM configuration_snapshots WHERE id = ?", (result["snapshot_id"],)).fetchone()
        self.assertNotIn("do-not-store", snapshot["configuration_json"])
        self.assertIn("[REDACTED]", snapshot["configuration_json"])
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Remote service is not using HTTPS", titles)
        self.assertIn("Duplicate Wazuh rule identifiers", titles)

    def test_recommendation_requires_repeated_confirmed_outcomes(self):
        conn, org_id = assurance_connection()
        for index, truth in enumerate(("benign", "benign", "malicious"), start=1):
            record_verdict(
                conn,
                org_id=org_id,
                decided_by=1,
                detection_occurred=True,
                ground_truth=truth,
                confidence=1.0,
                rationale=f"Confirmed investigation outcome number {index}.",
                alert_id=20,
            )
        recommendations = generate_rule_recommendations(conn, org_id=org_id, created_by=1)
        self.assertEqual(len(recommendations), 1)
        self.assertEqual(recommendations[0]["type"], "reduce_false_positives")
        self.assertEqual(generate_rule_recommendations(conn, org_id=org_id, created_by=1), [])


class AssuranceRouteTests(unittest.TestCase):
    def test_admin_can_open_workspace_download_template_and_label_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "soc_operator.db"
            with (
                patch("web.app.DB_PATH", database),
                patch("web.security.DB_PATH", database),
                patch("web.routes.assurance.DB_PATH", database),
            ):
                init_db()
                conn = sqlite3.connect(database)
                conn.row_factory = sqlite3.Row
                owner_id = int(
                    conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES ('owner', ?)",
                        (hash_password("owner-password-123"),),
                    ).lastrowid
                )
                conn.commit()
                conn.close()
                init_db()
                conn = sqlite3.connect(database)
                conn.row_factory = sqlite3.Row
                org_id = int(
                    conn.execute(
                        "SELECT default_org_id FROM users WHERE id = ?", (owner_id,)
                    ).fetchone()[0]
                )
                conn.execute(
                    """
                    INSERT INTO alerts
                        (org_id, source, title, severity, raw_payload, normalized_payload)
                    VALUES (?, 'wazuh', 'Route alert', 'high', '{}', ?)
                    """,
                    (org_id, json.dumps({"rule": {"id": "1001", "name": "Route alert"}})),
                )
                alert_id = int(conn.execute("SELECT MAX(id) FROM alerts").fetchone()[0])
                conn.commit()
                conn.close()

                client = app.test_client()
                self.assertEqual(client.get("/api/assurance/ground-truth").status_code, 405)
                with client.session_transaction() as sess:
                    sess["user_id"] = owner_id
                    sess["org_id"] = org_id
                    sess["session_version"] = 0
                    sess["csrf_token"] = "assurance-csrf"
                self.assertEqual(client.get("/assurance").status_code, 200)
                self.assertEqual(
                    client.get("/downloads/organization-assurance-template.docx").status_code,
                    200,
                )
                response = client.post(
                    f"/api/assurance/alerts/{alert_id}/verdict",
                    json={
                        "ground_truth": "malicious",
                        "confidence": 1,
                        "rationale": "The incident response team confirmed compromise.",
                    },
                    headers={"X-CSRF-Token": "assurance-csrf"},
                )
                self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
                self.assertEqual(response.get_json()["verdict"]["classification"], "true_positive")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
