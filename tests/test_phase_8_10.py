"""Focused verification for notification, capability, and operations controls."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.database_backup import create_backup, verify_backup
from web.security import consume_rate_limit
from web.services.capabilities import (
    approve_capability_proposal,
    execute_capability_proposal,
    propose_catalog_capability,
)
from web.services.notifications import dispatch_pending, enqueue_notification
from web.services.responders import approve_responder_action, create_responder_action, execute_responder_action
from web.services.schema_features import init_feature_db


def production_connection(path: str = ":memory:") -> tuple[sqlite3.Connection, int]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
        CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
        CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
        CREATE TABLE runs (id INTEGER PRIMARY KEY);
        CREATE TABLE cases (id INTEGER PRIMARY KEY, case_id TEXT, title TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
        INSERT INTO users VALUES (1, 'requester', 'x');
        INSERT INTO users VALUES (2, 'approver', 'x');
        INSERT INTO cases (id, title) VALUES (10, 'Test case');
        """
    )
    init_feature_db(conn)
    org_id = int(conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()["id"])
    conn.execute("UPDATE cases SET org_id = ? WHERE id = 10", (org_id,))
    conn.execute(
        "INSERT INTO observables (org_id, case_id, type, value, source) VALUES (?, 10, 'ip', '203.0.113.9', 'test')",
        (org_id,),
    )
    conn.commit()
    return conn, org_id


class CapabilityTests(unittest.TestCase):
    def test_responder_enable_requires_independent_approval(self):
        conn, org_id = production_connection()
        proposal = propose_catalog_capability(
            conn,
            org_id=org_id,
            catalog_id="misp-push",
            requested_by=1,
            source="ai",
        )
        with self.assertRaises(PermissionError):
            approve_capability_proposal(conn, proposal["id"], org_id=org_id, approved_by=1)
        approve_capability_proposal(conn, proposal["id"], org_id=org_id, approved_by=2)
        result = execute_capability_proposal(conn, proposal["id"], org_id=org_id)
        self.assertEqual(result["status"], "executed")
        enabled = conn.execute(
            "SELECT enabled FROM responder_capabilities WHERE org_id = ? AND responder_type = 'push_misp_indicator'",
            (org_id,),
        ).fetchone()
        self.assertEqual(enabled["enabled"], 1)

    def test_system_installer_is_disabled_without_operator_gate(self):
        conn, org_id = production_connection()
        proposal = propose_catalog_capability(conn, org_id=org_id, catalog_id="jq", requested_by=1)
        approve_capability_proposal(conn, proposal["id"], org_id=org_id, approved_by=2)
        with patch.dict("os.environ", {}, clear=True):
            result = execute_capability_proposal(conn, proposal["id"], org_id=org_id)
        self.assertEqual(result["status"], "failed")
        self.assertIn("disabled", result["result"]["error"])

    def test_enabled_responder_still_requires_action_approval(self):
        conn, org_id = production_connection()
        action = create_responder_action(
            conn,
            action_type="push_misp_indicator",
            target="203.0.113.9",
            case_id=10,
            requested_by=1,
            org_id=org_id,
        )
        with self.assertRaises(PermissionError):
            execute_responder_action(conn, action["id"], org_id, real_execution_enabled=True)
        approve_responder_action(conn, action["id"], 2, org_id)
        result = execute_responder_action(
            conn,
            action["id"],
            org_id,
            real_execution_enabled=True,
            live_executor=lambda *_: {"executed": True, "mode": "live"},
        )
        self.assertEqual(result["status"], "executed")


class NotificationAndRateLimitTests(unittest.TestCase):
    def test_notification_deduplication_and_retry(self):
        conn, org_id = production_connection()
        first = enqueue_notification(conn, org_id=org_id, event_type="test", message="one", dedup_key="same")
        second = enqueue_notification(conn, org_id=org_id, event_type="test", message="two", dedup_key="same")
        self.assertEqual(first, second)
        with patch("web.services.notifications._dispatch", side_effect=RuntimeError("provider down")):
            result = dispatch_pending(conn)
        self.assertEqual(result[0]["status"], "retrying")

    def test_rate_limit_is_shared_in_database(self):
        conn, _ = production_connection()
        self.assertTrue(consume_rate_limit(conn, "client-1", 2))
        self.assertTrue(consume_rate_limit(conn, "client-1", 2))
        self.assertFalse(consume_rate_limit(conn, "client-1", 2))


class BackupTests(unittest.TestCase):
    def test_backup_has_hash_manifest_and_integrity_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "source.db"
            conn = sqlite3.connect(database)
            conn.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO evidence (value) VALUES ('preserved')")
            conn.commit()
            conn.close()
            backup = create_backup(database, root / "backups")
            result = verify_backup(backup)
            self.assertTrue(result["ok"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
