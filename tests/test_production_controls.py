"""Focused tests for the Phase 0-7 production security boundaries."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from flask import Flask
from werkzeug.exceptions import BadRequest

from cryptography.fernet import Fernet

from scripts.job_queue import JobQueue
from scripts.learning import LearningStore
from web.security import enforce_csrf, permissions_for_user, session_or_api_scope
from web.routes.chat import chat_bp, _action_requires_approval, _tool_scope_target
from web.services.alert_ingest import find_correlated_case, upsert_observable
from web.services.credential_vault import open_secret, seal_secret
from web.services.responders import approve_responder_action, create_responder_action, execute_responder_action
from web.services.schema_features import init_feature_db


class CredentialVaultTests(unittest.TestCase):
    def test_secret_round_trip_is_encrypted(self):
        with patch.dict(os.environ, {"AI_SOC_CREDENTIAL_KEY": Fernet.generate_key().decode("ascii")}, clear=False):
            sealed = seal_secret("top-secret")
            self.assertTrue(sealed.startswith("enc:v1:"))
            self.assertNotIn("top-secret", sealed)
            self.assertEqual(open_secret(sealed), "top-secret")


class AuthorizationTests(unittest.TestCase):
    def test_first_legacy_user_receives_initial_admin_role(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
            CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
            CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
            CREATE TABLE runs (id INTEGER PRIMARY KEY);
            CREATE TABLE cases (id INTEGER PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
            INSERT INTO users VALUES (1, 'legacy-admin', 'x');
            """
        )
        init_feature_db(conn)
        role = conn.execute(
            "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = 1"
        ).fetchone()
        self.assertEqual(role["name"], "admin")

    def test_permissions_are_union_of_all_org_roles(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT, permissions TEXT);
            CREATE TABLE user_roles (user_id INTEGER, role_id INTEGER, org_id INTEGER);
            CREATE TABLE organization_memberships (id INTEGER PRIMARY KEY, org_id INTEGER, user_id INTEGER, status TEXT);
            INSERT INTO roles VALUES (1, 'analyst', '["case.update"]');
            INSERT INTO roles VALUES (2, 'reviewer', '["learning.review"]');
            INSERT INTO user_roles VALUES (7, 1, 3);
            INSERT INTO user_roles VALUES (7, 2, 3);
            INSERT INTO organization_memberships VALUES (1, 3, 7, 'active');
            """
        )
        self.assertEqual(permissions_for_user(conn, 7, 3), {"case.update", "learning.review"})
        conn.execute("UPDATE organization_memberships SET status = 'suspended' WHERE user_id = 7 AND org_id = 3")
        self.assertEqual(permissions_for_user(conn, 7, 3), set())
        self.assertEqual(permissions_for_user(conn, 7, None), set())

    def test_bogus_bearer_does_not_bypass_browser_csrf(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        with app.test_request_context("/api/state", method="POST", headers={"Authorization": "Bearer junk"}):
            from flask import session

            session["user_id"] = 7
            session["csrf_token"] = "expected"
            with self.assertRaises(BadRequest):
                enforce_csrf()

    def test_invalid_bearer_never_falls_back_to_cookie_session(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"

        @app.post("/ingest")
        @session_or_api_scope("alert.ingest")
        def ingest():
            return {"ok": True}

        with patch("web.security.authenticate_api_client", return_value=None):
            client = app.test_client()
            with client.session_transaction() as sess:
                sess["user_id"] = 7
                sess["org_id"] = 3
            response = client.post("/ingest", headers={"Authorization": "Bearer junk"})
        self.assertEqual(response.status_code, 401)


class JobDurabilityTests(unittest.TestCase):
    def test_idempotency_key_returns_existing_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = JobQueue(Path(tmp) / "jobs.db")
            first = queue.create_job(1, "playbooks/a.yaml", {"title": "A"}, {}, org_id=4, idempotency_key="alert-1")
            second = queue.create_job(1, "playbooks/a.yaml", {"title": "A"}, {}, org_id=4, idempotency_key="alert-1")
            self.assertEqual(first, second)
            self.assertEqual(len(queue.list_jobs()), 1)

    def test_expired_exhausted_job_is_failed_not_left_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "jobs.db"
            queue = JobQueue(db_path)
            job_id = queue.create_job(1, "playbooks/a.yaml", {"title": "A"}, {})
            conn = sqlite3.connect(db_path)
            conn.execute(
                "UPDATE jobs SET status = 'running', attempt_count = max_attempts, lease_expires_at = datetime('now', '-1 minute') WHERE id = ?",
                (job_id,),
            )
            conn.commit()
            conn.close()
            self.assertEqual(queue.recover_stale_jobs(), 0)
            self.assertEqual(queue.get_job(job_id).status.value, "failed")


class TenantObservableTests(unittest.TestCase):
    def test_same_ioc_does_not_correlate_or_upsert_across_orgs(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
            CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
            CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
            CREATE TABLE runs (id INTEGER PRIMARY KEY);
            CREATE TABLE cases (id INTEGER PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
            """
        )
        init_feature_db(conn)
        org_1 = conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()[0]
        org_2 = conn.execute("INSERT INTO organizations (name, slug) VALUES ('Second', 'second') RETURNING id").fetchone()[0]
        conn.execute("INSERT INTO cases (id, org_id) VALUES (1, ?)", (org_1,))
        conn.execute("INSERT INTO cases (id, org_id) VALUES (2, ?)", (org_2,))
        upsert_observable(conn, obs_type="ip", value="203.0.113.7", source="test", case_id=1, org_id=org_1)
        upsert_observable(conn, obs_type="ip", value="203.0.113.7", source="test", case_id=2, org_id=org_2)
        self.assertEqual(find_correlated_case(conn, [{"type": "ip", "value": "203.0.113.7"}], org_1), 1)
        self.assertEqual(find_correlated_case(conn, [{"type": "ip", "value": "203.0.113.7"}], org_2), 2)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM observables").fetchone()[0], 2)


class ResponderApprovalTests(unittest.TestCase):
    def _connection(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
            CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
            CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
            CREATE TABLE runs (id INTEGER PRIMARY KEY);
            CREATE TABLE cases (id INTEGER PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
            INSERT INTO users VALUES (1, 'requester', 'x');
            INSERT INTO users VALUES (2, 'approver', 'x');
            INSERT INTO cases (id) VALUES (10);
            """
        )
        init_feature_db(conn)
        org_id = int(conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()["id"])
        conn.execute("UPDATE cases SET org_id = ? WHERE id = 10", (org_id,))
        return conn, org_id

    def test_responder_requires_independent_untampered_approval(self):
        conn, org_id = self._connection()
        action = create_responder_action(conn, action_type="block_ip", target="203.0.113.5", case_id=10, requested_by=1, org_id=org_id)
        with self.assertRaises(PermissionError):
            approve_responder_action(conn, action["id"], 1, org_id)
        approve_responder_action(conn, action["id"], 2, org_id)
        result = execute_responder_action(conn, action["id"], org_id)
        self.assertEqual(result["result"]["mode"], "dry_run")
        with self.assertRaises(PermissionError):
            execute_responder_action(conn, action["id"], org_id)

        second = create_responder_action(conn, action_type="block_ip", target="203.0.113.6", case_id=10, requested_by=1, org_id=org_id)
        approve_responder_action(conn, second["id"], 2, org_id)
        conn.execute("UPDATE responder_actions SET target = ? WHERE id = ?", ("203.0.113.99", second["id"]))
        with self.assertRaises(PermissionError):
            execute_responder_action(conn, second["id"], org_id)


class ChatApprovalTests(unittest.TestCase):
    def test_tool_policy_cannot_be_downgraded_by_client_or_model(self):
        self.assertTrue(_action_requires_approval({"action_type": "tool_execution", "tool_name": "nmap", "requires_approval": False}))
        self.assertFalse(_action_requires_approval({"action_type": "tool_execution", "tool_name": "whois", "requires_approval": True}))
        self.assertTrue(_action_requires_approval({"action_type": "tool_execution", "tool_name": "unknown", "requires_approval": False}))
        self.assertTrue(_action_requires_approval({"action_type": "tool_execution", "tool_name": "curl", "requires_approval": False}))

    def test_network_tool_target_must_be_a_case_observable(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE observables (org_id INTEGER, case_id INTEGER, value TEXT)")
        conn.execute("INSERT INTO observables VALUES (3, 9, 'example.com')")
        self.assertEqual(_tool_scope_target(conn, 9, 3, "whois", ["example.com"]), "example.com")
        with self.assertRaises(PermissionError):
            _tool_scope_target(conn, 9, 3, "whois", ["outside.example"])

    def test_approved_chat_action_cannot_be_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "data" / "soc_operator.db"
            db_path.parent.mkdir(parents=True)
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.executescript(
                """
                CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
                CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
                CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
                CREATE TABLE runs (id INTEGER PRIMARY KEY);
                CREATE TABLE cases (id INTEGER PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
                CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
                INSERT INTO users VALUES (1, 'requester', 'x');
                INSERT INTO users VALUES (2, 'approver', 'x');
                INSERT INTO cases (id) VALUES (10);
                """
            )
            init_feature_db(conn)
            from web.services.chat import init_chat_db
            init_chat_db(conn)
            org_id = conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()[0]
            conn.execute("UPDATE cases SET org_id = ? WHERE id = 10", (org_id,))
            conn.execute("INSERT OR IGNORE INTO organization_memberships (org_id, user_id) VALUES (?, 1), (?, 2)", (org_id, org_id))
            role_id = conn.execute("SELECT id FROM roles WHERE name = 'senior_analyst'").fetchone()[0]
            conn.execute("INSERT INTO user_roles (org_id, user_id, role_id) VALUES (?, 2, ?)", (org_id, role_id))
            thread_id = conn.execute("INSERT INTO chat_threads (case_id, created_by, org_id) VALUES (10, 1, ?)", (org_id,)).lastrowid
            conn.execute("INSERT INTO observables (org_id, case_id, type, value, source) VALUES (?, 10, 'domain', 'example.com', 'test')", (org_id,))
            action_id = conn.execute(
                "INSERT INTO chat_actions (thread_id, case_id, action_type, label, description, tool_name, tool_args_json, requires_approval, status, requested_by, org_id) VALUES (?, 10, 'tool_execution', 'Lookup', 'Passive WHOIS lookup', 'whois', '{\"args\": [\"example.com\"]}', 0, 'proposed', 1, ?)",
                (thread_id, org_id),
            ).lastrowid
            conn.commit()
            conn.close()

            app = Flask(__name__)
            app.secret_key = "test-secret"
            app.register_blueprint(chat_bp)
            execute = Mock(return_value={"status": "done", "exit_code": 0, "stdout": "ok", "stderr": "", "command_preview": "whois example.com"})
            with patch("web.routes.chat.ROOT", root), patch("scripts.common.ROOT", root), patch("web.security.DB_PATH", db_path), patch("web.services.chat.execute_tool", execute):
                client = app.test_client()
                with client.session_transaction() as sess:
                    sess["user_id"] = 2
                    sess["org_id"] = org_id
                first = client.post(f"/api/chat/10/action/{action_id}/approve")
                second = client.post(f"/api/chat/10/action/{action_id}/approve")
            self.assertEqual(first.status_code, 200)
            self.assertEqual(second.status_code, 409)
            execute.assert_called_once()


class ControlledLearningTests(unittest.TestCase):
    def test_sensitive_evidence_is_redacted_and_promotion_requires_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = LearningStore(Path(tmp) / "learning.db", Path(tmp) / "drafts")
            store.record_event(
                source="alert",
                category="alert_pattern",
                subject="Repeated login",
                summary="Repeated signal",
                evidence={"api_key": "do-not-store", "nested": {"password": "hidden"}},
                org_id=9,
            )
            conn = sqlite3.connect(str(Path(tmp) / "learning.db"))
            evidence = conn.execute("SELECT evidence_json FROM learning_events").fetchone()[0]
            conn.close()
            self.assertNotIn("do-not-store", evidence)
            suggestion = store.list_skill_suggestions(org_id=9)[0]
            store.transition_suggestion(suggestion["id"], org_id=9, status="under_review", reviewed_by=2)
            with self.assertRaises(PermissionError):
                store.transition_suggestion(suggestion["id"], org_id=9, status="approved", reviewed_by=2)
            store.record_evaluation(suggestion["id"], org_id=9, corpus_version="regression-v1", score=0.95, passed=True, evaluated_by=2)
            promoted = store.transition_suggestion(suggestion["id"], org_id=9, status="approved", reviewed_by=2)
            self.assertEqual(promoted["status"], "approved")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
