"""Tests for organization user invitations and reviewed policy enforcement."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse
from unittest.mock import patch

from web.app import app, hash_password, init_db, verify_password
from web.services.organization_policy import (
    allowed_playbooks_for_user,
    approve_policy_draft,
    create_policy_draft,
    policy_allows_target,
)
from web.services.schema_features import init_feature_db


def policy_connection() -> tuple[sqlite3.Connection, int]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
        CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
        CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
        CREATE TABLE runs (id INTEGER PRIMARY KEY);
        CREATE TABLE cases (id INTEGER PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
        INSERT INTO users VALUES (1, 'owner', 'x');
        INSERT INTO users VALUES (2, 'alice', 'x');
        """
    )
    init_feature_db(conn)
    org_id = int(conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()[0])
    conn.execute("INSERT OR IGNORE INTO organization_memberships (org_id, user_id) VALUES (?, 2)", (org_id,))
    analyst_id = int(conn.execute("SELECT id FROM roles WHERE name = 'analyst'").fetchone()[0])
    conn.execute(
        "INSERT INTO user_roles (org_id, user_id, role_id, source) VALUES (?, 2, ?, 'manual')",
        (org_id, analyst_id),
    )
    conn.commit()
    return conn, org_id


class OrganizationPolicyTests(unittest.TestCase):
    def test_draft_grants_nothing_until_approval_then_enforces_scope(self):
        conn, org_id = policy_connection()
        with tempfile.TemporaryDirectory() as tmp:
            policy_file = Path(tmp) / "organization.yaml"
            policy_file.write_text(
                """
access_policy:
  organization_name: Example SOC
  role_policies:
    senior_analyst:
      playbooks: [identity-compromise.yaml]
      scope:
        hosts: [soc-host-1]
        cidrs: [203.0.113.0/24]
        domains: ['*.example.com']
  users:
    - username: alice
      roles: [senior_analyst]
      playbooks: []
      scope:
        hosts: []
        cidrs: []
        domains: []
""",
                encoding="utf-8",
            )
            draft = create_policy_draft(
                conn,
                org_id=org_id,
                source_path=policy_file,
                source_name=policy_file.name,
                created_by=1,
                llm_callback=None,
                known_playbooks=["identity-compromise.yaml", "malware.yaml"],
            )
            before = {
                row[0]
                for row in conn.execute(
                    "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = 2"
                ).fetchall()
            }
            self.assertEqual(before, {"analyst"})

            result = approve_policy_draft(conn, draft["id"], org_id=org_id, approved_by=1)
            conn.commit()

        after = {
            row[0]
            for row in conn.execute(
                "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = 2"
            ).fetchall()
        }
        self.assertEqual(after, {"analyst", "senior_analyst"})
        self.assertEqual(result["applied_users"], ["alice"])
        self.assertEqual(
            allowed_playbooks_for_user(
                conn,
                org_id=org_id,
                user_id=2,
                available=["identity-compromise.yaml", "malware.yaml"],
            ),
            ["identity-compromise.yaml"],
        )
        self.assertTrue(policy_allows_target(conn, org_id=org_id, user_id=2, target="203.0.113.44"))
        self.assertTrue(policy_allows_target(conn, org_id=org_id, user_id=2, target="mail.example.com"))
        self.assertFalse(policy_allows_target(conn, org_id=org_id, user_id=2, target="198.51.100.10"))


class UserInvitationTests(unittest.TestCase):
    def test_admin_invites_and_user_activates_with_one_time_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "soc_operator.db"
            with (
                patch("web.app.DB_PATH", database),
                patch("web.security.DB_PATH", database),
                patch("web.routes.admin.DB_PATH", database),
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
                org_id = int(conn.execute("SELECT default_org_id FROM users WHERE id = ?", (owner_id,)).fetchone()[0])
                analyst_id = int(conn.execute("SELECT id FROM roles WHERE name = 'analyst'").fetchone()[0])
                conn.close()

                app.config.update(TESTING=True, SERVER_NAME="localhost")
                admin_client = app.test_client()
                with admin_client.session_transaction() as sess:
                    sess["user_id"] = owner_id
                    sess["org_id"] = org_id
                    sess["csrf_token"] = "admin-csrf"
                response = admin_client.post(
                    "/api/admin/users",
                    json={"username": "alice", "email": "alice@example.com", "role_ids": [analyst_id]},
                    headers={"X-CSRF-Token": "admin-csrf"},
                )
                self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
                activation_path = urlparse(response.get_json()["activation_url"]).path

                conn = sqlite3.connect(database)
                conn.row_factory = sqlite3.Row
                invited = conn.execute("SELECT * FROM users WHERE username = 'alice'").fetchone()
                invitation = conn.execute("SELECT token_hash FROM user_invitations WHERE user_id = ?", (invited["id"],)).fetchone()
                self.assertEqual(invited["must_change_password"], 1)
                self.assertNotIn(activation_path.rsplit("/", 1)[-1], invitation["token_hash"])
                conn.close()

                invited_client = app.test_client()
                self.assertEqual(invited_client.get(activation_path).status_code, 200)
                with invited_client.session_transaction() as sess:
                    csrf = sess["csrf_token"]
                activated = invited_client.post(
                    activation_path,
                    data={
                        "csrf_token": csrf,
                        "password": "alice-password-123",
                        "confirm_password": "alice-password-123",
                    },
                )
                self.assertEqual(activated.status_code, 302)
                self.assertEqual(invited_client.get(activation_path).status_code, 400)

                conn = sqlite3.connect(database)
                conn.row_factory = sqlite3.Row
                active = conn.execute("SELECT password_hash, must_change_password FROM users WHERE username = 'alice'").fetchone()
                conn.close()
                self.assertEqual(active["must_change_password"], 0)
                self.assertTrue(verify_password("alice-password-123", active["password_hash"]))

                signed_in = invited_client.post(
                    "/login",
                    data={"csrf_token": csrf, "username": "alice", "password": "alice-password-123"},
                )
                self.assertEqual(signed_in.status_code, 302)
                reset = admin_client.post(
                    f"/api/admin/users/{invited['id']}/reset-activation",
                    headers={"X-CSRF-Token": "admin-csrf"},
                )
                self.assertEqual(reset.status_code, 200)
                revoked = invited_client.get("/")
                self.assertEqual(revoked.status_code, 302)
                self.assertEqual(urlparse(revoked.location).path, "/login")


class ResponderPolicyRouteTests(unittest.TestCase):
    def test_responder_listing_works_and_proposal_respects_policy_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "data" / "soc_operator.db"
            database.parent.mkdir(parents=True)
            with (
                patch("web.app.DB_PATH", database),
                patch("web.security.DB_PATH", database),
                patch("web.routes.operations.ROOT", root),
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
                org_id = int(conn.execute("SELECT default_org_id FROM users WHERE id = ?", (owner_id,)).fetchone()[0])
                case_id = int(
                    conn.execute(
                        "INSERT INTO cases (org_id, title, severity) VALUES (?, 'Scope test', 'medium')",
                        (org_id,),
                    ).lastrowid
                )
                conn.execute(
                    "INSERT INTO observables (org_id, case_id, type, value, source) VALUES (?, ?, 'ip', '198.51.100.8', 'test')",
                    (org_id, case_id),
                )
                policy = {
                    "organization_name": "Example",
                    "role_policies": {
                        "admin": {
                            "playbooks": ["*"],
                            "scope": {
                                "hosts": [], "cidrs": ["203.0.113.0/24"], "domains": [],
                                "users": [], "indicators": [],
                            },
                        }
                    },
                    "users": [],
                }
                policy_json = json.dumps(policy, sort_keys=True, separators=(",", ":"))
                digest = hashlib.sha256(policy_json.encode()).hexdigest()
                draft_id = int(
                    conn.execute(
                        """
                        INSERT INTO organization_policy_drafts
                            (org_id, source_name, source_sha256, evidence_path, extracted_json,
                             policy_digest, extraction_model, created_by)
                        VALUES (?, 'test.yaml', 'source', 'evidence/test.yaml', ?, ?, 'test', ?)
                        """,
                        (org_id, json.dumps(policy, sort_keys=True), digest, owner_id),
                    ).lastrowid
                )
                approve_policy_draft(conn, draft_id, org_id=org_id, approved_by=owner_id)
                conn.commit()
                conn.close()

                client = app.test_client()
                with client.session_transaction() as sess:
                    sess["user_id"] = owner_id
                    sess["org_id"] = org_id
                    sess["session_version"] = 0
                    sess["csrf_token"] = "test-csrf"
                listing = client.get(f"/api/cases/{case_id}/responders")
                self.assertEqual(listing.status_code, 200, listing.get_data(as_text=True))
                denied = client.post(
                    f"/api/cases/{case_id}/responders",
                    json={"action_type": "block_ip", "target": "198.51.100.8"},
                    headers={"X-CSRF-Token": "test-csrf"},
                )
                self.assertEqual(denied.status_code, 403)
                self.assertIn("organization policy scope", denied.get_json()["error"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
