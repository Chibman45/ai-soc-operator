from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

from web.app import app
from web.services.schema_features import init_feature_db


class OAuthClientStub:
    def __init__(self, claims):
        self.claims = claims

    def authorize_access_token(self):
        return {"access_token": "must-not-be-stored", "refresh_token": "must-not-be-stored"}

    def parse_id_token(self, _token, nonce):
        assert nonce == "expected-nonce"
        return self.claims


def create_database(path: Path, *, email: str | None = "analyst@example.com"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT);
        CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT, key_name TEXT, key_value TEXT);
        CREATE TABLE platform_config (id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
        CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT);
        CREATE TABLE cases (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE activity_log (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER);
        INSERT INTO users (username, password_hash) VALUES ('analyst', 'unused');
        """
    )
    init_feature_db(conn)
    org_id = int(conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()[0])
    conn.execute("UPDATE users SET email = ?, default_org_id = ? WHERE id = 1", (email, org_id))
    conn.execute("INSERT OR IGNORE INTO organization_memberships (org_id, user_id, status) VALUES (?, 1, 'active')", (org_id,))
    conn.commit()
    conn.close()
    return org_id


def connection_factory(path: Path):
    def connect():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn
    return connect


def test_verified_preprovisioned_email_can_sign_in_without_storing_tokens(tmp_path):
    database = tmp_path / "oauth.db"
    org_id = create_database(database)
    oauth_client = OAuthClientStub(
        {"iss": "https://identity.openai.example", "sub": "openai-user-1", "email": "analyst@example.com", "email_verified": True, "name": "Analyst"}
    )
    app.config.update(TESTING=True, SECRET_KEY="oauth-test")
    with patch("web.app.get_db", side_effect=connection_factory(database)), patch("web.app._openai_oauth_client", return_value=oauth_client):
        client = app.test_client()
        with client.session_transaction() as session:
            session["openai_oauth_nonce"] = "expected-nonce"
            session["openai_oauth_intent"] = "login"
        response = client.get("/auth/openai/callback")
        assert response.status_code == 302
        with client.session_transaction() as session:
            assert session["user_id"] == 1
            assert session["org_id"] == org_id
            assert session["auth_method"] == "openai_chatgpt"
    conn = connection_factory(database)()
    identity = conn.execute("SELECT subject, claims_json FROM auth_identities").fetchone()
    assert identity["subject"] == "openai-user-1"
    stored = json.loads(identity["claims_json"])
    assert "access_token" not in stored and "refresh_token" not in stored
    conn.close()


def test_unprovisioned_email_is_rejected(tmp_path):
    database = tmp_path / "oauth.db"
    create_database(database)
    oauth_client = OAuthClientStub(
        {"sub": "openai-user-2", "email": "unknown@example.com", "email_verified": True}
    )
    app.config.update(TESTING=True, SECRET_KEY="oauth-test")
    with patch("web.app.get_db", side_effect=connection_factory(database)), patch("web.app._openai_oauth_client", return_value=oauth_client):
        client = app.test_client()
        with client.session_transaction() as session:
            session["openai_oauth_nonce"] = "expected-nonce"
            session["openai_oauth_intent"] = "login"
        response = client.get("/auth/openai/callback")
        assert response.status_code == 302
        with client.session_transaction() as session:
            assert "user_id" not in session
    conn = connection_factory(database)()
    assert conn.execute("SELECT COUNT(*) FROM auth_identities").fetchone()[0] == 0
    conn.close()


def test_unverified_email_is_rejected(tmp_path):
    database = tmp_path / "oauth.db"
    create_database(database)
    oauth_client = OAuthClientStub(
        {"sub": "openai-user-3", "email": "analyst@example.com", "email_verified": False}
    )
    app.config.update(TESTING=True, SECRET_KEY="oauth-test")
    with patch("web.app.get_db", side_effect=connection_factory(database)), patch("web.app._openai_oauth_client", return_value=oauth_client):
        client = app.test_client()
        with client.session_transaction() as session:
            session["openai_oauth_nonce"] = "expected-nonce"
            session["openai_oauth_intent"] = "login"
        client.get("/auth/openai/callback")
    conn = connection_factory(database)()
    assert conn.execute("SELECT COUNT(*) FROM auth_identities").fetchone()[0] == 0
    conn.close()


def test_authenticated_bootstrap_user_can_link_verified_identity(tmp_path):
    database = tmp_path / "oauth.db"
    org_id = create_database(database, email=None)
    oauth_client = OAuthClientStub(
        {"sub": "openai-admin-1", "email": "owner@example.com", "email_verified": True}
    )
    app.config.update(TESTING=True, SECRET_KEY="oauth-test")
    with patch("web.app.get_db", side_effect=connection_factory(database)), patch("web.app._openai_oauth_client", return_value=oauth_client):
        client = app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = 1
            session["username"] = "analyst"
            session["org_id"] = org_id
            session["session_version"] = 0
            session["openai_oauth_nonce"] = "expected-nonce"
            session["openai_oauth_intent"] = "link"
        response = client.get("/auth/openai/callback")
        assert response.status_code == 302
    conn = connection_factory(database)()
    assert conn.execute("SELECT email FROM users WHERE id = 1").fetchone()[0] == "owner@example.com"
    assert conn.execute("SELECT subject FROM auth_identities WHERE user_id = 1").fetchone()[0] == "openai-admin-1"
    conn.close()
