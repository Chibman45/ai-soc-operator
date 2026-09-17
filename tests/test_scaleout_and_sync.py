from __future__ import annotations

import sqlite3

from web.security import claim_case_for_mutation
from web.services.external_sync import sync_misp_events, sync_thehive_cases
from web.services.infrastructure import _dependency_order
from web.services.schema_features import init_feature_db


def feature_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT);
        CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT, key_name TEXT, key_value TEXT);
        CREATE TABLE platform_config (id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
        CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT);
        CREATE TABLE cases (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, case_id TEXT, title TEXT, severity TEXT, status TEXT DEFAULT 'open', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, summary TEXT, report_path TEXT);
        CREATE TABLE activity_log (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER);
        """
    )
    init_feature_db(conn)
    return conn


class TheHiveStub:
    def list_cases(self, **_kwargs):
        return [{"_id": "hive-1", "title": "Credential abuse", "severity": 3, "status": "Open", "updatedAt": 1_700_000_000_000}]


class MispStub:
    def event_search(self, _body):
        return {
            "response": [
                {"Event": {"id": "42", "info": "Known campaign", "published": True, "Attribute": [{"type": "ip-src", "value": "203.0.113.9"}]}}
            ]
        }


def test_thehive_sync_is_idempotent_and_maps_external_case():
    conn = feature_db()
    first = sync_thehive_cases(conn, org_id=1, client=TheHiveStub())
    second = sync_thehive_cases(conn, org_id=1, client=TheHiveStub())
    assert first == {"platform": "thehive", "object_type": "case", "seen": 1, "changed": 1}
    assert second["changed"] == 0
    assert conn.execute("SELECT COUNT(*) FROM cases WHERE source_platform = 'thehive'").fetchone()[0] == 1
    mapping = conn.execute("SELECT external_id, local_case_id FROM external_objects WHERE platform = 'thehive'").fetchone()
    assert mapping["external_id"] == "hive-1"
    assert mapping["local_case_id"] is not None


def test_misp_sync_is_idempotent():
    conn = feature_db()
    assert sync_misp_events(conn, org_id=1, client=MispStub())["changed"] == 1
    assert sync_misp_events(conn, org_id=1, client=MispStub())["changed"] == 0
    event = conn.execute("SELECT external_id, title, published FROM intel_events").fetchone()
    assert dict(event) == {"external_id": "42", "title": "Known campaign", "published": 1}


def test_case_claim_allows_one_analyst_and_rejects_another():
    conn = feature_db()
    case_id = conn.execute("INSERT INTO cases (org_id, title) VALUES (1, 'Race')").lastrowid
    assert claim_case_for_mutation(conn, case_id, 10, 1) is True
    assert claim_case_for_mutation(conn, case_id, 11, 1) is False
    row = conn.execute("SELECT assignee_id, row_version FROM cases WHERE id = ?", (case_id,)).fetchone()
    assert row["assignee_id"] == 10
    assert row["row_version"] == 1


def test_dependency_order_places_referenced_table_first():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));")
    assert _dependency_order(conn, ["child", "parent"]) == ["parent", "child"]


def test_postgres_translation_preserves_quoted_question_marks():
    from web.services.database import _translate_sql

    translated = _translate_sql("INSERT OR IGNORE INTO sample(value, note) VALUES (?, '?')")
    assert translated == "INSERT INTO sample(value, note) VALUES (%s, '?') ON CONFLICT DO NOTHING"


def test_backend_state_is_restart_gated(tmp_path, monkeypatch):
    from web.services import credential_vault, database

    monkeypatch.delenv("AI_SOC_DATABASE_URL", raising=False)
    monkeypatch.setattr(database, "BACKEND_STATE_PATH", tmp_path / "backend.json")
    monkeypatch.setattr(credential_vault, "KEY_FILE", tmp_path / "credential.key")
    monkeypatch.setattr(database, "_STARTUP_STATE", {})
    database.write_backend_state(
        postgres_dsn="postgresql://operator:secret@localhost/soc",
        redis_url="redis://localhost:6379/0",
        result_backend="redis://localhost:6379/1",
    )
    assert database.active_backend() == "sqlite"
    monkeypatch.setattr(database, "_STARTUP_STATE", None)
    assert database.active_backend() == "postgresql"
    assert database.runtime_queue_settings()["broker_url"] == "redis://localhost:6379/0"
