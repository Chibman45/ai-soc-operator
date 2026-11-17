"""Multi-host lease, RLS, and secret-rotation controls."""

from __future__ import annotations

import json
import sqlite3

from cryptography.fernet import Fernet

from scripts.postgres_rls import policy_statements
from web.services.credential_vault import open_secret, rotate_credentials, seal_secret
from web.services.distributed_lock import acquire_lease, init_lock_schema, release_lease
from web.services.playbook_jobs import dispatch_playbook_job


def test_distributed_lease_has_single_owner_and_owner_checked_release():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_lock_schema(conn)
    first = acquire_lease(conn, "sync:1:wazuh", owner_token="worker-a")
    assert first == "worker-a"
    assert acquire_lease(conn, "sync:1:wazuh", owner_token="worker-b") is None
    assert release_lease(conn, "sync:1:wazuh", "worker-b") is False
    assert release_lease(conn, "sync:1:wazuh", "worker-a") is True
    assert acquire_lease(conn, "sync:1:wazuh", owner_token="worker-b") == "worker-b"


def test_rls_policy_uses_transaction_tenant_setting_and_rejects_identifiers():
    statements = policy_statements("cases")
    assert any("ENABLE ROW LEVEL SECURITY" in value for value in statements)
    assert any("current_setting('app.current_org_id'" in value for value in statements)
    try:
        policy_statements("cases; DROP TABLE users")
        raise AssertionError("unsafe identifier accepted")
    except ValueError:
        pass


def test_keyring_rotation_preserves_decryption(monkeypatch):
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE credentials (id INTEGER PRIMARY KEY, key_value TEXT, updated_at TIMESTAMP)")
    monkeypatch.setenv("AI_SOC_CREDENTIAL_KEY", old_key)
    conn.execute("INSERT INTO credentials (id, key_value) VALUES (1, ?)", (seal_secret("soc-secret"),))
    monkeypatch.setenv("AI_SOC_CREDENTIAL_KEYS", json.dumps({"old": old_key, "2026-10": new_key}))
    monkeypatch.setenv("AI_SOC_CREDENTIAL_ACTIVE_KEY", "2026-10")
    # Legacy v1 values remain readable through AI_SOC_CREDENTIAL_KEY while rotating to v2.
    assert rotate_credentials(conn) == 1
    value = conn.execute("SELECT key_value FROM credentials WHERE id = 1").fetchone()[0]
    assert value.startswith("enc:v2:2026-10:")
    assert open_secret(value) == "soc-secret"


def test_local_job_dispatch_carries_tenant_context(monkeypatch):
    captured = {}

    class Queue:
        def execute_job(self, job_id, executor, *, org_id=None):
            captured.update(job_id=job_id, org_id=org_id, executor=executor)

    monkeypatch.setattr("web.services.playbook_jobs.runtime_queue_settings", dict)
    assert dispatch_playbook_job(Queue(), "job-1", 42) == "local"
    assert captured["job_id"] == "job-1"
    assert captured["org_id"] == 42
