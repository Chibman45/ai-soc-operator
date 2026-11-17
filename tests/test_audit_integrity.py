"""Tamper-evident audit storage tests."""

import json

from scripts.common import audit, verify_audit_chain


def test_audit_chain_verifies_and_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_SOC_AUDIT_DIR", str(tmp_path))
    audit("first_event", org_id=1)
    audit("second_event", org_id=1)
    path = tmp_path / "actions.jsonl"
    assert verify_audit_chain(path)
    records = path.read_text(encoding="utf-8").splitlines()
    changed = json.loads(records[0])
    changed["org_id"] = 2
    records[0] = json.dumps(changed)
    path.write_text("\n".join(records) + "\n", encoding="utf-8")
    assert not verify_audit_chain(path)


def test_audit_chain_anchors_legacy_records_without_rewriting_them(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_SOC_AUDIT_DIR", str(tmp_path))
    path = tmp_path / "actions.jsonl"
    legacy = b'{"event":"legacy_event","timestamp":"2025-01-01T00:00:00+00:00"}\n'
    path.write_bytes(legacy)

    audit("first_chained_event", org_id=1)

    assert path.read_bytes().startswith(legacy)
    transition = json.loads(path.read_text(encoding="utf-8").splitlines()[1])
    assert transition["chain_transition"] == "legacy_anchor_v1"
    assert transition["previous_hash"].startswith("legacy-sha256:")
    assert verify_audit_chain(path)

    path.write_bytes(path.read_bytes().replace(b"legacy_event", b"changed_event", 1))
    assert not verify_audit_chain(path)
