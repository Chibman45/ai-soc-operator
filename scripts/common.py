"""Shared utilities: paths, timestamps, audit logging, session management."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(event: str, **fields: object) -> None:
    audit_dir = ROOT / "audit"
    audit_dir.mkdir(exist_ok=True)
    record = {"timestamp": utc_now(), "event": event, **fields}
    with (audit_dir / "actions.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-")
    return cleaned[:80] or "action"


class Session:
    """Manages a security operation session with evidence tracking."""

    def __init__(self, mode: str, target: str, purpose: str):
        self.session_id = (
            f"session-{utc_now().replace(':', '').replace('+00:00', 'Z')}-{os.getpid()}"
        )
        self.mode = mode
        self.target = target
        self.purpose = purpose
        self.started_at = utc_now()
        self.ended_at: str | None = None
        self.status = "active"
        self.host = socket.gethostname()
        self.user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

        # Create session directories
        for subdir in ["evidence", "outputs", "scans", "reports"]:
            (ROOT / subdir / self.session_id).mkdir(parents=True, exist_ok=True)

        # Write session metadata
        evidence_dir = ROOT / "evidence" / self.session_id
        metadata = {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "ended_at": None,
            "user": self.user,
            "host": self.host,
            "mode": mode,
            "target": target,
            "purpose": purpose,
            "status": "active",
        }
        (evidence_dir / "session.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )
        (evidence_dir / "session-note.md").write_text(
            "# Session Note\n\n"
            f"- Session ID: `{self.session_id}`\n"
            f"- Started (UTC): {self.started_at}\n"
            f"- Mode: {mode}\n"
            f"- Target: {target}\n"
            f"- Purpose: {purpose}\n\n"
            "## Actions\n\n",
            encoding="utf-8",
        )
        audit(
            "session_started",
            session_id=self.session_id,
            mode=mode,
            target=target,
            purpose=purpose,
        )

    def path(self, subdir: str) -> Path:
        return ROOT / subdir / self.session_id

    def note(self, heading: str, fields: dict[str, object]) -> None:
        note_file = self.path("evidence") / "session-note.md"
        lines = ["", f"### {heading}", ""]
        for key, value in fields.items():
            lines.append(f"- {key}: {value}")
        lines.append("")
        with note_file.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))

    def finish(self) -> None:
        self.ended_at = utc_now()
        self.status = "closed"
        metadata_path = self.path("evidence") / "session.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["ended_at"] = self.ended_at
        metadata["status"] = "closed"
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        self.note("Session End", {"Ended (UTC)": self.ended_at})
        audit("session_finished", session_id=self.session_id)


def current_session() -> Session | None:
    """Load the current active session, or return None."""
    marker = ROOT / ".current_session"
    if not marker.is_file():
        return None
    session_id = marker.read_text(encoding="utf-8").strip()
    metadata_path = ROOT / "evidence" / session_id / "session.json"
    if not metadata_path.is_file():
        return None
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    session = Session.__new__(Session)
    for key, value in metadata.items():
        setattr(session, key, value)
    return session
