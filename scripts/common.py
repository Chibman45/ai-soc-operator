"""Shared utilities: paths, timestamps, audit logging, session management."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_AUDIT_LOCK = threading.Lock()


def _storage_root(env_name: str, default: Path) -> Path:
    configured = os.environ.get(env_name, "").strip()
    return Path(configured).expanduser().resolve() if configured else default


def _audit_record_hash(record: dict[str, object]) -> str:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _legacy_audit_anchor(audit_file: Path) -> str | None:
    """Bind an existing pre-chain audit file without rewriting its history."""
    if not audit_file.exists() or audit_file.stat().st_size == 0:
        return None
    return f"legacy-sha256:{hashlib.sha256(audit_file.read_bytes()).hexdigest()}"


@contextmanager
def _process_file_lock(path: Path):
    """Serialize writers from multiple local worker processes."""
    with path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def utc_now() -> str:
    # Keep Python 3.10 compatibility; datetime.UTC was introduced in Python 3.11.
    return datetime.now(timezone.utc).isoformat()  # noqa: UP017


def audit(event: str, **fields: object) -> None:
    audit_dir = _storage_root("AI_SOC_AUDIT_DIR", ROOT / "audit")
    audit_dir.mkdir(parents=True, exist_ok=True)
    head_path = audit_dir / "chain.head"
    # The hash chain detects removal or modification when audit storage is shared by hosts.
    with _AUDIT_LOCK, _process_file_lock(audit_dir / ".write.lock"):
        audit_file = audit_dir / "actions.jsonl"
        legacy_anchor = None if head_path.exists() else _legacy_audit_anchor(audit_file)
        previous_hash = (
            head_path.read_text(encoding="ascii").strip()
            if head_path.exists()
            else legacy_anchor or "0" * 64
        )
        body = {"timestamp": utc_now(), "event": event, **fields, "previous_hash": previous_hash}
        # Mark only the transition record so verification can distinguish a protected
        # legacy prefix from chains created by earlier releases.
        if legacy_anchor:
            body["chain_transition"] = "legacy_anchor_v1"
        record = {**body, "record_hash": _audit_record_hash(body)}
        with audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary = head_path.with_name(f"chain.{os.getpid()}.tmp")
        temporary.write_text(record["record_hash"], encoding="ascii")
        temporary.replace(head_path)


def verify_audit_chain(path: Path | None = None) -> bool:
    audit_file = path or (_storage_root("AI_SOC_AUDIT_DIR", ROOT / "audit") / "actions.jsonl")
    previous_hash = "0" * 64
    legacy_prefix = bytearray()
    chained_records = 0
    try:
        for raw_line in audit_file.read_bytes().splitlines(keepends=True):
            record = json.loads(raw_line.decode("utf-8"))
            if "record_hash" not in record:
                if chained_records:
                    return False
                legacy_prefix.extend(raw_line)
                continue
            record_hash = str(record.pop("record_hash"))
            if not chained_records and legacy_prefix:
                legacy_anchor = f"legacy-sha256:{hashlib.sha256(legacy_prefix).hexdigest()}"
                if record.get("chain_transition") == "legacy_anchor_v1":
                    previous_hash = legacy_anchor
                elif record.get("previous_hash") != previous_hash:
                    # Compatibility for chains started before legacy anchoring existed.
                    return False
            if record.get("previous_hash") != previous_hash or _audit_record_hash(record) != record_hash:
                return False
            previous_hash = record_hash
            chained_records += 1
        return chained_records > 0
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        return False


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
            base = _storage_root("AI_SOC_EVIDENCE_DIR", ROOT / "evidence") if subdir == "evidence" else ROOT / subdir
            (base / self.session_id).mkdir(parents=True, exist_ok=True)

        # Write session metadata
        evidence_dir = _storage_root("AI_SOC_EVIDENCE_DIR", ROOT / "evidence") / self.session_id
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
        base = _storage_root("AI_SOC_EVIDENCE_DIR", ROOT / "evidence") if subdir == "evidence" else ROOT / subdir
        return base / self.session_id

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
