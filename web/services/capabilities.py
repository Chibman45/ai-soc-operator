"""Approval-gated capability publication and installation.

The learning engine may create proposals, but this module is the only boundary
allowed to publish a skill, enable a responder, or invoke an installer. It never
accepts free-form shell commands and never uses ``shell=True``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the maintained stdlib backport.
    import tomli as tomllib  # type: ignore
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.common import ROOT, audit
from web.services.notifications import enqueue_notification
from web.services.responders import RESPONDER_DEFINITIONS


CATALOG_PATH = ROOT / "config" / "capability-catalog.toml"
ALLOWED_KINDS = {"skill_publish", "responder_enable", "linux_package", "python_plugin"}


def load_capability_catalog(path: Path = CATALOG_PATH) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries = data.get("capabilities", {})
    return {str(key): value for key, value in entries.items() if isinstance(value, dict)}


def create_capability_proposal(
    conn,
    *,
    org_id: int,
    kind: str,
    target: str,
    reason: str,
    manifest: dict[str, Any],
    requested_by: int | None,
    source: str = "ai",
) -> dict[str, Any]:
    if kind not in ALLOWED_KINDS:
        raise ValueError("unsupported capability proposal kind")
    target = target.strip()
    reason = reason.strip()
    if not target or len(target) > 200 or not reason or len(reason) > 2000:
        raise ValueError("target and a concise explanation are required")
    normalized = _normalize_manifest(kind, target, manifest)
    digest = _proposal_digest(kind, target, reason, normalized)
    cursor = conn.execute(
        """
        INSERT INTO capability_proposals
            (org_id, kind, target, reason, source, manifest_json,
             manifest_digest, requested_by, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed')
        """,
        (
            org_id,
            kind,
            target,
            reason,
            source[:40],
            json.dumps(normalized, sort_keys=True),
            digest,
            requested_by,
        ),
    )
    proposal_id = int(cursor.lastrowid)
    enqueue_notification(
        conn,
        org_id=org_id,
        event_type="capability_approval_required",
        severity="high",
        message=f"Capability proposal {proposal_id} requests {kind}: {target}. Reason: {reason}",
        metadata={"proposal_id": proposal_id, "kind": kind, "target": target},
        dedup_key=f"capability:{proposal_id}:approval",
    )
    audit(
        "capability_proposed",
        proposal_id=proposal_id,
        org_id=org_id,
        kind=kind,
        target=target,
        source=source,
    )
    return {
        "id": proposal_id,
        "kind": kind,
        "target": target,
        "reason": reason,
        "status": "proposed",
        "manifest": normalized,
    }


def propose_catalog_capability(
    conn,
    *,
    org_id: int,
    catalog_id: str,
    requested_by: int | None,
    source: str = "ai",
    rationale: str | None = None,
) -> dict[str, Any]:
    entry = load_capability_catalog().get(catalog_id)
    if not entry:
        raise ValueError("capability is not present in the approved catalog")
    kind = str(entry.get("kind", ""))
    target = str(entry.get("package") or entry.get("responder") or catalog_id)
    manifest = {"catalog_id": catalog_id, **entry}
    reason = rationale.strip() if rationale and rationale.strip() else str(entry.get("reason", ""))
    if entry.get("risk"):
        reason = f"{reason} Risk: {entry['risk']}"
    return create_capability_proposal(
        conn,
        org_id=org_id,
        kind=kind,
        target=target,
        reason=reason,
        manifest=manifest,
        requested_by=requested_by,
        source=source,
    )


def approve_capability_proposal(conn, proposal_id: int, *, org_id: int, approved_by: int) -> dict[str, Any]:
    row = _get_proposal(conn, proposal_id, org_id)
    if row["requested_by"] == approved_by:
        raise PermissionError("the requester cannot approve their own capability proposal")
    _verify_proposal(row)
    updated = conn.execute(
        """
        UPDATE capability_proposals
        SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP,
            approval_expires_at = datetime('now', '+30 minutes'), updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND org_id = ? AND status = 'proposed'
        """,
        (approved_by, proposal_id, org_id),
    ).rowcount
    if not updated:
        raise ValueError("capability proposal is no longer awaiting approval")
    audit("capability_approved", proposal_id=proposal_id, org_id=org_id, approved_by=approved_by)
    return {"id": proposal_id, "status": "approved"}


def reject_capability_proposal(
    conn,
    proposal_id: int,
    *,
    org_id: int,
    rejected_by: int,
    reason: str = "",
) -> dict[str, Any]:
    updated = conn.execute(
        """
        UPDATE capability_proposals
        SET status = 'rejected', rejected_by = ?, rejected_at = CURRENT_TIMESTAMP,
            rejection_reason = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND org_id = ? AND status IN ('proposed', 'approved')
        """,
        (rejected_by, reason[:500], proposal_id, org_id),
    ).rowcount
    if not updated:
        raise ValueError("capability proposal cannot be rejected in its current state")
    audit("capability_rejected", proposal_id=proposal_id, org_id=org_id, rejected_by=rejected_by)
    return {"id": proposal_id, "status": "rejected"}


def execute_capability_proposal(conn, proposal_id: int, *, org_id: int, root: Path = ROOT) -> dict[str, Any]:
    row = _get_proposal(conn, proposal_id, org_id)
    if row["status"] != "approved":
        raise PermissionError("capability proposal must be approved before execution")
    expires = _parse_utc(row["approval_expires_at"])
    if not expires or expires < datetime.now(timezone.utc):
        raise PermissionError("capability approval has expired")
    manifest = _verify_proposal(row)
    claimed = conn.execute(
        "UPDATE capability_proposals SET status = 'executing', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ? AND status = 'approved'",
        (proposal_id, org_id),
    ).rowcount
    if not claimed:
        raise PermissionError("capability proposal is no longer executable")
    conn.commit()

    try:
        result = _execute_manifest(conn, row, manifest, root.resolve())
        status = "executed"
    except Exception as exc:
        result = {"ok": False, "error": str(exc)[:1000]}
        status = "failed"
    conn.execute(
        """
        UPDATE capability_proposals
        SET status = ?, result_json = ?, executed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND org_id = ? AND status = 'executing'
        """,
        (status, json.dumps(result, sort_keys=True), proposal_id, org_id),
    )
    audit("capability_execution_finished", proposal_id=proposal_id, org_id=org_id, status=status)
    return {"id": proposal_id, "status": status, "result": result}


def _execute_manifest(conn, row, manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    kind = str(row["kind"])
    if kind == "skill_publish":
        return _publish_skill(conn, row, manifest, root)
    if kind == "responder_enable":
        responder = str(manifest.get("responder", ""))
        if responder not in RESPONDER_DEFINITIONS:
            raise RuntimeError("responder is not supported by this release")
        conn.execute(
            """
            INSERT INTO responder_capabilities
                (org_id, responder_type, enabled, enabled_by_proposal_id, enabled_at, config_json)
            VALUES (?, ?, 1, ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(org_id, responder_type) DO UPDATE SET
                enabled = 1, enabled_by_proposal_id = excluded.enabled_by_proposal_id,
                enabled_at = CURRENT_TIMESTAMP, config_json = excluded.config_json
            """,
            (row["org_id"], responder, row["id"], json.dumps(manifest.get("config", {}), sort_keys=True)),
        )
        return {"ok": True, "responder": responder, "enabled": True}
    if kind == "linux_package":
        if os.environ.get("AI_SOC_ALLOW_SYSTEM_INSTALL", "").lower() not in {"1", "true", "yes"}:
            raise RuntimeError("system package installation is disabled by AI_SOC_ALLOW_SYSTEM_INSTALL")
        return _run_install(proposal_id=int(row["id"]), argv=_linux_install_argv(str(manifest["package"])), root=root)
    if kind == "python_plugin":
        if os.environ.get("AI_SOC_ALLOW_PLUGIN_INSTALL", "").lower() not in {"1", "true", "yes"}:
            raise RuntimeError("plugin installation is disabled by AI_SOC_ALLOW_PLUGIN_INSTALL")
        return _install_python_plugin(int(row["id"]), manifest, root)
    raise RuntimeError("unsupported capability execution kind")


def _publish_skill(conn, row, manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    suggestion_id = int(manifest.get("suggestion_id", 0))
    suggestion = conn.execute(
        "SELECT * FROM skill_suggestions WHERE id = ? AND org_id = ?",
        (suggestion_id, row["org_id"]),
    ).fetchone()
    if not suggestion or suggestion["status"] != "publication_requested":
        raise RuntimeError("skill suggestion is not ready for approved publication")
    draft_file = Path(str(suggestion["draft_path"])).resolve()
    draft_root = (root / "data" / "learning" / "skill_drafts").resolve()
    if draft_file.name != "SKILL.md" or not draft_file.is_file() or not draft_file.is_relative_to(draft_root):
        raise RuntimeError("skill draft path is outside the controlled learning directory")
    content = draft_file.read_text(encoding="utf-8")
    if not content.startswith("---\n") or "\nname:" not in content or "\ndescription:" not in content:
        raise RuntimeError("skill draft frontmatter is invalid")
    destination_root = (root / "skills" / "generated").resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    destination = (destination_root / str(suggestion["slug"])).resolve()
    if not destination.is_relative_to(destination_root):
        raise RuntimeError("skill publication destination escaped its root")
    temp_destination = destination.with_name(destination.name + ".pending")
    if any(path.is_symlink() for path in draft_file.parent.rglob("*")):
        raise RuntimeError("skill drafts containing symbolic links cannot be published")
    if temp_destination.exists():
        shutil.rmtree(temp_destination)
    shutil.copytree(draft_file.parent, temp_destination, symlinks=False)
    # An existing publication requires an explicit rollback/version workflow;
    # never erase a live skill as a side effect of a new approval.
    if destination.exists():
        shutil.rmtree(temp_destination)
        raise RuntimeError("a published skill with this slug already exists")
    temp_destination.replace(destination)
    conn.execute(
        "UPDATE skill_suggestions SET status = 'published', published_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ?",
        (suggestion_id, row["org_id"]),
    )
    return {"ok": True, "suggestion_id": suggestion_id, "published_path": str(destination)}


def _linux_install_argv(package_name: str) -> list[str]:
    if platform.system().lower() != "linux":
        raise RuntimeError("Linux package installation is available only on Linux hosts")
    if not package_name.replace("-", "").replace("_", "").isalnum():
        raise RuntimeError("catalog package name is invalid")
    manager = next((name for name in ("apt-get", "dnf", "yum", "zypper", "pacman") if shutil.which(name)), None)
    if not manager:
        raise RuntimeError("no supported Linux package manager was found")
    args = {
        "apt-get": ["apt-get", "install", "-y", package_name],
        "dnf": ["dnf", "install", "-y", package_name],
        "yum": ["yum", "install", "-y", package_name],
        "zypper": ["zypper", "--non-interactive", "install", package_name],
        "pacman": ["pacman", "--noconfirm", "-S", package_name],
    }[manager]
    if os.geteuid() != 0:
        if not shutil.which("sudo"):
            raise RuntimeError("package installation requires root or passwordless sudo")
        probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10, check=False)
        if probe.returncode != 0:
            raise RuntimeError("passwordless sudo is unavailable; enter credentials only in a local terminal")
        args = ["sudo", "-n", *args]
    return args


def _install_python_plugin(proposal_id: int, manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    requirements = manifest.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise RuntimeError("plugin catalog must provide hashed requirements for every artifact")
    lines = []
    for item in requirements:
        if not isinstance(item, dict):
            raise RuntimeError("plugin requirement entries must be objects")
        requirement = str(item.get("requirement", ""))
        sha256 = str(item.get("sha256", "")).lower()
        if "==" not in requirement or len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
            raise RuntimeError("plugin requirements must be exactly pinned with SHA-256 hashes")
        lines.append(f"{requirement} --hash=sha256:{sha256}")
    target = root / "data" / "plugins" / "python"
    target.mkdir(parents=True, exist_ok=True)
    temp_dir = root / "data" / "tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", dir=temp_dir, delete=False, encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
        requirements_path = Path(handle.name)
    try:
        argv = [sys.executable, "-m", "pip", "install", "--require-hashes", "--no-deps", "--target", str(target), "-r", str(requirements_path)]
        return _run_install(proposal_id=proposal_id, argv=argv, root=root)
    finally:
        requirements_path.unlink(missing_ok=True)


def _run_install(*, proposal_id: int, argv: list[str], root: Path) -> dict[str, Any]:
    evidence_dir = root / "evidence" / f"capability-{proposal_id}"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    safe_env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    }
    completed = subprocess.run(
        argv,
        cwd=root,
        env=safe_env,
        shell=False,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    result = {
        "ok": completed.returncode == 0,
        "argv": argv,
        "cwd": str(root),
        "returncode": completed.returncode,
        "stdout": completed.stdout[-20000:],
        "stderr": completed.stderr[-10000:],
    }
    (evidence_dir / "installation-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"installer exited with code {completed.returncode}; see {evidence_dir}")
    return result


def _normalize_manifest(kind: str, target: str, manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("capability manifest must be an object")
    normalized = json.loads(json.dumps(manifest, sort_keys=True))
    if kind in {"linux_package", "python_plugin", "responder_enable"}:
        catalog_id = str(normalized.get("catalog_id", ""))
        catalog_entry = load_capability_catalog().get(catalog_id)
        if not catalog_entry:
            raise ValueError("installable and responder capabilities must come from the approved catalog")
        expected = {"catalog_id": catalog_id, **catalog_entry}
        if normalized != expected:
            raise ValueError("capability manifest does not match the approved catalog")
    if kind == "skill_publish" and int(normalized.get("suggestion_id", 0)) <= 0:
        raise ValueError("skill publication requires a learning suggestion id")
    return normalized


def _proposal_digest(kind: str, target: str, reason: str, manifest: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"kind": kind, "target": target, "reason": reason, "manifest": manifest},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _get_proposal(conn, proposal_id: int, org_id: int):
    row = conn.execute(
        "SELECT * FROM capability_proposals WHERE id = ? AND org_id = ?",
        (proposal_id, org_id),
    ).fetchone()
    if not row:
        raise ValueError("capability proposal not found")
    return row


def _verify_proposal(row) -> dict[str, Any]:
    manifest = json.loads(row["manifest_json"])
    digest = _proposal_digest(row["kind"], row["target"], row["reason"], manifest)
    if not row["manifest_digest"] or not hmac.compare_digest(row["manifest_digest"], digest):
        raise PermissionError("capability proposal changed after creation")
    return _normalize_manifest(row["kind"], row["target"], manifest)


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
