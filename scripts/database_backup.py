"""Create and verify consistent SQLite backups for the single-node profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from scripts.common import ROOT, audit


DEFAULT_DB = ROOT / "data" / "soc_operator.db"
DEFAULT_BACKUP_DIR = ROOT / "backups"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_backup(source: Path = DEFAULT_DB, destination_dir: Path = DEFAULT_BACKUP_DIR) -> Path:
    if not source.is_file():
        raise FileNotFoundError(source)
    destination_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = destination_dir / f"soc-operator-{stamp}.sqlite3"
    # sqlite3 connection context managers commit but do not close; explicit
    # closing is required so Windows can move or delete completed backups.
    with closing(sqlite3.connect(str(source))) as source_conn, closing(sqlite3.connect(str(destination))) as backup_conn:
        source_conn.backup(backup_conn)
        check = backup_conn.execute("PRAGMA integrity_check").fetchone()[0]
        if check != "ok":
            raise RuntimeError(f"backup integrity check failed: {check}")
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": str(source.resolve()),
        "backup": destination.name,
        "sha256": sha256(destination),
        "size": destination.stat().st_size,
    }
    destination.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    audit("database_backup_created", path=str(destination), sha256=manifest["sha256"])
    return destination


def verify_backup(path: Path) -> dict:
    resolved = path.resolve()
    manifest_path = resolved.with_suffix(".manifest.json")
    if not resolved.is_file() or not manifest_path.is_file():
        raise FileNotFoundError("backup and manifest are required")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("backup") != resolved.name or manifest.get("sha256") != sha256(resolved):
        raise RuntimeError("backup manifest validation failed")
    with closing(sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True)) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise RuntimeError(f"backup integrity check failed: {integrity}")
    return {"ok": True, "path": str(resolved), "sha256": manifest["sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--database", type=Path, default=DEFAULT_DB)
    create.add_argument("--output", type=Path, default=DEFAULT_BACKUP_DIR)
    verify = subparsers.add_parser("verify")
    verify.add_argument("backup", type=Path)
    args = parser.parse_args()
    result = create_backup(args.database, args.output) if args.command == "create" else verify_backup(args.backup)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
