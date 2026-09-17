"""Validated, restart-gated migration from local SQLite to PostgreSQL/Celery."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from scripts.common import ROOT, audit
from scripts.database_backup import create_backup, verify_backup
from web.services.credential_vault import open_secret, seal_secret
from web.services.database import _translate_schema, write_backend_state


SQLITE_PATH = ROOT / "data" / "soc_operator.db"
BACKUP_DIR = ROOT / "backups"


def validate_infrastructure(postgres_dsn: str, redis_url: str, result_backend: str = "") -> dict[str, Any]:
    """Test target services without storing or logging their credentials."""
    if urlparse(postgres_dsn).scheme not in {"postgres", "postgresql"}:
        raise ValueError("PostgreSQL URL must start with postgresql:// or postgres://")
    if urlparse(redis_url).scheme not in {"redis", "rediss"}:
        raise ValueError("Redis URL must start with redis:// or rediss://")
    try:
        import psycopg
        from redis import Redis
    except ImportError as exc:
        raise RuntimeError("Install the PostgreSQL and Redis runtime dependencies first") from exc

    with psycopg.connect(postgres_dsn, connect_timeout=5) as target:
        database = target.execute("SELECT current_database()").fetchone()[0]
    redis_client = Redis.from_url(redis_url, socket_connect_timeout=5, socket_timeout=5)
    redis_client.ping()
    if result_backend:
        if urlparse(result_backend).scheme not in {"redis", "rediss"}:
            raise ValueError("Celery result backend must be a Redis URL")
        Redis.from_url(result_backend, socket_connect_timeout=5, socket_timeout=5).ping()
    return {"ok": True, "postgres_database": database, "redis": "reachable"}


def save_infrastructure_settings(
    conn,
    *,
    org_id: int,
    user_id: int,
    postgres_dsn: str,
    redis_url: str,
    result_backend: str,
    test_result: dict[str, Any],
) -> None:
    """Store only encrypted service URLs after successful connectivity checks."""
    conn.execute(
        """
        INSERT INTO infrastructure_settings
            (org_id, postgres_dsn, redis_url, celery_result_backend, requested_backend,
             status, last_tested_at, last_test_result, last_test_message, updated_by, updated_at)
        VALUES (?, ?, ?, ?, 'postgresql', 'validated', CURRENT_TIMESTAMP, 'passed', ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(org_id) DO UPDATE SET
            postgres_dsn = excluded.postgres_dsn, redis_url = excluded.redis_url,
            celery_result_backend = excluded.celery_result_backend,
            requested_backend = 'postgresql', status = 'validated',
            last_tested_at = CURRENT_TIMESTAMP, last_test_result = 'passed',
            last_test_message = excluded.last_test_message, updated_by = excluded.updated_by,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            org_id,
            seal_secret(postgres_dsn),
            seal_secret(redis_url),
            seal_secret(result_backend or redis_url),
            json.dumps(test_result, sort_keys=True),
            user_id,
        ),
    )


def configured_infrastructure(conn, org_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM infrastructure_settings WHERE org_id = ?", (org_id,)).fetchone()
    if not row:
        return {"configured": False, "status": "sqlite"}
    return {
        "configured": bool(row["postgres_dsn"] and row["redis_url"]),
        "status": row["status"],
        "last_tested_at": row["last_tested_at"],
        "last_test_result": row["last_test_result"],
        "updated_at": row["updated_at"],
    }


def migrate_to_postgresql(conn, *, org_id: int, user_id: int) -> dict[str, Any]:
    """Backup SQLite, copy into an empty PostgreSQL database, verify, then stage restart."""
    settings = conn.execute("SELECT * FROM infrastructure_settings WHERE org_id = ?", (org_id,)).fetchone()
    if settings and settings["status"] == "restart_required":
        # A previous data copy may have succeeded while the final atomic state
        # file write failed. Retrying stages activation without recopying data.
        postgres_dsn = open_secret(settings["postgres_dsn"])
        redis_url = open_secret(settings["redis_url"])
        result_backend = open_secret(settings["celery_result_backend"] or settings["redis_url"])
        write_backend_state(postgres_dsn=postgres_dsn, redis_url=redis_url, result_backend=result_backend)
        previous = conn.execute(
            "SELECT id, verification_json FROM infrastructure_migrations "
            "WHERE org_id = ? AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (org_id,),
        ).fetchone()
        return {
            "migration_id": previous["id"] if previous else None,
            "status": "restart_required",
            "verification": json.loads(previous["verification_json"] or "{}") if previous else {},
        }
    if not settings or settings["status"] != "validated":
        raise ValueError("Validate and save PostgreSQL and Redis settings before migration")
    postgres_dsn = open_secret(settings["postgres_dsn"])
    redis_url = open_secret(settings["redis_url"])
    result_backend = open_secret(settings["celery_result_backend"] or settings["redis_url"])
    validate_infrastructure(postgres_dsn, redis_url, result_backend)

    migration = conn.execute(
        """
        INSERT INTO infrastructure_migrations
            (org_id, source_backend, target_backend, status, phase, requested_by, started_at)
        VALUES (?, 'sqlite', 'postgresql', 'running', 'backup', ?, CURRENT_TIMESTAMP)
        """,
        (org_id, user_id),
    )
    migration_id = int(migration.lastrowid)
    conn.commit()
    copy_verified = False
    try:
        backup = create_backup(SQLITE_PATH, BACKUP_DIR)
        backup_check = verify_backup(backup)
        conn.execute(
            "UPDATE infrastructure_migrations SET backup_path = ?, phase = 'copy' WHERE id = ?",
            (str(backup), migration_id),
        )
        conn.commit()
        verification = _copy_sqlite_to_postgres(SQLITE_PATH, postgres_dsn)
        verification["backup_sha256"] = backup_check["sha256"]

        conn.execute(
            """
            UPDATE infrastructure_migrations
            SET status = 'completed', phase = 'restart_required', verification_json = ?,
                finished_at = CURRENT_TIMESTAMP WHERE id = ?
            """,
            (json.dumps(verification, sort_keys=True), migration_id),
        )
        conn.execute(
            "UPDATE infrastructure_settings SET status = 'restart_required', updated_at = CURRENT_TIMESTAMP WHERE org_id = ?",
            (org_id,),
        )
        conn.commit()
        copy_verified = True
        # Write the restart boundary only after the migration audit state is
        # durable. This process keeps its startup backend until services restart.
        write_backend_state(
            postgres_dsn=postgres_dsn,
            redis_url=redis_url,
            result_backend=result_backend,
        )
        audit("infrastructure_migration_completed", org_id=org_id, migration_id=migration_id)
        return {"migration_id": migration_id, "status": "restart_required", "verification": verification}
    except Exception as exc:
        if copy_verified:
            conn.execute(
                "UPDATE infrastructure_migrations SET error_message = ? WHERE id = ?",
                ("activation staging failed: " + str(exc)[:900], migration_id),
            )
            conn.commit()
            audit("infrastructure_activation_staging_failed", org_id=org_id, migration_id=migration_id)
            raise
        conn.execute(
            """
            UPDATE infrastructure_migrations
            SET status = 'failed', phase = 'failed', error_message = ?, finished_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (str(exc)[:1000], migration_id),
        )
        conn.execute(
            "UPDATE infrastructure_settings SET status = 'validated', updated_at = CURRENT_TIMESTAMP WHERE org_id = ?",
            (org_id,),
        )
        conn.commit()
        audit("infrastructure_migration_failed", org_id=org_id, migration_id=migration_id)
        raise


def _copy_sqlite_to_postgres(sqlite_path: Path, postgres_dsn: str) -> dict[str, Any]:
    try:
        import psycopg
        from psycopg import sql
    except ImportError as exc:
        raise RuntimeError("PostgreSQL mode requires psycopg[binary]") from exc

    source = sqlite3.connect(str(sqlite_path))
    source.row_factory = sqlite3.Row
    tables = [
        row[0]
        for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    ]
    ordered = _dependency_order(source, tables)
    counts: dict[str, int] = {}
    try:
        with psycopg.connect(postgres_dsn, autocommit=False) as target:
            existing = target.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()"
            ).fetchall()
            if existing:
                raise RuntimeError("PostgreSQL target must be empty; refusing to overwrite existing tables")
            for table in ordered:
                ddl = source.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
                ).fetchone()[0]
                target.execute(_translate_schema(ddl))
            target.execute("SET CONSTRAINTS ALL DEFERRED")
            for table in ordered:
                columns = [row[1] for row in source.execute(f'PRAGMA table_info("{table}")').fetchall()]
                rows = source.execute(f'SELECT * FROM "{table}"').fetchall()
                if rows:
                    statement = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                        sql.Identifier(table),
                        sql.SQL(", ").join(map(sql.Identifier, columns)),
                        sql.SQL(", ").join(sql.Placeholder() for _ in columns),
                    )
                    with target.cursor() as cursor:
                        cursor.executemany(statement, [tuple(row) for row in rows])
                counts[table] = len(rows)
            for row in source.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL ORDER BY name"
            ).fetchall():
                target.execute(_translate_schema(row[0]))
            for table in ordered:
                if "id" in [row[1] for row in source.execute(f'PRAGMA table_info("{table}")').fetchall()]:
                    sequence = target.execute(
                        "SELECT pg_get_serial_sequence(%s, 'id')", (table,)
                    ).fetchone()[0]
                    if sequence:
                        target.execute(
                            "SELECT setval(%s, COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM "
                            + sql.Identifier(table).as_string(target),
                            (sequence,),
                        )
            verified = {}
            for table, expected in counts.items():
                actual = target.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table))).fetchone()[0]
                if int(actual) != expected:
                    raise RuntimeError(f"row-count verification failed for {table}")
                verified[table] = expected
            target.commit()
    finally:
        source.close()
    return {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "tables": len(counts),
        "rows": sum(counts.values()),
        "table_counts": counts,
    }


def _dependency_order(conn: sqlite3.Connection, tables: list[str]) -> list[str]:
    """Order table creation so PostgreSQL foreign-key references already exist."""
    remaining = set(tables)
    dependencies = {
        table: {
            row[2]
            for row in conn.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
            if row[2] in remaining and row[2] != table
        }
        for table in tables
    }
    ordered: list[str] = []
    while remaining:
        ready = sorted(table for table in remaining if not (dependencies[table] & remaining))
        if not ready:
            raise RuntimeError("database contains a foreign-key cycle that requires a manual migration")
        ordered.extend(ready)
        remaining.difference_update(ready)
    return ordered
