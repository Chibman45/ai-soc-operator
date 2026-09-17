"""Runtime database selection with a SQLite-compatible PostgreSQL adapter."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from scripts.common import ROOT


DEFAULT_SQLITE_PATH = ROOT / "data" / "soc_operator.db"
BACKEND_STATE_PATH = ROOT / "data" / "runtime_backend.json"
_STARTUP_STATE: dict[str, Any] | None = None


class HybridRow:
    """Provide sqlite3.Row-style numeric and named access for PostgreSQL rows."""

    def __init__(self, values: Sequence[Any], columns: Sequence[str]):
        self._values = tuple(values)
        self._columns = tuple(columns)
        self._mapping = dict(zip(self._columns, self._values))

    def __getitem__(self, key):
        return self._values[key] if isinstance(key, int) else self._mapping[key]

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def keys(self):
        return self._columns


class StaticCursor:
    def __init__(self, rows: list[Any] | None = None, *, rowcount: int = 0, lastrowid: Any = None):
        self._rows = rows or []
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows


class PostgresCursor:
    def __init__(self, cursor, *, lastrowid: Any = None, prefetched: list[Any] | None = None):
        self._cursor = cursor
        self.lastrowid = lastrowid
        self.rowcount = cursor.rowcount
        self._prefetched = prefetched or []

    @property
    def _columns(self) -> list[str]:
        return [item.name for item in (self._cursor.description or [])]

    def _wrap(self, row):
        return HybridRow(row, self._columns) if row is not None else None

    def fetchone(self):
        if self._prefetched:
            return self._prefetched.pop(0)
        return self._wrap(self._cursor.fetchone())

    def fetchall(self):
        prefetched, self._prefetched = self._prefetched, []
        return [*prefetched, *(self._wrap(row) for row in self._cursor.fetchall())]


class PostgresConnection:
    backend = "postgresql"

    def __init__(self, dsn: str):
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("PostgreSQL mode requires psycopg[binary]") from exc
        self._psycopg = psycopg
        self._conn = psycopg.connect(dsn, autocommit=False)
        self.row_factory = None

    def execute(self, sql: str, params: Sequence[Any] | None = None):
        pragma = _pragma_table(sql)
        if pragma:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT ordinal_position, column_name, data_type,
                       CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END,
                       column_default, 0
                FROM information_schema.columns
                WHERE table_schema = current_schema() AND table_name = %s
                ORDER BY ordinal_position
                """,
                (pragma,),
            )
            return StaticCursor([HybridRow(row, ("cid", "name", "type", "notnull", "dflt_value", "pk")) for row in cur.fetchall()])
        if sql.strip().upper().startswith("PRAGMA "):
            return StaticCursor()
        if "FROM sqlite_master" in sql:
            return StaticCursor()

        translated = _translate_sql(sql)
        insert_table = _insert_table(translated)
        auto_returning = bool(insert_table and " RETURNING " not in translated.upper() and insert_table not in _NO_INTEGER_ID)
        if auto_returning:
            translated = translated.rstrip().rstrip(";") + " RETURNING id"
        control = self._conn.cursor()
        control.execute("SAVEPOINT ai_soc_statement")
        cur = self._conn.cursor()
        try:
            cur.execute(translated, tuple(params or ()))
        except self._psycopg.errors.UniqueViolation as exc:
            # PostgreSQL aborts the whole transaction after a constraint error;
            # a statement savepoint preserves SQLite's recoverable behavior.
            control.execute("ROLLBACK TO SAVEPOINT ai_soc_statement")
            control.execute("RELEASE SAVEPOINT ai_soc_statement")
            raise sqlite3.IntegrityError(str(exc)) from exc
        except Exception:
            control.execute("ROLLBACK TO SAVEPOINT ai_soc_statement")
            control.execute("RELEASE SAVEPOINT ai_soc_statement")
            raise
        control.execute("RELEASE SAVEPOINT ai_soc_statement")
        lastrowid = None
        prefetched: list[Any] = []
        if auto_returning and cur.description:
            row = cur.fetchone()
            if row:
                lastrowid = row[0]
        return PostgresCursor(cur, lastrowid=lastrowid, prefetched=prefetched)

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]):
        cur = self._conn.cursor()
        cur.executemany(_translate_sql(sql), list(rows))
        return PostgresCursor(cur)

    def executescript(self, script: str):
        for statement in _split_sql(script):
            if statement.strip():
                self.execute(_translate_schema(statement))
        return StaticCursor()

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, _tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


def connect_database(path: Path | str | None = None, *, runtime: bool = True):
    sqlite_path = Path(path or DEFAULT_SQLITE_PATH)
    if runtime and sqlite_path.resolve() == DEFAULT_SQLITE_PATH.resolve():
        dsn = active_postgres_dsn()
        if dsn:
            return PostgresConnection(dsn)
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(sqlite_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def active_backend() -> str:
    return "postgresql" if active_postgres_dsn() else "sqlite"


def active_postgres_dsn() -> str | None:
    env_dsn = os.environ.get("AI_SOC_DATABASE_URL", "").strip()
    if env_dsn.startswith(("postgresql://", "postgres://")):
        return env_dsn
    state = _startup_state()
    if state.get("backend") != "postgresql" or state.get("status") != "active":
        return None
    sealed = str(state.get("postgres_dsn", ""))
    if not sealed:
        return None
    from web.services.credential_vault import open_secret

    return open_secret(sealed)


def write_backend_state(*, postgres_dsn: str, redis_url: str, result_backend: str) -> None:
    from web.services.credential_vault import seal_secret

    BACKEND_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "backend": "postgresql",
        "queue": "celery",
        "status": "active",
        "postgres_dsn": seal_secret(postgres_dsn),
        "redis_url": seal_secret(redis_url),
        "result_backend": seal_secret(result_backend or redis_url),
    }
    temp = BACKEND_STATE_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temp, BACKEND_STATE_PATH)
    try:
        BACKEND_STATE_PATH.chmod(0o600)
    except OSError:
        pass


def runtime_queue_settings() -> dict[str, str]:
    state = _startup_state()
    if state.get("queue") != "celery" or state.get("status") != "active":
        return {}
    from web.services.credential_vault import open_secret

    return {
        "broker_url": open_secret(str(state.get("redis_url", ""))),
        "result_backend": open_secret(str(state.get("result_backend", ""))),
    }


def _read_backend_state() -> dict[str, Any]:
    if not BACKEND_STATE_PATH.is_file():
        return {}
    try:
        return json.loads(BACKEND_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _startup_state() -> dict[str, Any]:
    """Freeze backend selection until restart after a successful migration."""
    global _STARTUP_STATE
    if _STARTUP_STATE is None:
        _STARTUP_STATE = _read_backend_state()
    return _STARTUP_STATE


_NO_INTEGER_ID = {
    "api_rate_limits",
    "integration_sync_state",
    "jobs",
    "operations_state",
    "poller_state",
}


def _pragma_table(sql: str) -> str | None:
    match = re.match(r"\s*PRAGMA\s+table_info\(([^)]+)\)", sql, re.IGNORECASE)
    return match.group(1).strip(" '\"") if match else None


def _insert_table(sql: str) -> str | None:
    match = re.match(r"\s*INSERT\s+(?:OR\s+IGNORE\s+)?INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)", sql, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _translate_schema(sql: str) -> str:
    value = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", "BIGSERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
    value = re.sub(r"\bAUTOINCREMENT\b", "", value, flags=re.IGNORECASE)
    value = re.sub(r"\bBLOB\b", "BYTEA", value, flags=re.IGNORECASE)
    return _translate_sql(value)


def _translate_sql(sql: str) -> str:
    value = sql
    ignore = bool(re.match(r"\s*INSERT\s+OR\s+IGNORE", value, re.IGNORECASE))
    value = re.sub(r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", value, flags=re.IGNORECASE)
    value = re.sub(r"\bIFNULL\s*\(", "COALESCE(", value, flags=re.IGNORECASE)
    value = re.sub(r"datetime\('now'\s*,\s*'\+([^']+)'\)", r"(CURRENT_TIMESTAMP + INTERVAL '\1')", value, flags=re.IGNORECASE)
    value = re.sub(r"datetime\('now'\s*,\s*'-([^']+)'\)", r"(CURRENT_TIMESTAMP - INTERVAL '\1')", value, flags=re.IGNORECASE)
    value = re.sub(r"datetime\('now'\s*,\s*\?\s*\)", r"(CURRENT_TIMESTAMP + CAST(? AS INTERVAL))", value, flags=re.IGNORECASE)
    value = _replace_qmarks(value)
    if ignore and "ON CONFLICT" not in value.upper():
        value = value.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    return value


def _replace_qmarks(sql: str) -> str:
    result: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            result.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    result.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
        elif char in {"'", '"'}:
            quote = char
            result.append(char)
        elif char == "?":
            result.append("%s")
        else:
            result.append(char)
        index += 1
    return "".join(result)


def _split_sql(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in script:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
            current.append(char)
        elif char == ";":
            statements.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        statements.append("".join(current))
    return statements
