"""Optional background poller that pulls alerts from the Wazuh Indexer.

Opt-in by design: it only does work when the ``wazuh_indexer`` platform is
enabled with credentials. When started, it wakes on a fixed interval, queries
the indexer for alerts newer than a stored watermark (filtered by rule level),
and feeds each new alert through the shared :func:`ingest_alert_record` path —
the very same pipeline used by the manual ``/api/ingest/alert`` route, so a
polled alert selects a playbook, correlates IOCs, and queues a run exactly like
a pushed one.

Two safeguards keep it from re-processing:
  * a per-source watermark on the alert ``timestamp`` (only pull newer docs), and
  * a dedup check on ``source_alert_id`` (the Elasticsearch ``_id``) so a
    document already stored is never ingested twice, even if timestamps tie.

The poller runs in its own daemon thread and opens its own SQLite connection,
because sqlite3 connections are bound to the thread that created them.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any

from scripts.common import audit


class WazuhAlertPoller:
    """Background scheduler that ingests new Wazuh Indexer alerts."""

    def __init__(
        self,
        *,
        interval: int = 60,
        min_level: int = 7,
        batch_size: int = 50,
        index: str = "wazuh-alerts-*",
    ) -> None:
        self.interval = max(10, int(interval))
        self.min_level = int(min_level)
        self.batch_size = max(1, int(batch_size))
        self.index = index

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Observability for the status endpoint.
        self.last_poll_at: str | None = None
        self.last_error: str | None = None
        self.last_batch_count = 0
        self.total_ingested = 0
        self.total_skipped = 0

    # ── lifecycle ──────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def start(self) -> bool:
        """Start the polling loop. Returns False if already running."""
        with self._lock:
            if self.running:
                return False
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, name="wazuh-alert-poller", daemon=True
            )
            self._thread.start()
            audit(
                "wazuh_poller_started",
                interval=self.interval,
                min_level=self.min_level,
                index=self.index,
            )
            return True

    def stop(self) -> bool:
        """Signal the loop to stop. Returns False if it wasn't running."""
        with self._lock:
            if not self.running:
                self._stop.set()
                return False
            self._stop.set()
            audit("wazuh_poller_stopped", total_ingested=self.total_ingested)
            return True

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "interval": self.interval,
            "min_level": self.min_level,
            "batch_size": self.batch_size,
            "index": self.index,
            "last_poll_at": self.last_poll_at,
            "last_error": self.last_error,
            "last_batch_count": self.last_batch_count,
            "total_ingested": self.total_ingested,
            "total_skipped": self.total_skipped,
            "watermark": self._read_watermark(),
        }

    # ── loop ───────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # keep the loop alive across transient failures
                self.last_error = str(exc)[:300]
                audit("wazuh_poller_cycle_error", error=self.last_error)
            # Interruptible sleep so stop() takes effect promptly.
            self._stop.wait(self.interval)

    # ── one polling cycle ──────────────────────────────────────────────────

    def poll_once(self) -> dict[str, Any]:
        """Run a single poll cycle. Safe to call directly (e.g. manual trigger).

        Returns a summary dict: ``{ok, ingested, skipped, error}``.
        """
        self.last_poll_at = datetime.now(timezone.utc).isoformat()

        client = self._build_indexer_client()
        if client is None:
            self.last_error = "wazuh_indexer not enabled/configured"
            return {"ok": False, "ingested": 0, "skipped": 0, "error": self.last_error}

        from web.app import get_db
        from web.services.schema_features import init_feature_db

        conn = get_db()
        try:
            init_feature_db(conn)
            self._ensure_state_table(conn)
            watermark = self._read_watermark(conn)

            # First run with no watermark: baseline to "now" so we ingest only
            # alerts arriving from here forward, rather than flooding on the
            # entire historical index. Set WAZUH_POLL_BACKFILL=1 to pull the
            # latest batch instead of baselining.
            if not watermark and not _truthy(os.environ.get("WAZUH_POLL_BACKFILL")):
                now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
                self._write_watermark(conn, now_iso)
                self.last_error = None
                self.last_batch_count = 0
                return {"ok": True, "ingested": 0, "skipped": 0, "error": None, "baselined": now_iso}

            filters: list[dict[str, Any]] = [
                {"range": {"rule.level": {"gte": self.min_level}}}
            ]
            if watermark:
                filters.append({"range": {"timestamp": {"gt": watermark}}})
            query = {"bool": {"filter": filters}}
            sort = [{"timestamp": {"order": "asc"}}]

            resp = client.search_alerts(
                query=query, sort=sort, size=self.batch_size, index=self.index
            )
            hits = (resp or {}).get("hits", {}).get("hits", [])

            ingested = 0
            skipped = 0
            new_watermark = watermark
            for hit in hits:
                doc_id = str(hit.get("_id", "")) or None
                source_doc = hit.get("_source", {}) or {}
                ts = source_doc.get("timestamp")

                if doc_id and self._already_ingested(conn, doc_id):
                    skipped += 1
                    if ts:
                        new_watermark = _max_ts(new_watermark, ts)
                    continue

                try:
                    self._ingest(conn, doc_id, source_doc)
                    ingested += 1
                    if ts:
                        new_watermark = _max_ts(new_watermark, ts)
                except Exception as exc:
                    # Stop advancing past a failed alert so the next cycle
                    # retries it; dedup prevents double-ingest of successes.
                    self.last_error = f"ingest failed for {doc_id}: {str(exc)[:200]}"
                    audit("wazuh_poller_ingest_error", doc_id=doc_id, error=str(exc)[:200])
                    break

            if new_watermark and new_watermark != watermark:
                self._write_watermark(conn, new_watermark)

            self.last_batch_count = len(hits)
            self.total_ingested += ingested
            self.total_skipped += skipped
            if ingested or not hits:
                self.last_error = None
            return {"ok": True, "ingested": ingested, "skipped": skipped, "error": self.last_error}
        finally:
            conn.close()

    # ── helpers ─────────────────────────────────────────────────────────────

    def _ingest(self, conn, doc_id: str | None, source_doc: dict[str, Any]) -> None:
        from web.services.alert_ingest import ingest_alert_record

        org_id = self._configured_org_id(conn)
        ingest_alert_record(
            conn,
            source="wazuh",
            source_alert_id=doc_id,
            payload=source_doc,
            org_id=org_id,
        )

    def _build_indexer_client(self) -> Any:
        """Load saved credentials, rebuild config, and return the indexer client."""
        from web.app import get_db, load_config_for_web
        from scripts.orchestrator import build_clients
        from web.services.credential_vault import open_secret

        conn = get_db()
        try:
            org_id = self._configured_org_id(conn)
            credentials = {
                row["key_name"]: open_secret(row["key_value"])
                for row in conn.execute(
                    "SELECT key_name, key_value FROM credentials WHERE org_id = ?",
                    (org_id,),
                ).fetchall()
            }
        finally:
            conn.close()

        config = load_config_for_web(org_id)
        clients = build_clients(config, credentials=credentials)
        return clients.get("wazuh_indexer")

    def _configured_org_id(self, conn) -> int:
        configured = os.environ.get("AI_SOC_POLLER_ORG_ID", "").strip()
        if configured:
            return int(configured)
        row = conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
        if not row:
            raise RuntimeError("No organization exists for the Wazuh poller")
        return int(row["id"])

    def _already_ingested(self, conn, doc_id: str) -> bool:
        org_id = self._configured_org_id(conn)
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE org_id = ? AND source = 'wazuh' AND source_alert_id = ? LIMIT 1",
            (org_id, doc_id),
        ).fetchone()
        return row is not None

    def _ensure_state_table(self, conn) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS poller_state (
                name TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()

    def _read_watermark(self, conn=None) -> str | None:
        own = conn is None
        if own:
            from web.app import get_db
            conn = get_db()
        try:
            try:
                self._ensure_state_table(conn)
                state_name = f"wazuh_indexer_watermark:{self._configured_org_id(conn)}"
                row = conn.execute(
                    "SELECT value FROM poller_state WHERE name = ?",
                    (state_name,),
                ).fetchone()
            except Exception:
                return None
            return row["value"] if row else None
        finally:
            if own:
                conn.close()

    def _write_watermark(self, conn, value: str) -> None:
        state_name = f"wazuh_indexer_watermark:{self._configured_org_id(conn)}"
        conn.execute(
            """
            INSERT INTO poller_state (name, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            """,
            (state_name, value),
        )
        conn.commit()


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _max_ts(a: str | None, b: str | None) -> str | None:
    """Return the lexicographically greater ISO8601 timestamp (None-safe)."""
    if a is None:
        return b
    if b is None:
        return a
    return a if a >= b else b


# Module-level singleton wired up by web.app at startup.
_poller: WazuhAlertPoller | None = None


def get_poller() -> WazuhAlertPoller:
    global _poller
    if _poller is None:
        _poller = WazuhAlertPoller(
            interval=int(os.environ.get("WAZUH_POLL_INTERVAL", "60") or "60"),
            min_level=int(os.environ.get("WAZUH_POLL_MIN_LEVEL", "7") or "7"),
            batch_size=int(os.environ.get("WAZUH_POLL_BATCH", "50") or "50"),
            index=os.environ.get("WAZUH_POLL_INDEX", "wazuh-alerts-*"),
        )
    return _poller
