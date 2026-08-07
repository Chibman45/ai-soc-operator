"""Tests for the Wazuh alert poller."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Use a temp DB for isolation — patch DB_PATH before importing anything that
# reads it at module level.
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
_TEST_DB = Path(_tmp.name)

import web.app as _app_mod
_app_mod.DB_PATH = _TEST_DB

from web.app import app, get_db, init_db
from web.services.wazuh_poller import get_poller


def _make_fake_client(hits):
    """Build a fake indexer client that returns the given hits."""
    client = MagicMock()
    client.search_alerts.return_value = {"hits": {"hits": hits}}
    return client


CANNED_HIT = {
    "_id": "abc",
    "_source": {
        "rule": {"id": "100001", "description": "Test", "level": 5},
        "agent": {"id": "001", "name": "kali"},
        "timestamp": "2026-08-06T00:00:00.000Z",
        "full_log": "test",
    },
}


class WazuhPollerTests(unittest.TestCase):

    def setUp(self):
        # Fresh DB for each test.
        if _TEST_DB.exists():
            try:
                _TEST_DB.unlink()
            except PermissionError:
                pass  # Windows: file may still be held open
        init_db()

        # Reset the singleton so each test gets a fresh poller.
        import web.services.wazuh_poller as _mod
        _mod._poller = None
        self.poller = get_poller()

        # Enable backfill so the first poll actually ingests instead of
        # baselining to "now" with an empty watermark.
        os.environ["WAZUH_POLL_BACKFILL"] = "1"

    def tearDown(self):
        os.environ.pop("WAZUH_POLL_BACKFILL", None)

    @patch("web.services.wazuh_poller.WazuhAlertPoller._build_indexer_client")
    def test_poll_once_ingests_new_alert(self, mock_build):
        fake = _make_fake_client([CANNED_HIT])
        mock_build.return_value = fake

        result = self.poller.poll_once()

        self.assertTrue(result["ok"])
        self.assertEqual(result["ingested"], 1)
        self.assertEqual(result["skipped"], 0)

        # Verify the alert row was written.
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM alerts WHERE source = 'wazuh' AND source_alert_id = 'abc'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["title"], "Test")

    @patch("web.services.wazuh_poller.WazuhAlertPoller._build_indexer_client")
    def test_poll_once_deduplicates(self, mock_build):
        fake = _make_fake_client([CANNED_HIT])
        mock_build.return_value = fake

        # First poll — should ingest.
        r1 = self.poller.poll_once()
        self.assertEqual(r1["ingested"], 1)

        # Second poll — same doc_id, should skip.
        r2 = self.poller.poll_once()
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["skipped"], 1)
        self.assertEqual(r2["ingested"], 0)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
