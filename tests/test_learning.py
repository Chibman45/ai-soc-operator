"""Tests for local learning and skill suggestion drafts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.learning import LearningStore


class LearningStoreTests(unittest.TestCase):
    def test_record_event_creates_skill_suggestion_draft(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LearningStore(
                db_path=root / "data" / "soc_operator.db",
                draft_dir=root / "drafts",
            )

            store.record_event(
                source="playbook",
                category="pending_capability",
                subject="identity-compromise:write_case",
                severity="medium",
                summary="TheHive write step needs execution support.",
                evidence={"step": "write_case"},
            )

            suggestions = store.list_skill_suggestions()
            self.assertEqual(len(suggestions), 1)
            draft = Path(suggestions[0]["draft_path"])
            self.assertTrue(draft.is_file())
            self.assertIn("Identity Compromise", draft.read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
