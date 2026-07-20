"""Tests for the playbook document parser."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.playbook_parser import (
    extract_text,
    parse_with_llm,
    validate_playbook,
    parse_playbook_document,
)


VALID_PLAYBOOK = {
    "id": "test-playbook",
    "name": "Test Playbook",
    "version": 1,
    "steps": [
        {"id": "classify", "type": "llm", "prompt": "Analyze this alert"},
        {"id": "report", "type": "report", "report_type": "soc"},
    ],
}

VALID_PLAYBOOK_YAML = """id: test-playbook
name: Test Playbook
version: 1
steps:
  - id: classify
    type: llm
    prompt: "Analyze this alert"
  - id: report
    type: report
    report_type: soc
"""


class ExtractTextTests(unittest.TestCase):
    def test_extract_txt(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("Hello world")
            f.flush()
            result = extract_text(Path(f.name))
        self.assertEqual(result, "Hello world")

    def test_extract_md(self):
        with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as f:
            f.write("# Title\n\nContent here")
            f.flush()
            result = extract_text(Path(f.name))
        self.assertIn("Title", result)

    def test_extract_yaml_passthrough(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("key: value")
            f.flush()
            result = extract_text(Path(f.name))
        self.assertEqual(result, "key: value")

    def test_extract_unsupported_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".xyz", mode="w", encoding="utf-8", delete=False) as f:
            f.write("data")
            f.flush()
            with self.assertRaises(RuntimeError):
                extract_text(Path(f.name))


class ParseWithLLMTests(unittest.TestCase):
    def test_valid_json_response(self):
        mock_response = json.dumps(VALID_PLAYBOOK)
        result = parse_with_llm("test document", lambda sys, user: mock_response)
        self.assertEqual(result["id"], "test-playbook")
        self.assertIn("steps", result)

    def test_strips_markdown_fences(self):
        mock_response = f"```json\n{json.dumps(VALID_PLAYBOOK)}\n```"
        result = parse_with_llm("test", lambda sys, user: mock_response)
        self.assertEqual(result["id"], "test-playbook")

    def test_invalid_json_returns_error(self):
        result = parse_with_llm("test", lambda sys, user: "not json at all")
        self.assertIn("error", result)

    def test_llm_failure_returns_error(self):
        result = parse_with_llm("test", lambda sys, user: 1/0)
        self.assertIn("error", result)


class ValidatePlaybookTests(unittest.TestCase):
    def test_valid_playbook(self):
        errors = validate_playbook(VALID_PLAYBOOK)
        self.assertEqual(errors, [])

    def test_missing_id(self):
        pb = {"name": "Test", "steps": [{"id": "a", "type": "llm"}]}
        errors = validate_playbook(pb)
        self.assertTrue(any("id" in e for e in errors))

    def test_missing_name(self):
        pb = {"id": "test", "steps": [{"id": "a", "type": "llm"}]}
        errors = validate_playbook(pb)
        self.assertTrue(any("name" in e for e in errors))

    def test_missing_steps(self):
        pb = {"id": "test", "name": "Test"}
        errors = validate_playbook(pb)
        self.assertTrue(any("steps" in e for e in errors))

    def test_empty_steps(self):
        pb = {"id": "test", "name": "Test", "steps": []}
        errors = validate_playbook(pb)
        self.assertTrue(any("non-empty" in e for e in errors))

    def test_invalid_step_type(self):
        pb = {"id": "test", "name": "Test", "steps": [{"id": "a", "type": "invalid"}]}
        errors = validate_playbook(pb)
        self.assertTrue(any("invalid type" in e for e in errors))

    def test_step_missing_id(self):
        pb = {"id": "test", "name": "Test", "steps": [{"type": "llm"}]}
        errors = validate_playbook(pb)
        self.assertTrue(any("missing 'id'" in e for e in errors))

    def test_valid_triggers(self):
        pb = {**VALID_PLAYBOOK, "triggers": [{"alert_rule": "Brute Force"}]}
        errors = validate_playbook(pb)
        self.assertEqual(errors, [])

    def test_invalid_trigger(self):
        pb = {**VALID_PLAYBOOK, "triggers": [{"invalid": "key"}]}
        errors = validate_playbook(pb)
        self.assertTrue(any("Trigger" in e for e in errors))

    def test_non_dict_input(self):
        errors = validate_playbook("not a dict")
        self.assertEqual(len(errors), 1)


class ParsePlaybookDocumentTests(unittest.TestCase):
    def test_yaml_file(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(VALID_PLAYBOOK_YAML)
            f.flush()
            result = parse_playbook_document(Path(f.name), lambda s, u: "{}")
        self.assertTrue(result["valid"])
        self.assertIsNotNone(result["playbook"])
        self.assertEqual(result["playbook"]["id"], "test-playbook")

    def test_nonexistent_file(self):
        result = parse_playbook_document(Path("/nonexistent.yaml"), lambda s, u: "{}")
        self.assertFalse(result["valid"])
        self.assertIn("not found", result["errors"][0])

    def test_unsupported_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"data")
            f.flush()
            result = parse_playbook_document(Path(f.name), lambda s, u: "{}")
        self.assertFalse(result["valid"])

    def test_txt_file_with_llm(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("SOC procedure for handling brute force attacks...")
            f.flush()
            mock_response = json.dumps(VALID_PLAYBOOK)
            result = parse_playbook_document(
                Path(f.name), lambda s, u: mock_response
            )
        self.assertTrue(result["valid"])
        self.assertIsNotNone(result["playbook"])

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("")
            f.flush()
            result = parse_playbook_document(Path(f.name), lambda s, u: "{}")
        self.assertFalse(result["valid"])
        self.assertIn("empty", result["errors"][0].lower())

    def test_invalid_yaml(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("{{invalid yaml: [}")
            f.flush()
            result = parse_playbook_document(Path(f.name), lambda s, u: "{}")
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
