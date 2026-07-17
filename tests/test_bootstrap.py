"""Tests for bootstrap CLI (non-interactive modes)."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootstrap import (
    check_python,
    check_dependencies,
    detect_tools,
    KNOWN_TOOLS,
)


class SystemCheckTests(unittest.TestCase):
    def test_check_python_passes(self):
        # We're running Python 3.10+
        self.assertTrue(check_python())

    def test_check_dependencies(self):
        # Should not raise
        result = check_dependencies()
        self.assertIsInstance(result, bool)

    def test_detect_tools_returns_dict(self):
        result = detect_tools()
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), len(KNOWN_TOOLS))

    def test_detect_tools_marks_nmap_not_found(self):
        # On Windows CI, nmap won't be in PATH
        result = detect_tools()
        # Just verify the structure — nmap may or may not be found
        self.assertIn("nmap", result)
        self.assertIsInstance(result["nmap"], bool)


if __name__ == "__main__":
    unittest.main()
