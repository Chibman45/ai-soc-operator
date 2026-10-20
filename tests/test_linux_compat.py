"""Supported Linux distribution and prerequisite matrix tests."""

from __future__ import annotations

import unittest

from scripts.linux_compat import (
    classify_distribution,
    parse_os_release,
    required_packages,
)


class LinuxCompatibilityTests(unittest.TestCase):
    def test_parses_os_release_quoted_values(self):
        values = parse_os_release('ID="ubuntu"\nVERSION_ID="24.04"\nID_LIKE=debian\n')
        self.assertEqual(values["ID"], "ubuntu")
        self.assertEqual(values["VERSION_ID"], "24.04")

    def test_approved_distribution_matrix(self):
        fixtures = [
            ({"ID": "ubuntu", "VERSION_ID": "22.04"}, "ubuntu-22.04"),
            ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "ubuntu-24.04"),
            ({"ID": "debian", "VERSION_ID": "12"}, "debian-12"),
            ({"ID": "kali", "VERSION_ID": "2026.3"}, "kali-rolling"),
        ]
        for release, expected in fixtures:
            with self.subTest(expected=expected):
                self.assertEqual(classify_distribution(release), expected)

    def test_unsupported_distribution_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "Unsupported Linux distribution"):
            classify_distribution({"ID": "ubuntu", "VERSION_ID": "20.04"})

    def test_required_packages_cover_documents_https_runtime_and_oauth(self):
        packages = set(required_packages("debian-12"))
        self.assertTrue(
            {
                "python3", "python3-venv", "tesseract-ocr", "poppler-utils",
                "nginx", "openssl", "nodejs", "npm",
            }.issubset(packages)
        )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
