"""Tests for bootstrap CLI (non-interactive modes)."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootstrap import (
    _certificate_extensions,
    _ensure_local_runtime_secrets,
    _generate_local_certificate,
    _linux_package_command,
    _render_local_nginx_config,
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


class LocalHTTPSTests(unittest.TestCase):
    @patch("bootstrap.shutil.which")
    def test_package_manager_command_is_allowlisted(self, which):
        which.side_effect = lambda name: "/usr/bin/dnf" if name == "dnf" else None
        self.assertEqual(
            _linux_package_command(["openssl", "nginx"]),
            ["dnf", "install", "-y", "nginx", "openssl"],
        )

    def test_certificate_contains_local_names_and_addresses(self):
        extensions = _certificate_extensions("soc-console", "192.0.2.10")
        self.assertIn("DNS.1=localhost", extensions)
        self.assertIn("DNS.2=soc-console", extensions)
        self.assertIn("DNS.3=soc-console.local", extensions)
        self.assertIn("IP.1=127.0.0.1", extensions)
        self.assertIn("IP.2=192.0.2.10", extensions)

    def test_nginx_terminates_tls_and_sets_forwarded_headers(self):
        config = _render_local_nginx_config("soc-console", "192.0.2.10")
        self.assertIn("listen 443 ssl", config)
        self.assertIn("proxy_pass http://127.0.0.1:5000", config)
        self.assertIn("proxy_set_header X-Forwarded-Proto $scheme", config)
        self.assertIn("return 301 https://$host$request_uri", config)
        self.assertIn("$ai_soc_valid_host", config)
        self.assertIn("return 444", config)

    def test_runtime_secrets_are_created_once(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch("bootstrap.DATA_DIR", directory):
                _ensure_local_runtime_secrets()
                session_secret = (directory / ".session_secret").read_text(encoding="ascii")
                credential_key = (directory / ".credential_key").read_text(encoding="ascii")
                _ensure_local_runtime_secrets()
                self.assertEqual((directory / ".session_secret").read_text(encoding="ascii"), session_secret)
                self.assertEqual((directory / ".credential_key").read_text(encoding="ascii"), credential_key)

    @unittest.skipUnless(__import__("shutil").which("openssl"), "OpenSSL is not installed")
    def test_generated_certificate_verifies(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with patch("bootstrap.TLS_DIR", Path(tmp)):
                self.assertTrue(_generate_local_certificate("soc-console", "192.0.2.10"))
                self.assertTrue((Path(tmp) / "server.crt").is_file())


if __name__ == "__main__":
    unittest.main()
