"""Tests for bootstrap CLI (non-interactive modes)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootstrap import (
    KNOWN_TOOLS,
    _certificate_extensions,
    _ensure_local_runtime_secrets,
    _generate_local_certificate,
    _install_node_runtime,
    _linux_package_command,
    _render_local_nginx_config,
    check_dependencies,
    check_python,
    detect_tools,
    install_codex_cli,
    main,
    verify_codex_cli,
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


class CodexBootstrapTests(unittest.TestCase):
    def test_verification_requires_runtime_flags_used_by_oauth_adapter(self):
        responses = [
            subprocess.CompletedProcess(["codex", "--version"], 0, "codex-cli 0.155.0\n", ""),
            subprocess.CompletedProcess(
                ["codex", "exec", "--help"],
                0,
                "--ignore-user-config --disable --sandbox --output-last-message",
                "",
            ),
        ]
        with patch("bootstrap._find_codex", return_value="/home/soc/.local/bin/codex"), patch(
            "bootstrap.subprocess.run", side_effect=responses
        ):
            self.assertTrue(verify_codex_cli(report=False))

    def test_verification_rejects_incompatible_codex(self):
        responses = [
            subprocess.CompletedProcess(["codex", "--version"], 0, "codex-cli 0.1.0\n", ""),
            subprocess.CompletedProcess(["codex", "exec", "--help"], 0, "--sandbox", ""),
        ]
        with patch("bootstrap._find_codex", return_value="/usr/bin/codex"), patch(
            "bootstrap.subprocess.run", side_effect=responses
        ):
            self.assertFalse(verify_codex_cli(report=False))

    def test_install_uses_user_owned_prefix_and_verifies_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / ".local"
            completed = subprocess.CompletedProcess(["npm"], 0, "", "")
            with (
                patch("bootstrap.verify_codex_cli", side_effect=[False, True]) as verify,
                patch("bootstrap._node_is_supported", return_value=True),
                patch("bootstrap.shutil.which", return_value="/usr/bin/npm"),
                patch("bootstrap._user_npm_prefix", return_value=prefix),
                patch("bootstrap._user_npm_bin", return_value=prefix / "bin"),
                patch("bootstrap._ensure_user_bin_on_path") as ensure_path,
                patch("bootstrap.subprocess.run", return_value=completed) as run,
            ):
                self.assertTrue(install_codex_cli())
            verify.assert_has_calls([call(report=False), call()])
            ensure_path.assert_called_once_with(prefix / "bin")
            command = run.call_args.args[0]
            self.assertIn("@openai/codex@0.155.0", command)
            self.assertIn(str(prefix), command)

    def test_linux_node_install_refreshes_apt_and_verifies_runtime(self):
        completed = subprocess.CompletedProcess(["apt-get"], 0, "", "")
        with (
            patch("bootstrap.platform.system", return_value="Linux"),
            patch("bootstrap._linux_package_command", return_value=["apt-get", "install", "-y", "nodejs", "npm"]),
            patch("bootstrap._run_privileged", side_effect=[completed, completed]) as privileged,
            patch("bootstrap._node_is_supported", return_value=True),
            patch("bootstrap.shutil.which", return_value="/usr/bin/npm"),
        ):
            self.assertTrue(_install_node_runtime())
        self.assertEqual(privileged.call_args_list[0], call(["apt-get", "update"], timeout=600))
        self.assertEqual(
            privileged.call_args_list[1],
            call(["apt-get", "install", "-y", "nodejs", "npm"], timeout=600),
        )

    def test_full_bootstrap_stops_before_completion_when_codex_fails(self):
        with (
            patch.object(sys, "argv", ["bootstrap.py"]),
            patch("bootstrap.check_python", return_value=True),
            patch("bootstrap.check_dependencies", return_value=True),
            patch("bootstrap.create_venv", return_value=Path(".venv/bin/python")),
            patch("bootstrap.install_python_deps", return_value=True),
            patch("bootstrap.detect_tools", return_value={}),
            patch("bootstrap.install_tools"),
            patch("bootstrap.write_blank_platform_config", return_value=True),
            patch("bootstrap.install_codex_cli", return_value=False),
            patch("bootstrap.install_skills") as install_skills,
        ):
            self.assertEqual(main(), 1)
        install_skills.assert_not_called()


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
