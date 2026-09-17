"""Tests for organization AI selection and the constrained OAuth adapter."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.soc_client.codex_oauth import CodexOAuthClient, codex_environment
from web.services.ai_provider import load_ai_client, provider_config, save_provider_config
from web.services.schema_features import init_feature_db


def _database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
        CREATE TABLE credentials (id INTEGER PRIMARY KEY, platform TEXT, key_name TEXT, key_value TEXT);
        CREATE TABLE platform_config (id INTEGER PRIMARY KEY, platform TEXT UNIQUE, base_url TEXT, enabled INTEGER, updated_at TIMESTAMP);
        CREATE TABLE runs (id INTEGER PRIMARY KEY);
        CREATE TABLE cases (id INTEGER PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE activity_log (id INTEGER PRIMARY KEY, run_id INTEGER);
        INSERT INTO users VALUES (1, 'owner', 'x');
        """
    )
    init_feature_db(conn)
    return conn


class AIProviderConfigTests(unittest.TestCase):
    def test_api_key_selection_is_organization_scoped_and_uses_selected_model(self):
        conn = _database()
        org_id = int(conn.execute("SELECT id FROM organizations").fetchone()[0])
        conn.execute(
            "INSERT INTO credentials (platform, key_name, key_value, org_id) VALUES ('openai', 'OPENAI_API_KEY', 'secret', ?)",
            (org_id,),
        )
        save_provider_config(conn, org_id=org_id, user_id=1, provider="api_key", model="gpt-5.2")
        client = load_ai_client(conn, org_id)
        self.assertEqual(provider_config(conn, org_id), {"provider": "api_key", "model": "gpt-5.2"})
        self.assertEqual(client.model, "gpt-5.2")
        self.assertEqual(client._api_key, "secret")

    def test_oauth_selection_requires_completed_device_login(self):
        conn = _database()
        org_id = int(conn.execute("SELECT id FROM organizations").fetchone()[0])
        with patch("scripts.soc_client.codex_oauth.codex_login_status", return_value=False):
            with self.assertRaisesRegex(ValueError, "complete ChatGPT OAuth"):
                save_provider_config(
                    conn, org_id=org_id, user_id=1, provider="codex_oauth", model="gpt-5.6-sol"
                )


class CodexOAuthClientTests(unittest.TestCase):
    def test_environment_does_not_forward_soc_credentials(self):
        with patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "api-secret", "THEHIVE_API_KEY": "hive-secret", "PATH": "runtime-path"},
            clear=True,
        ):
            environment = codex_environment(Path("C:/oauth-home"))
        self.assertEqual(environment["PATH"], "runtime-path")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("THEHIVE_API_KEY", environment)

    def test_chat_uses_selected_model_read_only_sandbox_and_isolated_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def fake_run(command, **kwargs):
                output_index = command.index("--output-last-message") + 1
                Path(command[output_index]).write_text('{"answer":"ok"}', encoding="utf-8")
                self.assertIn("read-only", command)
                self.assertIn("shell_tool", command)
                self.assertIn("browser_use", command)
                self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-sol")
                self.assertNotEqual(Path(kwargs["cwd"]).resolve(), root.resolve())
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with (
                patch("scripts.soc_client.codex_oauth.ROOT", root),
                patch("scripts.soc_client.codex_oauth.codex_login_status", return_value=True),
                patch("scripts.soc_client.codex_oauth.codex_command", side_effect=lambda *args: list(args)),
                patch("scripts.soc_client.codex_oauth.subprocess.run", side_effect=fake_run),
                patch("scripts.soc_client.codex_oauth.audit"),
            ):
                client = CodexOAuthClient(org_id=7, model="gpt-5.6-sol")
                self.assertEqual(client.chat("Analyze this"), '{"answer":"ok"}')
                self.assertEqual(client._api_key, "")


if __name__ == "__main__":
    unittest.main()
