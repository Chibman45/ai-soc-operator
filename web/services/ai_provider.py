"""Organization-scoped AI provider selection and model validation."""

from __future__ import annotations

import re

from web.services.credential_vault import open_secret


DEFAULT_MODEL = "gpt-5.6"
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
API_MODEL_SUGGESTIONS = ["gpt-5.6", "gpt-5.2", "gpt-5.1", "gpt-5"]
CODEX_MODEL_SUGGESTIONS = ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-6-astra", "gpt-5.5"]


def provider_config(conn, org_id: int) -> dict[str, str]:
    row = conn.execute("SELECT provider, model FROM ai_provider_config WHERE org_id = ?", (org_id,)).fetchone()
    return {
        "provider": str(row["provider"]) if row else "api_key",
        "model": str(row["model"]) if row else DEFAULT_MODEL,
    }


def save_provider_config(conn, *, org_id: int, user_id: int, provider: str, model: str) -> None:
    if provider not in {"api_key", "codex_oauth"}:
        raise ValueError("AI provider must be API key or ChatGPT OAuth")
    if not MODEL_RE.fullmatch(model):
        raise ValueError("model identifier contains unsupported characters")
    if provider == "api_key":
        key = conn.execute(
            "SELECT 1 FROM credentials WHERE org_id = ? AND key_name = 'OPENAI_API_KEY'", (org_id,)
        ).fetchone()
        if not key:
            raise ValueError("save an OpenAI API key before selecting API-key mode")
    else:
        from scripts.soc_client.codex_oauth import codex_login_status

        if not codex_login_status(org_id):
            raise ValueError("complete ChatGPT OAuth connection before selecting OAuth mode")
    conn.execute(
        """
        INSERT INTO ai_provider_config (org_id, provider, model, configured_by, configured_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(org_id) DO UPDATE SET provider = excluded.provider, model = excluded.model,
            configured_by = excluded.configured_by, configured_at = CURRENT_TIMESTAMP
        """,
        (org_id, provider, model, user_id),
    )


def load_ai_client(conn, org_id: int):
    config = provider_config(conn, org_id)
    if config["provider"] == "codex_oauth":
        from scripts.soc_client.codex_oauth import CodexOAuthClient

        return CodexOAuthClient(org_id=org_id, model=config["model"])
    credential = conn.execute(
        "SELECT key_value FROM credentials WHERE org_id = ? AND key_name = 'OPENAI_API_KEY'", (org_id,)
    ).fetchone()
    if not credential:
        return None
    from scripts.soc_client.openai import OpenAIClient

    return OpenAIClient(open_secret(credential["key_value"]), model=config["model"])
