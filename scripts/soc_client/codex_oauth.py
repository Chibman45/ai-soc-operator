"""ChatGPT OAuth-backed AI client executed through the official Codex CLI."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from scripts.common import ROOT, audit
from scripts.soc_client.openai import OpenAIClient


MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")


def codex_home_for_org(org_id: int) -> Path:
    path = (ROOT / "data" / "codex-oauth" / f"org-{int(org_id)}").resolve()
    allowed = (ROOT / "data" / "codex-oauth").resolve()
    if path.parent != allowed:
        raise RuntimeError("invalid organization credential path")
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def codex_executable() -> str | None:
    configured = os.environ.get("AI_SOC_CODEX_BIN", "").strip()
    if configured:
        candidate = Path(configured).expanduser().resolve()
        return str(candidate) if candidate.is_file() else None
    return shutil.which("codex") or shutil.which("codex.cmd") or shutil.which("codex.exe")


def codex_command(*args: str) -> list[str]:
    executable = codex_executable()
    if not executable:
        raise RuntimeError("Codex CLI is not installed; install it through an approved capability request")
    if os.name == "nt" and executable.lower().endswith((".cmd", ".bat")):
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", subprocess.list2cmdline([executable, *args])]
    return [executable, *args]


def codex_environment(codex_home: Path) -> dict[str, str]:
    """Pass only OS/runtime values required by Codex, excluding SOC secrets."""
    allowed = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
        "HOME", "USERPROFILE", "LANG", "LC_ALL", "HTTPS_PROXY", "HTTP_PROXY",
        "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment["CODEX_HOME"] = str(codex_home)
    return environment


def codex_login_status(org_id: int) -> bool:
    try:
        result = subprocess.run(
            codex_command("login", "status"),
            cwd=str(codex_home_for_org(org_id)),
            env=codex_environment(codex_home_for_org(org_id)),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return result.returncode == 0 and "logged in" in (result.stdout + result.stderr).lower()
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return False


class CodexOAuthClient(OpenAIClient):
    """Expose the existing AI client interface through a constrained Codex run."""

    def __init__(self, *, org_id: int, model: str):
        if not MODEL_RE.fullmatch(model):
            raise ValueError("invalid Codex model identifier")
        super().__init__(api_key="", model=model)
        self.org_id = int(org_id)
        self.codex_home = codex_home_for_org(self.org_id)

    def chat(self, prompt: str, system: str = "", temperature: float = 0.3, max_tokens: int = 2048) -> str:
        del temperature, max_tokens  # Codex controls these through its selected model profile.
        if not codex_login_status(self.org_id):
            raise RuntimeError("ChatGPT OAuth is disconnected; reconnect it from Credentials")
        instruction = (
            "You are an inference component inside AI SOC Operator. Do not run tools, inspect files, "
            "or modify anything. Return only the requested analysis.\n\n"
        )
        if system:
            instruction += f"System instructions:\n{system}\n\n"
        instruction += f"User input:\n{prompt}"
        with tempfile.TemporaryDirectory(prefix="ai-soc-codex-") as workspace:
            output_path = Path(workspace) / "response.txt"
            command = codex_command(
                "exec", "--ephemeral", "--ignore-user-config", "--ignore-rules",
                "--disable", "shell_tool", "--disable", "unified_exec",
                "--disable", "browser_use", "--disable", "computer_use",
                "--disable", "apps", "--disable", "plugins",
                "--skip-git-repo-check", "--sandbox", "read-only", "--model", self.model,
                "--cd", workspace, "--output-last-message", str(output_path), "-",
            )
            completed = subprocess.run(
                command,
                input=instruction,
                cwd=workspace,
                env=codex_environment(self.codex_home),
                capture_output=True,
                text=True,
                timeout=int(os.environ.get("AI_SOC_CODEX_TIMEOUT", "180")),
                check=False,
            )
            if completed.returncode != 0 or not output_path.is_file():
                detail = (completed.stderr or completed.stdout or "Codex execution failed")[-500:]
                raise RuntimeError(detail)
            response = output_path.read_text(encoding="utf-8").strip()
        audit("codex_oauth_call", org_id=self.org_id, model=self.model)
        return response
