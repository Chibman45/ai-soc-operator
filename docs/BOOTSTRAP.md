# Bootstrap

`bootstrap.py` is the one-command setup flow for AI SOC Operator.

## What it does

1. Checks the Python version
2. Creates a local `.venv/`
3. Installs Python dependencies into the venv
4. Detects installed security tools
5. Writes a blank `config/platforms.toml`
6. Installs and verifies the official Codex CLI
7. Installs the Codex skill into `~/.agents/skills/`
8. Installs the `ai-soc-operator` command
9. Sets up the web portal admin account
10. Offers local Nginx HTTPS configuration on Linux
11. Runs a mandatory self-test

## Installation flow

Run:

```bash
python3 bootstrap.py
```

The full setup is fail-closed. It reports completion only after the virtual
environment, Python runtime and test dependencies, Codex CLI, bundled skills,
launcher, runtime imports, playbooks, and test suite have all passed.

## Mandatory Codex CLI

Bootstrap first checks an explicit `AI_SOC_CODEX_BIN`, the current `PATH`, and
the user-local npm prefix. If a compatible CLI is not found, it:

1. Installs Node.js 16+ and npm through an allowlisted operating-system package manager when required.
2. Installs the repository-tested, pinned `@openai/codex` release into `~/.local` with npm audit/funding prompts disabled.
3. Adds `~/.local/bin` to the current process and shell startup PATH.
4. Verifies `codex --version` and the `codex exec` flags required by the OAuth adapter.

No remote installation script is piped into a shell. If package installation,
network download, or CLI verification fails, bootstrap exits with status 1 and
prints the remediation instead of continuing with an incomplete installation.

After setup, start the portal with:

```bash
ai-soc-operator
```

## Command installation

Bootstrap installs the launcher in one of two places:

- `/usr/local/bin/ai-soc-operator` when passwordless sudo is available
- `~/.local/bin/ai-soc-operator` otherwise

If `~/.local/bin` is used and is not already on your PATH, bootstrap appends:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

to `~/.bashrc`, and to `~/.zshrc` when that file exists.

## Sudo handling

Bootstrap checks `sudo -n true` before attempting any sudo-based repair or install.

If sudo is not available non-interactively, it does not hang waiting for a password. Instead it prints the exact command to run manually and asks you to re-run bootstrap afterwards.

This applies to:

- `python3-venv` repair during virtual environment creation
- Linux tool installation
- mandatory Node.js/npm installation for Codex CLI
- launcher installation to `/usr/local/bin`

## Web portal setup

The web portal becomes the source of truth for platform settings:

- API keys are saved in SQLite on the server
- base URLs are saved in SQLite on the server
- connection tests run from the server
- `config/platforms.toml` is regenerated from database state before a run

## Notes

- Bootstrap is intentionally zero-secret for platform config
- You still create the web admin account during setup
- The launcher uses the repo’s `.venv/bin/python` automatically when available
