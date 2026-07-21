#!/usr/bin/env python3
"""AI SOC Operator — one-command bootstrap CLI.

Usage:
    python3 bootstrap.py                    # Full interactive setup
    python3 bootstrap.py --check            # Check-only (no changes)
    python3 bootstrap.py --install-skills   # Install Codex skills only
    python3 bootstrap.py --validate         # Validate existing config

After cloning the repo, run this once. It will:
1. Check Python version and system requirements
2. Install Python dependencies
3. Detect already-installed security tools
4. Configure the web portal admin account
5. Validate connectivity to configured platforms
6. Install the Codex skill to ~/.agents/skills/
7. Run a self-test
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import sys
import venv
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "soc_operator.db"
VENV_DIR = ROOT / ".venv"
SKILLS_SRC = ROOT / "skills"
SKILLS_DEST = Path.home() / ".agents" / "skills"
VENV_PYTHON: Path | None = None

# ── Colors ──

BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


def status(msg: str) -> None:
    print(f"{GREEN}✓{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}⚠{RESET} {msg}")


def error(msg: str) -> None:
    print(f"{RED}✗{RESET} {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}\n")


# ── Step 1: System checks ──

def check_python() -> bool:
    header("Step 1/8 — System Requirements")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 10):
        error(f"Python {major}.{minor} detected. Python 3.10+ required.")
        return False
    status(f"Python {major}.{minor}.{sys.version_info[2]}")
    return True


def check_dependencies() -> bool:
    missing = []
    for pkg in ["yaml", "tomllib"]:
        try:
            __import__(pkg)
        except ImportError:
            if pkg == "yaml":
                missing.append("pyyaml")
            elif pkg == "tomllib":
                # tomllib is stdlib in 3.11+, need tomli for 3.10
                if sys.version_info < (3, 11):
                    missing.append("tomli")
    if missing:
        warn(f"Missing packages: {', '.join(missing)}")
        return False
    status("Core Python packages available")
    return True


def _venv_python() -> Path:
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def create_venv() -> Path | None:
    global VENV_PYTHON
    py = _venv_python()
    if py.is_file():
        VENV_PYTHON = py
        return py

    def _attempt_create() -> bool:
        try:
            builder = venv.EnvBuilder(with_pip=True, clear=False, symlinks=True)
            builder.create(VENV_DIR)
            return py.is_file()
        except Exception as exc:
            warn(f"venv creation failed: {exc}")
            return False

    if _attempt_create():
        VENV_PYTHON = py
        status(f"Virtual environment created at {VENV_DIR}")
        return py

    if platform.system() == "Linux":
        warn("Trying to install python3-venv and python3-pip, then retrying venv creation")
        result = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "python3-venv", "python3-pip"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and _attempt_create():
            VENV_PYTHON = py
            status(f"Virtual environment created at {VENV_DIR}")
            return py
        if result.returncode != 0:
            error(f"Unable to install python3-venv/python3-pip:\n{result.stderr}")
    return None


def install_python_deps() -> bool:
    req = ROOT / "requirements.txt"
    if not req.is_file():
        warn("requirements.txt not found, skipping pip install")
        return True
    python_bin = VENV_PYTHON or sys.executable
    result = subprocess.run(
        [str(python_bin), "-m", "pip", "install", "-q", "-r", str(req)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        error(f"pip install failed:\n{result.stderr}")
        return False
    status("Python dependencies installed")
    return True


# ── Step 2: Detect installed tools ──

KNOWN_TOOLS = {
    "nmap": {"apt": "nmap", "brew": "nmap", "desc": "Network discovery and port scanning"},
    "masscan": {"apt": "masscan", "brew": "masscan", "desc": "Fast port scanner"},
    "whatweb": {"apt": "whatweb", "brew": "whatweb", "desc": "Web fingerprinting"},
    "nikto": {"apt": "nikto", "brew": "nikto", "desc": "Web vulnerability scanner"},
    "gobuster": {"apt": "gobuster", "brew": "gobuster", "desc": "Content discovery"},
    "ffuf": {"apt": None, "brew": "ffuf", "desc": "Fuzzing and content discovery"},
    "enum4linux-ng": {"apt": "enum4linux-ng", "brew": None, "desc": "SMB enumeration"},
    "snmpwalk": {"apt": "snmp", "brew": "net-snmp", "desc": "SNMP enumeration"},
    "hydra": {"apt": "hydra", "brew": "hydra", "desc": "Credential testing"},
    "sqlmap": {"apt": "sqlmap", "brew": "sqlmap", "desc": "SQL injection testing"},
    "semgrep": {"apt": None, "brew": "semgrep", "desc": "Static analysis"},
    "bandit": {"apt": None, "brew": None, "desc": "Python security linting"},
    "yara": {"apt": "yara", "brew": "yara", "desc": "Malware triage rules"},
    "vol": {"apt": None, "brew": None, "desc": "Memory forensics"},
    "tshark": {"apt": "tshark", "brew": "wireshark", "desc": "Packet analysis"},
    "lynis": {"apt": "lynis", "brew": "lynis", "desc": "System hardening audit"},
    "pandoc": {"apt": "pandoc", "brew": "pandoc", "desc": "Document conversion"},
    "shellcheck": {"apt": "shellcheck", "brew": "shellcheck", "desc": "Shell script linting"},
}


def detect_tools() -> dict[str, bool]:
    header("Step 2/6 — Installed Tools Detection")
    found = {}
    for tool, meta in KNOWN_TOOLS.items():
        path = shutil.which(tool)
        if path:
            status(f"{tool:20s} — {meta['desc']}")
            found[tool] = True
        else:
            warn(f"{tool:20s} — not found ({meta['desc']})")
            found[tool] = False
    installed = sum(found.values())
    print(f"\n  {installed}/{len(found)} tools detected")
    return found


def install_tools(found: dict[str, bool]) -> None:
    missing = [tool for tool, present in found.items() if not present]
    if not missing:
        status("All required tools already installed")
        return

    print("\nMissing tools:")
    for tool in missing:
        print(f"  - {tool}")

    answer = input("Install missing tools now? [y/N] ").strip().lower()
    if answer not in {"y", "yes"}:
        warn("Skipping tool installation")
        return

    if platform.system() == "Darwin":
        warn("macOS detected — install these with Homebrew:")
        for tool in missing:
            pkg = KNOWN_TOOLS.get(tool, {}).get("brew")
            if pkg:
                print(f"  brew install {pkg}")
            else:
                warn(f"No Homebrew package mapping for {tool}")
        return

    if platform.system() != "Linux":
        warn("Automatic tool installation is only implemented for Linux")
        return

    apt_packages = []
    for tool in missing:
        pkg = KNOWN_TOOLS.get(tool, {}).get("apt")
        if pkg:
            apt_packages.append(pkg)
        else:
            warn(f"No apt package mapping for {tool} — skipping")

    if not apt_packages:
        warn("No installable packages found")
        return

    cmd = ["sudo", "apt-get", "install", "-y", *sorted(set(apt_packages))]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        error(f"Tool installation failed:\n{result.stderr}")
        return
    status("Missing tools installed")



PLATFORM_DEFAULTS = {
    "thehive": "https://thehive.example.com",
    "cortex": "https://cortex.example.com",
    "wazuh_manager": "https://wazuh-manager.example.com:55000",
    "wazuh_indexer": "https://wazuh-indexer.example.com:9200",
    "virustotal": "https://www.virustotal.com",
    "abuseipdb": "https://api.abuseipdb.com",
    "shodan": "https://api.shodan.io",
    "urlscan": "https://urlscan.io",
    "hybrid_analysis": "https://www.hybrid-analysis.com",
    "misp": "https://misp.example.com",
}


def write_blank_platform_config() -> None:
    output = CONFIG_DIR / "platforms.toml"
    lines = [
        "# AI SOC Operator — Platform Configuration",
        "# Generated by bootstrap.py",
        "# Edit platform connections in the web portal settings.",
        "",
    ]
    for name, base_url in PLATFORM_DEFAULTS.items():
        lines.extend([
            f"[platforms.{name}]",
            "enabled = false",
            f'base_url = "{base_url}"',
            "",
        ])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    status(f"Blank platform config written to {output}")


# ── Step 5: Validate connectivity ──

def validate_connectivity(config: dict[str, Any]) -> None:
    header("Step 5/6 — Connectivity Validation")
    import ssl
    import urllib.error
    import urllib.request

    for name, platform_cfg in config.get("platforms", {}).items():
        if not platform_cfg.get("enabled"):
            continue
        base_url = platform_cfg.get("base_url", "")
        if not base_url:
            warn(f"{name}: no base_url configured")
            continue
        try:
            parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(base_url)
            context = ssl.create_default_context()
            request = urllib.request.Request(
                base_url,
                headers={"User-Agent": "ai-soc-operator-bootstrapper/1.0"},
                method="HEAD",
            )
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context)
            )
            opener.open(request, timeout=10)
            status(f"{name}: reachable at {base_url}")
        except urllib.error.HTTPError as e:
            # 401/403 means the server is there but auth is needed — that's fine
            if e.code in (401, 403):
                status(f"{name}: reachable at {base_url} (HTTP {e.code} — auth required, expected)")
            else:
                warn(f"{name}: HTTP {e.code} from {base_url}")
        except Exception as e:
            warn(f"{name}: not reachable ({e})")


# ── Step 6: Install Codex skills ──

def install_skills() -> bool:
    header("Step 3/6 — Installing Codex Skills")
    if not SKILLS_SRC.is_dir():
        warn(f"Skills source not found: {SKILLS_SRC}")
        return False

    SKILLS_DEST.mkdir(parents=True, exist_ok=True)
    installed = 0
    for skill_dir in SKILLS_SRC.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            continue
        dest = SKILLS_DEST / skill_dir.name
        if dest.exists():
            warn(f"Skill already exists: {dest.name} — skipping (use --force to overwrite)")
            continue
        # Copy skill directory
        import shutil as _shutil
        _shutil.copytree(skill_dir, dest)
        status(f"Installed skill: {skill_dir.name}")
        installed += 1

    if installed:
        status(f"{installed} skill(s) installed to {SKILLS_DEST}")
    else:
        status("All skills already installed")
    return True


# ── Step 7: Scope configuration ──

def configure_scope() -> None:
    header("Step 4/6 — Target Scope")
    scope_file = CONFIG_DIR / "scope.toml"
    if scope_file.exists():
        status(f"Scope already configured: {scope_file}")
        return

    print("Define your authorized test targets.")
    print("You can edit config/scope.toml later.\n")

    hosts = input("  Allowed hosts (comma-separated IPs, Enter to skip): ").strip()
    cidrs = input("  Allowed CIDRs (comma-separated, Enter to skip): ").strip()
    domains = input("  Allowed domains (comma-separated, Enter to skip): ").strip()

    lines = [
        "# Target scope — authorized hosts, CIDRs, and domains",
        "# Edit this file to add or remove targets.",
        "",
    ]
    if hosts:
        host_list = [h.strip() for h in hosts.split(",") if h.strip()]
        lines.append(f"allowed_hosts = {json.dumps(host_list)}")
    else:
        lines.append("allowed_hosts = []")

    if cidrs:
        cidr_list = [c.strip() for c in cidrs.split(",") if c.strip()]
        lines.append(f"allowed_cidrs = {json.dumps(cidr_list)}")
    else:
        lines.append("allowed_cidrs = []")

    if domains:
        domain_list = [d.strip() for d in domains.split(",") if d.strip()]
        lines.append(f"allowed_domains = {json.dumps(domain_list)}")
    else:
        lines.append("allowed_domains = []")

    lines.extend([
        "",
        "excluded_hosts = []",
        "excluded_cidrs = []",
        "excluded_domains = []",
        "",
        "[rules]",
        "credential_testing = false",
        "exploitation = false",
        "traffic_interception = false",
        "system_changes = false",
        "data_destruction = false",
        "online_active_testing = false",
        "malware_sandbox_submission = false",
    ])

    scope_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    status(f"Scope written to {scope_file}")


# ── Step 8: Web credentials ──

def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest() + f":{salt}"


def setup_web_credentials() -> None:
    header("Step 5/6 — Web Portal Admin Account")
    create_account = input("Create web portal admin account? [Y/n] ").strip().lower()
    if create_account in {"n", "no"}:
        warn("Skipping web portal setup")
        return

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT
            )
            """
        )
        existing = conn.execute("SELECT username FROM users ORDER BY id LIMIT 1").fetchone()
        if existing:
            status(f"Web user already exists: {existing[0]} — skipping")
            return

        username = input("  Username [admin]: ").strip() or "admin"
        while True:
            password = getpass.getpass("  Password (min 8 chars): ")
            confirm = getpass.getpass("  Confirm password: ")
            if len(password) < 8:
                warn("Password must be at least 8 characters")
                continue
            if password != confirm:
                warn("Passwords do not match")
                continue
            break

        password_hash = hash_password(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, datetime.utcnow().isoformat() + "Z"),
        )
        conn.commit()
        status(f"Created web portal admin account: {username}")
        print("Web portal ready — run: python3 web/app.py")
    finally:
        conn.close()


# ── Step 9: Self-test ──

def run_self_test() -> bool:
    header("Step 6/6 — Self-Test")
    # Test playbook loading
    try:
        sys.path.insert(0, str(ROOT))
        from scripts.playbook_engine import load_playbook
        for pb_file in (ROOT / "playbooks").glob("*.yaml"):
            load_playbook(pb_file)
        status(f"Playbooks load successfully")
    except Exception as e:
        error(f"Playbook loading failed: {e}")
        return False

    # Test client imports
    try:
        from scripts.soc_client.thehive import TheHiveClient
        from scripts.soc_client.cortex import CortexClient
        from scripts.soc_client.wazuh import WazuhManagerClient, WazuhIndexerClient
        from scripts.soc_client.enrichment import EnrichmentClient
        status("All platform clients import successfully")
    except Exception as e:
        error(f"Client import failed: {e}")
        return False

    # Test orchestrator import
    try:
        from scripts.orchestrator import extract_iocs, auto_select_playbook
        status("Orchestrator imports successfully")
    except Exception as e:
        error(f"Orchestrator import failed: {e}")
        return False

    # Run pytest if available
    test_dir = ROOT / "tests"
    if test_dir.is_dir():
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_dir), "-q", "--tb=line"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        if result.returncode == 0:
            # Extract pass count from output
            for line in result.stdout.strip().split("\n"):
                if "passed" in line:
                    status(f"Tests: {line.strip()}")
                    break
            else:
                status("All tests passed")
        else:
            warn(f"Some tests failed (run pytest manually for details)")

    return True


# ── Main ──

def main() -> int:
    parser = argparse.ArgumentParser(
        description="AI SOC Operator — Bootstrap CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Check system requirements only (no changes)",
    )
    parser.add_argument(
        "--install-skills", action="store_true",
        help="Install Codex skills only",
    )
    parser.add_argument(
        "--validate", action="store_true",
        help="Validate existing configuration",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite existing skills and config",
    )
    args = parser.parse_args()

    print(f"\n{BOLD}AI SOC Operator — Bootstrap{RESET}")
    print(f"Platform: {platform.system()} {platform.machine()}")
    print(f"Python: {sys.version.split()[0]}")
    print()

    # ── Check mode ──
    if args.check:
        ok = check_python()
        ok = check_dependencies() and ok
        detect_tools()
        return 0 if ok else 1

    # ── Skills-only mode ──
    if args.install_skills:
        install_skills()
        return 0

    # ── Validate mode ──
    if args.validate:
        config = load_existing_config()
        if config:
            validate_connectivity(config)
        run_self_test()
        return 0

    # ── Full bootstrap ──
    if not check_python():
        return 1
    check_dependencies()
    create_venv()
    install_python_deps()
    found = detect_tools()
    install_tools(found)
    write_blank_platform_config()
    install_skills()
    configure_scope()
    setup_web_credentials()
    run_self_test()

    header("Bootstrap Complete")
    print(f"{GREEN}AI SOC Operator is ready.{RESET}")
    print(f"\nNext steps:")
    print(f"  1. Review config/platforms.toml and config/scope.toml")
    print(f"  2. Open the web portal → Settings → Platform Connections to add your API keys and base URLs")
    print(f"  3. Activate the virtual environment:")
    print(f"     source .venv/bin/activate")
    print(f"  4. Run an alert through the orchestrator:")
    print(f"     python3 -m scripts.orchestrator --alert alert.json")
    print(f"  5. Or use a specific playbook:")
    print(f"     python3 -m scripts.orchestrator --alert alert.json --playbook playbooks/identity-compromise.yaml")
    print()
    return 0


def load_existing_config() -> dict[str, Any] | None:
    config_path = CONFIG_DIR / "platforms.toml"
    if not config_path.is_file():
        warn("No config/platforms.toml found. Run bootstrap without --validate first.")
        return None
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore
    with config_path.open("rb") as f:
        return tomllib.load(f)


if __name__ == "__main__":
    raise SystemExit(main())
