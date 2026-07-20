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
4. Prompt for platform credentials (TheHive, Cortex, Wazuh, threat intel)
5. Generate config/platforms.toml from your answers
6. Validate connectivity to configured platforms
7. Install the Codex skill to ~/.agents/skills/
8. Run a self-test
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
SKILLS_SRC = ROOT / "skills"
SKILLS_DEST = Path.home() / ".agents" / "skills"

# ── Colors ──

BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


def status(msg: str) -> None:
    print(f"  [OK] {msg}")


def warn(msg: str) -> None:
    print(f"  [!!] {msg}")


def error(msg: str) -> None:
    print(f"  [XX] {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")


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


def install_python_deps() -> bool:
    req = ROOT / "requirements.txt"
    if not req.is_file():
        warn("requirements.txt not found, skipping pip install")
        return True
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "-r", str(req)],
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
    "nmap": "Network discovery and port scanning",
    "masscan": "Fast port scanner",
    "whatweb": "Web fingerprinting",
    "nikto": "Web vulnerability scanner",
    "gobuster": "Content discovery",
    "ffuf": "Fuzzing and content discovery",
    "enum4linux-ng": "SMB enumeration",
    "snmpwalk": "SNMP enumeration",
    "hydra": "Credential testing",
    "sqlmap": "SQL injection testing",
    "semgrep": "Static analysis",
    "bandit": "Python security linting",
    "yara": "Malware triage rules",
    "vol": "Memory forensics",
    "tshark": "Packet analysis",
    "lynis": "System hardening audit",
    "pandoc": "Document conversion",
    "shellcheck": "Shell script linting",
}


def detect_tools() -> dict[str, bool]:
    header("Step 2/8 — Installed Tools Detection")
    found = {}
    for tool, desc in KNOWN_TOOLS.items():
        path = shutil.which(tool)
        if path:
            status(f"{tool:20s} — {desc}")
            found[tool] = True
        else:
            warn(f"{tool:20s} — not found ({desc})")
            found[tool] = False
    installed = sum(found.values())
    print(f"\n  {installed}/{len(found)} tools detected")
    return found


# ── Step 3: Credential prompts ──

def prompt_credential(env_name: str, description: str, required: bool = False) -> str | None:
    value = os.environ.get(env_name, "")
    if value:
        status(f"{env_name} already set in environment")
        return value
    if required:
        value = getpass.getpass(f"  {description} ({env_name}): ")
    else:
        value = input(f"  {description} ({env_name}, Enter to skip): ").strip()
    return value or None


def prompt_platform_config() -> dict[str, Any]:
    header("Step 3/8 — Platform Credentials")
    print("Enter credentials for the platforms you want to configure.")
    print("Press Enter to skip any platform you don't need yet.\n")

    config: dict[str, Any] = {"platforms": {}}

    # ── TheHive ──
    print(f"{BOLD}TheHive (case management):{RESET}")
    th_url = input("  Base URL (https://thehive.example.com): ").strip()
    if th_url:
        th_key = prompt_credential("THEHIVE_API_KEY", "API key", required=True)
        if th_key:
            config["platforms"]["thehive"] = {
                "enabled": True,
                "base_url": th_url,
                "credential_env": "THEHIVE_API_KEY",
            }
            os.environ["THEHIVE_API_KEY"] = th_key
            status("TheHive configured")
    print()

    # ── Cortex ──
    print(f"{BOLD}Cortex (analyzer/responder engine):{RESET}")
    cx_url = input("  Base URL (https://cortex.example.com): ").strip()
    if cx_url:
        cx_key = prompt_credential("CORTEX_API_KEY", "API key", required=True)
        if cx_key:
            config["platforms"]["cortex"] = {
                "enabled": True,
                "base_url": cx_url,
                "credential_env": "CORTEX_API_KEY",
            }
            os.environ["CORTEX_API_KEY"] = cx_key
            status("Cortex configured")
    print()

    # ── Wazuh Manager ──
    print(f"{BOLD}Wazuh Manager:{RESET}")
    wazuh_url = input("  Base URL (https://wazuh-manager.example.com:55000): ").strip()
    if wazuh_url:
        wazuh_key = prompt_credential("WAZUH_API_TOKEN", "API token", required=True)
        if wazuh_key:
            config["platforms"]["wazuh_manager"] = {
                "enabled": True,
                "base_url": wazuh_url,
                "credential_env": "WAZUH_API_TOKEN",
            }
            os.environ["WAZUH_API_TOKEN"] = wazuh_key
            status("Wazuh Manager configured")
    print()

    # ── Wazuh Indexer ──
    print(f"{BOLD}Wazuh Indexer (Elasticsearch-compatible):{RESET}")
    idx_url = input("  Base URL (https://wazuh-indexer.example.com:9200): ").strip()
    if idx_url:
        idx_user = input("  Username: ").strip()
        idx_pass = getpass.getpass("  Password: ")
        if idx_user and idx_pass:
            config["platforms"]["wazuh_indexer"] = {
                "enabled": True,
                "base_url": idx_url,
                "username_env": "WAZUH_INDEXER_USERNAME",
                "password_env": "WAZUH_INDEXER_PASSWORD",
            }
            os.environ["WAZUH_INDEXER_USERNAME"] = idx_user
            os.environ["WAZUH_INDEXER_PASSWORD"] = idx_pass
            status("Wazuh Indexer configured")
    print()

    # ── Threat Intelligence ──
    print(f"{BOLD}Threat Intelligence Platforms:{RESET}")

    vt_key = prompt_credential("VIRUSTOTAL_API_KEY", "VirusTotal API key")
    if vt_key:
        config["platforms"]["virustotal"] = {
            "enabled": True,
            "credential_env": "VIRUSTOTAL_API_KEY",
        }
        os.environ["VIRUSTOTAL_API_KEY"] = vt_key

    abuse_key = prompt_credential("ABUSEIPDB_API_KEY", "AbuseIPDB API key")
    if abuse_key:
        config["platforms"]["abuseipdb"] = {
            "enabled": True,
            "credential_env": "ABUSEIPDB_API_KEY",
        }
        os.environ["ABUSEIPDB_API_KEY"] = abuse_key

    shodan_key = prompt_credential("SHODAN_API_KEY", "Shodan API key")
    if shodan_key:
        config["platforms"]["shodan"] = {
            "enabled": True,
            "credential_env": "SHODAN_API_KEY",
        }
        os.environ["SHODAN_API_KEY"] = shodan_key

    urlscan_key = prompt_credential("URLSCAN_API_KEY", "urlscan.io API key")
    if urlscan_key:
        config["platforms"]["urlscan"] = {
            "enabled": True,
            "credential_env": "URLSCAN_API_KEY",
        }
        os.environ["URLSCAN_API_KEY"] = urlscan_key

    ha_key = prompt_credential("HYBRID_ANALYSIS_API_KEY", "Hybrid Analysis API key")
    if ha_key:
        config["platforms"]["hybrid_analysis"] = {
            "enabled": True,
            "credential_env": "HYBRID_ANALYSIS_API_KEY",
        }
        os.environ["HYBRID_ANALYSIS_API_KEY"] = ha_key

    misp_url = input("  MISC base URL (https://misp.example.com, Enter to skip): ").strip()
    if misp_url:
        misp_key = prompt_credential("MISP_API_KEY", "MISP API key", required=True)
        if misp_key:
            config["platforms"]["misp"] = {
                "enabled": True,
                "base_url": misp_url,
                "credential_env": "MISP_API_KEY",
            }
            os.environ["MISP_API_KEY"] = misp_key

    enabled = [k for k, v in config["platforms"].items() if v.get("enabled")]
    print(f"\n  {len(enabled)} platform(s) configured: {', '.join(enabled) or 'none'}")
    return config


# ── Step 4: Write config ──

def write_platform_config(config: dict[str, Any]) -> bool:
    header("Step 4/8 — Generating Configuration")
    output = CONFIG_DIR / "platforms.toml"
    lines = [
        "# AI SOC Operator — Platform Configuration",
        "# Generated by bootstrap.py",
        "# Do not commit this file with real credentials.",
        "",
    ]
    for name, platform_cfg in sorted(config.get("platforms", {}).items()):
        lines.append(f"[platforms.{name}]")
        lines.append(f"enabled = {str(platform_cfg.get('enabled', False)).lower()}")
        if "base_url" in platform_cfg:
            lines.append(f'base_url = "{platform_cfg["base_url"]}"')
        if "credential_env" in platform_cfg:
            lines.append(f'credential_env = "{platform_cfg["credential_env"]}"')
        if "username_env" in platform_cfg:
            lines.append(f'username_env = "{platform_cfg["username_env"]}"')
        if "password_env" in platform_cfg:
            lines.append(f'password_env = "{platform_cfg["password_env"]}"')
        lines.append("")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    status(f"Configuration written to {output}")
    return True


# ── Step 5: Validate connectivity ──

def validate_connectivity(config: dict[str, Any]) -> None:
    header("Step 5/8 — Connectivity Validation")
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
    header("Step 6/8 — Installing Codex Skills")
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

    # Install system command
    bin_src = ROOT / "bin" / "ai-soc-operator"
    bin_dest = Path("/usr/local/bin/ai-soc-operator")
    if bin_src.is_file() and not bin_dest.exists():
        try:
            import shutil as _shutil
            _shutil.copy2(bin_src, bin_dest)
            bin_dest.chmod(0o755)
            status(f"Installed system command: {bin_dest}")
        except PermissionError:
            warn(f"Could not install to {bin_dest} (permission denied)")
            warn(f"Run manually: sudo cp {bin_src} /usr/local/bin/")
    elif bin_dest.exists():
        status("System command already installed")
    return True


# ── Step 7: Scope configuration ──

def configure_scope() -> None:
    header("Step 7/8 — Target Scope")
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


# ── Step 8: Self-test ──

def run_self_test() -> bool:
    header("Step 8/8 — Self-Test")
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
    install_python_deps()
    detect_tools()
    config = prompt_platform_config()
    write_platform_config(config)
    validate_connectivity(config)
    install_skills()
    configure_scope()
    run_self_test()

    header("Bootstrap Complete")
    print(f"{GREEN}AI SOC Operator is ready.{RESET}")
    print(f"\nNext steps:")
    print(f"  1. Review config/platforms.toml and config/scope.toml")
    print(f"  2. Set platform credentials in your shell profile:")
    print(f"     export THEHIVE_API_KEY=your-key-here")
    print(f"     export CORTEX_API_KEY=your-key-here")
    print(f"  3. Run an alert through the orchestrator:")
    print(f"     python3 -m scripts.orchestrator --alert alert.json")
    print(f"  4. Or use a specific playbook:")
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
