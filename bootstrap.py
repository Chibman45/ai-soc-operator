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
4. Install the Codex skill to ~/.agents/skills/
5. Configure target scope
6. Configure the web portal admin account
7. Optionally configure local HTTPS through Nginx
8. Run a self-test
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import platform
import secrets
import shlex
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
TLS_DIR = DATA_DIR / "tls"
LOCAL_HTTPS_MARKER = CONFIG_DIR / "local-https.json"
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


def _configure_console_encoding() -> None:
    """Keep bootstrap output usable on Windows consoles with legacy encodings."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def sudo_available() -> bool:
    if platform.system() != "Linux":
        return False
    result = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
    return result.returncode == 0


def print_manual_sudo(command: list[str]) -> None:
    print("Run this manually with sudo, then re-run bootstrap:")
    print("  " + shlex.join(command))


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
        command = ["sudo", "apt-get", "install", "-y", "python3-venv", "python3-pip"]
        if not sudo_available():
            warn("sudo is not available non-interactively for python3-venv installation")
            print_manual_sudo(command)
            return None
        warn("Trying to install python3-venv and python3-pip, then retrying venv creation")
        result = subprocess.run(command, capture_output=True, text=True)
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
    header("Step 2/8 — Installed Tools Detection")
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
    if not sudo_available():
        warn("sudo is not available non-interactively for tool installation")
        print_manual_sudo(cmd)
        return
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        error(f"Tool installation failed:\n{result.stderr}")
        return
    status("Missing tools installed")


# ── Local HTTPS: private CA + Nginx reverse proxy ──

def _linux_package_command(packages: list[str]) -> list[str] | None:
    """Return one allowlisted package-manager command without invoking a shell."""
    package_names = sorted(set(packages))
    for manager, prefix in (
        ("apt-get", ["apt-get", "install", "-y"]),
        ("dnf", ["dnf", "install", "-y"]),
        ("yum", ["yum", "install", "-y"]),
        ("zypper", ["zypper", "--non-interactive", "install"]),
        ("pacman", ["pacman", "--noconfirm", "-S"]),
        ("apk", ["apk", "add", "--no-cache"]),
    ):
        if shutil.which(manager):
            return [*prefix, *package_names]
    return None


def _run_privileged(command: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess[str] | None:
    """Run an exact privileged argv or print it for manual execution."""
    if platform.system() != "Linux":
        return None
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        argv = command
    elif sudo_available():
        argv = ["sudo", "-n", *command]
    else:
        print_manual_sudo(["sudo", *command])
        return None
    return subprocess.run(argv, capture_output=capture_output, text=True, timeout=120, check=False)


def _local_network_identity() -> tuple[str, str]:
    import ipaddress
    import socket

    hostname = socket.gethostname().strip().lower()
    hostname = "".join(ch for ch in hostname if ch.isalnum() or ch in {"-", "."}).strip(".-") or "localhost"
    lan_ip = "127.0.0.1"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        candidate = sock.getsockname()[0]
        sock.close()
        if not ipaddress.ip_address(candidate).is_unspecified:
            lan_ip = candidate
    except OSError:
        pass
    return hostname, lan_ip


def _certificate_extensions(hostname: str, lan_ip: str) -> str:
    import ipaddress

    ipaddress.ip_address(lan_ip)
    dns_names = ["localhost"]
    if hostname != "localhost":
        dns_names.extend([hostname, f"{hostname}.local"])
    lines = [
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        "extendedKeyUsage=serverAuth",
        "subjectAltName=@alt_names",
        "[alt_names]",
    ]
    lines.extend(f"DNS.{index}={name}" for index, name in enumerate(dns_names, start=1))
    addresses = ["127.0.0.1"]
    if lan_ip not in addresses:
        addresses.append(lan_ip)
    lines.extend(f"IP.{index}={address}" for index, address in enumerate(addresses, start=1))
    return "\n".join(lines) + "\n"


def _render_local_nginx_config(hostname: str, lan_ip: str) -> str:
    names = list(dict.fromkeys(["localhost", hostname, f"{hostname}.local", lan_ip]))
    server_names = " ".join(names)
    allowed_hosts = "\n".join(f"    {name} 1;" for name in names)
    return f"""# Generated by AI SOC Operator bootstrap. Re-run bootstrap to update.
map $host $ai_soc_valid_host {{
    default 0;
{allowed_hosts}
}}

server {{
    listen 80;
    listen [::]:80;
    server_name {server_names};
    if ($ai_soc_valid_host = 0) {{ return 444; }}
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {server_names};
    if ($ai_soc_valid_host = 0) {{ return 444; }}

    ssl_certificate /etc/ai-soc-operator/tls/server.crt;
    ssl_certificate_key /etc/ai-soc-operator/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    server_tokens off;

    client_max_body_size 5m;
    proxy_connect_timeout 10s;
    proxy_send_timeout 120s;
    proxy_read_timeout 120s;

    location / {{
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
    }}
}}
"""


def _ensure_local_runtime_secrets() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secrets_to_create = {
        DATA_DIR / ".session_secret": secrets.token_hex(32),
        DATA_DIR / ".credential_key": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
    }
    for path, value in secrets_to_create.items():
        if not path.exists():
            path.write_text(value, encoding="ascii")
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _generate_local_certificate(hostname: str, lan_ip: str) -> bool:
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    ca_key = TLS_DIR / "local-ca.key"
    ca_cert = TLS_DIR / "local-ca.crt"
    server_key = TLS_DIR / "server.key"
    server_csr = TLS_DIR / "server.csr"
    server_cert = TLS_DIR / "server.crt"
    extensions = TLS_DIR / "server-extensions.cnf"
    extensions.write_text(_certificate_extensions(hostname, lan_ip), encoding="ascii")

    commands: list[list[str]] = []
    if not ca_key.exists() or not ca_cert.exists():
        commands.extend(
            [
                ["openssl", "genrsa", "-out", str(ca_key), "3072"],
                [
                    "openssl", "req", "-x509", "-new", "-sha256", "-days", "3650",
                    "-key", str(ca_key), "-out", str(ca_cert),
                    "-subj", "/CN=AI SOC Operator Local CA",
                ],
            ]
        )
    commands.extend(
        [
            ["openssl", "genrsa", "-out", str(server_key), "3072"],
            [
                "openssl", "req", "-new", "-sha256", "-key", str(server_key),
                "-out", str(server_csr), "-subj", f"/CN={hostname}",
            ],
            [
                "openssl", "x509", "-req", "-sha256", "-days", "397",
                "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(server_cert), "-extfile", str(extensions),
            ],
            ["openssl", "verify", "-CAfile", str(ca_cert), str(server_cert)],
        ]
    )
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode != 0:
            error(f"Certificate generation failed: {result.stderr.strip()[:500]}")
            return False
    for path in (ca_key, server_key):
        try:
            path.chmod(0o600)
        except OSError:
            pass
    server_csr.unlink(missing_ok=True)
    status("Local CA and HTTPS server certificate generated")
    return True


def _install_local_ca(ca_cert: Path) -> bool:
    distro = ""
    try:
        values = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
        distro = f"{values.get('ID', '')} {values.get('ID_LIKE', '')}".lower()
    except OSError:
        pass
    if shutil.which("update-ca-certificates"):
        destination = (
            "/etc/pki/trust/anchors/ai-soc-operator-local-ca.crt"
            if any(name in distro for name in ("suse", "opensuse"))
            else "/usr/local/share/ca-certificates/ai-soc-operator-local-ca.crt"
        )
        update_command = ["update-ca-certificates"]
    elif shutil.which("update-ca-trust"):
        destination = "/etc/pki/ca-trust/source/anchors/ai-soc-operator-local-ca.crt"
        update_command = ["update-ca-trust", "extract"]
    else:
        if shutil.which("trust"):
            anchored = _run_privileged(["trust", "anchor", str(ca_cert)])
            return bool(anchored and anchored.returncode == 0)
        warn(f"No supported system trust command found. Import this CA manually: {ca_cert}")
        return False
    copied = _run_privileged(["install", "-m", "0644", str(ca_cert), destination])
    if not copied or copied.returncode != 0:
        return False
    updated = _run_privileged(update_command)
    return bool(updated and updated.returncode == 0)


def setup_local_https(*, ask_enable: bool = True) -> bool:
    """Configure local TLS after explicit consent to privileged host changes."""
    header("Step 7/8 - Local HTTPS")
    if platform.system() != "Linux":
        warn("Automatic Nginx HTTPS setup is currently available only on Linux")
        return False
    if ask_enable:
        answer = input("Enable local HTTPS with Nginx? [Y/n] ").strip().lower()
        if answer not in {"", "y", "yes"}:
            if LOCAL_HTTPS_MARKER.exists():
                warn("Local HTTPS setup skipped; the existing HTTPS configuration was left unchanged")
            else:
                warn("Local HTTPS setup skipped; the portal remains loopback HTTP")
            return False

    missing = [binary for binary in ("nginx", "openssl") if not shutil.which(binary)]
    if missing:
        command = _linux_package_command(missing)
        if not command:
            warn("No supported Linux package manager found for Nginx/OpenSSL")
            return False
        print(f"The following system packages are required: {', '.join(missing)}")
        answer = input("Approve installation of these packages? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            warn("Package installation was not approved")
            return False
        installed = _run_privileged(command)
        if not installed or installed.returncode != 0:
            if installed:
                error(f"Package installation failed: {installed.stderr.strip()[:500]}")
            return False

    hostname, lan_ip = _local_network_identity()
    if not _generate_local_certificate(hostname, lan_ip):
        return False
    _ensure_local_runtime_secrets()
    staged_config = TLS_DIR / "ai-soc-operator.nginx.conf"
    staged_config.write_text(_render_local_nginx_config(hostname, lan_ip), encoding="utf-8")

    nginx_config_dir = Path("/etc/nginx/http.d") if Path("/etc/nginx/http.d").is_dir() else Path("/etc/nginx/conf.d")
    install_steps = [
        ["install", "-d", "-m", "0755", "/etc/ai-soc-operator/tls"],
        ["install", "-d", "-m", "0755", str(nginx_config_dir)],
        ["install", "-m", "0644", str(TLS_DIR / "server.crt"), "/etc/ai-soc-operator/tls/server.crt"],
        ["install", "-m", "0600", str(TLS_DIR / "server.key"), "/etc/ai-soc-operator/tls/server.key"],
        ["install", "-m", "0644", str(staged_config), str(nginx_config_dir / "ai-soc-operator.conf")],
    ]
    for command in install_steps:
        result = _run_privileged(command)
        if not result or result.returncode != 0:
            if result:
                error(f"Nginx file installation failed: {result.stderr.strip()[:500]}")
            return False

    nginx_test = _run_privileged(["nginx", "-t"])
    if not nginx_test or nginx_test.returncode != 0:
        if nginx_test:
            error(f"Nginx configuration validation failed: {nginx_test.stderr.strip()[:500]}")
        return False
    nginx_dump = _run_privileged(["nginx", "-T"])
    rendered = "" if not nginx_dump else f"{nginx_dump.stdout}\n{nginx_dump.stderr}"
    if not nginx_dump or nginx_dump.returncode != 0 or "AI SOC Operator bootstrap" not in rendered:
        error("Nginx does not include the generated AI SOC Operator configuration")
        return False
    if shutil.which("systemctl"):
        reload_result = _run_privileged(["systemctl", "enable", "--now", "nginx"])
        if reload_result and reload_result.returncode == 0:
            reload_result = _run_privileged(["systemctl", "reload", "nginx"])
    else:
        reload_result = _run_privileged(["nginx", "-s", "reload"])
        if reload_result and reload_result.returncode != 0:
            reload_result = _run_privileged(["nginx"])
    if not reload_result or reload_result.returncode != 0:
        error("Nginx could not be started or reloaded")
        return False

    trust_answer = input("Trust the generated local CA on this machine? [Y/n] ").strip().lower()
    trusted = trust_answer in {"", "y", "yes"} and _install_local_ca(TLS_DIR / "local-ca.crt")
    if trusted:
        status("Local CA added to the operating-system trust store")
    else:
        warn(f"Import {TLS_DIR / 'local-ca.crt'} into each browser/client that should trust this portal")

    marker = {
        "enabled": True,
        "hostname": hostname,
        "lan_ip": lan_ip,
        "local_url": "https://localhost",
        "network_url": f"https://{lan_ip}",
        "ca_certificate": str(TLS_DIR / "local-ca.crt"),
        "ca_trusted_locally": trusted,
    }
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOCAL_HTTPS_MARKER.write_text(json.dumps(marker, indent=2), encoding="utf-8")
    status(f"Local HTTPS configured: {marker['local_url']}")
    return True



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
    header("Step 3/8 — Platform Configuration")
    output = CONFIG_DIR / "platforms.toml"
    # Ensure config/ exists and is owned by current user (not root from a sudo run)
    output.parent.mkdir(parents=True, exist_ok=True)
    import os, stat
    if not os.access(output.parent, os.W_OK):
        warn(f"config/ is not writable. Run: sudo chown -R $USER {output.parent}")
        return
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
    header("Connectivity Validation")
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
    header("Step 4/8 — Installing Codex Skills")
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


def install_system_command() -> None:
    source = ROOT / "bin" / "ai-soc-operator"
    if not source.is_file():
        warn(f"Command template not found: {source}")
        return

    script = source.read_text(encoding="utf-8")
    script = script.replace('REPO_DIR="${AI_SOC_HOME:-$HOME/ai-soc-operator}"', f'REPO_DIR="{ROOT}"')

    target_dir = Path("/usr/local/bin")
    target = target_dir / "ai-soc-operator"
    local_target_dir = Path.home() / ".local" / "bin"
    local_target = local_target_dir / "ai-soc-operator"

    def write_target(dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(script, encoding="utf-8")
        dest.chmod(0o755)

    if sudo_available():
        tmp = Path("/tmp") / "ai-soc-operator"
        tmp.write_text(script, encoding="utf-8")
        tmp.chmod(0o755)
        result = subprocess.run(["sudo", "cp", str(tmp), str(target)], capture_output=True, text=True)
        if result.returncode != 0:
            error(f"Failed to install command to {target}:\n{result.stderr}")
            return
        subprocess.run(["sudo", "chmod", "+x", str(target)], capture_output=True, text=True)
        status(f"Installed command to {target}")
    else:
        write_target(local_target)
        bashrc = Path.home() / ".bashrc"
        zshrc = Path.home() / ".zshrc"
        path_line = 'export PATH="$HOME/.local/bin:$PATH"'
        for shell_rc in [bashrc, zshrc if zshrc.exists() else None]:
            if shell_rc is None:
                continue
            content = shell_rc.read_text(encoding="utf-8") if shell_rc.exists() else ""
            if path_line not in content:
                with shell_rc.open("a", encoding="utf-8") as handle:
                    handle.write("\n" + path_line + "\n")
        print("Added ~/.local/bin to PATH — run: source ~/.bashrc")
        status(f"Installed command to {local_target}")

    print("Command installed: ai-soc-operator")
    print("Run it from anywhere to start the web portal.")


# ── Step 7: Scope configuration ──

def configure_scope() -> None:
    header("Step 5/8 — Target Scope")
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
    header("Step 6/8 — Web Portal Admin Account")
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
            password = getpass.getpass("  Password (min 12 chars): ")
            confirm = getpass.getpass("  Confirm password: ")
            if len(password) < 12:
                warn("Password must be at least 12 characters")
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
        print("Web portal ready — run: python3 -m web.app")
    finally:
        conn.close()


# ── Step 9: Self-test ──

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
    _configure_console_encoding()
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
        "--setup-local-https", action="store_true",
        help="Configure Nginx and a private local CA for HTTPS",
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

    if args.setup_local_https:
        return 0 if setup_local_https(ask_enable=False) else 1

    # ── Validate mode ──
    if args.validate:
        config = load_existing_config()
        if config:
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
    install_system_command()
    configure_scope()
    setup_web_credentials()
    https_enabled = setup_local_https()
    run_self_test()

    header("Bootstrap Complete")
    print(f"{GREEN}AI SOC Operator is ready.{RESET}")
    print(f"\nNext steps:")
    print(f"  1. Review config/platforms.toml and config/scope.toml")
    print(f"  2. Open the web portal → Settings → Platform Connections to add your API keys and base URLs")
    if https_enabled:
        print(f"     Portal URL: https://localhost")
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
