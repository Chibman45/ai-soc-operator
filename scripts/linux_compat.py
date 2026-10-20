"""Supported Linux detection and prerequisite reporting for bootstrap and CI."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

SUPPORTED_DISTRIBUTIONS = {"ubuntu-22.04", "ubuntu-24.04", "debian-12", "kali-rolling"}
BASE_PACKAGES = (
    "python3", "python3-venv", "python3-pip", "tesseract-ocr", "poppler-utils",
    "nginx", "openssl", "nodejs", "npm", "ca-certificates", "curl",
)
REQUIRED_COMMANDS = {
    "python3": "python3",
    "tesseract": "tesseract-ocr",
    "pdftoppm": "poppler-utils",
    "nginx": "nginx",
    "openssl": "openssl",
    "node": "nodejs",
    "npm": "npm",
}


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def classify_distribution(values: dict[str, str]) -> str:
    distro = values.get("ID", "").strip().lower()
    version = values.get("VERSION_ID", "").strip().lower()
    if distro == "ubuntu" and version in {"22.04", "24.04"}:
        return f"ubuntu-{version}"
    if distro == "debian" and version.split(".", 1)[0] == "12":
        return "debian-12"
    if distro == "kali":
        return "kali-rolling"
    raise RuntimeError(f"Unsupported Linux distribution: {distro or 'unknown'} {version or 'unknown'}")


def detect_distribution(path: Path = Path("/etc/os-release")) -> str:
    if not path.is_file():
        raise RuntimeError("/etc/os-release is required to identify the Linux distribution")
    return classify_distribution(parse_os_release(path.read_text(encoding="utf-8")))


def required_packages(distribution: str) -> tuple[str, ...]:
    if distribution not in SUPPORTED_DISTRIBUTIONS:
        raise RuntimeError(f"Unsupported Linux distribution: {distribution}")
    return BASE_PACKAGES


def compatibility_report(path: Path = Path("/etc/os-release")) -> dict:
    distribution = detect_distribution(path)
    commands = {command: bool(shutil.which(command)) for command in REQUIRED_COMMANDS}
    commands["codex"] = bool(shutil.which("codex"))
    commands["gunicorn"] = bool(shutil.which("gunicorn"))
    return {
        "distribution": distribution,
        "supported": True,
        "packages": list(required_packages(distribution)),
        "commands": commands,
        "ready": all(commands.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the supported Linux runtime")
    parser.add_argument("--id", action="store_true", help="Print only the normalized distribution id")
    args = parser.parse_args()
    try:
        report = compatibility_report()
    except RuntimeError as exc:
        print(str(exc))
        return 1
    print(report["distribution"] if args.id else json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ready"] or args.id else 1


if __name__ == "__main__":
    raise SystemExit(main())
