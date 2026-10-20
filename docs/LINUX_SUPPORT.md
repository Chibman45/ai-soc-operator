# Linux support and validation

## Supported production hosts

| Distribution | Supported release | CI image |
|---|---|---|
| Ubuntu | 22.04 LTS | `ubuntu:22.04` |
| Ubuntu | 24.04 LTS | `ubuntu:24.04` |
| Debian | 12 | `debian:12` |
| Kali Linux | current rolling snapshot | Digest in `config/linux-support.toml` |

Other operating systems may be used for development, but they are not approved
production targets. Bootstrap reads `/etc/os-release` and stops on an
unsupported Linux release.

## Bootstrap prerequisites

`python3 bootstrap.py` detects existing commands before installing packages.
On a supported Linux host it installs only missing mandatory runtime packages:
Python and venv support, Tesseract, Poppler, Nginx, OpenSSL, Node.js/npm, CA
certificates, and curl. Python packages include Gunicorn and the bounded OCR
adapters. The Codex CLI is installed into the invoking user's local prefix only
when a compatible `codex` executable is not already available.

The separate command below is supported after the first bootstrap and as an
idempotent repair operation:

```bash
python3 bootstrap.py --setup-local-https
```

It regenerates the local server certificate, validates the complete Nginx
configuration, enables or reloads Nginx, and updates the local HTTPS marker. It
does not require a public domain.

## OCR resource controls

Uploaded documents are limited by request size, extension, declared MIME type,
file signature, page count, decoded pixel count, a single Tesseract OpenMP
thread, and a per-page OCR timeout. PDFs use native text first and render only
pages that do not contain enough native text. DOCX extraction includes body
paragraphs, tables, headers, footers, and embedded images. Every extracted
fragment retains a page, table, paragraph, or image provenance label.

## Validation levels

1. Repository tests validate distro detection, package mapping, repeated
   bootstrap behavior, TLS/Nginx rendering, OCR bounds, and document workflow.
2. GitHub Actions runs the checks in all four container images, including
   `bootstrap.py --check` and two consecutive local-HTTPS setup runs.
3. A real supported VM remains required before production approval. Containers
   cannot prove systemd persistence, host firewall behavior, boot-time service
   recovery, browser trust on another LAN workstation, or integration with the
   deployment's actual Wazuh, TheHive, Cortex, and MISP systems.

Record the exact distro and package versions, test output, Nginx config test,
reboot result, backup/restore result, and remote browser result in the
deployment evidence package.

## Firewall guidance

Allow TCP 443 only from approved analyst networks. Keep Gunicorn bound to
`127.0.0.1:5000`; do not expose it directly. TCP 80 may remain open only for
the generated HTTP-to-HTTPS redirect. Restrict SSH to the administration
network, and permit outbound connections only to approved AI and security
platform endpoints. The project does not mutate host firewall rules because
those rules belong to the organization's approved network policy.
