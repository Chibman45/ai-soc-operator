# AI SOC Operator

A playbook-driven SOC automation platform. Organizations supply their SOC playbooks as YAML. The platform executes them step by step — triaging alerts, enriching IOCs through threat intelligence platforms, mapping to MITRE ATT&CK, creating cases in TheHive, and generating analyst-ready reports.

All platform credentials and connections are managed through a built-in web portal. No secrets ever touch config files.

## Release Status

Application hardening Phases 0-10 now have a single-node implementation baseline. This
includes organization-scoped RBAC, authenticated SIEM ingestion, the live alert
queue, SLA metrics, encrypted credentials, durable local jobs, approval-gated
responder approvals, and controlled self-learning drafts and publication.

Phase 8 notification/intel delivery, Phase 9 container/operations controls, and
Phase 10 CI release assurance are implemented, but production approval still
depends on environment evidence. SQLite remains the default; PostgreSQL and
Redis/Celery are available through a verified, restart-gated scale-out path.
See [the production roadmap](docs/PRODUCTION_ROADMAP.md), [operations runbook](docs/OPERATIONS_RUNBOOK.md), and
[security policy](SECURITY.md) before deploying beyond a controlled environment.

## Quick Start

```bash
git clone https://github.com/Chibman45/ai-soc-operator.git
cd ai-soc-operator
python3 bootstrap.py
```

That's it. Bootstrap handles everything. When it finishes, start the platform with a single command:

```bash
ai-soc-operator
```

The terminal will print:

```
==================================================
  AI SOC Operator
  Local:   http://localhost:5000
  Network: http://192.168.x.x:5000
==================================================
```

Open the URL, log in with the credentials you created during bootstrap, and configure your platform connections from the Settings page.

## What Bootstrap Does

Bootstrap runs 9 steps automatically:

1. **System check** — Python 3.10+ and required system tools
2. **Virtual environment** — creates `.venv`, installs all Python dependencies into it
3. **Tool detection and install** — detects security tools (nmap, masscan, nikto, tshark, pandoc, etc.); offers to install missing ones via `apt-get` on Linux (prints `brew install` instructions on macOS)
4. **Codex CLI** — installs the official `@openai/codex` package into the current user's `~/.local` prefix and verifies the OAuth runtime capabilities
5. **Codex skills** — installs SOC orchestrator and analyst skills to `~/.agents/skills/`
6. **Target scope** — sets up `config/scope.toml` with your authorized hosts/CIDRs/domains
7. **Web portal admin account** — creates your login for the web portal (hashed password stored in local SQLite DB)
8. **Local HTTPS** — on Linux, offers to install Nginx, creates a private local CA, and configures trusted HTTPS without requiring a public domain
9. **Self-test** — loads all playbooks and runs the full test suite

The virtual environment, Python packages, Codex CLI, bundled skills, launcher,
and self-test are mandatory completion gates. Bootstrap exits nonzero and does
not print “Bootstrap Complete” if any of them fails. Security utilities and
local HTTPS remain optional because they depend on the deployment's approved
tooling and network design.

### Sudo handling

Before running any command that requires elevated privileges, bootstrap checks for passwordless sudo (`sudo -n true`). If available, it runs automatically. If not, it prints the exact command for you to copy-paste and run manually, then continues without blocking.

### Local HTTPS

On Linux, the full bootstrap offers local HTTPS by default. After approval it
installs Nginx and OpenSSL when needed, generates a private CA and a 397-day
server certificate for `localhost`, the machine hostname, and its current LAN
IP, then asks separately before changing the operating-system trust store.

Nginx owns ports 80 and 443 and proxies to Gunicorn on
`127.0.0.1:5000`. The application enables `ProxyFix` only in this generated
reverse-proxy mode. No public domain or Internet certificate service is needed.
Other analyst workstations must import `data/tls/local-ca.crt` before their
browsers will trust the local portal.
Never distribute `data/tls/local-ca.key`; bootstrap restricts it to the local
OS account because possession of that key permits signing trusted certificates.

To configure or repair only this layer, run:

```bash
python3 bootstrap.py --setup-local-https
```

### After bootstrap

The `ai-soc-operator` command is installed to:
- `/usr/local/bin/ai-soc-operator` (if passwordless sudo is available), or
- `~/.local/bin/ai-soc-operator` (no sudo needed)

If installed to `~/.local/bin`, bootstrap adds it to your PATH in `~/.bashrc` and `~/.zshrc` automatically.

> **If you move the repo after bootstrap**, set `AI_SOC_HOME=/new/path` in your `.bashrc` so the command can find it.

## Setting Up Platform Connections

Platform credentials are **never stored in config files**. They are encrypted in the active database and managed through the web portal.

1. Start the platform: `ai-soc-operator`
2. Open the URL in your browser and log in
3. Go to **Settings → Platform Connections**
4. Enter base URLs and API keys for the platforms you want to use
5. Click **Test Connections** to validate each one

### Choosing the organization AI agent

An administrator selects one shared AI mode from **Credentials -> AI Agent**:

- **OpenAI API key** sends model requests directly to the OpenAI API using the
  encrypted organization `OPENAI_API_KEY`.
- **ChatGPT OAuth** starts the official Codex CLI device-login flow. The admin
  opens the displayed OpenAI verification page, enters the one-time code, and
  then selects a supported Codex model.

Full bootstrap installs and verifies the `codex` executable on the application
host. An operator may instead provide an explicit `AI_SOC_CODEX_BIN` path to a
compatible installation. Its login state is stored under the local
`data/codex-oauth/org-<id>/` directory and is never returned to analysts or
written into generated configuration. OAuth inference runs in an empty
temporary workspace with a read-only sandbox and a scrubbed environment. The
admin can disconnect it from the same page.

The selection is organization-wide. Copilot chat, document parsing,
organization-policy extraction, and playbook LLM steps all load the same mode
and model. A ChatGPT subscription is not treated as an OpenAI API key; the two
options remain separate authentication and billing paths.

Supported platforms:

| Platform | What it does |
|---|---|
| TheHive | Case management — create cases, attach observables, add comments |
| Cortex | Run analyzers and responders against IOCs |
| Wazuh | Alert search, agent management, decoder/rule queries |
| VirusTotal | File, URL, domain, IP reputation |
| AbuseIPDB | IP reputation and abuse confidence scoring |
| Shodan | Host lookups and internet-wide search |
| urlscan.io | URL scanning and result retrieval |
| Hybrid Analysis | Hash search and sandbox reports |
| MISP | Internal threat intelligence attribute/event search |
| OpenAI | GPT model for LLM steps in playbooks (classification, summarization) |

## Single-user and local multi-user operation

The first account created by bootstrap is the administrator for the default
organization. A single operator can keep using that account with no additional
configuration. For a team on the same local network:

1. Sign in as the bootstrap administrator.
2. Open **Administration -> Users** and create an invitation.
3. Select any manual roles that should exist independently of organization policy.
4. Share the one-time HTTPS activation link securely with the intended user.
5. The user opens the link, sets a password of at least 12 characters, and signs in.

The activation link expires after 24 hours and is stored only as a SHA-256 digest.
An administrator can suspend a membership or reset its activation link. The
organization must always retain at least one active administrator.

Platform credentials belong to the organization, not to individual analysts.
Authorized workflows load those encrypted credentials on the server. The API
keys are never copied into an invited user's account, browser, prompt, or report.

### Optional PostgreSQL and Redis/Celery cutover

An administrator can open **Administration -> Infrastructure** to test and save
PostgreSQL and Redis URLs. SQLite remains active while settings are tested. A
migration is allowed only after connectivity validation and requires typing
`MIGRATE`. The system then creates and verifies a SQLite backup, refuses a
non-empty PostgreSQL target, copies all tables in foreign-key order, compares
table row counts, encrypts the runtime settings, and requests a service restart.
Failed migrations do not delete or deactivate SQLite.

For the bundled optional services, start the scale-out profile before testing:

```bash
docker compose --profile scaleout up -d postgres redis
```

After the portal reports `restart_required`, restart the web and worker services
and start the Celery worker:

```bash
docker compose --profile scaleout up -d --build
```

### Organization playbook access policy

Open **Administration -> Organization Policy** to submit YAML, JSON, PDF, DOCX,
Markdown, or text. Structured YAML/JSON is parsed directly. Other document types
use the organization's configured OpenAI credential to extract a policy draft.
AI output is untrusted and cannot grant access: an administrator must review the
normalized JSON and approve its exact digest before it becomes active.

An explicit structured policy can use this form:

```yaml
access_policy:
  organization_name: Example SOC
  role_policies:
    analyst:
      playbooks: [identity-compromise.yaml]
      scope:
        hosts: [workstation-01]
        cidrs: [10.20.0.0/16]
        domains: ['*.example.internal']
        users: [alice@example.internal]
        indicators: []
  users:
    - username: alice
      roles: [analyst]
      playbooks: []
      scope:
        hosts: []
        cidrs: []
        domains: []
        users: []
        indicators: []
```

Role-based and user-specific playbook and target scope are combined. The active
policy limits playbook listings, manual runs, automated alert selection, network
tools, and responder proposals. Existing global scope controls remain in force,
so the effective boundary is the intersection of installation scope, case
observables, RBAC permissions, and the approved organization policy.

The web application builds a tenant-scoped runtime configuration in memory
before every playbook run. The bootstrap CLI remains the only supported way to
initialize `config/platforms.toml`; do not edit it manually.

## Running the Platform

### Web Portal

```bash
ai-soc-operator
```

The web portal provides:
- **Dashboard** — live alert queue, SLA metrics, active cases, recent runs, platform status
- **Cases** — case list with status, severity, and timeline
- **Playbooks** — upload, review, and approve playbook documents (PDF/DOCX/MD → YAML)
- **Reports** — SOC, incident, and executive reports per case
- **Settings** — platform connections, API keys, connection testing
- **SOC Copilot** — case-scoped AI assistant with approval-gated tool execution

### CLI (direct orchestrator)

```bash
# With virtual environment active
source .venv/bin/activate

# Auto-select playbook based on alert
python3 -m scripts.orchestrator --alert alert.json

# Specify a playbook
python3 -m scripts.orchestrator --alert alert.json --playbook playbooks/identity-compromise.yaml

# Dry run (no platform API calls)
python3 -m scripts.orchestrator --alert alert.json --dry-run
```

## Playbook Format

Playbooks are YAML files in `playbooks/`. You can also upload existing SOC documents (PDF, DOCX, Markdown) through the web portal — they are converted to YAML automatically via GPT.

```yaml
id: identity-compromise-v1
name: Identity Compromise Triage
triggers:
  - alert_rule: "Brute Force Detection"
  - mitre_technique: "T1078"
inputs:
  - name: alert
    required: true
steps:
  - id: classify
    type: llm
    prompt: "Classify this alert and extract IOCs..."
  - id: enrich
    type: toolchain
    run:
      - tool: virustotal
        operation: ip
        target: "{ioc.value}"
  - id: write_case
    type: thehive
    action: create_or_update_case
  - id: generate_report
    type: report
    report_type: soc
```

Step types: `llm` · `toolchain` · `rule` · `thehive` · `mitre_mapping` · `approval` · `report`

Three playbooks are included: identity compromise, phishing response, and malware outbreak.

## Safety Model

- **Tiered risk classification** (0–4): passive → local analysis → active discovery → intrusive → forbidden
- **Scope enforcement**: targets must be in `config/scope.toml`
- **Approval gates**: every platform write requires an explicit approval token
- **Audit trail**: every action logged to `audit/actions.jsonl`
- **Session management**: evidence, artifacts, and reports tied to session IDs
- **No destructive commands**: `rm -rf`, `shred`, `mkfs`, etc. are blocked
- **Credential isolation**: API keys and infrastructure URLs are encrypted at rest and are never written to generated config files or logs
- **Controlled learning**: learning evidence is redacted; skill publication, responder enablement, and allowlisted installs require an immutable proposal, an explanation, independent human approval, expiry, audit evidence, and explicit environment gates

## Project Structure

```
ai-soc-operator/
├── bootstrap.py              # One-command setup
├── bin/
│   └── ai-soc-operator       # Terminal launcher (venv-aware)
├── scripts/
│   ├── common.py             # Session management, audit logging
│   ├── playbook_engine.py    # YAML loader, variable resolution, step runner
│   ├── orchestrator.py       # Alert → playbook → case → report pipeline
│   ├── playbook_parser.py    # PDF/DOCX/MD → YAML playbook converter
│   ├── report_generator.py   # SOC/IR/Executive report builder
│   ├── evidence_index.py     # SHA-256 evidence indexing
│   ├── mitre_attack.py       # ATT&CK STIX mapping (offline cache)
│   ├── render_report.py      # Markdown/HTML/DOCX/PDF rendering
│   └── soc_client/
│       ├── thehive.py        # TheHive 5 API client
│       ├── cortex.py         # Cortex API client
│       ├── wazuh.py          # Wazuh Manager + Indexer clients
│       ├── enrichment.py     # Multi-platform threat intel aggregation
│       ├── scoring.py        # Deterministic incident scoring engine
│       └── openai.py         # GPT API client for LLM steps
├── web/
│   ├── app.py                # Flask web application
│   ├── routes/
│   │   └── chat.py           # SOC Copilot chat routes
│   ├── services/
│   │   └── chat.py           # Chat service, tool executor, approval gates
│   └── templates/            # Jinja2 HTML templates
├── playbooks/
│   ├── identity-compromise.yaml
│   ├── phishing-response.yaml
│   └── malware-outbreak.yaml
├── config/
│   ├── platforms.toml        # Generated at runtime from DB — do not edit manually
│   ├── risk-policy.toml      # Risk tier definitions
│   └── scope.toml            # Authorized target hosts/CIDRs/domains
├── skills/
│   ├── soc-orchestrator/SKILL.md
│   └── soc-analyst/SKILL.md
├── tests/                    # 218 tests covering all components
├── demo/
│   └── brute-force-alert.json  # Sample alert for testing
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PLAYBOOKS.md
│   └── PLATFORMS.md
├── requirements.txt
├── AGENTS.md
└── LICENSE
```

## Validation

```bash
source .venv/bin/activate
python3 -m pytest tests/ -v
python3 -m compileall scripts/ tests/ web/
```

## Requirements

- Python 3.10+
- Linux (Kali, Ubuntu, Debian) or macOS
- Internet access for threat intel platforms (optional — platform steps degrade gracefully if not configured)

No platform credentials are required to install or run the web portal. Connect platforms incrementally as you need them.

## License

MIT. This project is a workflow and automation framework, not authorization to access systems without proper authorization.
