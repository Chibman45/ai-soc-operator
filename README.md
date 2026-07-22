# AI SOC Operator

A playbook-driven SOC automation platform. Organizations supply their SOC playbooks as YAML. The platform executes them step by step — triaging alerts, enriching IOCs through threat intelligence platforms, mapping to MITRE ATT&CK, creating cases in TheHive, and generating analyst-ready reports.

All platform credentials and connections are managed through a built-in web portal. No secrets ever touch config files.

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

Bootstrap runs 7 steps automatically:

1. **System check** — Python 3.10+ and required system tools
2. **Virtual environment** — creates `.venv`, installs all Python dependencies into it
3. **Tool detection and install** — detects security tools (nmap, masscan, nikto, tshark, pandoc, etc.); offers to install missing ones via `apt-get` on Linux (prints `brew install` instructions on macOS)
4. **Codex skills** — installs SOC orchestrator and analyst skills to `~/.agents/skills/`
5. **Target scope** — sets up `config/scope.toml` with your authorized hosts/CIDRs/domains
6. **Web portal admin account** — creates your login for the web portal (hashed password stored in local SQLite DB)
7. **Self-test** — loads all playbooks and runs the full test suite

### Sudo handling

Before running any command that requires elevated privileges, bootstrap checks for passwordless sudo (`sudo -n true`). If available, it runs automatically. If not, it prints the exact command for you to copy-paste and run manually, then continues without blocking.

### After bootstrap

The `ai-soc-operator` command is installed to:
- `/usr/local/bin/ai-soc-operator` (if passwordless sudo is available), or
- `~/.local/bin/ai-soc-operator` (no sudo needed)

If installed to `~/.local/bin`, bootstrap adds it to your PATH in `~/.bashrc` and `~/.zshrc` automatically.

> **If you move the repo after bootstrap**, set `AI_SOC_HOME=/new/path` in your `.bashrc` so the command can find it.

## Setting Up Platform Connections

Platform credentials are **never stored in config files**. They live in the local SQLite database and are managed through the web portal.

1. Start the platform: `ai-soc-operator`
2. Open the URL in your browser and log in
3. Go to **Settings → Platform Connections**
4. Enter base URLs and API keys for the platforms you want to use
5. Click **Test Connections** to validate each one

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

Platform config is regenerated from the database automatically before every playbook run. The orchestrator always reads a fresh `config/platforms.toml`.

## Running the Platform

### Web Portal

```bash
ai-soc-operator
```

The web portal provides:
- **Dashboard** — active cases, recent runs, platform status
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
- **Credential isolation**: API keys stored in SQLite only, never in config files or logs

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
├── tests/                    # 205 tests covering all components
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
