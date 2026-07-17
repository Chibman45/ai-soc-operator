# AI SOC Operator

A playbook-driven SOC automation platform for Codex. Organizations supply their
SOC playbooks as YAML. The agent executes them step by step — triaging alerts,
enriching IOCs through threat intelligence platforms, mapping to MITRE ATT&CK,
creating cases in TheHive, and generating analyst-ready reports.

Built for competitive hackathon demonstration. Production-grade safety model.

## Quick start

```bash
git clone git@github.com:Chibman45/ai-soc-operator.git
cd ai-soc-operator
python3 bootstrap.py
```

The bootstrap CLI will:
1. Check Python version and required tools
2. Install Python dependencies
3. Detect already-installed tools (nmap, masscan, etc.)
4. Prompt for platform credentials (TheHive, Cortex, Wazuh, threat intel)
5. Generate `config/platforms.toml` from your answers
6. Validate connectivity to configured platforms
7. Install the Codex skill to `~/.agents/skills/`
8. Run a self-test

## Architecture

```
Alert → Playbook Engine → Enrichment → ATT&CK Map → TheHive Case → Report
  │          │                  │            │              │            │
  │     YAML steps         12 platforms   STIX cache    Case CRUD    SOC/IR/
  │     branching          + Cortex       offline       + observables Executive
  │     variable sub.      + Wazuh search               + comments
  │
  └── Bootstrap auto-configures all of the above
```

## Playbook-driven SOC

Organizations define their response procedures as YAML playbooks:

```yaml
id: identity-compromise-v1
name: Identity Compromise Triage
triggers:
  - alert_rule: "Brute Force Detection"
  - mitre_technique: "T1078"
inputs:
  - name: alert
    required: true
  - name: observables
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
```

The agent reads the playbook and executes each step using existing scripts,
calling platform APIs, generating reports, and recording everything in the
audit trail.

## Supported platforms

| Platform | Operations | Safety |
|---|---|---|
| TheHive | Cases, alerts, observables, comments, tasks | Scope-checked, approval-gated |
| Cortex | Analyzers, responders, job results | Remote action requires snapshot |
| Wazuh | Alert search, manager info, decoder rules | Read-only by default |
| Shodan | Host lookup, search | Disclosure approval required |
| VirusTotal | File, URL, domain, IP reputation | Third-party disclosure |
| AbuseIPDB | IP reputation | Third-party disclosure |
| urlscan.io | Search, result retrieval | Optional API key |
| PhishTank | URL phishing check | Community DB |
| Hybrid Analysis | Hash search, report summary | Third-party disclosure |
| MISP | Attribute/event search | Internal threat intel |

## Safety model

- **Tiered risk classification** (0-4): passive → local analysis → active discovery → intrusive → forbidden
- **Scope enforcement**: targets must be in `config/scope.toml`
- **Approval gates**: every platform write requires an explicit approval token
- **Audit trail**: every action logged to `audit/actions.jsonl`
- **Session management**: evidence, artifacts, and reports tied to sessions
- **No destructive commands**: shell, rm -rf, shred, etc. are blocked
- **Credential isolation**: API keys in environment variables, never in code

## Included skills

| Skill | Purpose |
|---|---|
| `soc-orchestrator` | Execute playbooks end to end |
| `soc-analyst` | Alert triage, IOC extraction, timeline building |
| `threat-intel-analyst` | Observable enrichment across platforms |
| `case-manager` | TheHive case lifecycle management |
| `report-writer` | SOC, incident, and executive reports |

## Project structure

```
ai-soc-operator/
├── bootstrap.py              # One-command setup CLI
├── scripts/
│   ├── __init__.py
│   ├── common.py             # Shared utilities, audit, session
│   ├── playbook_engine.py    # YAML playbook loader and runner
│   ├── orchestrator.py       # End-to-end alert → case → report
│   ├── soc_client/
│   │   ├── __init__.py
│   │   ├── thehive.py        # TheHive 5 API client
│   │   ├── cortex.py         # Cortex API client
│   │   ├── wazuh.py          # Wazuh API client
│   │   ├── enrichment.py     # Threat intel platform client
│   │   └── base.py           # Base HTTP client with safety
│   ├── report_generator.py   # SOC/IR/Executive report output
│   ├── evidence_index.py     # SHA-256 evidence indexing
│   ├── mitre_attack.py       # ATT&CK STIX mapping
│   └── render_report.py      # Markdown/HTML/DOCX/PDF conversion
├── playbooks/
│   ├── identity-compromise.yaml
│   ├── phishing-response.yaml
│   └── malware-outbreak.yaml
├── skills/
│   ├── soc-orchestrator/
│   │   └── SKILL.md
│   └── soc-analyst/
│       └── SKILL.md
├── config/
│   ├── platforms.example.toml
│   ├── risk-policy.toml
│   └── scope.example.toml
├── tests/
│   ├── test_playbook_engine.py
│   ├── test_orchestrator.py
│   ├── test_thehive.py
│   ├── test_cortex.py
│   ├── test_wazuh.py
│   ├── test_enrichment.py
│   └── test_bootstrap.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PLAYBOOKS.md
│   ├── BOOTSTRAP.md
│   └── PLATFORMS.md
├── requirements.txt
├── requirements-dev.txt
├── AGENTS.md
└── LICENSE
```

## Validation

```bash
python3 -m pytest tests/ -v
python3 -m compileall scripts/ tests/
```

## License

MIT. This project is a workflow and automation framework, not authorization
to access systems without proper authorization.
