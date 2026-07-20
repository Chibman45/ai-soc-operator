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

## Built with Codex

This project was built entirely using OpenAI Codex as the primary development partner. Here's how Codex accelerated the workflow and where key decisions were made.

### Architecture decisions with Codex

**Playbook engine design.** Codex proposed the YAML-based step runner with `llm | toolchain | rule | thehive | mitre_mapping | approval` step types. I provided the safety requirements (tiered risk, scope enforcement, approval gates) and Codex translated them into the `operator_core.py` classification system and `risk-policy.toml` configuration.

**TheHive write integration.** The original codebase had read-only TheHive queries. Codex designed the full write API client (`thehive.py`) — case CRUD, observable attachment, comment threading, alert handling — following the same safety model as the read operations. Every write is scope-checked, approval-gated, and audit-logged.

**Variable resolution and branching.** Codex built the `{dotted.path}` variable resolution system and conditional branching (`skip_to`, `in [...]`, numeric comparisons). The key insight was storing step results under a `steps` namespace to avoid overwriting explicit context — a bug Codex caught during testing.

### What Codex built

| Component | Codex contribution |
|---|---|
| `playbook_engine.py` | YAML loader, variable resolver, step runner, branching logic |
| `orchestrator.py` | End-to-end pipeline, playbook auto-selection, report generation |
| `soc_client/thehive.py` | Full TheHive 5 write API (cases, alerts, observables, comments) |
| `soc_client/cortex.py` | Cortex analyzer/responder client |
| `soc_client/wazuh.py` | Wazuh Manager + Indexer clients |
| `soc_client/enrichment.py` | Multi-platform threat intel aggregation |
| `soc_client/openai.py` | GPT-5.6 direct API client for LLM steps |
| `bootstrap.py` | 8-step interactive setup CLI |
| `scripts/load_secrets.sh` | Credential loading from external file |
| 3 playbooks | Identity compromise, phishing, malware outbreak |
| 113 tests | Engine, orchestrator, all clients, integration |

### Where I made key decisions

- **YAML over code:** Chose YAML playbooks so SOC teams can define procedures without writing Python. Codex implemented the engine; I decided the abstraction level.
- **Safety by default:** Required approval gates for every write operation, not just "dangerous" ones. This made the demo more convincing to security-focused judges.
- **Agent-as-orchestrator:** The Codex agent executes playbook steps — it reads the YAML, calls the right scripts, makes judgment calls. The code provides tools; the agent provides reasoning.
- **GPT-5.6 for LLM steps:** Direct API calls for classification and analysis ensure judges can see the model in action, not just Codex's internal model.

### Codex session

The majority of core functionality was built in Codex session: `[PASTE YOUR CODEX SESSION ID HERE]`

## License

MIT. This project is a workflow and automation framework, not authorization
to access systems without proper authorization.
