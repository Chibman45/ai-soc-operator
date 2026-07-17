# Architecture

## Design principles

1. **Playbook-driven**: Organizations define response procedures as YAML. The agent executes them.
2. **Safety by default**: Every action is scope-checked, approval-gated, and audit-logged.
3. **Modular clients**: Platform integrations are independent — add/remove without touching the core.
4. **Agent as orchestrator**: The Codex agent reads playbooks and executes steps. The code provides structured tools; the agent provides judgment.

## Execution flow

```
Alert arrives (Wazuh, manual, webhook, file)
        │
        ▼
┌─────────────────────┐
│   Orchestrator       │  Loads alert, selects playbook
│   (orchestrator.py)  │  Auto-selects by trigger matching
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│   Playbook Engine    │  Loads YAML, resolves inputs
│   (playbook_engine)  │  Executes steps sequentially
└─────────┬───────────┘
          │
    ┌─────┼─────┬──────────┬───────────┐
    ▼     ▼     ▼          ▼           ▼
  LLM   Tool  TheHive   MITRE      Approval
  Step  chain  Step     Mapping     Gate
    │     │     │          │           │
    │     │     │          │           │
    ▼     ▼     ▼          ▼           ▼
 Agent  API   Create    ATT&CK     Human
 calls  calls case      STIX      decides
        │     │          │
        │     │          │
        ▼     ▼          ▼
      Evidence + Audit Trail
        │
        ▼
   SOC Report (Markdown/HTML/DOCX/PDF)
```

## Component map

| Component | File | Purpose |
|---|---|---|
| Common utilities | `scripts/common.py` | Session, audit, SHA-256, safe names |
| Playbook engine | `scripts/playbook_engine.py` | YAML loader, variable resolution, step runner, branching |
| Orchestrator | `scripts/orchestrator.py` | Alert ingestion, playbook selection, pipeline execution |
| TheHive client | `scripts/soc_client/thehive.py` | Case, alert, observable, comment, task CRUD |
| Cortex client | `scripts/soc_client/cortex.py` | Analyzer/responder listing and execution |
| Wazuh clients | `scripts/soc_client/wazuh.py` | Manager API + Indexer search |
| Enrichment | `scripts/soc_client/enrichment.py` | Multi-platform threat intel aggregation |
| Base client | `scripts/soc_client/base.py` | HTTPS safety: redirect rejection, size limits, audit |
| Bootstrap | `bootstrap.py` | One-command setup CLI |

## Safety model

### Risk tiers

| Tier | Description | Examples |
|---|---|---|
| 0 | Passive, local read-only | `cat`, `head`, `whois`, report rendering |
| 1 | Local analysis | `semgrep`, `bandit`, `yara`, `vol` |
| 2 | Active discovery / remote read | `nmap`, `nikto`, Shodan lookup, VirusTotal query |
| 3 | Intrusive / remote write | `hydra`, `sqlmap`, TheHive case creation, Cortex analyzer run |
| 4 | Forbidden | `shred`, `mkfs`, `rm -rf /` |

### Gates

Every action passes through:
1. **Risk classification** — tier assigned from tool policy
2. **Scope check** — target must be in `config/scope.toml`
3. **Engagement rules** — tier 3 requires explicit rule enablement
4. **Approval token** — exact token match required
5. **Audit log** — every action recorded to `audit/actions.jsonl`
6. **Session tracking** — evidence tied to session IDs

### Credential isolation

- API keys in environment variables, never in code or config files committed to git
- `config/platforms.toml` is gitignored
- Bootstrap prompts for credentials interactively
- Secrets never appear in logs, prompts, or chat
