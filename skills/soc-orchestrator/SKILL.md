---
name: soc-orchestrator
description: >
  Execute SOC playbooks end to end. Ingest alerts, triage against
  organizational playbooks, enrich IOCs through threat intelligence
  platforms, map to MITRE ATT&CK, create TheHive cases, and generate
  analyst-ready reports. Use when an alert arrives or when the user
  asks to investigate, triage, or respond to a security event.
---

# SOC Orchestrator

Execute the organization's playbooks. Every action is audited.

## Quick start

```bash
python3 bootstrap.py                              # one-command setup
python3 -m scripts.orchestrator --alert alert.json  # run playbook
```

## Workflow

1. **Ingest**: Load the alert data (JSON file, Wazuh export, manual input).
2. **Select playbook**: Auto-match by alert rule name, MITRE technique, or tags.
   Or specify with `--playbook playbooks/identity-compromise.yaml`.
3. **Classify**: Extract IOCs, determine incident type, assess confidence.
4. **Enrich**: Query threat intel platforms for each IOC.
5. **Map**: Correlate with MITRE ATT&CK techniques.
6. **Decide**: Produce severity rating, containment recommendations, business impact.
7. **Case**: Create TheHive case with observables and analyst summary.
8. **Report**: Generate SOC/IR/Executive report with evidence links.
9. **Escalate**: Request human approval for containment actions if severity is high.

## Platform integration

Use `$soc-client` for TheHive, Cortex, Wazuh, and enrichment operations.
All platform calls go through `scripts/soc_client/` with safety controls:

- HTTPS only, no redirect following
- Credentials in environment variables
- Audit trail for every request
- Scope-checked targets
- Approval-gated writes

## Playbook format

Playbooks are YAML files in `playbooks/`. Each defines:
- `triggers`: what alerts activate this playbook
- `inputs`: required alert fields
- `steps`: sequential execution plan
- `branching`: conditional skip/escalate logic

Step types: `llm`, `toolchain`, `rule`, `thehive`, `mitre_mapping`, `approval`, `report`.

## Safety

- Never bypass scope, approval, or session controls.
- Never exfiltrate credentials or evidence.
- Always start a session before security operations.
- Record timestamps in UTC. Separate facts from hypotheses.
