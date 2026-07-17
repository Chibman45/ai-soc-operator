# Playbook Authoring Guide

## Overview

Playbooks are YAML files that define how the AI SOC analyst responds to specific
alert types. Organizations write their SOC SOPs as playbooks, and the agent
executes them step by step.

## Schema

```yaml
id: unique-playbook-id          # Required: machine-readable identifier
name: Human-readable name       # Required: display name
version: 1                      # Required: integer version
description: |                  # Optional: what this playbook does
  Multi-line description.

triggers:                       # How this playbook matches alerts
  - alert_rule: "Rule Name"     # Match by Wazuh/alert rule name
  - mitre_technique: "T1078"    # Match by MITRE ATT&CK technique
  - tags: ["tag1", "tag2"]      # Match by alert tags

inputs:                         # Variables the playbook expects
  - name: alert                 # Required input
    required: true
  - name: observables           # Optional input with default
    required: false
    default: []

steps:                          # Execution steps (run in order)
  - id: step_name               # Unique step identifier
    type: llm                   # Step type
    prompt: "..."               # Type-specific configuration
```

## Step types

### `llm` — Agent analysis

The agent analyzes input and produces structured output.

```yaml
- id: classify
  type: llm
  prompt: >
    Analyze this alert. Classify the incident type.
    Extract IOCs. Assign confidence: low/medium/high.
    Return JSON with: incident_type, confidence, iocs[], false_positive_probability.
```

The agent receives the prompt with resolved variables and produces analysis.
The result is stored under `steps.classify` for later steps to reference.

### `toolchain` — Platform API calls

Calls to threat intel platforms, enrichment services, or local tools.

```yaml
- id: enrich
  type: toolchain
  run:
    - tool: virustotal
      operation: ip
      target: "{ioc.value}"
      condition: "{ioc.type} == 'ip'"    # Optional: skip if false
    - tool: abuseipdb
      operation: check
      target: "{ioc.value}"
      condition: "{ioc.type} == 'ip'"
```

### `rule` — Conditional branching

Evaluates a condition and optionally skips to a target step.

```yaml
- id: check_false_positive
  type: rule
  when:
    condition: "classify.false_positive_probability > 0.7"
  action: skip_to
  target: generate_report
```

### `thehive` — Case management

Creates or updates TheHive cases, adds comments, attaches observables.

```yaml
- id: write_case
  type: thehive
  action: create_or_update_case
  inputs:
    title: "{classify.incident_type} - {alert.rule.name}"
    severity: "{decide.severity}"
    tags: "{map_mitre.techniques}"
    description: "{decide.summary}"
```

### `mitre_mapping` — ATT&CK technique mapping

Maps observed behavior to MITRE ATT&CK techniques using the local STIX cache.

```yaml
- id: map_mitre
  type: mitre_mapping
```

### `approval` — Human approval gate

Requires human approval before proceeding with risky actions.

```yaml
- id: escalate
  type: approval
  when:
    condition: "decide.severity in ['high', 'critical']"
  actions:
    - isolate_host
    - disable_account
```

### `report` — Report generation

Generates SOC, incident, or executive reports.

```yaml
- id: generate_report
  type: report
  report_type: soc
```

## Variable resolution

Variables are resolved using `{dotted.path}` syntax:

- `{alert.rule.name}` — from the alert data
- `{classify.confidence}` — from a previous step's result
- `{ioc.value}` — from loop iteration
- `{session.id}` — from the current session

### Conditional expressions

Conditions support:

| Operator | Example |
|---|---|
| `==` | `classify.confidence == 'high'` |
| `!=` | `classify.false_positive != true` |
| `>` | `classify.fp_prob > 0.7` |
| `<` | `enrich.threat_score < 3` |
| `>=` | `decide.severity >= 4` |
| `in [...]` | `decide.severity in ['high', 'critical']` |

## Example: Identity Compromise Playbook

See `playbooks/identity-compromise.yaml` for a complete working example.

The playbook:
1. Classifies the alert and extracts IOCs
2. Checks if it's likely a false positive (skips if so)
3. Enriches IOCs through VirusTotal, AbuseIPDB, and Shodan
4. Maps to MITRE ATT&CK techniques
5. Produces an analyst summary
6. Creates a TheHive case
7. Attaches enriched observables to the case
8. Generates a SOC report
9. Requests approval for containment if severity is high/critical
