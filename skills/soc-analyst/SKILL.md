---
name: soc-analyst
description: >
  Investigate security alerts, authentication events, endpoint telemetry,
  network logs, and SIEM exports. Use for alert triage, IOC extraction,
  event correlation, timeline building, severity assessment, detection gaps,
  and evidence-backed SOC reports without offensive execution.
---

# SOC Analyst

Preserve source logs and analyze copies when possible.

## Workflow

1. Record alert source, time range, affected assets, and detection rule.
2. Hash or otherwise identify supplied evidence.
3. Normalize timestamps to UTC while retaining original timezone information.
4. Extract users, hosts, IPs, processes, hashes, domains, and event identifiers.
5. Correlate activity into a timeline and identify benign explanations.
6. Map observed behavior to candidate MITRE ATT&CK tactics and techniques.
7. Mark each conclusion as confirmed, likely, possible, or unknown.
8. Recommend containment only when evidence justifies it; identify business impact.
9. Save machine-readable extracts under `outputs/` and findings under `reports/`.

Start a session before analysis. Use `$soc-orchestrator` for playbook-driven
execution or investigate manually following these steps.

## Minimum questions

- What generated the alert and what behavior was detected?
- Is the timestamp trustworthy and normalized?
- Which identity, device, workload, and network path are involved?
- Is activity expected for the user, service, geography, and time?
- What evidence supports compromise versus misconfiguration or false positive?

## Common pivots

- **Authentication**: failures followed by success, impossible travel, new device, privilege changes, MFA events, service-account anomalies.
- **Endpoint**: parent-child process chain, command line, file hash, persistence location, network connection, user context.
- **Network**: source/destination, DNS history, TLS details, bytes transferred, periodicity, protocol mismatch.

## Finding fields

Title, severity, confidence, affected assets, UTC timeline, evidence, analysis, business impact, containment, remediation, and detection improvements.
