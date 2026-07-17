# Demo: Identity Compromise Response

## Scenario

A Wazuh alert fires: 15 failed SSH login attempts from a Russian IP address
followed by a successful login to `web-server-01`. The previous successful
login was from the office 18 hours ago. This is a classic credential stuffing
or brute force attack.

## What the demo shows

```
Alert fires (brute-force-alert.json)
        │
        ▼
    Auto-select playbook
    (matches "Brute Force Detection" trigger)
        │
        ▼
    Step 1: CLASSIFY
    Agent analyzes alert, extracts IOCs:
    - IP: 203.0.113.42
    - User: admin
    - Confidence: HIGH
    - False positive probability: 0.15
        │
        ▼
    Step 2: CHECK_FALSE_POSITIVE
    0.15 < 0.7 → continue (not a false positive)
        │
        ▼
    Step 3: ENRICH
    - VirusTotal: 203.0.113.42 → malicious (score: 85/100)
    - AbuseIPDB: 203.0.113.42 → abuse confidence 92%
    - Shodan: 203.0.113.42 → SSH open, Tor exit node
        │
        ▼
    Step 4: MAP_MITRE
    - T1110 Brute Force (credential-access)
    - T1078 Valid Accounts (initial-access)
        │
        ▼
    Step 5: DECIDE
    Severity: HIGH
    Narrative: External IP performed credential stuffing against
    admin account, succeeded after 15 attempts. Previous login
    was from office IP. Likely compromised credentials.
    Containment: Reset admin password, block source IP, review
    access logs for lateral movement.
        │
        ▼
    Step 6: WRITE_CASE
    TheHive case created:
    - Title: "Brute Force Detection - admin@corp.com"
    - Severity: 4 (HIGH)
    - Tags: T1110, T1078, brute-force, credential-compromise
        │
        ▼
    Step 7: ATTACH_IOCS
    Observable added to case:
    - IP: 203.0.113.42 (VT: malicious, AbuseIPDB: 92%)
        │
        ▼
    Step 8: CASE_COMMENT
    Analyst summary attached to case
        │
        ▼
    Step 9: GENERATE_REPORT
    SOC report generated with full timeline and findings
        │
        ▼
    Step 10: ESCALATE
    Severity HIGH → approval gate triggered
    Actions requested: isolate_host, disable_account
    Waiting for senior analyst approval
```

## Running the demo

```bash
# With TheHive configured:
python3 -m scripts.orchestrator \
  --alert demo/brute-force-alert.json \
  --playbook playbooks/identity-compromise.yaml

# Dry run (no API calls):
python3 -m scripts.orchestrator \
  --alert demo/brute-force-alert.json \
  --playbook playbooks/identity-compromise.yaml \
  --dry-run

# Auto-select playbook:
python3 -m scripts.orchestrator \
  --alert demo/brute-force-alert.json
```

## Key talking points for judges

1. **Not a chatbot** — this is a structured execution engine that follows the
   organization's playbook step by step, with branching logic and approval gates.

2. **Production safety** — every action is scope-checked, approval-gated, and
   audit-logged. The agent cannot go rogue.

3. **Real integrations** — TheHive for case management, Cortex for analysis,
   7 threat intel platforms for enrichment, MITRE ATT&CK for mapping.

4. **Customizable** — the SOC team writes their own YAML playbooks. The agent
   executes them. No code changes needed for new response procedures.

5. **Full traceability** — from alert to case to report, every step is recorded
   with timestamps, hashes, and audit entries.
