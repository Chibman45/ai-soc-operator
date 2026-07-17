# Platform Integration Guide

## Overview

The AI SOC Operator integrates with security platforms through authenticated API
clients. Each client enforces HTTPS, redirect rejection, response size limits,
and audit logging.

## TheHive (case management)

**Purpose:** Create and manage security cases, attach observables, track investigation progress.

**Setup:**
1. Get your TheHive instance URL and API key
2. Run `python3 bootstrap.py` and enter TheHive credentials
3. Or set manually: `export THEHIVE_API_KEY=your-key`

**Operations:**
| Operation | Method | Description |
|---|---|---|
| `create_case` | POST | Create a new case with title, severity, tags |
| `update_case` | PATCH | Update case fields (severity, status, assignee) |
| `get_case` | GET | Retrieve case details |
| `list_cases` | POST | Search cases with query |
| `add_comment` | POST | Add analyst notes to a case |
| `add_task` | POST | Create an investigation task |
| `add_task_log` | POST | Log progress on a task |
| `add_observable` | POST | Attach an IOC (IP, hash, domain) to a case |
| `list_alerts` | POST | Search alerts |
| `get_alert` | GET | Retrieve alert details |
| `handle_alert` | POST | Import alert to case or merge |
| `create_alert` | POST | Create a new alert |

**Example (from playbook):**
```bash
python3 -m scripts.orchestrator \
  --alert alerts/brute-force.json \
  --playbook playbooks/identity-compromise.yaml
```

## Cortex (analyzer/responder engine)

**Purpose:** Run security analyzers against observables, execute automated responses.

**Setup:**
1. Get your Cortex instance URL and API key
2. Run `python3 bootstrap.py` and enter Cortex credentials
3. Or set manually: `export CORTEX_API_KEY=your-key`

**Operations:**
| Operation | Method | Description |
|---|---|---|
| `list_analyzers` | GET | List available analyzers (optionally by data type) |
| `get_analyzer` | GET | Get analyzer details |
| `run_analyzer` | POST | Execute an analyzer against an observable |
| `get_job` | GET | Check analyzer job status |
| `get_job_report` | GET | Retrieve analyzer job report |
| `list_responders` | GET | List available responders |
| `run_responder` | POST | Execute a responder action |

**Safety:** Running analyzers and responders requires scope, snapshot, and explicit
approval. These are Tier 3 operations.

## Wazuh (SIEM)

**Purpose:** Search alerts, query rules, get manager information.

### Wazuh Manager

| Operation | Method | Description |
|---|---|---|
| `get_manager_info` | GET | Server version and configuration |
| `get_rules` | GET | List detection rules |
| `get_rules_files` | GET | List rule files |
| `get_decoders` | GET | List decoders |
| `search_agent_alerts` | GET | Search alerts for a specific agent |

### Wazuh Indexer (Elasticsearch-compatible)

| Operation | Method | Description |
|---|---|---|
| `search_alerts` | POST | Full-text alert search |
| `search_alerts_by_rule` | POST | Alerts filtered by rule ID |
| `search_alerts_by_agent` | POST | Alerts filtered by agent ID |
| `search_alerts_by_level` | POST | Alerts filtered by minimum severity level |

**Setup:**
```bash
export WAZUH_API_TOKEN=your-manager-token
export WAZUH_INDEXER_USERNAME=your-username
export WAZUH_INDEXER_PASSWORD=your-password
```

## Threat Intelligence Platforms

### VirusTotal

- `lookup_ip(ip)` — IP reputation and analysis
- `lookup_domain(domain)` — Domain analysis
- `lookup_file(hash)` — File hash analysis
- `lookup_url(url)` — URL analysis

### AbuseIPDB

- `check_ip(ip, max_age_days)` — IP abuse confidence score

### Shodan

- `host_lookup(ip)` — Host information and open ports
- `search(query, limit)` — Search Shodan database

### urlscan.io

- `search(query, size)` — Search public scans
- `get_result(result_id)` — Get scan result details

### PhishTank

- `check_url(url)` — Check URL against phishing database

### Hybrid Analysis

- `hash_search(hash)` — Search sandbox reports by hash
- `report_summary(sha256)` — Get report summary

### MISP

- `attribute_search(body)` — Search threat attributes
- `event_search(body)` — Search threat events

## Enrichment

The `EnrichmentClient` aggregates lookups across all configured platforms:

```python
from scripts.soc_client.enrichment import EnrichmentClient

client = EnrichmentClient(config)
result = client.enrich("ip", "203.0.113.42")
# Returns: {"virustotal": {...}, "abuseipdb": {...}, "shodan": {...}}
```

Supported IOC types: `ip`, `domain`, `hash`, `sha256`, `md5`, `url`

## Credential Management

All credentials are stored as environment variables. Never in code or committed config.

| Variable | Platform |
|---|---|
| `THEHIVE_API_KEY` | TheHive |
| `CORTEX_API_KEY` | Cortex |
| `WAZUH_API_TOKEN` | Wazuh Manager |
| `WAZUH_INDEXER_USERNAME` | Wazuh Indexer |
| `WAZUH_INDEXER_PASSWORD` | Wazuh Indexer |
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `SHODAN_API_KEY` | Shodan |
| `URLSCAN_API_KEY` | urlscan.io |
| `PHISHTANK_APP_KEY` | PhishTank |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis |
| `MISP_API_KEY` | MISP |
