# About AI SOC Operator

## Project purpose

AI SOC Operator is a local-first, playbook-driven security operations platform.
It receives alerts, normalizes them, chooses an approved response playbook,
coordinates investigation steps, enriches indicators, manages cases, records
evidence, and produces analyst-ready reports. Its purpose is to make repeatable
SOC work faster while keeping scope, permissions, approvals, and ground-truth
decisions under human control.

The project can operate for one analyst on one host or for multiple users on the
same protected local network. Platform credentials belong to the organization
and remain server-side. Users receive access through organization membership,
assigned roles, and an administrator-approved organization policy.

## What it can be used for

- Continuous Wazuh, Elastic, or generic webhook alert ingestion.
- A live alert queue with normalization, playbook selection, job state, and
  case linkage.
- Playbook-guided investigation and reporting for identity compromise,
  phishing, malware, and organization-authored workflows.
- Organization-scoped case assignment, analyst roles, SLA measurement, and
  MTTA/MTTR reporting.
- IOC extraction and cross-case correlation to identify repeated indicators and
  possible campaign activity.
- Read-only enrichment through VirusTotal, AbuseIPDB, Shodan, urlscan.io,
  Hybrid Analysis, PhishTank, Cortex, and MISP.
- TheHive case synchronization and approval-gated case writes.
- Dry-run response proposals for blocking an IP, isolating a host, disabling or
  resetting a user, updating TheHive, and running Cortex integrations.
- Controlled self-learning that records outcomes and proposes reviewable skill,
  responder, plugin, or package-installation changes.
- Detection assurance using analyst-confirmed true-positive, false-positive,
  true-negative, false-negative, and needs-review outcomes.
- Read-only Wazuh, TheHive, Cortex, and MISP configuration validation against an
  approved organization architecture profile.
- Markdown, PDF/HTML fallback, STIX 2.1, and gated MISP intelligence workflows.

## Operating model

The first account created by `bootstrap.py` is the administrator of the default
organization. That account can run the system alone or invite additional users,
assign roles, suspend memberships, reset activation links, and approve the
organization's access policy. The default roles are administrator, manager,
senior analyst, analyst, and read-only.

Incoming alerts and synchronized external records use organization-scoped IDs,
idempotency keys, and external-object mappings. This prevents two workers or two
analysts from creating duplicate local records for the same source object. Case
mutation paths use ownership and concurrency controls, while durable jobs keep
alert processing separate from browser requests.

SQLite is the default database and is suitable for initial local operation.
Administrators can test PostgreSQL and Redis connections in the portal, perform
a guarded database migration, restart the services, and run Celery workers for
scale-out processing. Failed migrations retain SQLite and its verified backup.

## AI and knowledge model

An administrator selects one organization-wide AI connection:

- an encrypted `OPENAI_API_KEY`; or
- ChatGPT sign-in through the official Codex CLI installed on the application
  host, with an approved model selection.

The selected provider supports copilot analysis, document extraction, policy
and architecture drafts, playbook LLM steps, and advisory alert assessments.
Uploaded YAML, JSON, PDF, DOCX, Markdown, text, and chart images pass through a
shared validator and provenance-preserving extraction preview before any AI
analysis. Scanned pages and embedded diagrams use bounded local OCR. AI output
remains a draft until an authorized user explicitly approves it.
Model output is never treated as ground truth or authorization.

The checked-in platform knowledge catalogue contains bounded summaries and
official source links for every integrated platform. Relevant entries are
included in recommendation prompts and validation evidence. The catalogue is a
reviewed operational index rather than a mirror of all vendor documentation;
operators should re-review it when connected products or APIs are upgraded.

## Safety and trust boundaries

- Every security operation begins in a session and is written to the audit
  trail.
- Targets must pass installation scope, organization policy, role permission,
  and case-context checks.
- External writes and disruptive actions require explicit approval.
- The requester cannot approve their own protected action where separation of
  duties is required.
- Credentials are encrypted at rest and are not returned to analysts, written
  to reports, or inserted into AI prompts.
- Uploaded alerts, documents, external API responses, and vendor documentation
  are treated as untrusted data.
- AI learning creates evidence-backed drafts. It cannot independently grant a
  permission, publish code, enable a responder, install software, or alter a
  production rule.
- Package or plugin proposals must explain the task need, source, permissions,
  exact command, risks, and removal procedure before an administrator can
  approve an allowlisted repository-local installation.

## Connected platforms

The platform currently includes integrations or configuration support for
Wazuh Manager and Indexer, TheHive, Cortex, MISP, VirusTotal, AbuseIPDB, Shodan,
urlscan.io, Hybrid Analysis, PhishTank, and OpenAI/Codex. Each connection is
optional except the organization AI provider for AI-dependent workflows.
Unavailable enrichment providers degrade independently rather than exposing a
credential or silently authorizing another provider.

## Deployment

`python3 bootstrap.py` creates the Python environment, installs dependencies and
the pinned Codex CLI, installs the launcher and skills, creates the first admin,
and runs the test suite. On Linux it can also configure Nginx, Gunicorn,
Werkzeug `ProxyFix`, and a private local CA for HTTPS on a trusted LAN without a
public domain. Docker Compose is available for persistent single-node operation
and the optional PostgreSQL, Redis, and Celery profile.

Implementation completeness does not by itself prove that a deployment is
production-ready. Before operational approval, validate the exact SIEM and case
management versions, certificates, network controls, backup and restore,
credential rotation, worker recovery, notification delivery, load behavior,
logging, and incident-response procedures in the target environment.

## Project status and roadmap

The repository contains the current Phases 0-10 implementation baseline plus
detection assurance and organization architecture analysis. Rule
recommendations stop at `approved_for_replay`. Automated replay, shadow, canary,
production rollout, and evidence-driven rollback remain intentionally separated
as a later phase so an AI recommendation cannot become a production change
without a tested change-control system.

AI SOC Operator is released under the MIT License. It is an automation
framework, not authorization to access, scan, change, or isolate systems without
the system owner's permission.
