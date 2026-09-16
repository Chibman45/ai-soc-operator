# Threat Model

## Assets

Integration credentials, alerts, evidence, reports, analyst identities, approvals, responder targets, playbooks, skill drafts, and the audit trail.

## Trust Boundaries

1. Browser to Flask session boundary.
2. SIEM to bearer-authenticated ingestion boundary.
3. Flask to database and job-worker boundary.
4. Worker to playbook/tool sandbox boundary.
5. Worker to Wazuh, TheHive, Cortex, MISP, and enrichment providers.
6. Untrusted alert/enrichment text to the AI context boundary.

## Priority Threats And Controls

| Threat | Control implemented in Phases 0-7 | Residual work |
|---|---|---|
| Broken access control or IDOR | Shared permissions and organization-scoped queries | Independent penetration test |
| CSRF and session theft | Session-bound CSRF, secure cookie policy, security headers, stable secret | TLS/reverse proxy in Phase 9 |
| Webhook spoofing and replay | Hashed scoped bearer clients and source-alert idempotency | Key rotation UI and rate limiting in Phase 9 |
| Credential database disclosure | Fernet encryption with external production key | Managed secret store integration in Phase 9 |
| Duplicate or interrupted actions | Idempotency keys, job attempts, leases, checkpoints | External queue and multi-worker recovery in Phase 9 |
| Approval bypass | Permission check, separation of duties, digest binding, expiry | Two-person quorum for selected live adapters |
| Prompt injection into learning | Sensitive-field redaction and review-only drafts | Adversarial evaluation corpus expansion |
| Cross-tenant AI context leakage | Organization-scoped global and case context | PostgreSQL RLS defense in depth |
| Malicious playbook upload | Extension, YAML structure, filename, size, and permission controls | Isolated parser and signature policy in Phase 9 |

## Detection Events

Monitor `login_failed`, `login_rate_limited`, `authorization_denied`, `csrf_rejected`, `api_client_created`, `api_client_revoked`, `alert_ingested`, `job_failed`, `playbook_approval_requested`, responder transitions, and learning promotions. Never include raw secrets or unrestricted evidence in these events.

