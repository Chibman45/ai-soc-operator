# Production Specification: Phases 0-7

## Scope

This release establishes the application-level production boundary for identity, authorization, tenant isolation, alert ingestion, case workflows, durable local jobs, responder dry-runs, and controlled learning. Deployment, notification delivery, CI/CD, and release operations remain tracked as Phases 8-10.

## Service Objectives

- Accepted alerts receive a durable alert ID and idempotent job ID.
- Every run is recoverable to a terminal or retryable state after a worker interruption.
- No case, alert, observable, chat, report, job, or responder action is visible across organizations.
- High-risk actions require a different authorized approver and expire after 15 minutes.
- Skill candidates cannot become active code through the learning API.

## Data Classification

| Class | Examples | Required handling |
|---|---|---|
| Restricted | API keys, tokens, credentials | Encrypt at rest; never log or return after creation |
| Confidential | Alerts, evidence, case/chat content | Organization scope, access control, retention policy |
| Internal | Playbooks, skill drafts, operational metrics | Authenticated access and audit trail |
| Public | Product documentation | Review before publication |

## Run Agent Contract

1. Authenticate the user and verify `tool.execute` in the active organization.
2. Validate the playbook name and constrain local alert files to approved data roots.
3. create an immutable run identity with an idempotency key.
4. Queue the run without storing decrypted platform credentials in the job payload.
5. Build clients from organization-scoped credentials inside the worker.
6. Record progress at checkpoints and honor pause or cancellation requests.
7. Pause at playbook approval gates and continue only after another authorized user approves.
8. Persist the result, case, evidence references, audit events, and learning signals.

## Release Gates

- Full test suite, compile check, route authorization matrix, and cross-tenant tests pass.
- No unresolved critical or high security findings.
- Credential migration succeeds with production keys and plaintext values are absent from the database.
- Duplicate alert and run requests produce one operational action.
- Responder self-approval, expired approval, changed preview, and cross-tenant access are rejected.
- Learning promotion without a passing evaluation is rejected.

