# Production Roadmap

## Implemented In This Release: Phases 0-7

- Phase 0: production specification, security policy, threat model, and release gates.
- Phase 1: centralized multi-role authorization, route hardening, admin bootstrap, and tenant-aware access.
- Phase 2: hardened password hashing, stable sessions, CSRF, security headers, login throttling, and encrypted credentials.
- Phase 3: organizations, memberships, service clients, mandatory application-level tenant scoping, and idempotency constraints.
- Phase 4: persistent job attempts, cooperative controls, leases, stale-job recovery primitives, and scoped runtime credentials.
- Phase 5: authenticated and normalized ingestion, duplicate suppression, assignment filters, SLA access, and IOC isolation.
- Phase 6: responder proposal, approval, rejection, execution-preview history, separation of duties, expiry, and tamper binding.
- Phase 7: redacted learning evidence, evaluation records, controlled promotion states, canary, and rollback status.

## Implemented Baseline: Phases 8-10

### Phase 8: Notifications And Intel Delivery

Slack/SMTP/console workers, SLA and job scans, retry/dead-letter handling, STIX export, and separately approved MISP synchronization are implemented.

### Phase 9: Deployment And Operations

The single-node profile now has non-root containers, Gunicorn, readiness probes, shared ingestion rate limiting, worker telemetry, and verified SQLite backups. TLS termination is an operator deployment requirement. PostgreSQL row-level security and Redis/Celery remain the mandatory scale-out migration before multi-host operation.

### Phase 10: CI/CD And Release Assurance

CI now runs the test matrix, coverage, SAST, dependency, container, and secret scans. Tagged releases produce an SBOM, keyless signature, and provenance attestation. Staging soak/load evidence and a practiced rollback remain release-environment gates.

These controls provide a production-oriented single-node baseline. A release is not production-approved until the environment-specific TLS, backup restore, staging soak, load, notification, responder, and rollback gates have evidence.
