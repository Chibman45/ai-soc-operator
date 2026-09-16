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

## Explicitly Deferred: Phases 8-10

### Phase 8: Notifications And Intel Delivery

Wire Slack and SMTP delivery workers, SLA warning/breach scheduling, dead-letter notifications, STIX delivery UX, and approval-gated MISP synchronization.

### Phase 9: Deployment And Operations

Add PostgreSQL with row-level security, an external Redis/Celery queue, non-root containers, production WSGI/reverse proxy, TLS, rate limiting, centralized telemetry, backup/restore, and disaster-recovery drills.

### Phase 10: CI/CD And Release Assurance

Add pinned lock files, test matrices, SAST, dependency/container/secret scanning, SBOM and provenance, signed images, staging soak tests, load tests, and controlled release rollback.

The application-level controls in Phases 0-7 are prerequisites, not a claim that deployment is production-ready before Phases 8-10 pass.

