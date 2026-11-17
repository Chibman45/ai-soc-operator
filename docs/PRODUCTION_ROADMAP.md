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

## Implemented Baseline: Phases 5-10

### Phase 5: Browser Acceptance

The Playwright suite exercises login, the dashboard and alert queue, case
assignment and claim, independent approval, document-upload preview, and role
denial in Chromium. It runs against isolated test data and preserves traces and
screenshots when CI fails.

### Phase 6: Staging Integration

The staging harness models the Wazuh-to-notification chain, bounded retry and
failure injection, duplicate suppression, allowlisted secret loading, and
signed redacted evidence. Live mode rejects deterministic adapters and requires
an operator-controlled adapter factory so platform writes remain scoped and
approval-gated.

### Phase 7: Operational Evidence

Backup/restore, credential rotation, worker recovery, notification dead-letter,
responder rollback, tenant isolation, HTTPS, load/soak, and previous-release
rollback drills emit hash-chained signed evidence. Production approval requires
live results from the target Linux environment.

### Phase 8: Detection Rule Lifecycle

The Detection Lifecycle workspace provides sanitized tenant-scoped corpora,
stable pseudonyms, immutable evidence and rule digests, deterministic replay
with TP/FP/TN/FN metrics, shadow and canary gates, independent approval, drift
scoring, production previews, and independently verified rollback previews.
Rule writes remain disabled until an approved live adapter is configured.

### Phase 9: Deployment And Operations

SQLite remains the single-host default. PostgreSQL scale-out now has an RLS
installer and connection-bound tenant context; Redis/Celery remains the
distributed queue path. Worker leases serialize integration sync, stale job
ownership is fenced and redelivered, credential keyrings support rotation, and
audit records are hash chained on configurable shared storage. Multi-host
approval still requires live PostgreSQL/RLS, failover, shared evidence, and
load evidence.

### Phase 10: CI/CD And Release Assurance

CI uses hash-locked dependencies, immutable action SHAs, digest-pinned
containers, browser acceptance, coverage, SAST, dependency, container, and
secret scans. Tagged releases qualify the exact candidate digest before
promotion, then publish an SPDX SBOM, SBOM attestation, keyless signature,
provenance, and retained digest evidence. Staging soak/load evidence and a
practiced rollback remain release-environment gates.

These controls provide a production-oriented single-node baseline. A release is not production-approved until the environment-specific TLS, backup restore, staging soak, load, notification, responder, and rollback gates have evidence.

## Detection Assurance Baseline

The portal now supports an approved organization architecture profile,
AI-assisted alert assessment, analyst ground-truth labels, TP/FP/TN/FN metrics,
read-only Wazuh/TheHive/Cortex/MISP snapshots, deterministic configuration
findings, and evidence-bound rule recommendations. The downloadable Word
template collects the architecture and governance information required by this
workflow.

Approved recommendations can now be represented as versioned rule artifacts
and evaluated against sealed replay corpora. The platform intentionally stops
at signed production and rollback previews unless an organization supplies and
approves a live platform adapter; evidence alone never authorizes a rule write.
