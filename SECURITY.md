# Security Policy

## Supported Branch

Security fixes are applied to `main`. Production operators should deploy a signed release rather than an arbitrary branch or development checkout.

## Reporting A Vulnerability

Do not open a public issue containing secrets, customer evidence, exploit details, or production identifiers. Contact the repository owner privately with the affected version, component, impact, and a safe reproduction. The maintainer should acknowledge the report within two business days, establish severity, and coordinate remediation and disclosure.

## Security Invariants

- Every operational record and API query is scoped to an organization.
- Platform credentials are encrypted at rest and never written into job payloads or audit logs.
- Browser mutations require CSRF validation; SIEM ingestion requires a scoped bearer client.
- External writes and containment actions require explicit, unexpired approval.
- A requester cannot approve their own responder action.
- Learning output remains a candidate draft until evaluation and human promotion complete.
- Alert content, enrichment output, and uploaded documents are untrusted input.

## Production Configuration

Production startup requires `AI_SOC_ENV=production`, `AI_SOC_SESSION_SECRET`, and `AI_SOC_CREDENTIAL_KEY`. TLS termination, a production WSGI server, centralized logs, backups, and monitoring are required before exposure to a network. Phases 8-10 in `docs/PRODUCTION_ROADMAP.md` track that deployment work.

