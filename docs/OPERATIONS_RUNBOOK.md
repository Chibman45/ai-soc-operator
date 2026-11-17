# Operations Runbook

## Supported production profile

The default deployable profile is a single Linux host using SQLite WAL, one
Gunicorn process, the operations worker, and persistent Docker volumes. Bind the
default Compose port to loopback and terminate TLS in a managed reverse proxy or
load balancer. Do not expose port 5051 directly to an untrusted network.

PostgreSQL and a Redis/Celery execution plane are available through the
administrator-only Infrastructure migration workflow. The workflow validates
connections, creates and verifies a SQLite backup, requires an empty target,
verifies row counts, and activates only after restart. PostgreSQL and Celery
are required before running multiple web hosts or workers against shared data.
Install row-level-security policies with the database owner, then run the
portal with a non-owner runtime role that does not have `BYPASSRLS`:

```bash
python -m scripts.postgres_rls
```

Application connections bind `app.current_org_id` before organization-owned
data is accessed.

## Start

1. Generate `AI_SOC_SESSION_SECRET` with at least 32 random bytes.
2. Generate `AI_SOC_CREDENTIAL_KEY` with `Fernet.generate_key()`, or configure
   the versioned keyring described below.
3. Place them in the host secret manager or a root-readable `.env` file.
4. Run `docker compose up --build -d`.
5. Confirm `/health/live` returns `ok` and `/health/ready` reports the worker.

System-package installation is intentionally unavailable in the non-root
application container. An approved package proposal can execute only in a
controlled host deployment with `AI_SOC_ALLOW_SYSTEM_INSTALL=1` and passwordless
sudo. Plugin installs remain repository-local and require
`AI_SOC_ALLOW_PLUGIN_INSTALL=1` plus fully hashed catalog requirements.

## Backup and recovery

Create a consistent backup with:

```bash
python -m scripts.database_backup create
python -m scripts.database_backup verify backups/soc-operator-<timestamp>.sqlite3
```

Copy both the database and its manifest to encrypted off-host storage. A restore
is a deliberate operator procedure: stop web and worker services, verify the
backup, preserve the current database, replace it, start services, and verify
readiness plus a representative case and audit record. Record the drill result.

## Notifications

The worker sends console notifications by default. Set Slack or SMTP environment
variables to add providers. Failed deliveries retry with bounded exponential
backoff and then enter `dead_letter`; managers can inspect and requeue them via
the notification API.

## Credential rotation

Set `AI_SOC_CREDENTIAL_KEYS` to a secret-manager-provided JSON object mapping
key IDs to Fernet keys, and set `AI_SOC_CREDENTIAL_ACTIVE_KEY` to the new key
ID. Keep the previous key until rotation and backup verification finish, then
run:

```bash
python -m scripts.rotate_credentials
```

The operation is transactional and does not log plaintext. Test platform
connections before removing the previous key from the secret manager.

## Release evidence

Run deterministic contracts locally, then run live adapters only in the
approved staging environment:

```bash
python -m scripts.staging_acceptance --alert demo/alert.json
python -m scripts.staging_acceptance --mode live --alert demo/alert.json \
  --adapter organization_staging:build_adapters --config config/platforms.toml
python -m scripts.operational_drills --mode live \
  --adapter organization_drills:build_adapter --context staging-context.json
```

Live runs require `AI_SOC_EVIDENCE_SIGNING_KEY` and
`AI_SOC_EVIDENCE_SIGNING_KEY_ID`. For multi-host operation, place
`AI_SOC_AUDIT_DIR` and `AI_SOC_EVIDENCE_DIR` on access-controlled shared
storage. Deterministic evidence alone cannot approve a release.

## Rollback

Deploy images by immutable digest. Preserve the prior digest and database backup
for every release. For application rollback, stop services, verify and restore
the pre-release database only when a migration is incompatible, select the prior
image digest, start services, and run the health and smoke checks.
