# Operations Runbook

## Supported production profile

The default deployable profile is a single Linux host using SQLite WAL, one
Gunicorn process, the operations worker, and persistent Docker volumes. Bind the
default Compose port to loopback and terminate TLS in a managed reverse proxy or
load balancer. Do not expose port 5051 directly to an untrusted network.

PostgreSQL and a Redis/Celery execution plane are available through the
administrator-only Infrastructure migration workflow. The workflow validates
connections, creates and verifies a SQLite backup, requires an empty target,
verifies row counts, and activates only after restart. PostgreSQL row-level
security remains a later defense-in-depth control. PostgreSQL and Celery are
required before running multiple web hosts or workers against shared data.

## Start

1. Generate `AI_SOC_SESSION_SECRET` with at least 32 random bytes.
2. Generate `AI_SOC_CREDENTIAL_KEY` with `Fernet.generate_key()`.
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

## Rollback

Deploy images by immutable digest. Preserve the prior digest and database backup
for every release. For application rollback, stop services, verify and restore
the pre-release database only when a migration is incompatible, select the prior
image digest, start services, and run the health and smoke checks.
