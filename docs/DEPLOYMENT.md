# Deployment and operations

The Compose defaults are intentionally restrictive: no PostgreSQL host port, non-root images, `no-new-privileges`, read-only API/worker filesystems, bounded tmpfs, strict same-origin browser behavior, and loopback host binding.

`POSTGRES_PASSWORD`, `APP_DB_PASSWORD`, `API_TOKEN`, and `AUDIT_HASH_SALT` are independent required settings. Compose fails during interpolation if any is absent; there are no cross-secret fallbacks.

For production:

1. terminate TLS at a maintained reverse proxy;
2. restrict `/api/admin/*`, `/metrics`, and worker metrics to trusted networks;
3. use managed secrets and independent database passwords;
4. set an explicit `CORS_ORIGINS` allowlist only if cross-origin reads are required;
5. collect JSON logs and scrape API port 8000 `/metrics` plus worker port 9101 inside the Compose network;
6. back up and restore-test `pgdata`;
7. pin and review container digests according to local policy;
8. enable `RETENTION_ENABLED` only after approving the operational-metadata windows.

Retention never deletes source events or evidence. When enabled it prunes old audit rows, collector-run history, and stale materialized correlation rows; candidates can be recomputed.

Create and verify a logical backup regularly:

```bash
scripts/backup.sh
scripts/verify-backup.sh backups/osint-YYYYMMDDTHHMMSSZ.dump
```

The verification restore uses a uniquely named temporary database and refuses to target the live `osint` database. Backup files are mode `0600` and excluded from Git/Docker contexts. Store production copies encrypted outside the Compose host and test recovery according to the operator's retention policy.

The initial bearer secret is appropriate for local automation, not multi-user authorization. Prefer an identity-aware reverse proxy for an internet deployment.
