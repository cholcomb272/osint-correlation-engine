# Setup guide

## Docker Compose

1. Copy `.env.example` to `.env`.
2. Generate independent random values for the two database passwords, API token, and audit hash salt.
3. Keep `BIND_ADDRESS=127.0.0.1` unless LAN access is intentional.
4. Run `docker compose up --build -d`.
5. Check `docker compose ps`, `/health`, and `/ready`.

The first startup runs `db-bootstrap` and `migrate`, then starts API and worker. `db-bootstrap` creates a non-owner `osint_app` login and grants data access without DDL or role-management privileges. It is idempotent for an existing volume.

## Existing prototype upgrade

Back up the named volume according to local operational policy before any production upgrade. Do not remove `pgdata`. Start the v2 Compose project normally; the initial revision detects the prototype `events` table, adds missing columns, backfills knowledge timestamps from existing timestamps, and creates new tables.

Validate after upgrade:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/ready
docker compose exec -T worker python -m app.cli health
```

## Source development

The backend defaults to `sqlite:///./osint.db` when `DB_HOST` and `DATABASE_URL` are absent. This mode is for local tests only. Run `alembic upgrade head` before launching against PostgreSQL.

The Vite development server proxies API paths to `127.0.0.1:8787`.
