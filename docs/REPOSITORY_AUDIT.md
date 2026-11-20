# Repository audit and migration plan

Audit date: 2026-11-19

## Baseline

- Runtime: FastAPI, SQLAlchemy, PostgreSQL 16, APScheduler, Docker Compose.
- Entry point: `app.main:app`; the API process also owned scheduled collection.
- Durable tables: `events`, legacy `evidence`, and `network_measurements`.
- UI: one static HTML file with a bearer-token input.
- Collectors: CISA and provider status feeds, RIPEstat BGP update activity, and IODA outage events.
- Baseline verification: 18 tests passed. One dependency deprecation warning was present.

## Risks found

1. `create_all()` could not safely evolve an installed PostgreSQL database.
2. Running more than one API worker would duplicate scheduled collection.
3. Read access required an administrative shared secret, and the browser handled that secret.
4. Correlations were calculated on request and lacked a durable evidence/assessment history.
5. Evidence provenance, source independence, contradiction, and replay timestamps were incomplete.
6. There was no request rate limiting, audit log, metrics endpoint, or readiness distinction.
7. Repository artifacts included local report exports. They are now excluded from release contexts.
8. The workspace is not currently a Git repository, so tracked-file and history review cannot yet be performed.

No database port was published by Compose, and the application image already used an unprivileged user.

## Incremental migration strategy

The v2 migration is additive. Existing table names, primary keys, fingerprints, and rows are retained. New nullable timestamp and classification columns are added to `events`; existing `observed_at` and `ingested_at` remain supported. New evidence, correlation, assessment, investigation, collector, audit, and baseline tables are created alongside the legacy tables. The initial Alembic revision detects an installed prototype schema before adding columns, so it works for both a clean database and an existing volume.

The API and worker share the same modular-monolith image. Collection moves to the worker, public reads require no browser credential, and administrative mutations continue to require the server-side bearer secret. Rollback does not delete legacy event or measurement data.
