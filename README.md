# OSINT Correlation Engine — Global Intelligence Fusion

An evidence-driven, open-source platform for collecting, normalizing, correlating, and investigating public global events and infrastructure disruption data.

The engine helps network engineers, SREs, and researchers distinguish technical relationships from timing coincidences. It does **not** independently establish cyberattack attribution. Correlation strength is an explainable heuristic, never a probability.

## What is included

- Credential-free public React/TypeScript dashboard
- Global event map, unified multidomain timeline, persistent intelligence knowledge graph, and field-level uncertainty inspector
- Hierarchical, multi-label event classification across cyber, internet, infrastructure, strategic, and natural-event domains
- Autonomous evidence-connected clusters and investigation candidates with competing explanations and unresolved questions
- Evidence-first Cytoscape topology with deterministic provider/ASN investigation layout; inferred candidates and hypotheses are opt-in
- FastAPI public and authenticated administrative APIs
- PostgreSQL storage with additive Alembic migrations
- Dedicated scheduled collection worker with checkpoints and health history
- Official provider status feeds plus multi-publisher infrastructure/security disclosure feeds
- Structured USGS earthquake, GDACS hazard, NASA EONET, NOAA space-weather, and CISA KEV collection
- Passive RIPEstat BGP update activity and IODA outage-event telemetry
- Bounded, incident-aware ASN target discovery using RIPEstat announced prefixes
- Evidence-strength and telemetry-coverage panels showing representative prefixes, ASN/provider scope, cadence, and missing sources
- Semantic/type compatibility, dependency, ASN, region, anomaly, maintenance, source-derivation, and contradiction factors
- Immutable classification history and persistent investigation workspaces
- Historical replay that excludes future knowledge
- Provider/region/category baselines using median absolute deviation
- JSON, CSV, and readable investigation exports
- Prometheus metrics, structured logs, rate limiting, audit logging, and least-privilege runtime database role

All collection uses documented public sources. There is no active scanning or probing.

## Quick start

Requirements: Docker Engine with Compose v2. On Raspberry Pi, use a current 64-bit OS and allow extra time for the first multi-stage build.

```bash
cp .env.example .env
# Replace POSTGRES_PASSWORD, APP_DB_PASSWORD, API_TOKEN, and AUDIT_HASH_SALT.
docker compose up --build -d
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/ready
```

Open <http://127.0.0.1:8787>. The public dashboard never asks for or stores an API key.

Compose preserves the existing `pgdata` volume. On an upgrade from the prototype, Alembic adds fields and tables without replacing `events`, `network_measurements`, their primary keys, or stored rows.

The default host bind is loopback. For a trusted LAN, set `BIND_ADDRESS=0.0.0.0` and put TLS at a reverse proxy before exposing the service beyond that LAN. PostgreSQL is not published to the host.

Compose requires all four secrets and refuses to render when any is missing. `APP_DB_PASSWORD` never falls back to the PostgreSQL owner password, and `AUDIT_HASH_SALT` never falls back to the administrative API token.

## Collection and administration

The worker collects automatically. Administrators can trigger an idempotent backfill without putting the API secret in a browser:

```bash
docker compose exec -T worker python -m app.cli collect --days 365
docker compose exec -T worker python -m app.cli collect-measurements --days 30
docker compose exec -T worker python -m app.cli correlate --days 30
docker compose exec -T worker python -m app.cli fusion --days 90
docker compose exec -T worker python -m app.cli health
```

The authenticated API remains available for automation:

```bash
set -a; . ./.env; set +a
curl -fsS -X POST -H "Authorization: Bearer ${API_TOKEN}" \
  "http://127.0.0.1:8787/api/admin/collect?days=365" | python3 -m json.tool
unset API_TOKEN POSTGRES_PASSWORD APP_DB_PASSWORD AUDIT_HASH_SALT
```

The legacy authenticated `POST /api/collect` endpoint remains compatible. Public reads use `/api/public/*`; legacy `GET /api/events`, `/api/measurements`, and `/api/correlations` are also read-only and public.

Feed backfill reaches only as far as publishers retain entries. The platform never fabricates historical measurements.

Feed coverage is defined in `app/data/sources.json`. The bundled registry includes
official provider status and national CERT/advisory sources alongside Federal
News Network, BleepingComputer, and The Record disclosure feeds. Structured
adapters cover significant earthquakes, global disaster alerts, open natural
events, space-weather alerts, and known exploited vulnerabilities. Disclosure
publishers are never normalized as affected infrastructure providers. General
news is filtered, reported breaches retain cause classification `unknown`, and
multiple articles naming the same service are labeled repeated reporting rather
than independent technical corroboration. Operators can replace the registry at
build/deployment time with `FEED_SOURCE_REGISTRY`; configured HTTPS hosts form
the feed collector's outbound allowlist.

## API examples

```bash
curl -fsS 'http://127.0.0.1:8787/api/public/incidents?days=30&page_size=50'
curl -fsS 'http://127.0.0.1:8787/api/public/correlations?days=30&hours=24'
curl -fsS 'http://127.0.0.1:8787/api/public/topology?days=30&page_size=100'
curl -fsS 'http://127.0.0.1:8787/api/public/knowledge-graph?days=30&page_size=100'
curl -fsS 'http://127.0.0.1:8787/api/public/map?days=30'
curl -fsS 'http://127.0.0.1:8787/api/public/coverage'
curl -fsS --get 'http://127.0.0.1:8787/api/public/replay' \
  --data-urlencode 'cutoff=2026-11-18T09:00:00Z' --data 'days=30'
```

Interactive OpenAPI documentation is at `/docs`.

## Architecture

The deployment is a modular monolith with separate process roles:

- `api`: public dashboard/API, admin API, validation, rate limiting, metrics
- `worker`: scheduled collection, correlation materialization, collector metrics
- `migrate`: one-shot Alembic upgrade
- `db-bootstrap`: one-shot least-privilege role reconciliation
- `db`: PostgreSQL 16, internal-only

See [Architecture](docs/ARCHITECTURE.md), [Setup](docs/SETUP.md), and [Deployment](docs/DEPLOYMENT.md).

## Development and tests

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q

cd frontend
npm ci
npm test
npm run build
```

The frontend toolchain requires Node 22. End-to-end tests run with `npm run test:e2e` against a running deployment. Core tests are deterministic and do not call live external services.

Run the versioned correlation-accuracy regression benchmark and optionally save
its JSON report:

```bash
python -m app.cli benchmark --output artifacts/correlation-benchmark.json
```

Its precision/recall figures describe only the published synthetic fixtures;
they are regression metrics, not real-world calibration or probabilities.

Load the explicitly synthetic demonstration records with:

```bash
docker compose exec -T worker python -m app.demo
```

## Evidence semantics

Cause classification, severity, evidence confidence, investigation state, source reliability, and correlation strength are separate fields. Classifications default to `unknown` and each change creates an immutable assessment record with rationale and evidence references.

Temporal proximity contributes at most 0.10. A different publisher is not automatically independent technical corroboration. Scheduled maintenance, future events, policy announcements, same-upstream reports, source delays, and contradictory evidence are handled explicitly. Every candidate states what supports it, what weakens it, and what additional observations would change the assessment.

Shared provider and provider-owned ASN scope are retained as separate facts but scored as one overlapping infrastructure dimension. Security advisories and policy/news records remain contextual evidence and do not form operational dependency candidates.

See [Correlation methodology](docs/CORRELATION_METHODOLOGY.md) and [Data provenance](docs/DATA_PROVENANCE.md).

## Backup and restore verification

Backups are sensitive and are excluded from Git and Docker build contexts. Create and restore-test a PostgreSQL custom-format backup without touching the live database:

```bash
scripts/backup.sh
scripts/verify-backup.sh backups/osint-YYYYMMDDTHHMMSSZ.dump
```

Set `OSINT_DOCKER_SUDO=1` when Docker access on the host requires `sudo`. The verification script restores into a uniquely named temporary database, checks event, measurement, and migration data, and removes only that temporary database.

## Security

Do not commit `.env`. The dashboard contains no secret and does not use browser local storage for authentication. Admin writes require the bearer secret or direct server-side CLI access. For internet deployment, add TLS, an identity-aware reverse proxy, centralized secret management, and network-level access restrictions.

Report vulnerabilities according to [SECURITY.md](SECURITY.md). Known constraints and the release security review are in [Release notes](RELEASE_NOTES.md).

External engineers can follow the [independent clean-install review](docs/INDEPENDENT_REVIEW.md)
and submit the completed [review report](docs/INDEPENDENT_REVIEW_REPORT.md). The
automation creates evidence; an independent human must still assess semantics.

## License

Apache License 2.0. See [LICENSE](LICENSE).
