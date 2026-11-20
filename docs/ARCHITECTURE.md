# Architecture

## Runtime topology

```text
Public browser ──read-only HTTP──> FastAPI API ──SQL──> PostgreSQL
                                      │                  ▲
Prometheus <── /metrics               │                  │
                                      │           migrations/bootstrap
Public feeds/telemetry ──HTTPS──> Worker ──normalized events/evidence
```

API and worker use the same image and domain modules. They are separate processes so API scaling cannot duplicate scheduled jobs. PostgreSQL is the only required durable dependency; there is no queue or unnecessary microservice.

## Backend modules

- `app/main.py`: compatibility models/helpers, application creation, public legacy reads, admin compatibility writes, HTTP safeguards.
- `app/api_v2.py`: v2 public/admin routes and Pydantic request schemas.
- `app/v2_models.py`: additive evidence, assessment, correlation, dependency, investigation, collector, baseline, and audit tables.
- `app/services/correlation.py`: independently testable pair evaluation, replay filtering, persistence.
- `app/services/topology.py`: server-filtered, paginated graph projection.
- `app/services/analytics.py`: robust historical baselines and change-point candidates.
- `app/worker.py`: scheduled collection/correlation, health records, retention, worker metrics.
- `migrations/`: additive upgrade path for clean and prototype databases.

## Data flow

1. A collector retrieves an allowlisted HTTPS source with bounded retries and response size.
2. Source records normalize into idempotent event or measurement fingerprints.
3. Every normalized event links to a provenance artifact containing timestamps, URL, content hash, excerpt, structured observation, and reliability state.
4. Correlation evaluates compatible event pairs. Time alone is insufficient.
5. Candidate factors and contradictions are returned publicly and may be materialized by the worker.
6. Investigators attach events/evidence, write explicitly labeled assertions, create hypotheses, and append immutable classifications.
7. Replay applies a knowledge-time cutoff before recomputing candidates.

## Stable graph identities

Graph IDs are deterministic: `incident:<database-id>`, `provider:<normalized-name>`, `asn:<asn>`, `region:<region>`, `evidence:<id>`, `network_anomaly:<id>`, and `hypothesis:<id>`. Correlation stable IDs hash the ordered event pair and relationship type.

The topology API caps incident pages at 200 and supports focus-based neighborhood expansion. This avoids sending the entire database to Cytoscape.
