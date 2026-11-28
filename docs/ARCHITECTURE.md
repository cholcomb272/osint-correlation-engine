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
- `app/v2_models.py`: additive evidence, assessment, correlation, dependency, investigation, entity/ontology, knowledge-graph, cluster, coverage, baseline, and audit tables.
- `app/collectors/structured.py`: pure parsers for documented JSON/GeoJSON public sources.
- `app/services/correlation.py`: independently testable pair evaluation, replay filtering, persistence.
- `app/services/ontology.py`: entity resolution, multi-label classification, field-level uncertainty, and immutable relationship revision history.
- `app/services/fusion.py`: multidimensional relationship materialization, cluster discovery, and autonomous investigation-candidate reassessment.
- `app/services/knowledge_graph.py`: server-filtered persistent intelligence graph projection with layered relationship semantics.
- `app/services/topology.py`: server-filtered, paginated graph projection.
- `app/services/analytics.py`: robust historical baselines and change-point candidates.
- `app/worker.py`: scheduled collection/correlation, health records, retention, worker metrics.
- `migrations/`: additive upgrade path for clean and prototype databases.

## Data flow

1. A collector retrieves an allowlisted HTTPS source with bounded retries and response size.
2. Source records normalize into idempotent event or measurement fingerprints.
3. Every normalized event links to a provenance artifact containing timestamps, URL, content hash, excerpt, structured observation, and reliability state.
4. Ontology reconciliation resolves reusable entities, appends multi-label classifications, and records unresolved analytical fields without forcing attribution.
5. Relationship-specific fusion evaluates shared vulnerabilities, infrastructure, platforms, geography, organizations, lineage, and appropriate time windows.
6. Evidence-connected components become explicitly non-causal clusters; significant components create investigation candidates with alternatives and collection questions.
7. Legacy infrastructure correlation remains independently testable. Time alone is insufficient, and telemetry matching is cached per event.
8. Investigators attach events/evidence, write explicitly labeled assertions, create hypotheses, and append immutable classifications.
9. Replay applies a knowledge-time cutoff before recomputing candidates.

## Stable graph identities

Graph IDs are deterministic: `incident:<database-id>`, `provider:<normalized-name>`, `asn:<asn>`, `region:<region>`, `evidence:<id>`, `network_anomaly:<id>`, and `hypothesis:<id>`. Correlation stable IDs hash the ordered event pair and relationship type.

The topology API caps incident pages at 200 and supports focus-based neighborhood expansion. This avoids sending the entire database to Cytoscape.

Knowledge-graph IDs use `event:<id>` and `entity:<stable-id>`. Relationships
retain separate relevance, evidence-quality, correlation-strength, and nullable
causal-confidence dimensions. The public default omits contextual associations;
clients must explicitly opt into exploratory context.
