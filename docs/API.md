# API guide

OpenAPI schemas are served at `/openapi.json` and interactive documentation at `/docs`.

## Public read-only routes

- `GET /api/public/overview`
- `GET /api/public/incidents`
- `GET /api/public/correlations`
- `GET /api/public/topology`
- `GET /api/public/providers`
- `GET /api/public/trends`
- `GET /api/public/replay`
- `GET /api/public/source-health`
- `GET /api/public/events/{id}/intelligence`
- `GET /api/public/entities` and `GET /api/public/entities/{stable_id}`
- `GET /api/public/knowledge-graph`
- `GET /api/public/map`
- `GET /api/public/clusters`
- `GET /api/public/investigation-candidates`
- `GET /api/public/coverage`
- `GET /api/public/intelligence-requirements`
- `GET /api/public/investigations`
- `GET /api/public/investigations/{id}/export?format=json|csv|report`

Pagination and upper bounds are validated by FastAPI. Public routes are rate-limited per direct client address. Deployments behind a proxy should configure trusted proxy behavior at the network boundary.

`GET /api/public/topology` defaults to an evidence-first graph. `include_inferred=true` opts into non-causal correlation candidates and `include_hypotheses=true` opts into investigator assertions. The response includes `evidence_summary` counts, `telemetry_coverage` scope/cadence/gap metadata, and a `view` object describing active semantics. Every inferred edge carries `semantic_status=inferred_candidate_not_causal` and `causal_claim=false` before an inspector is opened.

## Administrative routes

Send `Authorization: Bearer <API_TOKEN>` to `/api/admin/*`. Administrative routes create evidence, append assessments, rebuild correlations, trigger collection, manage investigations, attach evidence/events, create hypotheses/notes, export private workspaces, and read the audit log.

The shared secret is an initial-release automation mechanism. It belongs in a secret manager or process environment and must never be passed to the dashboard. For multi-user internet operation, place the admin path behind identity-aware authentication rather than expanding the custom secret mechanism.

`POST /api/admin/fusion/rebuild` reconciles the ontology, materializes
knowledge relationships, and reassesses clusters. Intelligence requirements
are managed under `/api/admin/intelligence-requirements`; their structured
scope and trigger policy prioritize broad discovery without changing collector
source code.

## Compatibility routes

Public `GET /api/events`, `/api/measurements`, and `/api/correlations` preserve the MVP response shape. Authenticated MVP writes remain available and are audit logged.
