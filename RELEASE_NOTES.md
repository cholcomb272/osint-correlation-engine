# Release notes

## 0.1.0-beta.1 — 2026-11-20

### Added

- additive Alembic migration preserving the MVP event and measurement tables;
- evidence lifecycle, immutable assessments, dependency/correlation records, investigations, hypotheses, notes, collector health, checkpoints, baselines, and audit log;
- evidence-aware modular correlation and historical replay;
- public read-only API plus authenticated admin API/CLI;
- dedicated worker and least-privilege PostgreSQL runtime role;
- React/TypeScript/Cytoscape dashboard and source-backed graph;
- Prometheus metrics, structured logs, rate/request-size limits, strict CORS, outbound allowlist, and dependency/secret scanning CI;
- deterministic scenario, API, migration, frontend, and browser tests;
- public release documentation and synthetic demo data;
- evidence-first topology defaults, deterministic provider/ASN investigation layout, explicit non-causal candidate labels, evidence-strength summary, and telemetry-coverage indicators;
- overlapping provider/ASN dimension discount and policy/advisory compatibility safeguards;
- executable backup plus non-destructive temporary-database restore verification.

### Security review findings

- No database port is published; containers run unprivileged with `no-new-privileges`.
- Public frontend assets contain no API token handling.
- Local timestamped report exports are ignored from Git and Docker contexts.
- Local evidence bundles and database backups are ignored from Git and Docker contexts.
- npm production and development audit reports zero known vulnerabilities at release preparation time.
- The initial public commit was scanned for generated secrets, private-key markers, private LAN addresses, and host-specific names before publication.

### Known limitations

- Feed/API history is bounded by public source retention and availability.
- RIPEstat representative prefixes do not establish provider-wide impact.
- IODA event availability and methods vary by entity and time.
- Baseline scores are robust heuristics, not calibrated probabilities; missing coverage can resemble zero activity.
- No live public DNS telemetry connector is enabled because no suitable access credential/source is bundled.
- Shared-secret admin authentication is intended for local/initial release use behind TLS and network controls.
- The first migration uses additive metadata creation to adopt the prototype schema; future changes should use conventional granular revisions.
