# Release notes

## 0.2.0-alpha.2 — 2026-11-20

### Intelligence coverage and validation

- Replaced the fixed three-prefix network target set with bounded RIPEstat
  announced-prefix discovery for configured and recent incident ASNs, retaining
  target-selection provenance and safe seed fallbacks.
- Added explicit observation modalities so multiple BGP-derived feeds cannot be
  counted as independent technical corroboration.
- Expanded the dashboard coverage panel with actual observed prefixes,
  incident-aware targets, observation modalities, intervals, and scope limits.
- Added a versioned ten-scenario synthetic benchmark with confusion matrix,
  precision, recall, specificity, F1, per-scenario diagnostics, CLI JSON export,
  unit coverage, and CI enforcement.
- Added a clean-clone review harness, independent-review checklist, and report
  template. Automation is not represented as an independent human review.

### Known alpha limitations

- RIPEstat target expansion broadens passive BGP visibility but does not prove
  incident-specific impact or complete provider-prefix coverage.
- Independent technical corroboration still depends on public modality and
  system availability; most historical events will not have two qualifying
  modalities from two shared telemetry systems.
- Benchmark metrics cover synthetic regression fixtures and are not calibrated
  estimates of field accuracy.
- An external engineer must still perform and sign the independent review.

## 0.2.0-alpha.1 — 2026-11-20

Initial intelligence-expansion tag. Superseded by alpha.2 because its
independent-corroboration gate required multiple modalities but did not also
require multiple telemetry systems.

## 0.1.0-beta.2 — 2026-11-20

### Security hardening

- Compose now requires `POSTGRES_PASSWORD`, `APP_DB_PASSWORD`, `API_TOKEN`, and `AUDIT_HASH_SALT` independently.
- Removed the runtime-database-password fallback to the PostgreSQL owner password.
- Removed the audit-hash-salt fallback to the administrative API token.
- Production configuration validates that the audit salt is present and at least 32 characters.

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
