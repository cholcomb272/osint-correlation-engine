# Repository audit and incremental roadmap

Audit refreshed: 2026-11-28

## Verified baseline

- Runtime is a modular FastAPI/SQLAlchemy/PostgreSQL application with separate
  API and APScheduler worker processes, Alembic migrations, and a Vite/React UI.
- Application entry points are `app.main:app`, `python -m app.worker`, and
  `python -m app.cli`. Compose runs one-shot database bootstrap and migration
  services before the least-privilege API and worker roles.
- Migration `20261119_0001` introduced evidence, assessments, correlations,
  investigations, operational metadata, and security controls without replacing
  prototype event or measurement rows.
- The pre-expansion deployed database contained 231 events and 18,612 passive
  measurements. A custom-format backup was restored into a temporary database
  before applying the new migration.
- The pre-expansion automated baseline was 52 backend tests, one frontend
  component test, a TypeScript/Vite build, and the browser test. The expanded
  suite contains 65 backend tests.

## Architectural assumptions and gaps found

1. The event schema treated most records as infrastructure incidents and lost
   multidomain type, location, language, significance, and extraction-confidence
   detail during normalization.
2. Cause classification defaulted correctly to `unknown`, but one cause field
   was being asked to represent what happened, affected scope, mechanism, and
   attribution. This made partial knowledge difficult to express.
3. Correlation was primarily pairwise and infrastructure-oriented. There was no
   persistent general entity graph, group relationship, or cross-domain cluster.
4. Publisher independence and technical independence were carefully separated,
   but no general relationship model existed for contextual or organizational
   relevance outside provider/ASN topology semantics.
5. The collector registry was English-heavy and concentrated on provider status,
   cyber advisories, reporting, and two network-telemetry systems. Source health
   could not show domain/geographic/language visibility gaps.
6. Topology recomputed all historical candidate pairs before filtering to the
   requested page. Broader collection exposed this hidden scaling boundary; the
   deployed 30-day request rose to about 57 seconds.
7. Documentation described the infrastructure platform accurately but did not
   yet describe a multidomain ontology, persistent knowledge graph, or the limits
   of autonomous investigation candidates.

## Implemented additive phase

- Migration `20261128_0002` adds event ontology fields, entities and aliases,
  event-entity roles, immutable multi-label classifications, field-level
  assessments, knowledge relationships and revisions, clusters, autonomous
  investigation candidates, intelligence requirements, and source-coverage snapshots.
- Structured adapters add official earthquake, hazard, natural-event,
  space-weather, and exploited-vulnerability observations while preserving
  source occurrence/publication/collection semantics and provenance.
- The fusion service performs generalized entity reconciliation, relationship-
  specific temporal evaluation, evidence-lineage discounting, cluster discovery,
  competing explanations, unresolved questions, and automatic reassessment.
- The dashboard and public API expose a global map, multidomain timeline,
  persistent knowledge graph, event uncertainty/evidence inspection, autonomous
  candidates, and explicit coverage gaps without a browser credential.
- Correlation telemetry matching is cached per event, and infrastructure topology
  evaluation is bounded to its page or focused neighborhood. The same deployed
  30-day topology request dropped from about 57 seconds to about one second.

## Remaining roadmap and acceptance boundaries

The current registry is a foundation, not comprehensive global intelligence
coverage. Generalized aviation, maritime, rail, grid/energy, water, healthcare,
payments, DNS, satellite/GNSS, conflict, sanctions, and multilingual reporting
connectors remain future work and require suitable documented public access.

Entity resolution is deterministic and explainable; it does not yet provide
high-recall multilingual alias resolution. Cluster detection is connected-
component based and produces investigation candidates, not calibrated anomaly
or coordination judgments. Existing historical replay continues to protect the
legacy correlation path from future knowledge, while full versioned reconstruction
of every ontology relationship and cluster remains an additional validation phase.

Broader empirical evaluation is still required. Synthetic fixtures prevent known
semantic regressions but do not measure real-world recall, relationship precision,
or analyst usefulness. An independent engineer must still perform the documented
clean-install and evidence review; the implementer cannot self-certify independence.
