# Data provenance

## Public sources

- CISA news/advisory RSS: publisher reports, not proof that an infrastructure incident occurred.
- Cloudflare, GitHub, and Google Cloud status feeds: official provider reports; feed retention bounds backfill.
- RIPEstat BGP update activity: passive routing activity for representative prefixes; not proof of provider-wide impact.
- IODA outage events: passive public anomaly events; data-source and method metadata are retained.

No historical BGP, DNS, traffic, or outage data is fabricated when a source is unavailable.

## Timestamp semantics

The event model separates occurrence, first observation, publisher report, collection, retrieval, scheduled start/end, and resolution timestamps. `observed_at` remains as an MVP compatibility timestamp. All normalized values are UTC; an original timezone label may be retained.

Historical replay uses the earliest available knowledge timestamp and excludes records reported or ingested after the cutoff.

## Evidence lifecycle

Evidence artifacts store original URL, publisher/upstream source, publication/observation/ingestion/retrieval timestamps, SHA-256 content hash, excerpt or structured observation, collection method, reliability, verification state, and bounded raw metadata. User-entered notes are explicitly labeled `investigator_assertion`.

Publisher independence and independent technical corroboration are different fields.

## Coverage semantics

The topology API reports configured/observed prefixes, monitored and incident ASNs/providers, approximate observation cadence, per-resource sample totals, and telemetry sources with no observations in the selected window. Coverage of a representative prefix or ASN is not coverage of every affected service, route, region, or customer path. Sample counts are repeated observations, not independent corroborations.
