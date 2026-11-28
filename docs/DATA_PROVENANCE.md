# Data provenance

## Public sources

- CISA news/advisory RSS: publisher reports, not proof that an infrastructure incident occurred.
- Cloudflare, GitHub, and Google Cloud status feeds: official provider reports; feed retention bounds backfill.
- Federal News Network, BleepingComputer, and The Record feeds: secondary
  disclosure reporting used to discover cross-sector incident claims. Articles
  are retained as source reports; the publisher is not treated as the affected
  provider and a reported breach defaults to unknown cause.
- UK NCSC, CERT-EU, Canadian Centre for Cyber Security, and Australian Cyber
  Security Centre feeds: official advisory context. Advisories are not treated
  as operational disruption evidence.
- RIPEstat announced-prefix discovery and BGP update activity: passive routing
  activity for a bounded set of public prefixes originated by configured or
  recently observed incident ASNs; not proof of provider-wide impact.
- IODA outage events: passive public anomaly events; data-source and method metadata are retained.
- USGS significant-earthquake GeoJSON: authoritative earthquake observations with source coordinates and occurrence times.
- GDACS event feed: international hazard alerts and severity metadata; alerts are not proof of infrastructure impact.
- NASA EONET: open natural-event records with source-provided geometry and category metadata.
- NOAA SWPC alerts: official space-weather alert messages and issuance times.
- CISA Known Exploited Vulnerabilities: vulnerability exploitation catalog entries; catalog inclusion is not an infrastructure outage or attribution claim.

No historical BGP, DNS, traffic, or outage data is fabricated when a source is unavailable.

## Timestamp semantics

The event model separates occurrence, first observation, publisher report, collection, retrieval, scheduled start/end, and resolution timestamps. `observed_at` remains as an MVP compatibility timestamp. All normalized values are UTC; an original timezone label may be retained.

Historical replay uses the earliest available knowledge timestamp and excludes records reported or ingested after the cutoff.

## Evidence lifecycle

Evidence artifacts store original URL, publisher/upstream source, publication/observation/ingestion/retrieval timestamps, SHA-256 content hash, excerpt or structured observation, collection method, reliability, verification state, and bounded raw metadata. User-entered notes are explicitly labeled `investigator_assertion`.

Publisher independence and independent technical corroboration are different fields.
Articles that explicitly name the same service may be linked as
`reports_same_service`. That relationship means repeated reporting of a named
subject; it is not a dependency, causal claim, or technical corroboration.
Telemetry system names are also distinct from observation modalities. For
example, RIPE RIS BGP activity and an IODA BGP-derived event remain one
`bgp_control_plane` modality, not two independent technical observations.
Likewise, multiple modalities exposed by one aggregator remain limited-source
evidence until a second shared telemetry system corroborates both event scopes.

## Coverage semantics

The topology API reports configured/observed prefixes, why each target was
selected, monitored and incident ASNs/providers, observation modality,
approximate cadence, per-resource sample totals, and telemetry systems with no
observations in the selected window. Target discovery is deterministic and
bounded by `BGP_PREFIXES_PER_ASN` and `MAX_MONITORED_ASNS`. Coverage of a
representative prefix or ASN is not coverage of every affected service, route,
region, or customer path. Sample counts are repeated observations, not
independent corroborations.
