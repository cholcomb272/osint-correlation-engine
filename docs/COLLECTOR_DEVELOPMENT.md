# Collector development guide

Collectors must implement the `Collector` protocol in `app.collectors.base` or provide an adapter with equivalent `CollectorResult` semantics.

Required properties:

- public, documented, passive data access;
- HTTPS endpoint present in the fixed outbound allowlist;
- source-specific timestamp mapping without inventing occurrence times;
- stable fingerprint for idempotent replay;
- bounded response size, timeout, rate, and exponential retry;
- one-source failure isolation;
- checkpoint updates only after durable processing;
- raw metadata retention limited to legally and technically appropriate fields;
- fixtures that do not require a live service.

Do not silently substitute generated measurements when a provider is unavailable. Report the failed run and preserve the prior checkpoint.

Each source must document publisher, collection method, likely reporting delay, retention/backfill limits, and whether it is an original technical observation or a report derived from another upstream source.
