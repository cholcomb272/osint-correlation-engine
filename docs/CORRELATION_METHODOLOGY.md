# Correlation methodology

Correlation candidates are evidence triage, not causation or cyber attribution.

## Dimensions

The evaluator keeps these components visible and separately testable:

1. temporal proximity (maximum contribution 0.10);
2. shared provider (0.30), ASN (0.35), and region (0.10);
3. documented provider dependency;
4. semantic overlap after stop-word removal;
5. incident-type compatibility;
6. passive network anomaly magnitude;
7. independent technical corroboration;
8. publisher and upstream-source derivation;
9. source reporting delay;
10. scheduled maintenance and future-event safeguards;
11. contradictory evidence.

Weights are transparent heuristics. They have not been calibrated as probabilities.

Evidence dimensions are not assumed to be independent. When a provider and its configured ASN describe the same scope, both facts remain visible but the provider contribution is discounted so the pair is scored once at the more specific ASN weight.

## Candidate gate

An event pair must be time-compatible, incident-type compatible, and have a positive technical component beyond time and generic language. Consequently, CISA policy/news records and security advisories do not produce operational dependency candidates. Scheduled maintenance is excluded by default and future scheduled windows are never shown as occurred incidents.

Different publishers do not prove technical independence. Known shared upstream
derivation is discounted. Independent technical corroboration requires at least
two distinct observation modalities and at least two shared telemetry systems
associated with both event scopes. Multiple APIs reporting the same BGP
control-plane behavior do not satisfy that rule. Multiple modalities from one
aggregator also remain limited-source evidence rather than independent
corroboration.

## Confidence language

`low`, `moderate`, and `high` are assessment bands over heuristic strength. `high` also requires independent technical telemetry. Each response includes supporting factors, contradictions, and observations that would strengthen or weaken the candidate.

The public topology is evidence-first: direct observations and confirmed dependencies are visible initially, while inferred candidates and investigator hypotheses require explicit opt-in. An inferred edge is labeled as a non-causal candidate before inspection.

## Baselines

Historical views compute rolling daily frequency by provider, region, or category. Median and median absolute deviation provide a robust anomaly score, and adjacent-window median shifts identify change-point candidates. Coverage ratio is exposed because a zero can mean either no incident or missing source data.

## Regression benchmark

`python -m app.cli benchmark` evaluates versioned synthetic scenarios covering
timing-only coincidences, confirmed dependencies, defensive remediation,
maintenance, shared-upstream duplication, independent network modalities,
same-modality feeds, limited-source multi-modal evidence, contradictory
evidence, and delayed historical reports.
The emitted confusion matrix and precision/recall values detect code regressions
against those fixtures only. They are not real-world accuracy estimates or
calibrated probability claims.
