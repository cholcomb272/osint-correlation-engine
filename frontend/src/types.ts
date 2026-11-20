export interface Incident {
  id: number
  stable_id: string
  source: string
  title: string
  url: string
  observed_at: string
  category: string
  provider?: string
  asn?: string
  region?: string
  service?: string
  severity: string
  cause_classification: string
  evidence_confidence: number
  is_scheduled: boolean
}

export interface GraphElement {
  data: Record<string, string | number | boolean | string[] | null | undefined>
}

export interface EvidenceSummary {
  direct_observations: number
  confirmed_dependencies: number
  inferred_relationships: number
  temporal_associations: number
  hypotheses: number
  independent_technical_corroboration: number
  visible_edges: number
  hidden_inferred_edges: number
}

export interface TelemetryResource {
  source: string
  resource: string
  provider?: string
  asn?: string
  signal_types: string[]
  observation_families: string[]
  target_selection_reasons: string[]
  incident_aware: boolean
  sample_count: number
  first_observed_at: string
  last_observed_at: string
  observation_interval_seconds?: number
}

export interface TelemetryCoverage {
  window_start: string
  window_end: string
  configured_prefixes: string[]
  configured_asns: string[]
  observed_prefixes: string[]
  monitored_prefix_count: number
  incident_aware_prefix_count: number
  monitored_asn_count: number
  incident_asn_count: number
  covered_incident_asn_count: number
  asn_coverage_ratio?: number
  incident_provider_count: number
  covered_incident_provider_count: number
  provider_coverage_ratio?: number
  observation_interval_seconds?: number
  sources: Array<{ source: string; sample_count: number; status: string }>
  observation_families: Array<{ family: string; sample_count: number }>
  observation_family_count: number
  missing_event_asns: string[]
  missing_event_providers: string[]
  resources: TelemetryResource[]
  scope_note: string
}

export interface GraphResponse {
  nodes: GraphElement[]
  edges: GraphElement[]
  pagination: { page: number; page_size: number; total_incidents: number; has_next: boolean }
  evidence_summary: EvidenceSummary
  telemetry_coverage: TelemetryCoverage
  view: { mode: string; include_inferred: boolean; include_hypotheses: boolean; default_layout: string }
  score_semantics: string
}

export interface Correlation {
  left_event_id: number
  right_event_id: number
  relationship_types: string[]
  strength: number
  confidence_assessment: string
  explanation: string
  supporting_factors: string[]
  contradictory_factors: string[]
  evidence_basis: string
  independent_publishers: boolean
  independent_technical_corroboration: boolean
  left: Incident
  right: Incident
}
