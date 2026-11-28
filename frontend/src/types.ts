export interface Incident {
  id: number
  stable_id: string
  source: string
  title: string
  url: string
  observed_at: string
  occurrence_at?: string
  first_observed_at?: string
  published_at?: string
  collected_at?: string
  category: string
  domain: string
  event_type: string
  significance: string
  provider?: string
  asn?: string
  region?: string
  service?: string
  severity: string
  cause_classification: string
  evidence_confidence: number
  is_scheduled: boolean
  latitude?: number
  longitude?: number
  location_name?: string
  language?: string
}

export interface KnowledgeNode {
  id: string
  type: 'event' | 'entity'
  label: string
  domain?: string
  event_type?: string
  significance?: string
  entity_type?: string
  observed_at?: string
  latitude?: number
  longitude?: number
  source?: string
  url?: string
}

export interface KnowledgeEdge {
  id: string
  source: string
  target: string
  predicate: string
  semantic_tier: string
  relevance: number
  evidence_quality: number
  correlation_strength: number
  causal_confidence?: number
  causal_claim: boolean
  explanation: string
  provenance: Record<string, unknown>
  evidence: Record<string, number[]>
}

export interface KnowledgeGraphResponse {
  nodes: KnowledgeNode[]
  edges: KnowledgeEdge[]
  pagination: { page: number; page_size: number; total_relationships: number; has_next: boolean }
  filters: Record<string, unknown>
  generated_at: string
  semantics: Record<string, string>
}

export interface IntelligenceCluster {
  stable_id: string
  title: string
  cluster_type: string
  status: string
  significance: string
  anomaly_score?: number
  explanation: string
  dimensions: { domains?: string[]; event_types?: string[] }
  window_start: string
  window_end: string
  event_ids: number[]
  event_count: number
}

export interface InvestigationCandidate {
  stable_id: string
  title: string
  priority: string
  status: string
  trigger_type: string
  rationale: string
  known_facts: string[]
  competing_explanations: string[]
  unresolved_questions: string[]
  collection_priorities: string[]
  created_at: string
  last_reassessed_at: string
}

export interface CoverageSource {
  source_id: string
  name: string
  domains: string[]
  geographic_scope: string[]
  languages: string[]
  source_role: string
  adapter: string
  expected_cadence_minutes?: number
  status: string
  captured_at?: string
  observed_items: number
  freshness_seconds?: number
  completeness?: number
  gaps: string[]
  notes: string[]
}

export interface EventIntelligenceResponse {
  event: Incident
  classifications: Record<string, {
    label: string
    parent_label?: string
    knowledge_status: string
    confidence: number
    rationale: string
    assessed_at: string
  }>
  field_assessments: Record<string, {
    value?: string
    knowledge_status: string
    confidence: number
    rationale: string
    plausible_explanations: string[]
    evidence_to_strengthen: string[]
    evidence_to_weaken: string[]
    collection_actions: string[]
    assessed_at: string
  }>
  unresolved_fields: string[]
  evidence: Array<{
    id: number
    original_url: string
    publisher: string
    upstream_source?: string
    published_at?: string
    observed_at?: string
    verification_status: string
    reliability: string
    is_primary_source: boolean
    collection_method: string
  }>
  relationships: KnowledgeEdge[]
  semantics: string
}

export interface GraphElement {
  data: Record<string, string | number | boolean | string[] | null | undefined>
}

export interface EvidenceSummary {
  direct_observations: number
  confirmed_dependencies: number
  reported_relationships: number
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
