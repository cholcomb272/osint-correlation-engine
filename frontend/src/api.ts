import type {
  Correlation, CoverageSource, EventIntelligenceResponse, GraphResponse, Incident, IntelligenceCluster,
  InvestigationCandidate, KnowledgeGraphResponse,
} from './types'

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { Accept: 'application/json' } })
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.json() as Promise<T>
}

export const api = {
  overview: () => get<Record<string, number | string>>('/api/public/overview'),
  incidents: (days = 30) => get<{ items: Incident[]; total: number }>(`/api/public/incidents?days=${days}&page_size=200`),
  correlations: (days = 30, minimum = 0.08) => get<{ items: Correlation[] }>(`/api/public/correlations?days=${days}&minimum=${minimum}&limit=200`),
  topology: (query: URLSearchParams) => get<GraphResponse>(`/api/public/topology?${query}`),
  trends: (dimension = 'provider') => get<{ items: Array<Record<string, unknown>> }>(`/api/public/trends?days=90&dimension=${dimension}`),
  sourceHealth: () => get<{ items: Array<Record<string, unknown>> }>('/api/public/source-health'),
  investigations: () => get<{ items: Array<Record<string, unknown>> }>('/api/public/investigations'),
  map: (days = 30, domain = '', minimumSignificance = 'low') => {
    const query = new URLSearchParams({ days: String(days), minimum_significance: minimumSignificance })
    if (domain) query.set('domain', domain)
    return get<{ items: Incident[]; coverage_warning: string }>(`/api/public/map?${query}`)
  },
  knowledgeGraph: (query: URLSearchParams) => get<KnowledgeGraphResponse>(`/api/public/knowledge-graph?${query}`),
  clusters: () => get<{ items: IntelligenceCluster[]; semantics: string }>('/api/public/clusters?days=30'),
  investigationCandidates: () => get<{ items: InvestigationCandidate[] }>('/api/public/investigation-candidates'),
  coverage: () => get<{ items: CoverageSource[]; configured_domains: string[]; known_global_gaps: string[] }>('/api/public/coverage'),
  eventIntelligence: (eventId: number) => get<EventIntelligenceResponse>(`/api/public/events/${eventId}/intelligence`),
  entities: (query = '') => get<{ items: Array<Record<string, unknown>>; total: number }>(
    `/api/public/entities?page_size=100${query.length >= 2 ? `&q=${encodeURIComponent(query)}` : ''}`,
  ),
}
