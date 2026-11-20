import type { GraphResponse, Incident, Correlation } from './types'

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
}
