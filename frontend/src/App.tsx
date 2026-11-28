import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition, type LayoutOptions } from 'cytoscape'
import { CircleMarker, MapContainer, Popup, TileLayer } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import {
  Activity, AlertTriangle, BarChart3, Clock3, Database, ExternalLink,
  FileSearch, Fullscreen, GitBranch, Globe2, HeartPulse, Layers3, Network,
  Radar, Search, ShieldCheck,
} from 'lucide-react'
import { api } from './api'
import type {
  Correlation, EvidenceSummary, EventIntelligenceResponse, GraphElement, GraphResponse, Incident,
  IntelligenceCluster, InvestigationCandidate, KnowledgeGraphResponse, TelemetryCoverage,
} from './types'

const sections = [
  ['overview', 'Overview', Activity],
  ['situation', 'Global Situation', Globe2],
  ['timeline', 'Intelligence Timeline', Clock3],
  ['knowledge', 'Intelligence Graph', Layers3],
  ['topology', 'Infrastructure Topology', Network],
  ['correlations', 'Correlation Explorer', GitBranch],
  ['investigations', 'Investigation Workspace', FileSearch],
  ['analytics', 'Historical Analytics', BarChart3],
  ['health', 'Coverage & Health', HeartPulse],
  ['admin', 'Administrative Operations', ShieldCheck],
] as const

function useLoad<T>(loader: () => Promise<T>, dependencies: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    loader().then(value => active && setData(value)).catch(reason => active && setError(String(reason)))
    return () => { active = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies)
  return { data, error }
}

const date = (value?: string) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Unknown'
const pct = (value?: number) => `${Math.round((value || 0) * 100)}%`

function Status({ error, empty = false }: { error?: string; empty?: boolean }) {
  if (error) return <div className="state error"><AlertTriangle size={18} /> {error}</div>
  if (empty) return <div className="state">No matching evidence is available for this window.</div>
  return <div className="state"><span className="spinner" /> Loading evidence…</div>
}

function Overview({ onNavigate }: { onNavigate: (section: string) => void }) {
  const { data, error } = useLoad(api.overview)
  const cards = [
    ['Active incidents', 'active_incidents', 'timeline'],
    ['Recent anomalies', 'recent_anomalies', 'topology'],
    ['Correlation candidates', 'correlation_candidates', 'correlations'],
    ['High-confidence relationships', 'high_confidence_relationships', 'correlations'],
    ['Cross-domain clusters', 'cross_domain_clusters', 'situation'],
    ['Investigation candidates', 'investigation_candidates', 'investigations'],
  ]
  return <>
    <header className="section-heading"><div><span className="eyebrow">CURRENT EVIDENCE PICTURE</span><h1>Infrastructure intelligence overview</h1></div>{data && <span className="asof">As of {date(String(data.generated_at))}</span>}</header>
    {!data ? <Status error={error} /> : <><div className="metric-grid">
      {cards.map(([label, key, target]) => <button className="metric" key={key} onClick={() => onNavigate(target)}><span>{label}</span><strong>{String(data[key] ?? 0)}</strong><small>Open details →</small></button>)}
    </div>
    <div className="notice"><ShieldCheck size={20} /><div><strong>Evidence boundary</strong><p>{String(data.disclaimer)}</p></div></div>
    <RecentActivity /></>}
  </>
}

function RecentActivity() {
  const { data, error } = useLoad(() => api.incidents(7))
  if (!data) return <Status error={error} />
  return <div className="panel"><div className="panel-title"><h2>Recent activity</h2><span>{data.total} source records</span></div><div className="activity-list">
    {data.items.slice(0, 8).map(item => <article key={item.id}><span className={`source-dot ${item.category}`} /><time>{date(item.observed_at)}</time><div><strong>{item.title}</strong><small>{item.domain?.replaceAll('_', ' ')} · {item.event_type?.replaceAll('_', ' ')} · {item.location_name || item.region || item.provider || 'affected entity unresolved'}</small></div></article>)}
  </div></div>
}

function Timeline({ onFocus }: { onFocus: (id: string) => void }) {
  const [days, setDays] = useState(30)
  const [query, setQuery] = useState('')
  const { data, error } = useLoad(() => api.incidents(days), [days])
  const items = data?.items.filter(item => `${item.title} ${item.provider} ${item.region}`.toLowerCase().includes(query.toLowerCase())) || []
  const [selected, setSelected] = useState<number | null>(null)
  return <><header className="section-heading"><div><span className="eyebrow">MULTIDOMAIN SOURCE RECORDS</span><h1>Unified intelligence timeline</h1></div></header>
    <div className="toolbar"><label><Search size={15} /><input aria-label="Search incidents" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search provider, region, title" /></label><label>Window<select value={days} onChange={event => setDays(Number(event.target.value))}><option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>1 year</option></select></label></div>
    {!data ? <Status error={error} /> : items.length === 0 ? <Status empty /> : <div className="timeline">{items.map(item => <button key={item.id} onClick={() => setSelected(item.id)}><time>{date(item.occurrence_at || item.observed_at)}</time><span className="timeline-marker" /><div><span className="badges"><i>{item.domain.replaceAll('_', ' ')}</i><i>{item.event_type.replaceAll('_', ' ')}</i><i>{item.significance}</i></span><strong>{item.title}</strong><small>{item.location_name || item.region || item.provider || 'Affected entity unresolved'} · evidence confidence {pct(item.evidence_confidence)}</small></div></button>)}</div>}
    {selected && <EventIntelligence eventId={selected} onTopology={() => onFocus(`incident:${selected}`)} onClose={() => setSelected(null)} />}
  </>
}

function EventIntelligence({ eventId, onTopology, onClose }: { eventId: number; onTopology: () => void; onClose: () => void }) {
  const { data, error } = useLoad(() => api.eventIntelligence(eventId), [eventId])
  return <div className="drawer-backdrop" role="presentation" onMouseDown={event => event.target === event.currentTarget && onClose()}><aside className="event-drawer" role="dialog" aria-modal="true" aria-label="Event intelligence">
    <div className="drawer-header"><div><span className="eyebrow">EVENT INTELLIGENCE</span><h2>{data?.event.title || 'Loading event…'}</h2></div><button className="secondary" onClick={onClose}>Close</button></div>
    {!data ? <Status error={error} /> : <EventIntelligenceDetails data={data} onTopology={onTopology} />}
  </aside></div>
}

function EventIntelligenceDetails({ data, onTopology }: { data: EventIntelligenceResponse; onTopology: () => void }) {
  return <>
    <div className="notice"><ShieldCheck size={20} /><div><strong>Analytical boundary</strong><p>{data.semantics}</p></div></div>
    <div className="drawer-actions"><button className="secondary" onClick={onTopology}><Network size={14} /> Open evidence neighborhood</button><a className="secondary" href={data.event.url} target="_blank" rel="noreferrer">Original source <ExternalLink size={14} /></a></div>
    <section className="intelligence-section"><h3>What is known</h3><div className="classification-grid">{Object.entries(data.classifications).map(([scheme, item]) => <article key={scheme}><span>{scheme.replaceAll('_', ' ')}</span><strong>{item.label.replaceAll('_', ' ')}</strong><small>{item.knowledge_status.replaceAll('_', ' ')} · confidence {pct(item.confidence)}</small><p>{item.rationale}</p></article>)}</div></section>
    <section className="intelligence-section"><h3>Field-level uncertainty</h3>{Object.entries(data.field_assessments).map(([field, item]) => <details key={field} open={data.unresolved_fields.includes(field)}><summary><span>{field.replaceAll('_', ' ')}</span><i className={`knowledge-status ${item.knowledge_status}`}>{item.knowledge_status.replaceAll('_', ' ')}</i></summary><p>{item.rationale}</p>{item.value && <dl><dt>Current value</dt><dd>{item.value}</dd></dl>}{item.plausible_explanations.length > 0 && <p><strong>Plausible explanations:</strong> {item.plausible_explanations.join('; ')}</p>}{item.evidence_to_strengthen.length > 0 && <p><strong>Would strengthen:</strong> {item.evidence_to_strengthen.join('; ')}</p>}{item.collection_actions.length > 0 && <p><strong>Collection actions:</strong> {item.collection_actions.join('; ')}</p>}</details>)}</section>
    <section className="intelligence-section"><h3>Evidence lineage</h3><div className="evidence-list">{data.evidence.map(item => <a key={item.id} href={item.original_url} target="_blank" rel="noreferrer"><strong>{item.publisher}</strong><span>{item.collection_method} · {item.is_primary_source ? 'primary source' : 'third-party report'} · {item.verification_status}</span><small>{date(item.published_at || item.observed_at)}</small></a>)}</div></section>
  </>
}

const significanceColors: Record<string, string> = { critical: '#e86274', high: '#e88d55', moderate: '#e3a84f', low: '#4fc4df', unknown: '#82929e' }

function GlobalSituation({ onEvent }: { onEvent: (id: number) => void }) {
  const [days, setDays] = useState(30)
  const [domain, setDomain] = useState('')
  const [minimum, setMinimum] = useState('low')
  const { data, error } = useLoad(() => api.map(days, domain, minimum), [days, domain, minimum])
  const { data: clusters } = useLoad(api.clusters)
  const domains = ['cybersecurity', 'internet_telecommunications', 'critical_infrastructure', 'transportation_logistics', 'geopolitical_strategic', 'environmental_natural']
  return <><header className="section-heading"><div><span className="eyebrow">GLOBAL SITUATIONAL AWARENESS</span><h1>Evidence-backed event map</h1></div></header>
    <div className="toolbar"><label>Window<select value={days} onChange={event => setDays(Number(event.target.value))}><option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>1 year</option></select></label><label>Domain<select value={domain} onChange={event => setDomain(event.target.value)}><option value="">All configured domains</option>{domains.map(value => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select></label><label>Minimum significance<select value={minimum} onChange={event => setMinimum(event.target.value)}><option>unknown</option><option>low</option><option>moderate</option><option>high</option><option>critical</option></select></label></div>
    <div className="situation-grid"><section className="map-panel">{!data && <Status error={error} />}<MapContainer center={[20, 0]} zoom={2} minZoom={2} maxZoom={10} scrollWheelZoom className="world-map"><TileLayer attribution="&copy; OpenStreetMap contributors" url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />{data?.items.map(item => <CircleMarker key={item.id} center={[Number(item.latitude), Number(item.longitude)]} radius={item.significance === 'critical' ? 10 : item.significance === 'high' ? 8 : 6} pathOptions={{ color: significanceColors[item.significance] || significanceColors.unknown, fillOpacity: .72, weight: 2 }} eventHandlers={{ click: () => onEvent(item.id) }}><Popup><strong>{item.title}</strong><br />{item.domain.replaceAll('_', ' ')} · {item.event_type.replaceAll('_', ' ')}<br /><button className="map-link" onClick={() => onEvent(item.id)}>Inspect evidence</button></Popup></CircleMarker>)}</MapContainer><p>{data?.coverage_warning || 'Loading coordinate coverage…'}</p></section><section className="cluster-feed"><div className="panel-title"><h2>Cross-domain clusters</h2><span>Relevance, not common cause</span></div>{clusters?.items.length ? clusters.items.map(item => <ClusterCard key={item.stable_id} item={item} />) : <Status empty />}</section></div>
  </>
}

function ClusterCard({ item }: { item: IntelligenceCluster }) {
  return <article><span className="badges"><i>{item.cluster_type.replaceAll('_', ' ')}</i><i>{item.significance}</i></span><h3>{item.title}</h3><p>{item.explanation}</p><small>{item.event_count} events · {date(item.window_start)} to {date(item.window_end)}</small></article>
}

function IntelligenceGraph({ initialFocus }: { initialFocus: string }) {
  const host = useRef<HTMLDivElement>(null)
  const graph = useRef<Core | null>(null)
  const [days, setDays] = useState(30)
  const [domain, setDomain] = useState('')
  const [entityType, setEntityType] = useState('')
  const [includeContext, setIncludeContext] = useState(false)
  const [focus, setFocus] = useState(initialFocus)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null)
  const query = useMemo(() => {
    const params = new URLSearchParams({ days: String(days), page_size: '300', include_contextual: String(includeContext) })
    if (domain) params.set('domain', domain)
    if (entityType) params.set('entity_type', entityType)
    if (focus) params.set('focus', focus.replace(/^incident:/, 'event:'))
    return params
  }, [days, domain, entityType, includeContext, focus])
  const { data, error } = useLoad(() => api.knowledgeGraph(query), [query.toString()])

  useEffect(() => setFocus(initialFocus), [initialFocus])
  useEffect(() => {
    if (!host.current || !data) return
    graph.current?.destroy()
    const elements: ElementDefinition[] = [
      ...data.nodes.map(node => ({ data: { ...node, display_label: node.label } })),
      ...data.edges.map(edge => ({ data: { ...edge, relationship_type: edge.predicate, visual_label: edge.predicate.replaceAll('_', ' ') } })),
    ]
    const cy = cytoscape({ container: host.current, elements, minZoom: .15, maxZoom: 4, hideEdgesOnViewport: true, textureOnViewport: true, style: [
      { selector: 'node', style: { label: 'data(display_label)', color: '#dce8ef', 'background-color': '#4fc4df', 'font-size': 9, 'text-wrap': 'wrap', 'text-max-width': '110px', 'text-valign': 'bottom', 'text-margin-y': 8, 'text-background-color': '#071017', 'text-background-opacity': .88, 'text-background-padding': '2px', width: 34, height: 34, 'border-width': 1, 'border-color': '#9fe9f7' } },
      { selector: 'node[type = "event"]', style: { shape: 'round-rectangle', 'background-color': '#e3a84f', 'border-color': '#ffd58d' } },
      { selector: 'node[type = "entity"]', style: { shape: 'hexagon', 'background-color': '#4fc4df' } },
      { selector: 'node[entity_type = "organization"]', style: { 'background-color': '#7f76e8' } },
      { selector: 'node[entity_type = "geographic_region"]', style: { shape: 'round-triangle', 'background-color': '#46ba91' } },
      { selector: 'node[entity_type = "vulnerability"]', style: { shape: 'diamond', 'background-color': '#e86274' } },
      { selector: 'edge', style: { width: 1.6, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'line-color': '#46ba91', 'target-arrow-color': '#46ba91', opacity: .72 } },
      { selector: 'edge[semantic_tier = "documented"]', style: { 'line-color': '#4fc4df', 'target-arrow-color': '#4fc4df' } },
      { selector: 'edge[semantic_tier = "supported_inference"]', style: { 'line-style': 'dashed', 'line-color': '#e3a84f', 'target-arrow-color': '#e3a84f', label: 'data(visual_label)', color: '#e3c37b', 'font-size': 7, 'text-background-color': '#071017', 'text-background-opacity': .9 } },
      { selector: 'edge[semantic_tier = "contextual"]', style: { 'line-style': 'dotted', 'line-color': '#82929e', 'target-arrow-color': '#82929e', opacity: .5 } },
      { selector: 'edge[semantic_tier = "hypothesis"]', style: { 'line-style': 'dotted', 'line-color': '#c77bd8', 'target-arrow-color': '#c77bd8' } },
      { selector: 'edge[semantic_tier = "contradicted"]', style: { 'line-style': 'dashed', width: 3, 'line-color': '#e86274', 'target-arrow-color': '#e86274' } },
      { selector: ':selected', style: { 'overlay-color': '#69d2ee', 'overlay-opacity': .2, 'overlay-padding': 8 } },
    ], layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.5, padding: 45, animate: false } as LayoutOptions })
    cy.on('tap', 'node, edge', event => setSelected(event.target.data()))
    cy.on('dbltap', 'node', event => setFocus(event.target.id()))
    graph.current = cy
    return () => cy.destroy()
  }, [data])

  useEffect(() => {
    graph.current?.nodes().forEach(node => {
      node.style('opacity', !search || String(node.data('label')).toLowerCase().includes(search.toLowerCase()) ? 1 : .12)
    })
  }, [search])
  return <><header className="section-heading"><div><span className="eyebrow">PERSISTENT INTELLIGENCE ONTOLOGY</span><h1>Intelligence knowledge graph</h1></div><button className="secondary" onClick={() => host.current?.parentElement?.requestFullscreen()}><Fullscreen size={15} /> Fullscreen</button></header>
    <div className="notice"><ShieldCheck size={20} /><div><strong>Layered relationship semantics</strong><p>{data?.semantics.causal_boundary || 'Observed facts, documented dependencies, analytical inferences, contextual associations, and hypotheses remain visually and analytically distinct.'}</p></div></div>
    <div className="graph-filterbar"><label><Search size={14} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Find event or entity" /></label><label>Window<select value={days} onChange={event => setDays(Number(event.target.value))}><option value={7}>7d</option><option value={30}>30d</option><option value={90}>90d</option><option value={365}>1y</option></select></label><label>Domain<input value={domain} onChange={event => setDomain(event.target.value)} placeholder="All" /></label><label>Entity type<select value={entityType} onChange={event => setEntityType(event.target.value)}><option value="">All</option><option value="organization">Organization</option><option value="service">Service</option><option value="autonomous_system">Autonomous system</option><option value="geographic_region">Geographic region</option><option value="vulnerability">Vulnerability</option></select></label><label className="context-toggle"><input type="checkbox" checked={includeContext} onChange={event => setIncludeContext(event.target.checked)} /> Include contextual associations</label></div>
    <div className="graph-shell"><div className="graph-stage">{!data && <Status error={error} />}<div className="cy" ref={host} /><div className="legend"><span className="observed">Observed</span><span className="reported">Documented</span><span className="inferred">Supported inference</span><span className="hypothesis">Hypothesis</span><span className="contradiction">Contradicted</span></div></div><KnowledgeInspector data={selected} onExpand={setFocus} /></div>
  </>
}

function KnowledgeInspector({ data, onExpand }: { data: Record<string, unknown> | null; onExpand: (id: string) => void }) {
  if (!data) return <aside className="inspector"><Layers3 size={26} /><h2>Knowledge inspector</h2><p>Select a node or edge to inspect its semantic tier, evidence dimensions, provenance, and causal boundary.</p></aside>
  return <aside className="inspector active"><span className="eyebrow">{String(data.type || data.predicate || 'knowledge record').replaceAll('_', ' ')}</span><h2>{String(data.label || data.predicate || data.id)}</h2>{Boolean(data.semantic_tier) && <div className={`semantic-callout ${String(data.semantic_tier)}`}><strong>{String(data.semantic_tier).replaceAll('_', ' ')}</strong><span>{data.causal_claim ? 'A causal claim is recorded; inspect its evidence.' : 'No causal or attribution claim is made.'}</span></div>}{['entity_type', 'domain', 'event_type', 'significance', 'relevance', 'evidence_quality', 'correlation_strength', 'causal_confidence', 'observed_at'].map(key => data[key] !== undefined && data[key] !== null ? <dl key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{key.endsWith('_at') ? date(String(data[key])) : typeof data[key] === 'number' && key !== 'significance' ? pct(Number(data[key])) : String(data[key]).replaceAll('_', ' ')}</dd></dl> : null)}{Boolean(data.explanation) && <p>{String(data.explanation)}</p>}{Boolean(data.url) && <a href={String(data.url)} target="_blank" rel="noreferrer">Open source <ExternalLink size={14} /></a>}{Boolean(data.id) && <button className="secondary" onClick={() => onExpand(String(data.id))}>Expand neighborhood</button>}</aside>
}

const edgeTypes = ['shares_provider', 'shares_asn', 'shares_region', 'reports_same_service', 'depends_on', 'confirmed_dependency', 'temporal_coincidence', 'independent_corroboration', 'observed_network_anomaly', 'suspected_common_cause', 'contradicts_hypothesis']

function investigationElements(data: GraphResponse): ElementDefinition[] {
  const nodes = data.nodes.map(node => ({ ...node }))
  const byId = new Map(nodes.map(node => [String(node.data.id), node]))
  const incidents = nodes.filter(node => node.data.type === 'incident')
  const groups = new Map<string, typeof incidents>()
  const position = new Map<string, { x: number; y: number }>()

  for (const incident of incidents) {
    const key = incident.data.provider
      ? `provider:${String(incident.data.provider).toLowerCase()}`
      : incident.data.asn
        ? `asn:${String(incident.data.asn).toLowerCase()}`
        : `source:${String(incident.data.source || 'unscoped').toLowerCase()}`
    groups.set(key, [...(groups.get(key) || []), incident])
  }

  const orderedGroups = [...groups.entries()].sort((left, right) => right[1].length - left[1].length || left[0].localeCompare(right[0]))
  let cursorX = 80
  let maximumY = 0
  for (const [, members] of orderedGroups) {
    members.sort((left, right) => String(left.data.observed_at || '').localeCompare(String(right.data.observed_at || '')) || String(left.data.id).localeCompare(String(right.data.id)))
    const columns = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(members.length))))
    const groupWidth = Math.max(230, columns * 160)
    const centerX = cursorX + groupWidth / 2
    const first = members[0]
    const scopeIds = [
      first.data.provider ? `provider:${String(first.data.provider).toLowerCase()}` : '',
      first.data.provider ? `cloud_platform:${String(first.data.provider).toLowerCase()}` : '',
      first.data.asn ? `asn:${String(first.data.asn).toLowerCase()}` : '',
    ].filter(id => byId.has(id))
    scopeIds.forEach((id, index) => position.set(id, { x: centerX + (index - (scopeIds.length - 1) / 2) * 105, y: 60 }))

    const incidentStartY = scopeIds.length ? 205 : 130
    members.forEach((incident, index) => {
      const x = cursorX + 80 + (index % columns) * 160
      const y = incidentStartY + Math.floor(index / columns) * 100
      position.set(String(incident.data.id), { x, y })
      maximumY = Math.max(maximumY, y)
    })

    const contextual = nodes.filter(node =>
      !position.has(String(node.data.id)) && ['region', 'service', 'datacenter'].includes(String(node.data.type)) &&
      members.some(member => [member.data.region, member.data.service, member.data.datacenter].filter(Boolean).map(value => String(value).toLowerCase()).includes(String(node.data.label || '').toLowerCase())),
    )
    contextual.forEach((node, index) => position.set(String(node.data.id), { x: centerX + (index - (contextual.length - 1) / 2) * 95, y: 125 }))
    cursorX += groupWidth + 150
  }

  const attachmentCount = new Map<string, number>()
  for (const edge of data.edges) {
    const source = String(edge.data.source)
    const target = String(edge.data.target)
    const incidentId = source.startsWith('incident:') ? source : target.startsWith('incident:') ? target : ''
    const attachmentId = incidentId === source ? target : source
    if (!incidentId || position.has(attachmentId)) continue
    const incidentPosition = position.get(incidentId)
    const attachment = byId.get(attachmentId)
    if (!incidentPosition || !attachment || !['evidence', 'network_anomaly', 'hypothesis', 'investigation_cluster'].includes(String(attachment.data.type))) continue
    const count = attachmentCount.get(incidentId) || 0
    const direction = count % 2 === 0 ? -1 : 1
    const distance = 46 + Math.floor(count / 2) * 34
    position.set(attachmentId, { x: incidentPosition.x + direction * distance, y: incidentPosition.y + 46 })
    attachmentCount.set(incidentId, count + 1)
  }

  const unpositioned = nodes.filter(node => !position.has(String(node.data.id)))
  unpositioned.forEach((node, index) => position.set(String(node.data.id), { x: 100 + (index % 10) * 125, y: maximumY + 175 + Math.floor(index / 10) * 100 }))
  return [
    ...nodes.map(node => ({ ...node, position: position.get(String(node.data.id)) } as ElementDefinition)),
    ...data.edges as ElementDefinition[],
  ]
}

function Topology({ initialFocus }: { initialFocus: string }) {
  const host = useRef<HTMLDivElement>(null)
  const graph = useRef<Core | null>(null)
  const [days, setDays] = useState(30)
  const [provider, setProvider] = useState('')
  const [region, setRegion] = useState('')
  const [severity, setSeverity] = useState('')
  const [confidence, setConfidence] = useState(0)
  const [layout, setLayout] = useState('investigation')
  const [search, setSearch] = useState('')
  const [focus, setFocus] = useState(initialFocus)
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null)
  const [enabledEdges, setEnabledEdges] = useState<string[]>(edgeTypes)
  const [showInferred, setShowInferred] = useState(false)
  const [showHypotheses, setShowHypotheses] = useState(false)
  const [page, setPage] = useState(1)
  const query = useMemo(() => {
    const params = new URLSearchParams({ days: String(days), page: String(page), page_size: '100', minimum_confidence: String(confidence) })
    if (provider) params.set('provider', provider)
    if (region) params.set('region', region)
    if (severity) params.set('severity', severity)
    if (focus) params.set('focus', focus)
    params.set('include_inferred', String(showInferred))
    params.set('include_hypotheses', String(showHypotheses))
    enabledEdges.forEach(value => params.append('edge_type', value))
    return params
  }, [days, page, provider, region, severity, confidence, focus, enabledEdges, showInferred, showHypotheses])
  const { data, error } = useLoad(() => api.topology(query), [query.toString()])

  useEffect(() => setFocus(initialFocus), [initialFocus])
  useEffect(() => {
    if (!host.current || !data) return
    graph.current?.destroy()
    const elements = layout === 'investigation' ? investigationElements(data) : [...data.nodes, ...data.edges] as ElementDefinition[]
    const cy = cytoscape({
      container: host.current,
      elements,
      minZoom: 0.15,
      maxZoom: 4,
      hideEdgesOnViewport: true,
      textureOnViewport: true,
      style: [
        { selector: 'node', style: { 'background-color': '#546474', label: 'data(display_label)', color: '#d9e7ef', 'font-size': 9, 'min-zoomed-font-size': 2, 'text-wrap': 'wrap', 'text-max-width': '105px', 'text-valign': 'bottom', 'text-margin-y': 8, 'text-background-color': '#071017', 'text-background-opacity': 0.86, 'text-background-padding': '2px', width: 28, height: 28, 'border-width': 1, 'border-color': '#8395a5' } },
        { selector: 'node[type = "incident"]', style: { 'background-color': '#f0a83b', shape: 'round-rectangle', width: 34, height: 34, 'border-color': '#ffd089' } },
        { selector: 'node[record_kind = "security_advisory"]', style: { 'background-color': '#8b78d7', 'border-color': '#c6b9ff', shape: 'round-diamond' } },
        { selector: 'node[record_kind = "policy_announcement"]', style: { 'background-color': '#62727e', 'border-color': '#9cabb5', shape: 'round-rectangle' } },
        { selector: 'node[type = "provider"]', style: { 'background-color': '#36a4c7', shape: 'hexagon', width: 42, height: 42 } },
        { selector: 'node[type = "cloud_platform"]', style: { 'background-color': '#248fb4', shape: 'hexagon', width: 46, height: 46 } },
        { selector: 'node[type = "asn"]', style: { 'background-color': '#7f76e8', shape: 'diamond' } },
        { selector: 'node[type = "region"]', style: { 'background-color': '#45bb91', shape: 'round-triangle' } },
        { selector: 'node[type = "network_anomaly"]', style: { 'background-color': '#e56373', shape: 'star' } },
        { selector: 'node[type = "evidence"]', style: { 'background-color': '#9ba8b4', shape: 'rectangle' } },
        { selector: 'node[type = "hypothesis"]', style: { 'background-color': '#d482e5', shape: 'vee' } },
        { selector: 'node[type = "investigation_cluster"]', style: { 'background-color': '#24475a', shape: 'round-rectangle', width: 52, height: 38, 'border-color': '#62bad1', 'border-width': 2 } },
        { selector: 'edge', style: { width: 1.5, 'line-color': '#526778', 'target-arrow-color': '#526778', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', opacity: 0.76, 'font-size': 7, color: '#e3b764', 'text-background-color': '#071017', 'text-background-opacity': 0.9, 'text-background-padding': '2px', 'text-rotation': 'autorotate' } },
        { selector: 'edge[evidence_basis = "observed"]', style: { 'line-style': 'solid', width: 1.6, 'line-color': '#4ebc95', 'target-arrow-color': '#4ebc95', opacity: 0.58 } },
        { selector: 'edge[evidence_basis = "reported"]', style: { 'line-style': 'dashed', 'line-color': '#62bad1', 'target-arrow-color': '#62bad1', label: 'data(visual_label)' } },
        { selector: 'edge[relationship_type = "observed_on"], edge[relationship_type = "supports_observation"], edge[relationship_type = "observed_network_anomaly"][evidence_basis = "observed"]', style: { 'curve-style': 'taxi', 'taxi-direction': 'auto', 'taxi-turn': 35 } },
        { selector: 'edge[evidence_basis = "inferred"]', style: { 'line-style': 'dashed', 'line-color': '#e7ab54', 'target-arrow-color': '#e7ab54', label: 'data(visual_label)' } },
        { selector: 'edge[evidence_basis = "hypothesis"]', style: { 'line-style': 'dotted', 'line-color': '#d482e5', 'target-arrow-color': '#d482e5', label: 'data(visual_label)' } },
        { selector: 'edge[relationship_type = "confirmed_dependency"]', style: { label: 'data(visual_label)', color: '#7de0bc' } },
        { selector: 'edge[relationship_type = "contradicts_hypothesis"]', style: { 'line-style': 'dashed', 'line-color': '#ee6376', 'target-arrow-color': '#ee6376', width: 3 } },
        { selector: ':selected', style: { 'overlay-color': '#69d2ee', 'overlay-opacity': 0.18, 'overlay-padding': 8 } },
      ],
      layout: layoutOptions(layout),
    })
    cy.on('tap', 'node, edge', event => setSelected(event.target.data()))
    cy.on('dbltap', 'node[type = "incident"]', event => setFocus(event.target.id()))
    graph.current = cy
    return () => cy.destroy()
  }, [data, layout])

  useEffect(() => {
    if (!graph.current) return
    graph.current.nodes().forEach(node => {
      const visible = !search || String(node.data('label') || '').toLowerCase().includes(search.toLowerCase())
      node.style('opacity', visible ? 1 : 0.12)
    })
  }, [search])

  const fullscreen = () => host.current?.parentElement?.requestFullscreen()
  return <><header className="section-heading"><div><span className="eyebrow">EVIDENCE TOPOLOGY</span><h1>Infrastructure topology</h1></div><button className="secondary" onClick={fullscreen}><Fullscreen size={15} /> Fullscreen</button></header>
    {data && <><EvidenceStrengthPanel summary={data.evidence_summary} /><TelemetryCoveragePanel coverage={data.telemetry_coverage} /></>}
    <div className="notice graph-mode-note"><ShieldCheck size={20} /><div><strong>Evidence-first view</strong><p>Direct observations and explicit dependencies are shown by default. Inferred candidates and hypotheses are opt-in and never assert causation.</p></div></div>
    <div className="graph-filterbar">
      <label><Search size={14} /><input aria-label="Search graph" value={search} onChange={event => setSearch(event.target.value)} placeholder="Find a node" /></label>
      <label>Window<select value={days} onChange={event => { setDays(Number(event.target.value)); setPage(1) }}><option value={7}>7d</option><option value={30}>30d</option><option value={90}>90d</option><option value={365}>1y</option></select></label>
      <label>Provider<input value={provider} onChange={event => setProvider(event.target.value)} placeholder="All" /></label>
      <label>Region<input value={region} onChange={event => setRegion(event.target.value)} placeholder="All" /></label>
      <label>Severity<select value={severity} onChange={event => setSeverity(event.target.value)}><option value="">All</option><option>critical</option><option>high</option><option>moderate</option><option>low</option><option>unknown</option></select></label>
      <label>Min confidence<select value={confidence} onChange={event => setConfidence(Number(event.target.value))}><option value={0}>Any</option><option value={0.25}>25%</option><option value={0.5}>50%</option><option value={0.75}>75%</option></select></label>
      <label>Layout<select value={layout} onChange={event => setLayout(event.target.value)}><option value="investigation">Investigation hierarchy</option><option value="cose">Force exploration</option><option value="breadthfirst">Generic hierarchy</option><option value="concentric">Concentric</option><option value="circle">Circle</option><option value="grid">Grid</option></select></label>
    </div>
    <div className="evidence-mode-controls"><label><input type="checkbox" checked={showInferred} onChange={event => setShowInferred(event.target.checked)} /> Show inferred candidates <small>not causal</small></label><label><input type="checkbox" checked={showHypotheses} onChange={event => setShowHypotheses(event.target.checked)} /> Show investigator hypotheses <small>unverified</small></label></div>
    <details className="edge-filters"><summary>Relationship-type filters ({enabledEdges.length}/{edgeTypes.length})</summary><div>{edgeTypes.map(type => <label key={type}><input type="checkbox" checked={enabledEdges.includes(type)} onChange={() => setEnabledEdges(current => current.includes(type) ? current.filter(item => item !== type) : [...current, type])} />{type.replaceAll('_', ' ')}</label>)}</div></details>
    <div className="graph-shell">
      <div className="graph-stage">{!data && <Status error={error} />}<div className="cy" ref={host} aria-label="Interactive evidence topology" /><div className="legend"><span className="observed">Direct observation</span><span className="reported">Repeated reporting</span><span className="inferred">Candidate — not causal</span><span className="hypothesis">Hypothesis — unverified</span><span className="contradiction">Contradictory evidence</span></div></div>
      <Inspector data={selected} onExpand={id => setFocus(id)} />
    </div>
    {data && <div className="pagination"><button disabled={page === 1} onClick={() => setPage(value => value - 1)}>Previous</button><span>Page {page} · {data.pagination.total_incidents} incidents</span><button disabled={!data.pagination.has_next} onClick={() => setPage(value => value + 1)}>Next</button><button onClick={() => setFocus('')}>Clear neighborhood</button></div>}
  </>
}

function EvidenceStrengthPanel({ summary }: { summary: EvidenceSummary }) {
  const metrics = [
    ['Direct observations', summary.direct_observations, 'Source records and technical observations'],
    ['Confirmed dependencies', summary.confirmed_dependencies, 'Evidence-backed dependency records'],
    ['Repeated reporting', summary.reported_relationships, 'Same named service; not technical corroboration'],
    ['Inferred candidates', summary.inferred_relationships, 'Hidden by default; not causal'],
    ['Temporal associations', summary.temporal_associations, 'Never sufficient by themselves'],
    ['Hypotheses', summary.hypotheses, 'Investigator assertions; unverified'],
    ['Independent technical', summary.independent_technical_corroboration, 'Candidate pairs with multiple shared observation modalities'],
  ]
  return <section className="evidence-summary" aria-label="Evidence strength summary"><div className="panel-title"><h2>Evidence strength</h2><span>{summary.visible_edges} edges visible · {summary.hidden_inferred_edges} inferred hidden</span></div><div>{metrics.map(([label, value, note]) => <article key={String(label)}><span>{label}</span><strong>{value}</strong><small>{note}</small></article>)}</div></section>
}

function formatInterval(seconds?: number) {
  if (!seconds) return 'No cadence'
  if (seconds >= 3600) return `${Math.round(seconds / 3600)}h cadence`
  if (seconds >= 60) return `${Math.round(seconds / 60)}m cadence`
  return `${seconds}s cadence`
}

function TelemetryCoveragePanel({ coverage }: { coverage: TelemetryCoverage }) {
  const observedSources = coverage.sources.filter(source => source.status === 'observed')
  const missingSources = coverage.sources.filter(source => source.status !== 'observed')
  const asnCoverage = coverage.incident_asn_count ? `${coverage.covered_incident_asn_count}/${coverage.incident_asn_count}` : 'No normalized ASNs'
  const providerCoverage = coverage.incident_provider_count ? `${coverage.covered_incident_provider_count}/${coverage.incident_provider_count}` : 'No normalized providers'
  return <section className="coverage-panel" aria-label="Telemetry coverage"><div className="coverage-heading"><div><span className="eyebrow">DATA COVERAGE</span><h2>Telemetry visibility, not incident proof</h2></div><span className={missingSources.length ? 'coverage-limited' : 'coverage-complete'}>{missingSources.length ? 'Limited coverage' : 'Configured sources reporting'}</span></div><div className="coverage-metrics"><article><strong>{coverage.monitored_prefix_count}</strong><span>monitored prefixes</span><small>{coverage.incident_aware_prefix_count} selected from recent incident ASNs</small></article><article><strong>{asnCoverage}</strong><span>incident ASN coverage</span><small>{coverage.monitored_asn_count} monitored ASNs</small></article><article><strong>{providerCoverage}</strong><span>incident provider coverage</span><small>Bounded ASN-derived targets</small></article><article><strong>{coverage.observation_family_count}</strong><span>observation modalities</span><small>{coverage.observation_families.map(item => item.family).join(', ') || 'No observations'}</small></article><article><strong>{formatInterval(coverage.observation_interval_seconds)}</strong><span>observation interval</span><small>{observedSources.length}/{coverage.sources.length} telemetry systems returned data</small></article></div><p>{coverage.scope_note}</p>{missingSources.length > 0 && <div className="coverage-gap"><AlertTriangle size={15} /><span>Missing telemetry in this window: {missingSources.map(source => source.source).join(', ')}</span></div>}<details><summary>Monitored resource details ({coverage.resources.length})</summary><div className="table-wrap"><table><thead><tr><th>Source</th><th>Resource</th><th>Provider / ASN</th><th>Signals / modality</th><th>Samples</th><th>Interval</th></tr></thead><tbody>{coverage.resources.map(resource => <tr key={`${resource.source}-${resource.resource}`}><td>{resource.source}</td><td>{resource.resource}{resource.incident_aware ? ' · incident target' : ''}</td><td>{resource.provider || '—'} / {resource.asn || '—'}</td><td>{resource.signal_types.join(', ')}<br />{resource.observation_families.join(', ')}</td><td>{resource.sample_count}</td><td>{formatInterval(resource.observation_interval_seconds)}</td></tr>)}</tbody></table></div></details></section>
}

function layoutOptions(name: string): LayoutOptions {
  if (name === 'investigation') return { name: 'preset', fit: true, padding: 55, animate: false } as LayoutOptions
  if (name === 'cose') return { name: 'cose', randomize: false, animate: false, nodeRepulsion: () => 7000, idealEdgeLength: () => 110 }
  if (name === 'breadthfirst') return { name: 'breadthfirst', directed: true, animate: false, avoidOverlap: true, spacingFactor: 1.6, roots: 'node[type = "provider"], node[type = "cloud_platform"], node[type = "asn"]' } as LayoutOptions
  return { name } as LayoutOptions
}

function Inspector({ data, onExpand }: { data: Record<string, unknown> | null; onExpand: (id: string) => void }) {
  if (!data) return <aside className="inspector"><Database size={26} /><h2>Evidence inspector</h2><p>Select a node or relationship to inspect provenance, assessment status, and supporting or contradictory evidence.</p></aside>
  const url = typeof data.url === 'string' && /^https?:\/\//.test(data.url) ? data.url : ''
  return <aside className="inspector active"><span className="eyebrow">{String(data.type || data.relationship_type || 'ENTITY').replaceAll('_', ' ')}</span><h2>{String(data.label || data.relationship_type || data.id)}</h2>
    {Boolean(data.semantic_status) && <div className={`semantic-callout ${String(data.evidence_basis || '')}`}><strong>{String(data.semantic_status).replaceAll('_', ' ')}</strong><span>{data.causal_claim === false ? 'This relationship does not assert causation or malicious activity.' : 'Inspect the supporting evidence before drawing conclusions.'}</span></div>}
    {['record_kind', 'evidence_basis', 'semantic_status', 'causal_claim', 'assessment_status', 'confidence_assessment', 'confidence', 'source', 'provider', 'asn', 'region', 'resource', 'observed_at', 'first_observed_at', 'last_observed_at'].map(key => data[key] !== undefined && data[key] !== null ? <dl key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{key.includes('_at') ? date(String(data[key])) : key === 'causal_claim' && data[key] === false ? 'No' : String(data[key]).replaceAll('_', ' ')}</dd></dl> : null)}
    {data.explanation ? <p>{String(data.explanation)}</p> : null}
    {url && <a href={url} target="_blank" rel="noreferrer">Open original source <ExternalLink size={14} /></a>}
    {(String(data.id || '').startsWith('incident:') || String(data.id || '').startsWith('investigation_cluster:')) && <button className="secondary" onClick={() => onExpand(String(data.id))}>Expand neighborhood</button>}
  </aside>
}

function Correlations() {
  const [minimum, setMinimum] = useState(0.08)
  const { data, error } = useLoad(() => api.correlations(30, minimum), [minimum])
  return <><header className="section-heading"><div><span className="eyebrow">EXPLAINABLE CANDIDATES</span><h1>Correlation explorer</h1></div><label className="inline-control">Minimum strength<select value={minimum} onChange={event => setMinimum(Number(event.target.value))}><option value={0.08}>Any candidate</option><option value={0.25}>0.25</option><option value={0.5}>0.50</option><option value={0.75}>0.75</option></select></label></header>
    <div className="notice"><AlertTriangle size={20} /><div><strong>Strength is not probability</strong><p>Temporal coincidence alone cannot create a candidate. Inspect technical scope, source derivation, and contradictory evidence.</p></div></div>
    {!data ? <Status error={error} /> : data.items.length === 0 ? <Status empty /> : <div className="correlation-list">{data.items.map((item, index) => <CorrelationCard key={`${item.left_event_id}-${item.right_event_id}-${index}`} item={item} />)}</div>}
  </>
}

function CorrelationCard({ item }: { item: Correlation }) {
  const [open, setOpen] = useState(false)
  const basisLabel = item.evidence_basis === 'observed' ? 'technically observed candidate' : item.evidence_basis === 'reported' ? 'repeated reporting · not technical' : 'inferred · not causal'
  return <article className="correlation-card"><button onClick={() => setOpen(value => !value)}><span className={`strength ${item.confidence_assessment}`}>{item.strength.toFixed(2)}</span><div><span className="badges"><i className="candidate-badge">{basisLabel}</i>{item.relationship_types.map(type => <i key={type}>{type.replaceAll('_', ' ')}</i>)}</span><strong>{item.left.title}</strong><span className="connector">↕ related candidate ↕</span><strong>{item.right.title}</strong></div><small>{open ? 'Collapse' : 'Explain'}</small></button>{open && <div className="explanation"><p>{item.explanation}</p><div><section><h3>Supporting evidence</h3><ul>{item.supporting_factors.map(value => <li key={value}>{value}</li>)}</ul></section><section><h3>Contradictory / limiting evidence</h3>{item.contradictory_factors.length ? <ul>{item.contradictory_factors.map(value => <li key={value}>{value}</li>)}</ul> : <p>No contradictory artifact is currently linked; absence is not confirmation.</p>}</section></div></div>}</article>
}

function Investigations() {
  const { data, error } = useLoad(api.investigations)
  const { data: candidates } = useLoad(api.investigationCandidates)
  return <><header className="section-heading"><div><span className="eyebrow">PERSISTENT WORKSPACES</span><h1>Investigations and autonomous candidates</h1></div></header><div className="notice"><FileSearch size={20} /><div><strong>Facts and assertions remain distinct</strong><p>Candidate investigations expose why they were surfaced, competing explanations, and unanswered questions. Promotion to a managed investigation remains an authenticated action.</p></div></div>
    <section className="candidate-section"><div className="panel-title"><h2>Autonomous investigation candidates</h2><span>{candidates?.items.length || 0} awaiting assessment</span></div>{!candidates ? <Status /> : candidates.items.length === 0 ? <Status empty /> : <div className="candidate-grid">{candidates.items.map(item => <InvestigationCandidateCard key={item.stable_id} item={item} />)}</div>}</section>
    <section className="candidate-section"><div className="panel-title"><h2>Public investigator workspaces</h2><span>Evidence-backed reports</span></div>{!data ? <Status error={error} /> : data.items.length === 0 ? <Status empty /> : <div className="card-grid">{data.items.map(item => <article className="panel" key={String(item.id)}><span className="eyebrow">{String(item.state)}</span><h2>{String(item.title)}</h2><p>{String(item.summary)}</p><a href={`/api/public/investigations/${item.id}/export?format=report`}>Readable report</a></article>)}</div>}</section>
  </>
}

function InvestigationCandidateCard({ item }: { item: InvestigationCandidate }) {
  return <article><span className="badges"><i>{item.priority} priority</i><i>{item.trigger_type.replaceAll('_', ' ')}</i></span><h3>{item.title}</h3><p>{item.rationale}</p><details><summary>Known facts ({item.known_facts.length})</summary><ul>{item.known_facts.map(value => <li key={value}>{value}</li>)}</ul></details><details><summary>Competing explanations ({item.competing_explanations.length})</summary><ul>{item.competing_explanations.map(value => <li key={value}>{value}</li>)}</ul></details><details><summary>Unresolved questions ({item.unresolved_questions.length})</summary><ul>{item.unresolved_questions.map(value => <li key={value}>{value}</li>)}</ul></details></article>
}

function Analytics() {
  const [dimension, setDimension] = useState('provider')
  const { data, error } = useLoad(() => api.trends(dimension), [dimension])
  return <><header className="section-heading"><div><span className="eyebrow">ROBUST HISTORICAL COMPARISON</span><h1>Historical analytics</h1></div><label className="inline-control">Dimension<select value={dimension} onChange={event => setDimension(event.target.value)}><option value="provider">Provider</option><option value="region">Region</option><option value="category">Category</option></select></label></header>
    <p className="method-note">Robust anomaly scores use median absolute deviation. Coverage gaps and zero-MAD series remain visible instead of being presented as calibrated probabilities.</p>
    {!data ? <Status error={error} /> : data.items.length === 0 ? <Status empty /> : <div className="analytics-list">{data.items.slice(0, 20).map(item => <article key={String(item.value)}><div><strong>{String(item.value)}</strong><small>coverage {pct(Number(item.coverage_ratio))} · median {String(item.daily_median)} · recent avg {String(item.recent_daily_average)}</small></div><Sparkline values={item.series as number[]} /><span className={Number(item.robust_anomaly_score || 0) > 3 ? 'anomaly' : ''}>{item.robust_anomaly_score === null ? 'insufficient variation' : `robust z ${item.robust_anomaly_score}`}</span></article>)}</div>}
  </>
}

function Sparkline({ values }: { values: number[] }) {
  const max = Math.max(1, ...values)
  const points = values.map((value, index) => `${(index / Math.max(1, values.length - 1)) * 160},${38 - (value / max) * 34}`).join(' ')
  return <svg className="sparkline" viewBox="0 0 160 40" role="img" aria-label="Historical event frequency"><polyline points={points} fill="none" stroke="currentColor" strokeWidth="2" /></svg>
}

function SourceHealth() {
  const { data, error } = useLoad(api.sourceHealth)
  const { data: coverage } = useLoad(api.coverage)
  return <><header className="section-heading"><div><span className="eyebrow">COLLECTION OPERATIONS</span><h1>Source health and visibility coverage</h1></div></header>
    {coverage && <><div className="coverage-domain-strip">{coverage.configured_domains.map(value => <span key={value}>{value.replaceAll('_', ' ')}</span>)}</div><div className="notice"><AlertTriangle size={20} /><div><strong>Known visibility gaps</strong><p>{coverage.known_global_gaps.join(' ')}</p></div></div><div className="source-coverage-grid">{coverage.items.map(item => <article key={item.source_id}><span className={`health ${item.status}`}>{item.status.replaceAll('_', ' ')}</span><h3>{item.name}</h3><p>{item.domains.map(value => value.replaceAll('_', ' ')).join(', ')}</p><small>{item.source_role.replaceAll('_', ' ')} · {item.geographic_scope.join(', ')} · {item.languages.join(', ')}</small>{item.gaps.map(gap => <em key={gap}>{gap}</em>)}</article>)}</div></>}
    {!data ? <Status error={error} /> : data.items.length === 0 ? <Status empty /> : <div className="table-wrap"><table><thead><tr><th>Collector</th><th>Status</th><th>Freshness</th><th>Inserted</th><th>Deduplicated</th><th>Last error</th></tr></thead><tbody>{data.items.map(item => <tr key={String(item.collector)}><td>{String(item.collector)}</td><td><span className={`health ${item.status}`}>{String(item.status)}</span></td><td>{date(item.source_freshness_at as string)}</td><td>{String(item.inserted)}</td><td>{String(item.deduplicated)}</td><td>{String(item.error || '—')}</td></tr>)}</tbody></table></div>}
  </>
}

function AdminOperations() {
  return <><header className="section-heading"><div><span className="eyebrow">PRIVILEGED WORKFLOWS</span><h1>Administrative operations</h1></div></header><div className="notice"><ShieldCheck size={20} /><div><strong>No secret is accepted by this dashboard</strong><p>Collection, moderation, assessments, and investigation changes use the authenticated admin API or the server-side CLI. Tokens never enter browser storage or frontend assets.</p></div></div><div className="terminal"><code>docker compose exec -T worker python -m app.cli collect --days 365</code><code>docker compose exec -T worker python -m app.cli collect-measurements --days 30</code><code>docker compose exec -T worker python -m app.cli correlate --days 30</code><code>docker compose exec -T worker python -m app.cli fusion --days 90</code><code>docker compose exec -T worker python -m app.cli health</code></div><div className="panel"><h2>Operational endpoints</h2><p><a href="/health">Liveness</a> · <a href="/ready">Readiness</a> · <a href="/docs">OpenAPI documentation</a> · <a href="/metrics">Prometheus metrics</a></p></div></>
}

export default function App() {
  const [active, setActive] = useState('overview')
  const [focus, setFocus] = useState('')
  const navigate = (section: string) => setActive(section)
  const focusGraph = (id: string) => { setFocus(id); setActive('topology') }
  const inspectMappedEvent = (id: number) => { setFocus(`event:${id}`); setActive('knowledge') }
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><span><Network /></span><div><strong>OSINT</strong><small>Fusion Platform</small></div></div><nav aria-label="Primary navigation">{sections.map(([id, label, Icon]) => <button key={id} className={active === id ? 'active' : ''} onClick={() => navigate(id)}><Icon size={17} />{label}</button>)}</nav><div className="sidebar-foot"><span className="live-dot" /> Public read-only view<small>Evidence over narrative</small></div></aside><main><div className="mobile-brand"><Network /> OSINT Intelligence Fusion</div>{active === 'overview' && <Overview onNavigate={navigate} />}{active === 'situation' && <GlobalSituation onEvent={inspectMappedEvent} />}{active === 'timeline' && <Timeline onFocus={focusGraph} />}{active === 'knowledge' && <IntelligenceGraph initialFocus={focus} />}{active === 'topology' && <Topology initialFocus={focus} />}{active === 'correlations' && <Correlations />}{active === 'investigations' && <Investigations />}{active === 'analytics' && <Analytics />}{active === 'health' && <SourceHealth />}{active === 'admin' && <AdminOperations />}</main></div>
}
