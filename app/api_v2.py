import csv
import hashlib
import io
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.main import (
    Event,
    FEED_SOURCES,
    NetworkMeasurement,
    as_utc,
    authorize,
    collect,
    collect_network_measurements,
    get_db,
)
from app.services.analytics import historical_trends
from app.services.correlation import candidate_correlations, persist_candidates
from app.services.fusion import run_fusion
from app.services.knowledge_graph import knowledge_graph
from app.services.topology import topology
from app.v2_models import (
    AuditLog,
    CollectorRun,
    CorrelationRecord,
    EventEvidence,
    EvidenceArtifact,
    Hypothesis,
    HypothesisEvidence,
    IncidentAssessment,
    Investigation,
    InvestigationEvent,
    InvestigationEvidence,
    InvestigationNote,
    EventClassification,
    EventFieldAssessment,
    EventCluster,
    ClusterEvent,
    IntelligenceEntity,
    IntelligenceRequirement,
    InvestigationCandidate,
    KnowledgeRelationship,
    RelationshipRevision,
    SourceCoverageSnapshot,
)


router = APIRouter()

CAUSES = {
    "confirmed_intrusion",
    "defensive_remediation_disruption",
    "unrelated_operational_failure",
    "unknown",
}
INVESTIGATION_STATES = {"Open", "Monitoring", "Needs corroboration", "Resolved", "Closed"}


def safe_reference_url(value: str) -> str:
    """Validate stored references; the server never fetches these URLs."""
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("must be an absolute HTTP(S) URL without credentials")
    host = parsed.hostname.casefold()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ValueError("local URLs are not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise ValueError("private, loopback, and link-local addresses are not allowed")
    return value.strip()


class EvidenceIn(BaseModel):
    original_url: str = Field(max_length=2000)
    publisher: str = Field(min_length=1, max_length=200)
    upstream_source: str | None = Field(default=None, max_length=200)
    published_at: datetime | None = None
    observed_at: datetime | None = None
    excerpt: str = Field(default="", max_length=10000)
    structured_observation: dict = Field(default_factory=dict)
    raw_metadata: dict = Field(default_factory=dict)
    collection_method: str = Field(default="manual_verified", max_length=100)
    reliability: float = Field(default=0.5, ge=0, le=1)
    verification_status: str = Field(default="unverified", pattern="^(unverified|verified|disputed|retracted)$")
    is_primary_source: bool = False

    @field_validator("original_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return safe_reference_url(value)


class AssessmentIn(BaseModel):
    cause_classification: str = "unknown"
    severity: str = Field(default="unknown", max_length=30)
    evidence_confidence: float = Field(default=0, ge=0, le=1)
    investigation_status: str = Field(default="unreviewed", max_length=40)
    rationale: str = Field(min_length=3, max_length=10000)
    evidence_ids: list[int] = Field(default_factory=list)
    assessed_by: str = Field(default="admin", max_length=100)

    @field_validator("cause_classification")
    @classmethod
    def cause_is_supported(cls, value: str) -> str:
        if value not in CAUSES:
            raise ValueError("unsupported cause classification")
        return value


class InvestigationIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    summary: str = Field(default="", max_length=20000)
    state: str = "Open"
    public: bool = False
    created_by: str = Field(default="admin", max_length=100)

    @field_validator("state")
    @classmethod
    def valid_state(cls, value: str) -> str:
        if value not in INVESTIGATION_STATES:
            raise ValueError("unsupported investigation state")
        return value


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    summary: str | None = Field(default=None, max_length=20000)
    state: str | None = None
    public: bool | None = None

    @field_validator("state")
    @classmethod
    def valid_state(cls, value: str | None) -> str | None:
        if value is not None and value not in INVESTIGATION_STATES:
            raise ValueError("unsupported investigation state")
        return value


class HypothesisIn(BaseModel):
    statement: str = Field(min_length=3, max_length=10000)
    status: str = Field(default="unverified", pattern="^(unverified|supported|weakened|rejected|confirmed)$")
    confidence: float = Field(default=0, ge=0, le=1)
    rationale: str = Field(default="", max_length=10000)
    created_by: str = Field(default="admin", max_length=100)


class HypothesisUpdate(BaseModel):
    status: str | None = Field(default=None, pattern="^(unverified|supported|weakened|rejected|confirmed)$")
    confidence: float | None = Field(default=None, ge=0, le=1)
    rationale: str | None = Field(default=None, max_length=10000)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=20000)
    author: str = Field(default="admin", max_length=100)


class EvidenceLinkIn(BaseModel):
    evidence_id: int
    role: str = Field(default="supports", pattern="^(supports|contradicts|context)$")


class IntelligenceScope(BaseModel):
    domains: list[str] = Field(default_factory=list, max_length=50)
    regions: list[str] = Field(default_factory=list, max_length=100)
    countries: list[str] = Field(default_factory=list, max_length=100)
    organizations: list[str] = Field(default_factory=list, max_length=100)
    entity_ids: list[str] = Field(default_factory=list, max_length=200)
    event_types: list[str] = Field(default_factory=list, max_length=100)
    relationship_types: list[str] = Field(default_factory=list, max_length=100)


class TriggerPolicy(BaseModel):
    minimum_significance: str = Field(default="moderate", pattern="^(unknown|low|moderate|high|critical)$")
    minimum_relevance: float = Field(default=0.6, ge=0, le=1)
    minimum_independent_sources: int = Field(default=1, ge=1, le=20)
    require_cross_domain: bool = False
    anomaly_score_threshold: float | None = Field(default=None, ge=0, le=100)
    create_investigation_candidate: bool = True


class RequirementIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=10000)
    active: bool = True
    priority: str = Field(default="normal", pattern="^(low|normal|high|critical)$")
    scope: IntelligenceScope = Field(default_factory=IntelligenceScope)
    trigger_policy: TriggerPolicy = Field(default_factory=TriggerPolicy)
    created_by: str = Field(default="admin", max_length=100)


class RequirementUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=10000)
    active: bool | None = None
    priority: str | None = Field(default=None, pattern="^(low|normal|high|critical)$")
    scope: IntelligenceScope | None = None
    trigger_policy: TriggerPolicy | None = None


def _audit(db: Session, request: Request, action: str, object_type: str, object_id: str | int | None = None, **details) -> None:
    remote = request.client.host if request.client else "unknown"
    salt = os.getenv("AUDIT_HASH_SALT", os.getenv("API_TOKEN", "local-audit"))
    db.add(
        AuditLog(
            actor="admin_api",
            action=action,
            object_type=object_type,
            object_id=str(object_id) if object_id is not None else None,
            request_id=getattr(request.state, "request_id", None),
            remote_address_hash=hashlib.sha256(f"{salt}|{remote}".encode()).hexdigest(),
            details=details,
        )
    )
    db.commit()


def event_payload(event: Event, now: datetime | None = None) -> dict:
    current = now or datetime.now(timezone.utc)
    return {
        "id": event.id,
        "stable_id": f"incident:{event.id}",
        "source": event.source,
        "title": event.title,
        "url": event.url,
        "observed_at": as_utc(event.observed_at).isoformat(),
        "occurrence_at": as_utc(event.occurrence_at).isoformat() if event.occurrence_at else None,
        "first_observed_at": as_utc(event.first_observed_at).isoformat() if event.first_observed_at else None,
        "publisher_reported_at": as_utc(event.publisher_reported_at).isoformat() if event.publisher_reported_at else None,
        "collected_at": as_utc(event.collected_at or event.ingested_at).isoformat(),
        "scheduled_start_at": as_utc(event.scheduled_start_at).isoformat() if event.scheduled_start_at else None,
        "scheduled_end_at": as_utc(event.scheduled_end_at).isoformat() if event.scheduled_end_at else None,
        "resolved_at": as_utc(event.resolved_at).isoformat() if event.resolved_at else None,
        "category": event.category,
        "domain": event.domain,
        "event_type": event.event_type,
        "significance": event.significance,
        "provider": event.provider,
        "asn": event.asn,
        "region": event.region,
        "service": event.service,
        "datacenter": event.datacenter,
        "latitude": event.latitude,
        "longitude": event.longitude,
        "location_name": event.location_name,
        "language": event.language,
        "extraction_confidence": event.extraction_confidence,
        "ontology_version": event.ontology_version,
        "severity": event.severity,
        "cause_classification": event.cause_classification,
        "investigation_status": event.investigation_status,
        "evidence_confidence": event.confidence,
        "source_reliability": event.source_reliability,
        "is_future": as_utc(event.observed_at) > current,
        "is_scheduled": event.category == "scheduled_maintenance",
        "time_semantics": "scheduled_window_start" if event.category == "scheduled_maintenance" else "publisher_reported_or_observed",
    }


def correlation_payload(db: Session, assessment) -> dict:
    left = db.get(Event, assessment.left_event_id)
    right = db.get(Event, assessment.right_event_id)
    result = assessment.to_dict()
    result["left"] = event_payload(left) if left else None
    result["right"] = event_payload(right) if right else None
    return result


@router.get("/api/public/incidents")
def public_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    days: int = Query(90, ge=1, le=3650),
    provider: str | None = Query(default=None, max_length=100),
    region: str | None = Query(default=None, max_length=100),
    category: str | None = Query(default=None, max_length=60),
    severity: str | None = Query(default=None, max_length=30),
    domain: str | None = Query(default=None, max_length=60),
    event_type: str | None = Query(default=None, max_length=100),
    significance: str | None = Query(default=None, max_length=30),
    q: str | None = Query(default=None, min_length=2, max_length=200),
    include_scheduled: bool = False,
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    conditions = [Event.observed_at >= now - timedelta(days=days), Event.observed_at <= now]
    if not include_scheduled:
        conditions.append(Event.category != "scheduled_maintenance")
    if provider:
        conditions.append(func.lower(Event.provider) == provider.casefold())
    if region:
        conditions.append(func.lower(Event.region) == region.casefold())
    if category:
        conditions.append(Event.category == category)
    if severity:
        conditions.append(Event.severity == severity)
    if domain:
        conditions.append(Event.domain == domain)
    if event_type:
        conditions.append(Event.event_type == event_type)
    if significance:
        conditions.append(Event.significance == significance)
    if q:
        conditions.append(func.lower(Event.title).contains(q.casefold()))
    total = db.scalar(select(func.count()).select_from(Event).where(*conditions)) or 0
    records = db.scalars(
        select(Event).where(*conditions).order_by(Event.observed_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return {"items": [event_payload(event, now) for event in records], "page": page, "page_size": page_size, "total": total}


@router.get("/api/public/correlations")
def public_correlations(
    days: int = Query(30, ge=1, le=3650),
    hours: float = Query(24, gt=0, le=720),
    minimum: float = Query(0.08, ge=0, le=1),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    assessments = candidate_correlations(db, days=days, window_hours=hours, minimum=minimum, limit=limit)
    return {
        "items": [correlation_payload(db, item) for item in assessments],
        "score_semantics": "Scores are transparent heuristic strengths, not probabilities or cyberattack attribution.",
    }


@router.get("/api/public/topology")
def public_topology(
    days: int = Query(30, ge=1, le=3650),
    provider: str | None = Query(default=None, max_length=100),
    region: str | None = Query(default=None, max_length=100),
    severity: str | None = Query(default=None, max_length=30),
    minimum_confidence: float = Query(0, ge=0, le=1),
    edge_type: list[str] | None = Query(default=None),
    include_inferred: bool = Query(False),
    include_hypotheses: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=200),
    focus: str | None = Query(default=None, max_length=300),
    db: Session = Depends(get_db),
):
    return topology(
        db, days=days, provider=provider, region=region, severity=severity,
        minimum_confidence=minimum_confidence, edge_types=edge_type,
        include_inferred=include_inferred, include_hypotheses=include_hypotheses,
        page=page, page_size=page_size, focus=focus,
    )


@router.get("/api/public/providers")
def public_providers(days: int = Query(90, ge=1, le=3650), db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(
        select(Event.provider, func.count(Event.id), func.max(Event.observed_at))
        .where(Event.provider.is_not(None), Event.observed_at >= cutoff, Event.category != "scheduled_maintenance")
        .group_by(Event.provider).order_by(func.count(Event.id).desc())
    ).all()
    return {"items": [{"provider": provider, "incident_count": count, "last_observed_at": as_utc(last).isoformat()} for provider, count, last in rows]}


@router.get("/api/public/trends")
def public_trends(
    days: int = Query(90, ge=14, le=3650),
    dimension: str = Query("provider", pattern="^(provider|region|category)$"),
    db: Session = Depends(get_db),
):
    return {"items": historical_trends(db, days=days, dimension=dimension)}


@router.get("/api/public/replay")
def public_replay(
    cutoff: datetime,
    days: int = Query(30, ge=1, le=3650),
    hours: float = Query(24, gt=0, le=720),
    db: Session = Depends(get_db),
):
    replay_cutoff = as_utc(cutoff)
    if replay_cutoff > datetime.now(timezone.utc):
        raise HTTPException(422, "replay cutoff cannot be in the future")
    assessments = candidate_correlations(db, days=days, window_hours=hours, cutoff=replay_cutoff)
    incidents = db.scalars(
        select(Event).where(
            Event.observed_at >= replay_cutoff - timedelta(days=days), Event.observed_at <= replay_cutoff,
            func.coalesce(Event.publisher_reported_at, Event.first_observed_at, Event.ingested_at, Event.observed_at) <= replay_cutoff,
        ).order_by(Event.observed_at.desc()).limit(500)
    ).all()
    return {
        "cutoff": replay_cutoff.isoformat(),
        "incidents": [event_payload(item, replay_cutoff) for item in incidents],
        "correlations": [correlation_payload(db, item) for item in assessments],
        "knowledge_rule": "Only evidence and reports available at or before the cutoff are included.",
    }


@router.get("/api/public/source-health")
def public_source_health(db: Session = Depends(get_db)):
    rows = db.execute(
        select(CollectorRun).order_by(CollectorRun.collector, CollectorRun.started_at.desc())
    ).scalars().all()
    latest = {}
    for run in rows:
        latest.setdefault(run.collector, run)
    return {
        "items": [
            {
                "collector": run.collector,
                "status": run.status,
                "started_at": as_utc(run.started_at).isoformat(),
                "finished_at": as_utc(run.finished_at).isoformat() if run.finished_at else None,
                "source_freshness_at": as_utc(run.source_freshness_at).isoformat() if run.source_freshness_at else None,
                "inserted": run.inserted,
                "deduplicated": run.deduplicated,
                "error": run.error,
            }
            for run in latest.values()
        ]
    }


@router.get("/api/public/overview")
def public_overview(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    recent = now - timedelta(days=30)
    active = db.scalar(select(func.count()).select_from(Event).where(Event.observed_at.between(recent, now), Event.category.not_in(["scheduled_maintenance", "policy_announcement", "security_advisory"]))) or 0
    anomalies = db.scalar(select(func.count()).select_from(NetworkMeasurement).where(NetworkMeasurement.observed_at.between(recent, now), or_(func.abs(NetworkMeasurement.z_score) >= 2, NetworkMeasurement.source == "ioda"))) or 0
    candidates = candidate_correlations(db, days=30, limit=500)
    return {
        "active_incidents": active,
        "recent_anomalies": anomalies,
        "correlation_candidates": len(candidates),
        "high_confidence_relationships": sum(item.confidence_assessment == "high" for item in candidates),
        "cross_domain_clusters": db.scalar(select(func.count()).select_from(EventCluster).where(EventCluster.status == "candidate", EventCluster.cluster_type == "cross_domain")) or 0,
        "investigation_candidates": db.scalar(select(func.count()).select_from(InvestigationCandidate).where(InvestigationCandidate.status == "new")) or 0,
        "generated_at": now.isoformat(),
        "disclaimer": "Candidates show evidence relationships, not attack attribution.",
    }


@router.get("/api/public/events/{event_id}/intelligence")
def public_event_intelligence(event_id: int, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "event not found")
    classifications = db.scalars(
        select(EventClassification)
        .where(EventClassification.event_id == event_id)
        .order_by(EventClassification.scheme, EventClassification.assessed_at.desc())
    ).all()
    current_classifications = {}
    for item in classifications:
        current_classifications.setdefault(
            item.scheme,
            {
                "label": item.label,
                "parent_label": item.parent_label,
                "knowledge_status": item.knowledge_status,
                "confidence": item.confidence,
                "rationale": item.rationale,
                "evidence_ids": item.evidence_ids,
                "assessed_at": as_utc(item.assessed_at).isoformat(),
            },
        )
    assessments = db.scalars(
        select(EventFieldAssessment)
        .where(EventFieldAssessment.event_id == event_id)
        .order_by(EventFieldAssessment.field_name, EventFieldAssessment.assessed_at.desc())
    ).all()
    current_fields = {}
    for item in assessments:
        current_fields.setdefault(
            item.field_name,
            {
                "value": item.value,
                "knowledge_status": item.knowledge_status,
                "confidence": item.confidence,
                "rationale": item.rationale,
                "plausible_explanations": item.plausible_explanations,
                "evidence_to_strengthen": item.evidence_to_strengthen,
                "evidence_to_weaken": item.evidence_to_weaken,
                "collection_actions": item.collection_actions,
                "evidence_ids": item.evidence_ids,
                "assessed_at": as_utc(item.assessed_at).isoformat(),
            },
        )
    evidence = db.execute(
        select(EvidenceArtifact)
        .join(EventEvidence, EventEvidence.evidence_id == EvidenceArtifact.id)
        .where(EventEvidence.event_id == event_id)
        .order_by(EvidenceArtifact.published_at)
    ).scalars().all()
    graph = knowledge_graph(db, days=3650, focus=f"event:{event_id}", include_contextual=True, page_size=200)
    return {
        "event": event_payload(event),
        "classifications": current_classifications,
        "field_assessments": current_fields,
        "unresolved_fields": [
            name for name, value in current_fields.items()
            if value["knowledge_status"] in {"unresolved", "reported_only"}
        ],
        "evidence": [
            {
                "id": item.id,
                "stable_id": item.stable_id,
                "original_url": item.original_url,
                "publisher": item.publisher,
                "upstream_source": item.upstream_source,
                "published_at": as_utc(item.published_at).isoformat() if item.published_at else None,
                "observed_at": as_utc(item.observed_at).isoformat() if item.observed_at else None,
                "verification_status": item.verification_status,
                "reliability": item.reliability,
                "is_primary_source": item.is_primary_source,
                "collection_method": item.collection_method,
            }
            for item in evidence
        ],
        "relationships": graph["edges"],
        "semantics": "Unresolved fields preserve uncertainty; relevance does not imply causation or attribution.",
    }


@router.get("/api/public/entities")
def public_entities(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    entity_type: str | None = Query(default=None, max_length=60),
    q: str | None = Query(default=None, min_length=2, max_length=200),
    db: Session = Depends(get_db),
):
    conditions = []
    if entity_type:
        conditions.append(IntelligenceEntity.entity_type == entity_type)
    if q:
        conditions.append(func.lower(IntelligenceEntity.canonical_name).contains(q.casefold()))
    total = db.scalar(select(func.count()).select_from(IntelligenceEntity).where(*conditions)) or 0
    records = db.scalars(
        select(IntelligenceEntity)
        .where(*conditions)
        .order_by(IntelligenceEntity.last_seen_at.desc(), IntelligenceEntity.canonical_name)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "items": [
            {
                "stable_id": item.stable_id,
                "entity_type": item.entity_type,
                "canonical_name": item.canonical_name,
                "country_code": item.country_code,
                "region": item.region,
                "latitude": item.latitude,
                "longitude": item.longitude,
                "attributes": item.attributes,
                "first_seen_at": as_utc(item.first_seen_at).isoformat() if item.first_seen_at else None,
                "last_seen_at": as_utc(item.last_seen_at).isoformat() if item.last_seen_at else None,
            }
            for item in records
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/api/public/entities/{stable_id}")
def public_entity(stable_id: str, db: Session = Depends(get_db)):
    entity = db.scalar(select(IntelligenceEntity).where(IntelligenceEntity.stable_id == stable_id))
    if entity is None:
        raise HTTPException(404, "entity not found")
    graph = knowledge_graph(db, days=3650, focus=f"entity:{stable_id}", include_contextual=True, page_size=200)
    node = next((item for item in graph["nodes"] if item["id"] == f"entity:{stable_id}"), None)
    return {"entity": node, "relationships": graph["edges"], "neighbors": [item for item in graph["nodes"] if item["id"] != f"entity:{stable_id}"]}


@router.get("/api/public/knowledge-graph")
def public_knowledge_graph(
    days: int = Query(30, ge=1, le=3650),
    domain: str | None = Query(default=None, max_length=60),
    entity_type: str | None = Query(default=None, max_length=60),
    predicate: list[str] | None = Query(default=None),
    semantic_tier: list[str] | None = Query(default=None),
    minimum_relevance: float = Query(0, ge=0, le=1),
    include_contextual: bool = False,
    focus: str | None = Query(default=None, max_length=120),
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return knowledge_graph(
        db,
        days=days,
        domain=domain,
        entity_type=entity_type,
        predicates=predicate,
        semantic_tiers=semantic_tier,
        minimum_relevance=minimum_relevance,
        include_contextual=include_contextual,
        focus=focus,
        page=page,
        page_size=page_size,
    )


@router.get("/api/public/map")
def public_map(
    days: int = Query(30, ge=1, le=3650),
    domain: str | None = Query(default=None, max_length=60),
    minimum_significance: str = Query("low", pattern="^(unknown|low|moderate|high|critical)$"),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    ranks = {"unknown": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}
    allowed = [value for value, rank in ranks.items() if rank >= ranks[minimum_significance]]
    conditions = [
        Event.observed_at >= datetime.now(timezone.utc) - timedelta(days=days),
        Event.observed_at <= datetime.now(timezone.utc),
        Event.latitude.is_not(None),
        Event.longitude.is_not(None),
        Event.significance.in_(allowed),
    ]
    if domain:
        conditions.append(Event.domain == domain)
    records = db.scalars(select(Event).where(*conditions).order_by(Event.observed_at.desc()).limit(limit)).all()
    return {
        "items": [event_payload(item) for item in records],
        "total_returned": len(records),
        "coverage_warning": "Only events with source-provided or explicitly resolved coordinates appear on the map.",
    }


@router.get("/api/public/clusters")
def public_clusters(
    days: int = Query(30, ge=1, le=3650),
    status_value: str = Query("candidate", alias="status", max_length=30),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    clusters = db.scalars(
        select(EventCluster)
        .where(EventCluster.status == status_value, EventCluster.window_end >= cutoff)
        .order_by(EventCluster.window_end.desc())
        .limit(limit)
    ).all()
    output = []
    for cluster in clusters:
        event_ids = db.scalars(select(ClusterEvent.event_id).where(ClusterEvent.cluster_id == cluster.id)).all()
        output.append(
            {
                "stable_id": cluster.stable_id,
                "title": cluster.title,
                "cluster_type": cluster.cluster_type,
                "status": cluster.status,
                "significance": cluster.significance,
                "anomaly_score": cluster.anomaly_score,
                "explanation": cluster.explanation,
                "dimensions": cluster.dimensions,
                "window_start": as_utc(cluster.window_start).isoformat(),
                "window_end": as_utc(cluster.window_end).isoformat(),
                "event_ids": list(event_ids),
                "event_count": len(event_ids),
            }
        )
    return {"items": output, "semantics": "Cluster membership indicates evidence-connected relevance, not common cause or coordination."}


@router.get("/api/public/investigation-candidates")
def public_investigation_candidates(
    status_value: str = Query("new", alias="status", max_length=30),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    records = db.scalars(
        select(InvestigationCandidate)
        .where(InvestigationCandidate.status == status_value)
        .order_by(InvestigationCandidate.created_at.desc())
        .limit(limit)
    ).all()
    return {
        "items": [
            {
                "stable_id": item.stable_id,
                "cluster_id": item.cluster_id,
                "title": item.title,
                "priority": item.priority,
                "status": item.status,
                "trigger_type": item.trigger_type,
                "rationale": item.rationale,
                "known_facts": item.known_facts,
                "competing_explanations": item.competing_explanations,
                "unresolved_questions": item.unresolved_questions,
                "collection_priorities": item.collection_priorities,
                "created_at": as_utc(item.created_at).isoformat(),
                "last_reassessed_at": as_utc(item.last_reassessed_at).isoformat(),
            }
            for item in records
        ]
    }


@router.get("/api/public/coverage")
def public_coverage(db: Session = Depends(get_db)):
    snapshots = db.scalars(
        select(SourceCoverageSnapshot).order_by(
            SourceCoverageSnapshot.source_id,
            SourceCoverageSnapshot.captured_at.desc(),
        )
    ).all()
    latest = {}
    for item in snapshots:
        latest.setdefault(item.source_id, item)
    items = []
    for source_id, definition in FEED_SOURCES.items():
        item = latest.get(source_id)
        items.append(
            {
                "source_id": source_id,
                "name": definition.name,
                "domains": definition.domains,
                "geographic_scope": definition.geographic_scope,
                "languages": definition.languages,
                "source_role": definition.source_role,
                "adapter": definition.adapter,
                "expected_cadence_minutes": definition.expected_cadence_minutes,
                "status": item.status if item else "not_yet_measured",
                "captured_at": as_utc(item.captured_at).isoformat() if item else None,
                "observed_items": item.observed_items if item else 0,
                "freshness_seconds": item.freshness_seconds if item else None,
                "completeness": item.completeness if item else None,
                "gaps": item.gaps if item else ["No coverage snapshot has been recorded since this source was configured."],
                "notes": item.notes if item else ["Configured source availability is not comprehensive domain coverage."],
            }
        )
    configured_domains = sorted({domain for definition in FEED_SOURCES.values() for domain in definition.domains})
    return {
        "items": items,
        "configured_domains": configured_domains,
        "known_global_gaps": [
            "No comprehensive global aviation, maritime, rail, energy, water, healthcare, or payments telemetry connector is configured.",
            "Most reporting and advisory sources are English-language.",
            "Source health measures collection, not real-world completeness.",
        ],
    }


@router.get("/api/public/intelligence-requirements")
def public_requirements(db: Session = Depends(get_db)):
    records = db.scalars(
        select(IntelligenceRequirement)
        .where(IntelligenceRequirement.active.is_(True))
        .order_by(IntelligenceRequirement.priority.desc(), IntelligenceRequirement.name)
    ).all()
    return {"items": [{"id": item.id, "name": item.name, "description": item.description, "priority": item.priority, "scope": item.scope, "trigger_policy": item.trigger_policy} for item in records]}


def investigation_payload(db: Session, record: Investigation, include_private: bool = False) -> dict:
    event_ids = db.scalars(select(InvestigationEvent.event_id).where(InvestigationEvent.investigation_id == record.id)).all()
    evidence_ids = db.scalars(select(InvestigationEvidence.evidence_id).where(InvestigationEvidence.investigation_id == record.id)).all()
    hypotheses = db.scalars(select(Hypothesis).where(Hypothesis.investigation_id == record.id).order_by(Hypothesis.created_at)).all()
    notes = db.scalars(select(InvestigationNote).where(InvestigationNote.investigation_id == record.id).order_by(InvestigationNote.created_at)).all()
    result = {
        "id": record.id,
        "title": record.title,
        "summary": record.summary,
        "state": record.state,
        "public": record.public,
        "created_at": as_utc(record.created_at).isoformat(),
        "updated_at": as_utc(record.updated_at).isoformat(),
        "events": [event_payload(event) for event in db.scalars(select(Event).where(Event.id.in_(event_ids))).all()] if event_ids else [],
        "evidence_ids": list(evidence_ids),
        "hypotheses": [
            {"id": item.id, "statement": item.statement, "status": item.status, "confidence": item.confidence, "rationale": item.rationale}
            for item in hypotheses
        ],
    }
    timeline = [
        {"timestamp": event["observed_at"], "type": "collected_fact", "label": event["title"], "event_id": event["id"]}
        for event in result["events"]
    ]
    timeline.extend(
        {"timestamp": as_utc(item.created_at).isoformat(), "type": "investigator_hypothesis", "label": item.statement, "hypothesis_id": item.id}
        for item in hypotheses
    )
    if include_private:
        result["notes"] = [
            {"id": note.id, "body": note.body, "assertion_type": note.assertion_type, "author": note.author, "created_at": as_utc(note.created_at).isoformat()}
            for note in notes
        ]
        timeline.extend(
            {"timestamp": as_utc(note.created_at).isoformat(), "type": "investigator_assertion", "label": note.body, "note_id": note.id}
            for note in notes
        )
    result["timeline"] = sorted(timeline, key=lambda item: item["timestamp"])
    return result


@router.get("/api/public/investigations")
def public_investigations(db: Session = Depends(get_db)):
    records = db.scalars(select(Investigation).where(Investigation.public.is_(True)).order_by(Investigation.updated_at.desc()).limit(100)).all()
    return {"items": [investigation_payload(db, record) for record in records]}


@router.get("/api/public/investigations/{investigation_id}")
def public_investigation(investigation_id: int, db: Session = Depends(get_db)):
    record = db.get(Investigation, investigation_id)
    if not record or not record.public:
        raise HTTPException(404, "investigation not found")
    return investigation_payload(db, record)


@router.post("/api/admin/evidence", dependencies=[Depends(authorize)], status_code=201)
def create_evidence(payload: EvidenceIn, request: Request, db: Session = Depends(get_db)):
    retrieved = datetime.now(timezone.utc)
    content = json.dumps(payload.structured_observation, sort_keys=True) + payload.excerpt
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    stable_id = "ev_" + hashlib.sha256(f"{payload.original_url}|{content_hash}".encode()).hexdigest()[:24]
    existing = db.scalar(select(EvidenceArtifact).where(EvidenceArtifact.stable_id == stable_id))
    if existing:
        return {"id": existing.id, "stable_id": existing.stable_id, "created": False}
    artifact = EvidenceArtifact(
        stable_id=stable_id,
        content_hash=content_hash,
        ingested_at=retrieved,
        retrieved_at=retrieved,
        **payload.model_dump(),
    )
    db.add(artifact)
    db.commit()
    db.refresh(artifact)
    _audit(db, request, "evidence.create", "evidence", artifact.id)
    return {"id": artifact.id, "stable_id": artifact.stable_id, "created": True}


@router.post("/api/admin/incidents/{event_id}/evidence", dependencies=[Depends(authorize)], status_code=201)
def link_event_evidence(event_id: int, payload: EvidenceLinkIn, request: Request, db: Session = Depends(get_db)):
    if not db.get(Event, event_id) or not db.get(EvidenceArtifact, payload.evidence_id):
        raise HTTPException(404, "incident or evidence not found")
    link = db.get(EventEvidence, (event_id, payload.evidence_id, payload.role))
    if not link:
        db.add(EventEvidence(event_id=event_id, evidence_id=payload.evidence_id, role=payload.role, added_by="admin"))
        db.commit()
    _audit(db, request, "incident.evidence.link", "event", event_id, evidence_id=payload.evidence_id, role=payload.role)
    return {"linked": True}


@router.post("/api/admin/incidents/{event_id}/assessments", dependencies=[Depends(authorize)], status_code=201)
def assess_incident(event_id: int, payload: AssessmentIn, request: Request, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(404, "incident not found")
    previous = db.scalar(select(IncidentAssessment).where(IncidentAssessment.event_id == event_id).order_by(IncidentAssessment.assessed_at.desc()))
    assessment = IncidentAssessment(event_id=event_id, supersedes_id=previous.id if previous else None, **payload.model_dump())
    db.add(assessment)
    event.cause_classification = payload.cause_classification
    event.severity = payload.severity
    event.investigation_status = payload.investigation_status
    event.confidence = payload.evidence_confidence
    db.commit()
    db.refresh(assessment)
    _audit(db, request, "incident.assess", "event", event_id, assessment_id=assessment.id)
    return {"id": assessment.id, "immutable": True}


@router.get("/api/admin/incidents/{event_id}/assessments", dependencies=[Depends(authorize)])
def assessment_history(event_id: int, db: Session = Depends(get_db)):
    records = db.scalars(select(IncidentAssessment).where(IncidentAssessment.event_id == event_id).order_by(IncidentAssessment.assessed_at.desc())).all()
    return {"items": [{"id": item.id, "cause_classification": item.cause_classification, "severity": item.severity, "evidence_confidence": item.evidence_confidence, "investigation_status": item.investigation_status, "rationale": item.rationale, "evidence_ids": item.evidence_ids, "assessed_by": item.assessed_by, "assessed_at": as_utc(item.assessed_at).isoformat(), "supersedes_id": item.supersedes_id} for item in records]}


@router.post("/api/admin/correlations/rebuild", dependencies=[Depends(authorize)])
def rebuild_correlations(request: Request, days: int = Query(30, ge=1, le=3650), db: Session = Depends(get_db)):
    assessments = candidate_correlations(db, days=days)
    persisted = persist_candidates(db, assessments)
    _audit(db, request, "correlations.rebuild", "correlation", details_count=persisted)
    return {"candidate_pairs": len(assessments), "relationship_records": persisted}


@router.post("/api/admin/fusion/rebuild", dependencies=[Depends(authorize)])
def rebuild_fusion(
    request: Request,
    days: int = Query(90, ge=1, le=3650),
    db: Session = Depends(get_db),
):
    result = run_fusion(db, days=days)
    _audit(
        db,
        request,
        "fusion.rebuild",
        "knowledge_graph",
        days=days,
        relationships=result["relationships"]["relationships_evaluated"],
        clusters=result["clusters"]["clusters"],
    )
    return result


@router.post("/api/admin/intelligence-requirements", dependencies=[Depends(authorize)], status_code=201)
def create_requirement(payload: RequirementIn, request: Request, db: Session = Depends(get_db)):
    existing = db.scalar(
        select(IntelligenceRequirement).where(
            func.lower(IntelligenceRequirement.name) == payload.name.casefold()
        )
    )
    if existing:
        raise HTTPException(409, "an intelligence requirement with this name already exists")
    record = IntelligenceRequirement(
        name=payload.name,
        description=payload.description,
        active=payload.active,
        priority=payload.priority,
        scope=payload.scope.model_dump(),
        trigger_policy=payload.trigger_policy.model_dump(),
        created_by=payload.created_by,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    _audit(db, request, "intelligence_requirement.create", "intelligence_requirement", record.id)
    return {
        "id": record.id,
        "name": record.name,
        "active": record.active,
        "priority": record.priority,
        "scope": record.scope,
        "trigger_policy": record.trigger_policy,
    }


@router.patch("/api/admin/intelligence-requirements/{requirement_id}", dependencies=[Depends(authorize)])
def update_requirement(
    requirement_id: int,
    payload: RequirementUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    record = db.get(IntelligenceRequirement, requirement_id)
    if record is None:
        raise HTTPException(404, "intelligence requirement not found")
    values = payload.model_dump(exclude_unset=True)
    if "scope" in values and payload.scope is not None:
        values["scope"] = payload.scope.model_dump()
    if "trigger_policy" in values and payload.trigger_policy is not None:
        values["trigger_policy"] = payload.trigger_policy.model_dump()
    for key, value in values.items():
        setattr(record, key, value)
    db.commit()
    _audit(
        db,
        request,
        "intelligence_requirement.update",
        "intelligence_requirement",
        record.id,
        fields=sorted(values),
    )
    return {
        "id": record.id,
        "name": record.name,
        "active": record.active,
        "priority": record.priority,
        "scope": record.scope,
        "trigger_policy": record.trigger_policy,
    }


@router.post("/api/admin/collect", dependencies=[Depends(authorize)])
def admin_collect(request: Request, days: int = Query(30, ge=1, le=3650), db: Session = Depends(get_db)):
    result = collect(days)
    _audit(db, request, "collectors.run", "feed_collectors", days=days)
    return result


@router.post("/api/admin/collect/measurements", dependencies=[Depends(authorize)])
def admin_collect_measurements(request: Request, days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db)):
    result = collect_network_measurements(days)
    _audit(db, request, "collectors.run", "measurement_collectors", days=days)
    return result


@router.post("/api/admin/investigations", dependencies=[Depends(authorize)], status_code=201)
def create_investigation(payload: InvestigationIn, request: Request, db: Session = Depends(get_db)):
    record = Investigation(**payload.model_dump())
    db.add(record)
    db.commit()
    db.refresh(record)
    _audit(db, request, "investigation.create", "investigation", record.id)
    return investigation_payload(db, record, include_private=True)


@router.patch("/api/admin/investigations/{investigation_id}", dependencies=[Depends(authorize)])
def update_investigation(investigation_id: int, payload: InvestigationUpdate, request: Request, db: Session = Depends(get_db)):
    record = db.get(Investigation, investigation_id)
    if not record:
        raise HTTPException(404, "investigation not found")
    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(record, key, value)
    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    _audit(db, request, "investigation.update", "investigation", record.id, fields=list(payload.model_dump(exclude_none=True)))
    return investigation_payload(db, record, include_private=True)


@router.get("/api/admin/investigations", dependencies=[Depends(authorize)])
def admin_investigations(db: Session = Depends(get_db)):
    records = db.scalars(select(Investigation).order_by(Investigation.updated_at.desc())).all()
    return {"items": [investigation_payload(db, record, include_private=True) for record in records]}


@router.post("/api/admin/investigations/{investigation_id}/events/{event_id}", dependencies=[Depends(authorize)], status_code=201)
def attach_investigation_event(investigation_id: int, event_id: int, request: Request, db: Session = Depends(get_db)):
    if not db.get(Investigation, investigation_id) or not db.get(Event, event_id):
        raise HTTPException(404, "investigation or event not found")
    if not db.get(InvestigationEvent, (investigation_id, event_id)):
        db.add(InvestigationEvent(investigation_id=investigation_id, event_id=event_id))
        db.commit()
    _audit(db, request, "investigation.event.attach", "investigation", investigation_id, event_id=event_id)
    return {"attached": True}


@router.post("/api/admin/investigations/{investigation_id}/evidence/{evidence_id}", dependencies=[Depends(authorize)], status_code=201)
def attach_investigation_evidence(investigation_id: int, evidence_id: int, request: Request, role: str = Query("context", pattern="^(supports|contradicts|context)$"), db: Session = Depends(get_db)):
    if not db.get(Investigation, investigation_id) or not db.get(EvidenceArtifact, evidence_id):
        raise HTTPException(404, "investigation or evidence not found")
    if not db.get(InvestigationEvidence, (investigation_id, evidence_id, role)):
        db.add(InvestigationEvidence(investigation_id=investigation_id, evidence_id=evidence_id, role=role))
        db.commit()
    _audit(db, request, "investigation.evidence.attach", "investigation", investigation_id, evidence_id=evidence_id, role=role)
    return {"attached": True}


@router.post("/api/admin/investigations/{investigation_id}/hypotheses", dependencies=[Depends(authorize)], status_code=201)
def create_hypothesis(investigation_id: int, payload: HypothesisIn, request: Request, db: Session = Depends(get_db)):
    if not db.get(Investigation, investigation_id):
        raise HTTPException(404, "investigation not found")
    record = Hypothesis(investigation_id=investigation_id, **payload.model_dump())
    db.add(record)
    db.commit()
    db.refresh(record)
    _audit(db, request, "hypothesis.create", "hypothesis", record.id, investigation_id=investigation_id)
    return {"id": record.id, "status": record.status}


@router.patch("/api/admin/hypotheses/{hypothesis_id}", dependencies=[Depends(authorize)])
def update_hypothesis(hypothesis_id: int, payload: HypothesisUpdate, request: Request, db: Session = Depends(get_db)):
    record = db.get(Hypothesis, hypothesis_id)
    if not record:
        raise HTTPException(404, "hypothesis not found")
    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(record, key, value)
    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    _audit(db, request, "hypothesis.update", "hypothesis", record.id, fields=list(payload.model_dump(exclude_none=True)))
    return {"id": record.id, "status": record.status, "confidence": record.confidence}


@router.post("/api/admin/hypotheses/{hypothesis_id}/evidence", dependencies=[Depends(authorize)], status_code=201)
def attach_hypothesis_evidence(hypothesis_id: int, payload: EvidenceLinkIn, request: Request, db: Session = Depends(get_db)):
    if not db.get(Hypothesis, hypothesis_id) or not db.get(EvidenceArtifact, payload.evidence_id):
        raise HTTPException(404, "hypothesis or evidence not found")
    stance = "contradicts" if payload.role == "contradicts" else "supports" if payload.role == "supports" else "context"
    if not db.get(HypothesisEvidence, (hypothesis_id, payload.evidence_id, stance)):
        db.add(HypothesisEvidence(hypothesis_id=hypothesis_id, evidence_id=payload.evidence_id, stance=stance, explanation="Linked by investigator"))
        db.commit()
    _audit(db, request, "hypothesis.evidence.attach", "hypothesis", hypothesis_id, evidence_id=payload.evidence_id, stance=stance)
    return {"attached": True, "stance": stance}


@router.post("/api/admin/investigations/{investigation_id}/notes", dependencies=[Depends(authorize)], status_code=201)
def create_note(investigation_id: int, payload: NoteIn, request: Request, db: Session = Depends(get_db)):
    if not db.get(Investigation, investigation_id):
        raise HTTPException(404, "investigation not found")
    note = InvestigationNote(investigation_id=investigation_id, assertion_type="investigator_assertion", **payload.model_dump())
    db.add(note)
    db.commit()
    db.refresh(note)
    _audit(db, request, "investigation.note.create", "investigation", investigation_id, note_id=note.id)
    return {"id": note.id, "assertion_type": note.assertion_type}


def _investigation_for_export(db: Session, investigation_id: int, public_only: bool) -> tuple[Investigation, dict]:
    record = db.get(Investigation, investigation_id)
    if not record or (public_only and not record.public):
        raise HTTPException(404, "investigation not found")
    return record, investigation_payload(db, record, include_private=not public_only)


@router.get("/api/admin/investigations/{investigation_id}/export", dependencies=[Depends(authorize)])
@router.get("/api/public/investigations/{investigation_id}/export")
def export_investigation(investigation_id: int, request: Request, format: str = Query("json", pattern="^(json|csv|report)$"), db: Session = Depends(get_db)):
    is_admin = request.url.path.startswith("/api/admin/")
    record, payload = _investigation_for_export(db, investigation_id, public_only=not is_admin)
    if format == "json":
        return payload
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "title", "source", "observed_at", "provider", "asn", "region", "category", "cause_classification"])
        writer.writeheader()
        for event in payload["events"]:
            writer.writerow({key: event.get(key) for key in writer.fieldnames})
        return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="investigation-{record.id}.csv"'})
    lines = [f"# {record.title}", "", record.summary, "", f"State: {record.state}", "", "## Evidence-backed incident timeline", ""]
    for event in payload["events"]:
        lines.append(f"- {event['observed_at']} — {event['title']} ({event['source']}) — {event['url']}")
    lines.extend(["", "## Hypotheses", ""])
    for hypothesis in payload["hypotheses"]:
        lines.append(f"- [{hypothesis['status']}] {hypothesis['statement']} — confidence assessment {hypothesis['confidence']:.2f}")
    lines.extend(["", "Correlation and confidence values are evidence assessments, not attribution probabilities."])
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")


@router.get("/api/admin/audit-log", dependencies=[Depends(authorize)])
def audit_log(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)).all()
    return {"items": [{"id": row.id, "occurred_at": as_utc(row.occurred_at).isoformat(), "actor": row.actor, "action": row.action, "object_type": row.object_type, "object_id": row.object_id, "request_id": row.request_id, "details": row.details} for row in rows]}
