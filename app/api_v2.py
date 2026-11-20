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
    NetworkMeasurement,
    as_utc,
    authorize,
    collect,
    collect_network_measurements,
    get_db,
)
from app.services.analytics import historical_trends
from app.services.correlation import candidate_correlations, persist_candidates
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
        "provider": event.provider,
        "asn": event.asn,
        "region": event.region,
        "service": event.service,
        "datacenter": event.datacenter,
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
    active = db.scalar(select(func.count()).select_from(Event).where(Event.observed_at.between(recent, now), Event.category == "service_incident")) or 0
    anomalies = db.scalar(select(func.count()).select_from(NetworkMeasurement).where(NetworkMeasurement.observed_at.between(recent, now), or_(func.abs(NetworkMeasurement.z_score) >= 2, NetworkMeasurement.source == "ioda"))) or 0
    candidates = candidate_correlations(db, days=30, limit=500)
    return {
        "active_incidents": active,
        "recent_anomalies": anomalies,
        "correlation_candidates": len(candidates),
        "high_confidence_relationships": sum(item.confidence_assessment == "high" for item in candidates),
        "generated_at": now.isoformat(),
        "disclaimer": "Candidates show evidence relationships, not attack attribution.",
    }


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
