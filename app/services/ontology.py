"""Unified intelligence ontology and evidence-backed graph materialization."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.main import Event, as_utc
from app.v2_models import (
    EntityAlias,
    EventClassification,
    EventEntity,
    EventEvidence,
    EventFieldAssessment,
    EvidenceArtifact,
    IntelligenceEntity,
    KnowledgeRelationship,
    RelationshipEvidence,
    RelationshipRevision,
)


ONTOLOGY_VERSION = "fusion-v1"
SPACE = re.compile(r"\s+")
GENERIC_MENTIONS = {
    "cloud",
    "network",
    "service",
    "system",
    "application",
    "platform",
    "security advisory",
}


def normalize_name(value: str) -> str:
    return SPACE.sub(" ", value.strip().casefold()).strip(" .,:;–—-")


def _stable_entity_id(entity_type: str, normalized_name: str) -> str:
    digest = hashlib.sha256(f"{entity_type}|{normalized_name}".encode()).hexdigest()[:24]
    return f"ent_{digest}"


def _event_evidence_ids(db: Session, event_id: int) -> list[int]:
    return list(
        db.scalars(
            select(EventEvidence.evidence_id)
            .where(EventEvidence.event_id == event_id)
            .order_by(EventEvidence.evidence_id)
        ).all()
    )


def upsert_entity(
    db: Session,
    *,
    entity_type: str,
    name: str,
    observed_at: datetime,
    attributes: dict | None = None,
    country_code: str | None = None,
    region: str | None = None,
    latitude: float | None = None,
    longitude: float | None = None,
    source: str = "system",
    confidence: float = 0.5,
) -> IntelligenceEntity | None:
    canonical = SPACE.sub(" ", str(name or "").strip())[:300]
    normalized = normalize_name(canonical)
    if not normalized or normalized in GENERIC_MENTIONS:
        return None
    entity = db.scalar(
        select(IntelligenceEntity).where(
            IntelligenceEntity.entity_type == entity_type,
            IntelligenceEntity.normalized_name == normalized,
        )
    )
    stamp = as_utc(observed_at)
    if entity is None:
        entity = IntelligenceEntity(
            stable_id=_stable_entity_id(entity_type, normalized),
            entity_type=entity_type,
            canonical_name=canonical,
            normalized_name=normalized,
            country_code=country_code,
            region=region,
            latitude=latitude,
            longitude=longitude,
            attributes=attributes or {},
            first_seen_at=stamp,
            last_seen_at=stamp,
        )
        db.add(entity)
        db.flush()
    else:
        entity.first_seen_at = min(as_utc(entity.first_seen_at), stamp) if entity.first_seen_at else stamp
        entity.last_seen_at = max(as_utc(entity.last_seen_at), stamp) if entity.last_seen_at else stamp
        if attributes:
            entity.attributes = {**(entity.attributes or {}), **attributes}
        entity.country_code = entity.country_code or country_code
        entity.region = entity.region or region
        entity.latitude = entity.latitude if entity.latitude is not None else latitude
        entity.longitude = entity.longitude if entity.longitude is not None else longitude
    alias = db.scalar(
        select(EntityAlias).where(
            EntityAlias.entity_id == entity.id,
            EntityAlias.normalized_alias == normalized,
        )
    )
    if alias is None:
        db.add(
            EntityAlias(
                entity_id=entity.id,
                alias=canonical,
                normalized_alias=normalized,
                source=source,
                confidence=confidence,
            )
        )
    return entity


def _link_event_entity(
    db: Session,
    event: Event,
    entity: IntelligenceEntity | None,
    role: str,
    confidence: float,
    evidence_ids: list[int],
    extraction_method: str,
) -> None:
    if entity is None:
        return
    key = (event.id, entity.id, role)
    link = db.get(EventEntity, key)
    if link is None:
        db.add(
            EventEntity(
                event_id=event.id,
                entity_id=entity.id,
                role=role,
                confidence=confidence,
                extraction_method=extraction_method,
                evidence_ids=evidence_ids,
                first_observed_at=event.occurrence_at or event.observed_at,
                last_observed_at=event.publisher_reported_at or event.observed_at,
            )
        )
    else:
        link.confidence = max(link.confidence, confidence)
        link.evidence_ids = sorted(set(link.evidence_ids or []) | set(evidence_ids))
        link.last_observed_at = max(
            as_utc(link.last_observed_at or event.observed_at),
            as_utc(event.publisher_reported_at or event.observed_at),
        )


def _latest_classification(db: Session, event_id: int, scheme: str) -> EventClassification | None:
    return db.scalar(
        select(EventClassification)
        .where(EventClassification.event_id == event_id, EventClassification.scheme == scheme)
        .order_by(EventClassification.assessed_at.desc(), EventClassification.id.desc())
        .limit(1)
    )


def _classify(
    db: Session,
    event: Event,
    *,
    scheme: str,
    label: str,
    parent: str | None,
    confidence: float,
    rationale: str,
    evidence_ids: list[int],
) -> None:
    if not label:
        return
    latest = _latest_classification(db, event.id, scheme)
    if latest and latest.label == label and latest.parent_label == parent and abs(latest.confidence - confidence) < 0.001:
        return
    db.add(
        EventClassification(
            event_id=event.id,
            scheme=scheme,
            label=label,
            parent_label=parent,
            knowledge_status="observed" if confidence >= 0.9 else "asserted",
            confidence=confidence,
            rationale=rationale,
            evidence_ids=evidence_ids,
            classifier_version=ONTOLOGY_VERSION,
            supersedes_id=latest.id if latest else None,
        )
    )


def _latest_field(db: Session, event_id: int, field_name: str) -> EventFieldAssessment | None:
    return db.scalar(
        select(EventFieldAssessment)
        .where(EventFieldAssessment.event_id == event_id, EventFieldAssessment.field_name == field_name)
        .order_by(EventFieldAssessment.assessed_at.desc(), EventFieldAssessment.id.desc())
        .limit(1)
    )


def _assess_field(
    db: Session,
    event: Event,
    *,
    field_name: str,
    value: dict,
    knowledge_status: str,
    confidence: float,
    rationale: str,
    plausible_explanations: list[str] | None = None,
    strengthen: list[str] | None = None,
    weaken: list[str] | None = None,
    collection_actions: list[str] | None = None,
    evidence_ids: list[int],
) -> None:
    latest = _latest_field(db, event.id, field_name)
    signature = json.dumps(value, sort_keys=True, default=str)
    if (
        latest
        and latest.knowledge_status == knowledge_status
        and json.dumps(latest.value or {}, sort_keys=True, default=str) == signature
        and abs(latest.confidence - confidence) < 0.001
        and latest.rationale == rationale
    ):
        return
    db.add(
        EventFieldAssessment(
            event_id=event.id,
            field_name=field_name,
            value=value,
            knowledge_status=knowledge_status,
            confidence=confidence,
            rationale=rationale,
            plausible_explanations=plausible_explanations or [],
            evidence_to_strengthen=strengthen or [],
            evidence_to_weaken=weaken or [],
            collection_actions=collection_actions or [],
            evidence_ids=evidence_ids,
            assessed_by=f"system:{ONTOLOGY_VERSION}",
            supersedes_id=latest.id if latest else None,
        )
    )


def _relationship_identity(subject_ref: str, predicate: str, object_ref: str) -> str:
    value = f"{subject_ref}|{predicate}|{object_ref}"
    return "krel_" + hashlib.sha256(value.encode()).hexdigest()[:24]


def upsert_relationship(
    db: Session,
    *,
    subject_ref: str,
    predicate: str,
    object_ref: str,
    semantic_tier: str,
    relevance: float,
    evidence_quality: float,
    correlation_strength: float,
    causal_confidence: float | None,
    explanation: str,
    evidence_ids: list[int],
    provenance: dict,
    first_observed_at: datetime | None,
    last_observed_at: datetime | None,
    attributes: dict | None = None,
) -> KnowledgeRelationship:
    stable_id = _relationship_identity(subject_ref, predicate, object_ref)
    relationship = db.scalar(
        select(KnowledgeRelationship).where(KnowledgeRelationship.stable_id == stable_id)
    )
    changed = False
    if relationship is None:
        relationship = KnowledgeRelationship(
            stable_id=stable_id,
            subject_ref=subject_ref,
            predicate=predicate,
            object_ref=object_ref,
            semantic_tier=semantic_tier,
            relevance=relevance,
            evidence_quality=evidence_quality,
            correlation_strength=correlation_strength,
            causal_confidence=causal_confidence,
            explanation=explanation,
            provenance=provenance,
            attributes=attributes or {},
            first_observed_at=first_observed_at,
            last_observed_at=last_observed_at,
        )
        db.add(relationship)
        db.flush()
        changed = True
    else:
        merged_provenance = {**(relationship.provenance or {}), **provenance}
        merged_attributes = {**(relationship.attributes or {}), **(attributes or {})}
        updates = {
            "semantic_tier": semantic_tier,
            "relevance": max(relationship.relevance, relevance),
            "evidence_quality": max(relationship.evidence_quality, evidence_quality),
            "correlation_strength": max(relationship.correlation_strength, correlation_strength),
            "causal_confidence": causal_confidence if causal_confidence is not None else relationship.causal_confidence,
            "explanation": explanation,
            "provenance": merged_provenance,
            "attributes": merged_attributes,
            "first_observed_at": min(as_utc(relationship.first_observed_at), as_utc(first_observed_at)) if relationship.first_observed_at and first_observed_at else relationship.first_observed_at or first_observed_at,
            "last_observed_at": max(as_utc(relationship.last_observed_at), as_utc(last_observed_at)) if relationship.last_observed_at and last_observed_at else relationship.last_observed_at or last_observed_at,
        }
        for key, value in updates.items():
            current = getattr(relationship, key)
            if isinstance(current, datetime) and isinstance(value, datetime):
                equal = as_utc(current) == as_utc(value)
            else:
                equal = current == value
            if not equal:
                setattr(relationship, key, value)
                changed = True
    for evidence_id in evidence_ids:
        if db.get(RelationshipEvidence, (relationship.id, evidence_id, "supports")) is None:
            db.add(RelationshipEvidence(relationship_id=relationship.id, evidence_id=evidence_id, stance="supports"))
            changed = True
    if changed:
        previous = db.scalar(
            select(RelationshipRevision)
            .where(RelationshipRevision.relationship_id == relationship.id)
            .order_by(RelationshipRevision.assessed_at.desc(), RelationshipRevision.id.desc())
            .limit(1)
        )
        db.add(
            RelationshipRevision(
                relationship_id=relationship.id,
                semantic_tier=relationship.semantic_tier,
                relevance=relationship.relevance,
                evidence_quality=relationship.evidence_quality,
                correlation_strength=relationship.correlation_strength,
                causal_confidence=relationship.causal_confidence,
                status=relationship.status,
                explanation=relationship.explanation,
                supporting_evidence_ids=evidence_ids,
                contradictory_evidence_ids=[],
                supersedes_id=previous.id if previous else None,
            )
        )
    return relationship


def _entity(
    db: Session,
    event: Event,
    evidence_ids: list[int],
    entity_type: str,
    name: str | None,
    role: str,
    confidence: float,
    attributes: dict | None = None,
    country_code: str | None = None,
) -> IntelligenceEntity | None:
    if not name:
        return None
    entity = upsert_entity(
        db,
        entity_type=entity_type,
        name=name,
        observed_at=event.occurrence_at or event.observed_at,
        attributes=attributes,
        country_code=country_code,
        region=event.region if entity_type in {"geographic_region", "location"} else None,
        latitude=event.latitude if entity_type == "location" else None,
        longitude=event.longitude if entity_type == "location" else None,
        source=event.source,
        confidence=confidence,
    )
    _link_event_entity(db, event, entity, role, confidence, evidence_ids, "structured_field")
    return entity


def reconcile_event(db: Session, event: Event) -> None:
    """Materialize ontology, uncertainty assessments, and direct graph edges."""
    evidence_ids = _event_evidence_ids(db, event.id)
    metadata = event.raw_metadata or {}
    source_role = str(metadata.get("source_role") or "official_report")
    direct = source_role == "direct_observation"
    evidence_quality = float(event.source_reliability if event.source_reliability is not None else event.confidence)
    extraction_confidence = float(event.extraction_confidence if event.extraction_confidence is not None else 0.6)

    _classify(
        db,
        event,
        scheme="domain",
        label=event.domain or "general",
        parent=None,
        confidence=extraction_confidence,
        rationale="Normalized from the source registry and structured source fields.",
        evidence_ids=evidence_ids,
    )
    _classify(
        db,
        event,
        scheme="event_type",
        label=event.event_type or event.category,
        parent=event.domain or "general",
        confidence=extraction_confidence,
        rationale="Event-type classification is independent from cause and attribution.",
        evidence_ids=evidence_ids,
    )
    _classify(
        db,
        event,
        scheme="source_record_category",
        label=event.category,
        parent=event.event_type or None,
        confidence=evidence_quality,
        rationale="Category asserted by the normalized source record.",
        evidence_ids=evidence_ids,
    )

    reporter = _entity(
        db,
        event,
        evidence_ids,
        "organization",
        str(metadata.get("publisher_name") or event.source),
        "reporter",
        evidence_quality,
        {"source_role": source_role},
    )
    provider = _entity(db, event, evidence_ids, "infrastructure_provider", event.provider, "affected_provider", extraction_confidence)
    asn = _entity(db, event, evidence_ids, "autonomous_system", event.asn, "infrastructure_scope", extraction_confidence)
    service = _entity(db, event, evidence_ids, "technology_platform", event.service, "affected_service", extraction_confidence)
    region = _entity(db, event, evidence_ids, "geographic_region", event.region, "affected_location", extraction_confidence)
    location = _entity(
        db,
        event,
        evidence_ids,
        "location",
        event.location_name,
        "event_location",
        extraction_confidence,
        {"latitude": event.latitude, "longitude": event.longitude},
    )

    cve_entities: list[IntelligenceEntity] = []
    for cve in metadata.get("cve_ids") or []:
        entity = _entity(db, event, evidence_ids, "vulnerability", str(cve).upper(), "associated_vulnerability", 0.98)
        if entity:
            cve_entities.append(entity)
    vendor = _entity(db, event, evidence_ids, "organization", metadata.get("vendor"), "technology_vendor", extraction_confidence)
    for country, code in zip(metadata.get("affected_countries") or [], metadata.get("country_codes") or []):
        _entity(db, event, evidence_ids, "country", country, "affected_location", 0.95, country_code=code)

    known_entity_names = {
        normalize_name(value)
        for value in (event.provider, event.asn, event.service, event.region, event.location_name, metadata.get("vendor"))
        if value
    }
    for mention in (metadata.get("entity_mentions") or [])[:30]:
        if not isinstance(mention, str) or normalize_name(mention) in known_entity_names:
            continue
        _entity(db, event, evidence_ids, "named_entity", mention, "mentioned", min(0.6, extraction_confidence))

    event_ref = f"event:{event.id}"
    semantic_tier = "observed_fact" if direct else "documented_fact"
    for entity, predicate, explanation, relevance in (
        (reporter, "REPORTED_BY", "The source document was published by this organization.", 1.0),
        (provider, "AFFECTS", "The normalized record explicitly names this affected provider.", 0.95),
        (service, "AFFECTS", "The normalized record explicitly names this service or platform.", 0.95),
        (asn, "ASSOCIATED_WITH", "The source configuration explicitly maps the event to this autonomous system.", 0.85),
        (region, "AFFECTS", "The normalized record explicitly identifies this affected region.", 0.9),
        (location, "OCCURRED_AT", "The source provides this event location.", 0.95),
    ):
        if entity is None:
            continue
        upsert_relationship(
            db,
            subject_ref=event_ref,
            predicate=predicate,
            object_ref=f"entity:{entity.stable_id}",
            semantic_tier=semantic_tier,
            relevance=relevance,
            evidence_quality=evidence_quality,
            correlation_strength=1.0,
            causal_confidence=None,
            explanation=explanation,
            evidence_ids=evidence_ids,
            provenance={"source": event.source, "source_role": source_role},
            first_observed_at=event.first_observed_at or event.observed_at,
            last_observed_at=event.publisher_reported_at or event.observed_at,
        )
    for vulnerability in cve_entities:
        upsert_relationship(
            db,
            subject_ref=event_ref,
            predicate="SHARES_VULNERABILITY",
            object_ref=f"entity:{vulnerability.stable_id}",
            semantic_tier="documented_fact",
            relevance=1.0,
            evidence_quality=evidence_quality,
            correlation_strength=1.0,
            causal_confidence=None,
            explanation="The source record explicitly identifies this vulnerability; it does not attribute a separate incident to it.",
            evidence_ids=evidence_ids,
            provenance={"source": event.source},
            first_observed_at=event.first_observed_at or event.observed_at,
            last_observed_at=event.publisher_reported_at or event.observed_at,
        )
        if vendor and service:
            upsert_relationship(
                db,
                subject_ref=f"entity:{vendor.stable_id}",
                predicate="PRODUCES",
                object_ref=f"entity:{service.stable_id}",
                semantic_tier="documented_fact",
                relevance=0.9,
                evidence_quality=evidence_quality,
                correlation_strength=1.0,
                causal_confidence=None,
                explanation="The vulnerability catalog identifies this vendor and product relationship.",
                evidence_ids=evidence_ids,
                provenance={"source": event.source},
                first_observed_at=event.first_observed_at or event.observed_at,
                last_observed_at=event.publisher_reported_at or event.observed_at,
            )

    affected = [entity for entity in (provider, service, asn, region, location) if entity]
    _assess_field(
        db,
        event,
        field_name="what_happened",
        value={"domain": event.domain, "event_type": event.event_type, "category": event.category},
        knowledge_status="observed" if direct else "reported",
        confidence=extraction_confidence,
        rationale="The event class is normalized independently from cause, mechanism, and attribution.",
        evidence_ids=evidence_ids,
    )
    _assess_field(
        db,
        event,
        field_name="what_was_affected",
        value={"entities": [{"stable_id": item.stable_id, "name": item.canonical_name, "type": item.entity_type} for item in affected]},
        knowledge_status="known" if affected else "unresolved",
        confidence=extraction_confidence if affected else 0.0,
        rationale="Affected entities are retained only when explicitly structured or extracted; the reporting publisher is never substituted.",
        strengthen=[] if affected else ["A primary source naming the affected organization, service, or location."],
        collection_actions=[] if affected else ["Collect a primary incident statement or structured technical observation."],
        evidence_ids=evidence_ids,
    )
    _assess_field(
        db,
        event,
        field_name="who_reported_it",
        value={"entity": reporter.stable_id if reporter else None, "source_role": source_role},
        knowledge_status="known",
        confidence=evidence_quality,
        rationale="Publisher identity is provenance and is not treated as the affected entity.",
        evidence_ids=evidence_ids,
    )
    _assess_field(
        db,
        event,
        field_name="independent_observation",
        value={"source_role": source_role, "direct_observation": direct},
        knowledge_status="observed" if direct else "reported_only",
        confidence=evidence_quality,
        rationale=(
            "The source supplies a direct structured observation."
            if direct
            else "The record is a report, advisory, or curated aggregation and is not independent technical corroboration by itself."
        ),
        strengthen=[] if direct else ["A technically independent observation covering the same entity, location, and time."],
        collection_actions=[] if direct else ["Search configured telemetry sources for event-specific observations."],
        evidence_ids=evidence_ids,
    )

    is_non_disruption_context = event.category in {"security_advisory", "vulnerability_exploitation", "policy_announcement"}
    _assess_field(
        db,
        event,
        field_name="mechanism",
        value={"mechanism": metadata.get("mechanism")},
        knowledge_status="known" if metadata.get("mechanism") else "not_applicable" if is_non_disruption_context else "unresolved",
        confidence=extraction_confidence if metadata.get("mechanism") else 0.0,
        rationale=(
            "The source explicitly states a mechanism."
            if metadata.get("mechanism")
            else "This source record does not establish a technical failure or attack mechanism."
        ),
        plausible_explanations=[] if is_non_disruption_context else ["ordinary operational failure", "external dependency failure", "environmental disruption", "malicious activity"],
        strengthen=["Primary technical root-cause analysis or independent measurements."],
        weaken=["Evidence showing an unrelated or routine operational explanation."],
        collection_actions=["Collect root-cause statements and event-specific telemetry."],
        evidence_ids=evidence_ids,
    )
    _assess_field(
        db,
        event,
        field_name="cause",
        value={"legacy_cause_classification": event.cause_classification},
        knowledge_status="known" if event.cause_classification != "unknown" else "not_applicable" if is_non_disruption_context else "unresolved",
        confidence=event.confidence if event.cause_classification != "unknown" else 0.0,
        rationale=(
            "Cause is separately assessed from the event type."
            if event.cause_classification != "unknown"
            else "Available evidence classifies the event but does not establish its cause."
        ),
        plausible_explanations=[] if is_non_disruption_context else ["operational failure", "defensive remediation", "malicious intrusion", "external physical or environmental cause"],
        strengthen=["A primary root-cause statement supported by technical evidence."],
        weaken=["Contradictory primary evidence or a retraction."],
        collection_actions=["Monitor the source and independent technical observers for a cause update."],
        evidence_ids=evidence_ids,
    )
    _assess_field(
        db,
        event,
        field_name="attribution",
        value={"attributed_actor": metadata.get("attributed_actor")},
        knowledge_status="reported" if metadata.get("attributed_actor") else "not_applicable" if event.domain in {"environmental_hazard", "space_weather"} or is_non_disruption_context else "unresolved",
        confidence=0.5 if metadata.get("attributed_actor") else 0.0,
        rationale=(
            "An actor is reported by the source but remains a claim unless supported by linked evidence."
            if metadata.get("attributed_actor")
            else "No responsible actor is established, and timing or geopolitical context is not attribution evidence."
        ),
        strengthen=["Multiple independent primary sources with attributable technical evidence."],
        weaken=["Contradictory forensics, retraction, or a confirmed non-malicious cause."],
        collection_actions=["Retain competing explanations and monitor for attributable forensic evidence."],
        evidence_ids=evidence_ids,
    )
    db.commit()
