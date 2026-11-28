"""Server-side query projection for the persistent intelligence graph."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.main import Event, as_utc
from app.v2_models import IntelligenceEntity, KnowledgeRelationship, RelationshipEvidence


DEFAULT_TIERS = {"observed_fact", "documented_fact", "supported_inference"}


def _event_node(event: Event) -> dict:
    return {
        "id": f"event:{event.id}",
        "type": "event",
        "label": event.title,
        "domain": event.domain,
        "event_type": event.event_type,
        "significance": event.significance,
        "severity": event.severity,
        "observed_at": as_utc(event.observed_at).isoformat(),
        "latitude": event.latitude,
        "longitude": event.longitude,
        "location_name": event.location_name,
        "source": event.source,
        "url": event.url,
    }


def _entity_node(entity: IntelligenceEntity) -> dict:
    return {
        "id": f"entity:{entity.stable_id}",
        "database_id": entity.id,
        "type": "entity",
        "entity_type": entity.entity_type,
        "label": entity.canonical_name,
        "country_code": entity.country_code,
        "region": entity.region,
        "latitude": entity.latitude,
        "longitude": entity.longitude,
        "attributes": entity.attributes,
        "first_seen_at": as_utc(entity.first_seen_at).isoformat() if entity.first_seen_at else None,
        "last_seen_at": as_utc(entity.last_seen_at).isoformat() if entity.last_seen_at else None,
    }


def knowledge_graph(
    db: Session,
    *,
    days: int = 30,
    domain: str | None = None,
    entity_type: str | None = None,
    predicates: list[str] | None = None,
    semantic_tiers: list[str] | None = None,
    minimum_relevance: float = 0.0,
    include_contextual: bool = False,
    focus: str | None = None,
    page: int = 1,
    page_size: int = 200,
    cutoff: datetime | None = None,
) -> dict:
    now = as_utc(cutoff or datetime.now(timezone.utc))
    start = now - timedelta(days=days)
    tiers = set(semantic_tiers or DEFAULT_TIERS)
    if include_contextual:
        tiers.update({"contextual_association", "plausible_hypothesis", "temporal_coincidence"})
    conditions = [
        KnowledgeRelationship.status == "active",
        KnowledgeRelationship.semantic_tier.in_(tiers),
        KnowledgeRelationship.relevance >= minimum_relevance,
        or_(KnowledgeRelationship.last_observed_at.is_(None), KnowledgeRelationship.last_observed_at >= start),
        or_(KnowledgeRelationship.first_observed_at.is_(None), KnowledgeRelationship.first_observed_at <= now),
    ]
    if cutoff is not None:
        conditions.append(KnowledgeRelationship.created_at <= now)
    if predicates:
        conditions.append(KnowledgeRelationship.predicate.in_(predicates))
    if focus:
        conditions.append(
            or_(
                KnowledgeRelationship.subject_ref == focus,
                KnowledgeRelationship.object_ref == focus,
            )
        )
    if domain:
        event_ids = db.scalars(
            select(Event.id).where(Event.domain == domain, Event.observed_at.between(start, now))
        ).all()
        event_refs = [f"event:{event_id}" for event_id in event_ids]
        if not event_refs:
            return _empty_graph(page, page_size, now, tiers)
        conditions.append(
            or_(
                KnowledgeRelationship.subject_ref.in_(event_refs),
                KnowledgeRelationship.object_ref.in_(event_refs),
            )
        )
    if entity_type:
        entity_ids = db.scalars(
            select(IntelligenceEntity.stable_id).where(
                IntelligenceEntity.entity_type == entity_type
            )
        ).all()
        entity_refs = [f"entity:{stable_id}" for stable_id in entity_ids]
        if not entity_refs:
            return _empty_graph(page, page_size, now, tiers)
        conditions.append(
            or_(
                KnowledgeRelationship.subject_ref.in_(entity_refs),
                KnowledgeRelationship.object_ref.in_(entity_refs),
            )
        )

    total = db.scalar(
        select(func.count()).select_from(KnowledgeRelationship).where(*conditions)
    ) or 0
    relationships = db.scalars(
        select(KnowledgeRelationship)
        .where(*conditions)
        .order_by(
            KnowledgeRelationship.relevance.desc(),
            KnowledgeRelationship.last_observed_at.desc(),
            KnowledgeRelationship.id,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    refs = {
        value
        for relationship in relationships
        for value in (relationship.subject_ref, relationship.object_ref)
    }
    event_ids = [int(value.split(":", 1)[1]) for value in refs if value.startswith("event:")]
    entity_stable_ids = [value.split(":", 1)[1] for value in refs if value.startswith("entity:")]
    events = db.scalars(select(Event).where(Event.id.in_(event_ids))).all() if event_ids else []
    entities = db.scalars(
        select(IntelligenceEntity).where(IntelligenceEntity.stable_id.in_(entity_stable_ids))
    ).all() if entity_stable_ids else []
    evidence_by_relationship: dict[int, dict[str, list[int]]] = {}
    if relationships:
        for relationship_id, evidence_id, stance in db.execute(
            select(
                RelationshipEvidence.relationship_id,
                RelationshipEvidence.evidence_id,
                RelationshipEvidence.stance,
            ).where(RelationshipEvidence.relationship_id.in_([item.id for item in relationships]))
        ):
            evidence_by_relationship.setdefault(relationship_id, {}).setdefault(stance, []).append(evidence_id)
    nodes = [_event_node(event) for event in events] + [_entity_node(entity) for entity in entities]
    edges = [
        {
            "id": relationship.stable_id,
            "source": relationship.subject_ref,
            "target": relationship.object_ref,
            "predicate": relationship.predicate,
            "semantic_tier": relationship.semantic_tier,
            "relevance": relationship.relevance,
            "evidence_quality": relationship.evidence_quality,
            "correlation_strength": relationship.correlation_strength,
            "causal_confidence": relationship.causal_confidence,
            "causal_claim": bool((relationship.attributes or {}).get("causal_claim", False)),
            "explanation": relationship.explanation,
            "provenance": relationship.provenance,
            "evidence": evidence_by_relationship.get(relationship.id, {}),
            "first_observed_at": as_utc(relationship.first_observed_at).isoformat() if relationship.first_observed_at else None,
            "last_observed_at": as_utc(relationship.last_observed_at).isoformat() if relationship.last_observed_at else None,
            "updated_at": as_utc(relationship.updated_at).isoformat(),
        }
        for relationship in relationships
    ]
    return {
        "nodes": sorted(nodes, key=lambda item: item["id"]),
        "edges": edges,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_relationships": total,
            "has_next": page * page_size < total,
        },
        "filters": {
            "semantic_tiers": sorted(tiers),
            "include_contextual": include_contextual,
            "domain": domain,
            "entity_type": entity_type,
            "predicates": predicates or [],
            "minimum_relevance": minimum_relevance,
            "focus": focus,
        },
        "generated_at": now.isoformat(),
        "semantics": {
            "relevance": "Investigative usefulness, separate from causal confidence.",
            "evidence_quality": "Quality of evidence supporting this relationship, not event truth probability.",
            "correlation_strength": "Heuristic relationship strength, not a calibrated probability.",
            "causal_confidence": "Null unless evidence specifically supports a causal claim.",
        },
    }


def _empty_graph(page: int, page_size: int, now: datetime, tiers: set[str]) -> dict:
    return {
        "nodes": [],
        "edges": [],
        "pagination": {"page": page, "page_size": page_size, "total_relationships": 0, "has_next": False},
        "filters": {"semantic_tiers": sorted(tiers)},
        "generated_at": now.isoformat(),
        "semantics": {
            "relevance": "Investigative usefulness, separate from causal confidence.",
            "evidence_quality": "Evidence quality is not event truth probability.",
            "correlation_strength": "Heuristic relationship strength, not a calibrated probability.",
            "causal_confidence": "Null unless relationship-specific causal evidence exists.",
        },
    }
