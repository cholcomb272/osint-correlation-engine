"""Cross-domain relationship, cluster, and investigation-candidate analysis.

This module intentionally separates relevance from causation. It can retain a
useful contextual association without promoting it to a dependency or causal
claim. All persisted edges point back to source evidence through the ontology
relationship tables.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from itertools import combinations

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.main import Event, as_utc
from app.services.correlation import knowledge_time
from app.services.ontology import reconcile_event, upsert_relationship
from app.v2_models import (
    ClusterEvent,
    EventCluster,
    EventEntity,
    EventEvidence,
    EvidenceArtifact,
    IntelligenceEntity,
    InvestigationCandidate,
    KnowledgeRelationship,
)


ENTITY_RULES = {
    "vulnerability": ("SHARES_VULNERABILITY", 90 * 24, 0.95, "supported_inference"),
    "infrastructure_provider": ("SHARES_INFRASTRUCTURE", 48, 0.85, "supported_inference"),
    "autonomous_system": ("SHARES_INFRASTRUCTURE", 48, 0.9, "supported_inference"),
    "technology_platform": ("ASSOCIATED_WITH", 30 * 24, 0.78, "contextual_association"),
    "country": ("GEOGRAPHIC_OVERLAP", 14 * 24, 0.62, "contextual_association"),
    "geographic_region": ("GEOGRAPHIC_OVERLAP", 7 * 24, 0.7, "contextual_association"),
    "location": ("GEOGRAPHIC_OVERLAP", 7 * 24, 0.8, "contextual_association"),
    "organization": ("ASSOCIATED_WITH", 30 * 24, 0.55, "contextual_association"),
}

SKIP_ROLES = {"reporter", "mentioned"}
SEVERITY_RANK = {"unknown": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}


def _evidence_ids(db: Session, event_ids: list[int]) -> dict[int, list[int]]:
    output: dict[int, list[int]] = defaultdict(list)
    if not event_ids:
        return output
    for event_id, evidence_id in db.execute(
        select(EventEvidence.event_id, EventEvidence.evidence_id).where(
            EventEvidence.event_id.in_(event_ids)
        )
    ):
        output[event_id].append(evidence_id)
    return output


def _lineages_by_event(
    db: Session, event_evidence: dict[int, list[int]]
) -> dict[int, set[str]]:
    artifact_ids = sorted(
        {artifact_id for values in event_evidence.values() for artifact_id in values}
    )
    artifact_lineage: dict[int, str] = {}
    if artifact_ids:
        for artifact_id, publisher, upstream in db.execute(
            select(
                EvidenceArtifact.id,
                EvidenceArtifact.publisher,
                EvidenceArtifact.upstream_source,
            ).where(EvidenceArtifact.id.in_(artifact_ids))
        ):
            value = (upstream or publisher or "").strip().casefold()
            if value:
                artifact_lineage[artifact_id] = value
    return {
        event_id: {
            artifact_lineage[artifact_id]
            for artifact_id in evidence_ids
            if artifact_id in artifact_lineage
        }
        for event_id, evidence_ids in event_evidence.items()
    }


def _event_ref(event_id: int) -> str:
    return f"event:{event_id}"


def _ordered(left: Event, right: Event) -> tuple[Event, Event]:
    return (left, right) if left.id < right.id else (right, left)


def _haversine_km(left: Event, right: Event) -> float | None:
    if None in (left.latitude, left.longitude, right.latitude, right.longitude):
        return None
    lat1, lon1, lat2, lon2 = map(
        math.radians,
        (left.latitude, left.longitude, right.latitude, right.longitude),
    )
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    value = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 6371.0 * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


def reconcile_existing_events(db: Session, *, days: int = 365, cutoff: datetime | None = None) -> int:
    now = as_utc(cutoff or datetime.now(timezone.utc))
    events = db.scalars(
        select(Event)
        .where(Event.observed_at.between(now - timedelta(days=days), now))
        .order_by(Event.id)
    ).all()
    for event in events:
        reconcile_event(db, event)
    return len(events)


def materialize_relationships(
    db: Session,
    *,
    days: int = 90,
    cutoff: datetime | None = None,
    max_relationships: int = 5000,
) -> dict:
    now = as_utc(cutoff or datetime.now(timezone.utc))
    start = now - timedelta(days=days)
    events = db.scalars(
        select(Event)
        .where(
            Event.observed_at.between(start, now),
            func.coalesce(
                Event.publisher_reported_at,
                Event.first_observed_at,
                Event.ingested_at,
                Event.observed_at,
            )
            <= now,
        )
        .order_by(Event.observed_at.desc())
        .limit(3000)
    ).all()
    event_by_id = {event.id: event for event in events}
    evidence = _evidence_ids(db, list(event_by_id))
    lineages = _lineages_by_event(db, evidence)
    links = db.execute(
        select(EventEntity, IntelligenceEntity)
        .join(IntelligenceEntity, IntelligenceEntity.id == EventEntity.entity_id)
        .where(EventEntity.event_id.in_(event_by_id))
    ).all() if event_by_id else []

    by_entity: dict[int, list[tuple[EventEntity, IntelligenceEntity]]] = defaultdict(list)
    for link, entity in links:
        if link.role not in SKIP_ROLES and entity.entity_type in ENTITY_RULES:
            by_entity[entity.id].append((link, entity))

    created_or_updated = 0
    relation_counts: dict[str, int] = defaultdict(int)
    for group in by_entity.values():
        if len(group) < 2:
            continue
        # A widely reused entity can create a combinatorial explosion. Recent,
        # high-confidence links are bounded before pair expansion.
        group = sorted(
            group,
            key=lambda pair: (
                pair[0].confidence,
                event_by_id[pair[0].event_id].observed_at,
            ),
            reverse=True,
        )[:100]
        entity = group[0][1]
        predicate, window_hours, base_relevance, semantic_tier = ENTITY_RULES[entity.entity_type]
        for (left_link, _), (right_link, _) in combinations(group, 2):
            if created_or_updated >= max_relationships:
                break
            left = event_by_id[left_link.event_id]
            right = event_by_id[right_link.event_id]
            delta_hours = abs((as_utc(left.observed_at) - as_utc(right.observed_at)).total_seconds()) / 3600
            if delta_hours > window_hours:
                continue
            left, right = _ordered(left, right)
            combined_evidence = sorted(set(evidence[left.id]) | set(evidence[right.id]))
            left_lineage = lineages.get(left.id, set())
            right_lineage = lineages.get(right.id, set())
            shared_lineage = sorted(left_lineage & right_lineage)
            independent_publishers = left.source.casefold() != right.source.casefold()
            lineage_note = (
                " The records share reporting lineage and are not independent corroboration."
                if shared_lineage
                else " Publisher lineage is not known to overlap; this still does not establish technical independence."
            )
            relevance = max(0.0, base_relevance - (0.12 if shared_lineage else 0.0))
            relationship_quality = min(
                float(left.source_reliability or left.confidence),
                float(right.source_reliability or right.confidence),
                left_link.confidence,
                right_link.confidence,
            )
            upsert_relationship(
                db,
                subject_ref=_event_ref(left.id),
                predicate=predicate,
                object_ref=_event_ref(right.id),
                semantic_tier=semantic_tier,
                relevance=relevance,
                evidence_quality=relationship_quality,
                correlation_strength=relevance,
                causal_confidence=None,
                explanation=(
                    f"Both events explicitly reference {entity.entity_type.replace('_', ' ')} "
                    f"{entity.canonical_name} and fall within the {window_hours:g}-hour "
                    f"window appropriate to this relationship type.{lineage_note} "
                    "This edge expresses analytical relevance, not causation."
                ),
                evidence_ids=combined_evidence,
                provenance={
                    "shared_entity": entity.stable_id,
                    "shared_entity_type": entity.entity_type,
                    "independent_publishers": independent_publishers,
                    "shared_reporting_lineage": shared_lineage,
                    "window_hours": window_hours,
                },
                first_observed_at=min(as_utc(left.observed_at), as_utc(right.observed_at)),
                last_observed_at=max(as_utc(left.observed_at), as_utc(right.observed_at)),
                attributes={"causal_claim": False, "relationship_specific_evidence": True},
            )
            created_or_updated += 1
            relation_counts[predicate] += 1

    # Location coordinates can relate records whose place names differ. Use
    # coarse spatial buckets before distance checks to keep runtime bounded.
    geolocated = [event for event in events if event.latitude is not None and event.longitude is not None][:1000]
    buckets: dict[tuple[int, int], list[Event]] = defaultdict(list)
    for event in geolocated:
        buckets[(math.floor(event.latitude / 3), math.floor(event.longitude / 3))].append(event)
    seen_pairs: set[tuple[int, int]] = set()
    for (lat_bucket, lon_bucket), bucket_events in buckets.items():
        candidates = list(bucket_events)
        for dlat in (-1, 0, 1):
            for dlon in (-1, 0, 1):
                if dlat or dlon:
                    candidates.extend(buckets.get((lat_bucket + dlat, lon_bucket + dlon), []))
        for left in bucket_events:
            for right in candidates:
                pair = tuple(sorted((left.id, right.id)))
                if left.id == right.id or pair in seen_pairs or created_or_updated >= max_relationships:
                    continue
                seen_pairs.add(pair)
                delta_hours = abs((as_utc(left.observed_at) - as_utc(right.observed_at)).total_seconds()) / 3600
                if delta_hours > 7 * 24:
                    continue
                distance = _haversine_km(left, right)
                if distance is None or distance > 250:
                    continue
                left, right = _ordered(left, right)
                combined_evidence = sorted(set(evidence[left.id]) | set(evidence[right.id]))
                relevance = round(max(0.4, 0.78 * (1 - distance / 500) * (1 - delta_hours / (14 * 24))), 3)
                predicate = "PRECEDES" if left.domain != right.domain and as_utc(left.observed_at) < as_utc(right.observed_at) else "GEOGRAPHIC_OVERLAP"
                upsert_relationship(
                    db,
                    subject_ref=_event_ref(left.id),
                    predicate=predicate,
                    object_ref=_event_ref(right.id),
                    semantic_tier="contextual_association",
                    relevance=relevance,
                    evidence_quality=min(float(left.source_reliability or left.confidence), float(right.source_reliability or right.confidence)),
                    correlation_strength=relevance,
                    causal_confidence=None,
                    explanation=(
                        f"The events were observed approximately {distance:.0f} km and {delta_hours:.1f} hours apart. "
                        "Geographic and temporal proximity make this useful context but do not demonstrate a causal chain."
                    ),
                    evidence_ids=combined_evidence,
                    provenance={"distance_km": round(distance, 2), "time_delta_hours": round(delta_hours, 2)},
                    first_observed_at=min(as_utc(left.observed_at), as_utc(right.observed_at)),
                    last_observed_at=max(as_utc(left.observed_at), as_utc(right.observed_at)),
                    attributes={"causal_claim": False},
                )
                created_or_updated += 1
                relation_counts[predicate] += 1
    db.commit()
    return {
        "events_considered": len(events),
        "relationships_evaluated": created_or_updated,
        "relationship_types": dict(sorted(relation_counts.items())),
        "bounded": created_or_updated >= max_relationships,
        "cutoff": now.isoformat(),
    }


def _component_graph(relationships: list[KnowledgeRelationship]) -> list[set[int]]:
    adjacency: dict[int, set[int]] = defaultdict(set)
    for relationship in relationships:
        if not relationship.subject_ref.startswith("event:") or not relationship.object_ref.startswith("event:"):
            continue
        left = int(relationship.subject_ref.split(":", 1)[1])
        right = int(relationship.object_ref.split(":", 1)[1])
        adjacency[left].add(right)
        adjacency[right].add(left)
    components: list[set[int]] = []
    unseen = set(adjacency)
    while unseen:
        root = unseen.pop()
        component = {root}
        queue = deque([root])
        while queue:
            current = queue.popleft()
            for neighbor in adjacency[current]:
                if neighbor not in component:
                    component.add(neighbor)
                    unseen.discard(neighbor)
                    queue.append(neighbor)
        if len(component) >= 2:
            components.append(component)
    return components


def discover_clusters(db: Session, *, days: int = 30, cutoff: datetime | None = None) -> dict:
    now = as_utc(cutoff or datetime.now(timezone.utc))
    start = now - timedelta(days=days)
    relationships = db.scalars(
        select(KnowledgeRelationship).where(
            KnowledgeRelationship.subject_ref.like("event:%"),
            KnowledgeRelationship.object_ref.like("event:%"),
            KnowledgeRelationship.status == "active",
            KnowledgeRelationship.relevance >= 0.6,
            KnowledgeRelationship.first_observed_at <= now,
            KnowledgeRelationship.last_observed_at >= start,
            KnowledgeRelationship.semantic_tier.in_(["supported_inference", "contextual_association"]),
        )
    ).all()
    components = _component_graph(relationships)
    active_cluster_ids: set[str] = set()
    candidates_changed = 0
    for component in components:
        events = db.scalars(select(Event).where(Event.id.in_(component))).all()
        if len(events) < 2:
            continue
        event_ids = sorted(event.id for event in events)
        identity = ",".join(map(str, event_ids))
        stable_id = "cluster_" + hashlib.sha256(identity.encode()).hexdigest()[:24]
        active_cluster_ids.add(stable_id)
        domains = sorted({event.domain for event in events})
        event_types = sorted({event.event_type for event in events})
        window_start = min(as_utc(event.observed_at) for event in events)
        window_end = max(as_utc(event.observed_at) for event in events)
        first_known = min(knowledge_time(event) for event in events)
        significance = max(
            (event.significance or event.severity or "unknown" for event in events),
            key=lambda value: SEVERITY_RANK.get(value, 0),
        )
        cluster_type = "cross_domain" if len(domains) > 1 else "entity_centered"
        title = (
            f"Cross-domain cluster: {', '.join(domains[:3])}"
            if cluster_type == "cross_domain"
            else f"{domains[0].replace('_', ' ').title()} cluster"
        )
        explanation = (
            f"{len(events)} events form a connected evidence graph across {len(domains)} domain(s). "
            "Membership indicates shared evidence context, not a common cause or coordinated activity."
        )
        cluster = db.scalar(select(EventCluster).where(EventCluster.stable_id == stable_id))
        if cluster is None:
            cluster = EventCluster(
                stable_id=stable_id,
                title=title,
                cluster_type=cluster_type,
                status="candidate",
                significance=significance,
                anomaly_score=None,
                explanation=explanation,
                dimensions={"domains": domains, "event_types": event_types},
                window_start=window_start,
                window_end=window_end,
                first_known_at=first_known,
                last_reassessed_at=now,
            )
            db.add(cluster)
            db.flush()
        else:
            cluster.title = title
            cluster.cluster_type = cluster_type
            cluster.status = "candidate"
            cluster.significance = significance
            cluster.explanation = explanation
            cluster.dimensions = {"domains": domains, "event_types": event_types}
            cluster.window_start = window_start
            cluster.window_end = window_end
            cluster.last_reassessed_at = now
        for event in events:
            link = db.get(ClusterEvent, (cluster.id, event.id))
            if link is None:
                db.add(
                    ClusterEvent(
                        cluster_id=cluster.id,
                        event_id=event.id,
                        role="member",
                        membership_strength=0.7,
                        rationale="Connected through one or more evidence-backed analytical relationships.",
                    )
                )

        should_investigate = len(events) >= 3 or (cluster_type == "cross_domain" and significance in {"high", "critical"})
        if should_investigate:
            candidate_id = "candidate_" + stable_id.removeprefix("cluster_")
            candidate = db.scalar(
                select(InvestigationCandidate).where(InvestigationCandidate.stable_id == candidate_id)
            )
            values = {
                "cluster_id": cluster.id,
                "title": f"Review {title.lower()}",
                "priority": "high" if significance in {"high", "critical"} else "normal",
                "trigger_type": "cross_domain_cluster" if cluster_type == "cross_domain" else "multi_event_cluster",
                "rationale": explanation,
                "known_facts": [
                    f"{len(events)} events are connected by persisted evidence relationships.",
                    f"Observed domains: {', '.join(domains)}.",
                    f"Observation window: {window_start.isoformat()} to {window_end.isoformat()}.",
                ],
                "competing_explanations": [
                    "A shared documented entity or dependency may explain the cluster.",
                    "Independent routine events may share context without a common cause.",
                    "Source amplification or repeated reporting may inflate apparent activity.",
                    "A physical, environmental, operational, or malicious common cause may exist but is not established.",
                ],
                "unresolved_questions": [
                    "Which relationships have direct or independently corroborated evidence?",
                    "Do source records share upstream reporting lineage?",
                    "Does event-specific telemetry support a common mechanism?",
                    "What evidence contradicts a shared-cause explanation?",
                ],
                "collection_priorities": [
                    "Collect primary statements and technical observations for the affected entities.",
                    "Check relationship-specific telemetry and documented dependencies.",
                    "Monitor for revisions, retractions, and contradictory evidence.",
                ],
                "last_reassessed_at": now,
            }
            if candidate is None:
                candidate = InvestigationCandidate(stable_id=candidate_id, **values)
                db.add(candidate)
            else:
                for key, value in values.items():
                    setattr(candidate, key, value)
            candidates_changed += 1

    stale = db.scalars(
        select(EventCluster).where(
            EventCluster.status == "candidate",
            EventCluster.window_end >= start,
        )
    ).all()
    for cluster in stale:
        if cluster.stable_id not in active_cluster_ids:
            cluster.status = "inactive"
            cluster.last_reassessed_at = now
    db.commit()
    return {
        "clusters": len(components),
        "investigation_candidates": candidates_changed,
        "relationships_considered": len(relationships),
        "cutoff": now.isoformat(),
    }


def run_fusion(db: Session, *, days: int = 90, cutoff: datetime | None = None) -> dict:
    reconciled = reconcile_existing_events(db, days=days, cutoff=cutoff)
    relationships = materialize_relationships(db, days=days, cutoff=cutoff)
    clusters = discover_clusters(db, days=min(days, 30), cutoff=cutoff)
    return {
        "events_reconciled": reconciled,
        "relationships": relationships,
        "clusters": clusters,
        "semantics": "Relevance and cluster membership do not establish causation, coordination, or attribution.",
    }
