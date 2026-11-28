"""Explainable correlation evaluation.

Scores are bounded heuristic strengths. They are deliberately not exposed as
probabilities and never establish attribution.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.main import (
    Event,
    NetworkMeasurement,
    as_utc,
    incident_types_compatible,
    semantic_relevance,
)
from app.v2_models import (
    CorrelationRecord,
    EventEvidence,
    EvidenceArtifact,
    ProviderDependency,
)


INFRASTRUCTURE_WEIGHTS = {"provider": 0.30, "asn": 0.35, "region": 0.10}


@dataclass
class CorrelationAssessment:
    left_event_id: int
    right_event_id: int
    relationship_types: list[str]
    strength: float
    confidence_assessment: str
    explanation: str
    supporting_factors: list[str] = field(default_factory=list)
    contradictory_factors: list[str] = field(default_factory=list)
    score_components: dict[str, float] = field(default_factory=dict)
    evidence_ids: list[int] = field(default_factory=list)
    independent_publishers: bool = False
    independent_technical_corroboration: bool = False
    evidence_basis: str = "inferred"
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None
    additional_observations: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = asdict(self)
        for key in ("first_observed_at", "last_observed_at"):
            if result[key]:
                result[key] = as_utc(result[key]).isoformat()
        result["score_semantics"] = "bounded heuristic strength; not a probability or attribution"
        return result


def knowledge_time(event: Event) -> datetime:
    return as_utc(
        event.publisher_reported_at
        or event.first_observed_at
        or event.ingested_at
        or event.observed_at
    )


def _evidence_for_events(db: Session, event_ids: list[int]) -> dict[int, list[tuple[EvidenceArtifact, str]]]:
    result = {event_id: [] for event_id in event_ids}
    if not event_ids:
        return result
    rows = db.execute(
        select(EventEvidence.event_id, EventEvidence.role, EvidenceArtifact)
        .join(EvidenceArtifact, EvidenceArtifact.id == EventEvidence.evidence_id)
        .where(EventEvidence.event_id.in_(event_ids))
    ).all()
    for event_id, role, artifact in rows:
        result.setdefault(event_id, []).append((artifact, role))
    return result


def _measurements_for_event(
    event: Event,
    measurements: list[NetworkMeasurement],
    window_hours: float = 2.0,
) -> list[NetworkMeasurement]:
    matches = []
    for measurement in measurements:
        same_technical_scope = any(
            left and right and left.casefold() == right.casefold()
            for left, right in (
                (event.provider, measurement.provider),
                (event.asn, measurement.asn),
                (event.region, measurement.region),
            )
        )
        distance = abs((as_utc(event.observed_at) - as_utc(measurement.observed_at)).total_seconds()) / 3600
        if same_technical_scope and distance <= window_hours:
            matches.append(measurement)
    return matches


def observation_family(source: str, signal_type: str, detail_value: str = "") -> str:
    """Group feeds by observation modality, not publisher/API name."""
    try:
        detail = json.loads(detail_value or "{}")
    except (TypeError, ValueError):
        detail = {}
    declared = str(detail.get("observation_family") or "").strip().casefold()
    if declared:
        return declared
    signal = signal_type.casefold()
    source = source.casefold()
    if signal in {"bgp_announcements", "bgp_withdrawals", "bgp_visibility_drop"}:
        return "bgp_control_plane"
    if signal == "reachability_loss":
        return "active_reachability"
    if signal == "dns_failure":
        return "dns_control_plane"
    if signal == "traffic_anomaly":
        return "network_telescope" if source == "ioda" else "traffic_telemetry"
    return f"unclassified:{source}"


def measurement_observation_family(measurement: NetworkMeasurement) -> str:
    return observation_family(
        measurement.source,
        measurement.signal_type,
        measurement.detail,
    )


def _shared_upstream(evidence: list[tuple[EvidenceArtifact, str]]) -> set[str]:
    return {
        artifact.upstream_source.strip().casefold()
        for artifact, _ in evidence
        if artifact.upstream_source
        and artifact.upstream_source.strip()
        and artifact.upstream_source.strip().casefold() != artifact.publisher.strip().casefold()
    }


def evaluate_pair(
    db: Session,
    left: Event,
    right: Event,
    *,
    measurements: list[NetworkMeasurement] | None = None,
    event_evidence: dict[int, list[tuple[EvidenceArtifact, str]]] | None = None,
    window_hours: float = 24,
) -> CorrelationAssessment | None:
    """Evaluate a pair while keeping evidence dimensions separate."""
    if left.id == right.id or window_hours <= 0:
        return None
    hours = abs((as_utc(left.observed_at) - as_utc(right.observed_at)).total_seconds()) / 3600
    if hours > window_hours:
        return None
    compatible, compatibility_reason = incident_types_compatible(left, right)
    if not compatible:
        return None

    measurements = measurements or []
    event_evidence = event_evidence or _evidence_for_events(db, [left.id, right.id])
    left_artifacts = event_evidence.get(left.id, [])
    right_artifacts = event_evidence.get(right.id, [])
    supporting: list[str] = [compatibility_reason]
    contradicting: list[str] = []
    components: dict[str, float] = {}
    relationships: list[str] = []
    overlapping_dimensions: list[list[str]] = []

    components["temporal_proximity"] = round(0.10 * (1 - hours / window_hours), 4)
    supporting.append(f"events are {hours:.2f} hours apart; time contributes at most 0.10")

    for dimension, weight in INFRASTRUCTURE_WEIGHTS.items():
        left_value = getattr(left, dimension)
        right_value = getattr(right, dimension)
        if left_value and right_value and left_value.casefold() == right_value.casefold():
            components[f"shared_{dimension}"] = weight
            relationships.append(f"shares_{dimension}")
            supporting.append(f"shared {dimension}: {left_value}")

    # A provider's published ASN is usually another description of the same
    # infrastructure scope, not an independent signal. Retain both relationship
    # labels for investigation, but count only the more specific ASN dimension.
    if "shared_provider" in components and "shared_asn" in components:
        components["overlapping_provider_asn_discount"] = -components["shared_provider"]
        overlapping_dimensions.append(["provider", "asn"])
        contradicting.append(
            "shared provider and ASN describe overlapping infrastructure scope; "
            "they are scored once at the more specific ASN weight"
        )

    semantic_score, shared_terms = semantic_relevance(left, right)
    if semantic_score:
        components["semantic_relevance"] = round(min(0.12, semantic_score * 0.12), 4)
        supporting.append("semantic overlap: " + ", ".join(shared_terms))

    left_service = (left.service or "").strip()
    right_service = (right.service or "").strip()
    if (
        left_service
        and right_service
        and left_service.casefold() == right_service.casefold()
        and left_service.casefold() not in {"api", "cloud", "network", "service", "system"}
    ):
        components["shared_reported_service"] = 0.15
        relationships.append("reports_same_service")
        supporting.append(
            f"both records explicitly name the same service or platform: {left_service}; "
            "this may be repeated reporting rather than independent evidence"
        )

    dependency = None
    if left.provider and right.provider:
        dependency = db.scalar(
            select(ProviderDependency).where(
                or_(
                    and_(func.lower(ProviderDependency.consumer) == left.provider.casefold(), func.lower(ProviderDependency.dependency) == right.provider.casefold()),
                    and_(func.lower(ProviderDependency.consumer) == right.provider.casefold(), func.lower(ProviderDependency.dependency) == left.provider.casefold()),
                )
            )
        )
    if dependency:
        if dependency.status == "confirmed":
            components["confirmed_dependency"] = min(0.35, dependency.confidence * 0.35)
            relationships.append("confirmed_dependency")
            supporting.append(f"confirmed provider dependency: {dependency.consumer} depends on {dependency.dependency}")
        else:
            components["unverified_dependency"] = min(0.08, dependency.confidence * 0.08)
            relationships.append("depends_on")
            supporting.append("an unverified dependency record exists; it is not treated as established")

    left_network = _measurements_for_event(left, measurements)
    right_network = _measurements_for_event(right, measurements)
    left_sources = {item.source.casefold() for item in left_network}
    right_sources = {item.source.casefold() for item in right_network}
    measurement_sources = left_sources | right_sources
    shared_sources = left_sources & right_sources
    left_families = {measurement_observation_family(item) for item in left_network}
    right_families = {measurement_observation_family(item) for item in right_network}
    shared_families = left_families & right_families
    independent_technical = bool(
        left_network
        and right_network
        and len(shared_families) >= 2
        and len(shared_sources) >= 2
    )
    if left_network and right_network:
        max_z = max(abs(item.z_score or 0) for item in [*left_network, *right_network])
        components["historical_anomaly_magnitude"] = round(min(0.10, max_z / 50), 4)
        relationships.append("observed_network_anomaly")
        supporting.append(
            "public network telemetry overlaps both incident scopes and has a maximum "
            f"absolute baseline deviation of {max_z:.2f}"
        )
    elif left_network or right_network:
        contradicting.append(
            "network telemetry overlaps only one incident scope; it is context and does "
            "not support a relationship between the events"
        )
    if independent_technical:
        components["independent_technical_corroboration"] = 0.10
        relationships.append("independent_corroboration")
        supporting.append(
            "multiple observation modalities and telemetry systems overlap both "
            "incident scopes: "
            + ", ".join(sorted(shared_families))
            + " via "
            + ", ".join(sorted(shared_sources))
        )
    elif left_network and right_network and len(shared_families) < 2:
        contradicting.append(
            "multiple telemetry feeds use the same observation modality; this is not "
            "independent technical corroboration"
        )
    elif left_network and right_network and len(shared_sources) < 2:
        contradicting.append(
            "multiple observation modalities come from fewer than two shared telemetry "
            "systems; this is not independent technical corroboration"
        )

    independent_publishers = left.source.casefold() != right.source.casefold()
    left_upstream = _shared_upstream(left_artifacts)
    right_upstream = _shared_upstream(right_artifacts)
    if independent_publishers and left_upstream and right_upstream and left_upstream.isdisjoint(right_upstream):
        supporting.append("publishers and known upstream reporting sources differ")
    elif independent_publishers and left_upstream and right_upstream:
        components["shared_upstream_discount"] = -0.10
        contradicting.append("different publishers appear to derive from the same upstream source")
    elif independent_publishers:
        contradicting.append(
            "publishers differ, but upstream reporting lineage is unknown; publisher "
            "independence is not independent technical corroboration"
        )
    else:
        components["same_publisher_discount"] = -0.15
        contradicting.append("same publisher; this is not independent corroboration")

    evidence_ids = sorted({artifact.id for artifact, _ in [*left_artifacts, *right_artifacts]})
    contradictory_artifacts = [
        artifact for artifact, role in [*left_artifacts, *right_artifacts]
        if role in {"contradicts", "contradictory"}
    ]
    if contradictory_artifacts:
        components["contradictory_evidence"] = -min(0.30, 0.10 * len(contradictory_artifacts))
        contradicting.append(f"{len(contradictory_artifacts)} linked evidence artifact(s) contradict the relationship")

    # Temporal coincidence alone, or time plus broad language, is not enough.
    # An explicitly shared named service may create a repeated-reporting candidate,
    # but it remains distinct from technical corroboration and dependency evidence.
    eligible_components = {
        key for key, value in components.items()
        if value > 0 and key not in {"temporal_proximity", "semantic_relevance"}
    }
    if not eligible_components:
        return None

    if not relationships:
        relationships.append("temporal_coincidence")
    strength = round(max(0.0, min(1.0, sum(components.values()))), 3)
    confidence = "high" if strength >= 0.75 and independent_technical else "moderate" if strength >= 0.4 else "low"
    basis = (
        "observed"
        if independent_technical
        else "reported"
        if eligible_components == {"shared_reported_service"}
        else "inferred"
    )
    explanation = (
        f"Proposed because {supporting[0].lower()} and "
        + "; ".join(supporting[1:])
        + ". This is a correlation candidate, not a causal or malicious-activity attribution."
    )
    return CorrelationAssessment(
        left_event_id=min(left.id, right.id),
        right_event_id=max(left.id, right.id),
        relationship_types=list(dict.fromkeys(relationships)),
        strength=strength,
        confidence_assessment=confidence,
        explanation=explanation,
        supporting_factors=supporting,
        contradictory_factors=contradicting,
        score_components=components,
        evidence_ids=evidence_ids,
        independent_publishers=independent_publishers,
        independent_technical_corroboration=independent_technical,
        evidence_basis=basis,
        first_observed_at=min(as_utc(left.observed_at), as_utc(right.observed_at)),
        last_observed_at=max(as_utc(left.observed_at), as_utc(right.observed_at)),
        additional_observations={
            "would_strengthen": ["matching DNS or traffic anomaly", "confirmed dependency record", "independent primary technical source"],
            "would_weaken": ["maintenance confirmation", "different affected infrastructure", "evidence of unrelated root causes"],
            "source_reporting_delay_hours": {
                str(left.id): round(abs((knowledge_time(left) - as_utc(left.observed_at)).total_seconds()) / 3600, 2),
                str(right.id): round(abs((knowledge_time(right) - as_utc(right.observed_at)).total_seconds()) / 3600, 2),
            },
            "overlapping_evidence_dimensions": overlapping_dimensions,
            "technical_observation_families": {
                str(left.id): sorted(left_families),
                str(right.id): sorted(right_families),
            },
            "technical_sources": sorted(measurement_sources),
            "shared_technical_sources": sorted(shared_sources),
        },
    )


def candidate_correlations(
    db: Session,
    *,
    days: int = 30,
    window_hours: float = 24,
    minimum: float = 0.08,
    cutoff: datetime | None = None,
    include_scheduled: bool = False,
    limit: int = 500,
) -> list[CorrelationAssessment]:
    now = as_utc(cutoff or datetime.now(timezone.utc))
    start = now - timedelta(days=days)
    conditions = [Event.observed_at >= start, Event.observed_at <= now]
    if not include_scheduled:
        conditions.append(Event.category != "scheduled_maintenance")
    # Historical replay excludes facts not available by the cutoff.
    conditions.append(
        func.coalesce(Event.publisher_reported_at, Event.first_observed_at, Event.ingested_at, Event.observed_at) <= now
    )
    events = db.scalars(select(Event).where(*conditions).order_by(Event.observed_at.desc()).limit(2000)).all()
    measurements = db.scalars(
        select(NetworkMeasurement).where(
            NetworkMeasurement.observed_at >= start - timedelta(hours=2),
            NetworkMeasurement.observed_at <= now,
            or_(func.abs(NetworkMeasurement.z_score) >= 2, NetworkMeasurement.source == "ioda"),
        ).limit(5000)
    ).all()
    evidence = _evidence_for_events(db, [event.id for event in events])

    results: list[CorrelationAssessment] = []
    for index, left in enumerate(events):
        for right in events[index + 1:]:
            if (as_utc(left.observed_at) - as_utc(right.observed_at)).total_seconds() > window_hours * 3600:
                break
            assessment = evaluate_pair(
                db, left, right, measurements=measurements, event_evidence=evidence, window_hours=window_hours
            )
            if assessment and assessment.strength >= minimum:
                results.append(assessment)
    return sorted(results, key=lambda item: item.strength, reverse=True)[:limit]


def persist_candidates(db: Session, assessments: list[CorrelationAssessment], *, cutoff: datetime | None = None) -> int:
    changed = 0
    for assessment in assessments:
        for relationship_type in assessment.relationship_types:
            identity = f"{assessment.left_event_id}:{assessment.right_event_id}:{relationship_type}"
            stable_id = "rel_" + hashlib.sha256(identity.encode()).hexdigest()[:24]
            record = db.scalar(select(CorrelationRecord).where(CorrelationRecord.stable_id == stable_id))
            values = {
                "left_event_id": assessment.left_event_id,
                "right_event_id": assessment.right_event_id,
                "relationship_type": relationship_type,
                "evidence_ids": assessment.evidence_ids,
                "source_provenance": {
                    "independent_publishers": assessment.independent_publishers,
                    "independent_technical_corroboration": assessment.independent_technical_corroboration,
                },
                "first_observed_at": assessment.first_observed_at,
                "last_observed_at": assessment.last_observed_at,
                "strength": assessment.strength,
                "confidence_assessment": assessment.confidence_assessment,
                "explanation": assessment.explanation,
                "supporting_factors": assessment.supporting_factors,
                "contradictory_factors": assessment.contradictory_factors,
                "independence": {
                    "publisher": assessment.independent_publishers,
                    "technical": assessment.independent_technical_corroboration,
                },
                "additional_observations": assessment.additional_observations,
                "score_components": assessment.score_components,
                "evidence_basis": assessment.evidence_basis,
                "replay_cutoff": cutoff,
                "updated_at": datetime.now(timezone.utc),
            }
            if record:
                for key, value in values.items():
                    setattr(record, key, value)
            else:
                db.add(CorrelationRecord(stable_id=stable_id, **values))
            changed += 1
    db.commit()
    return changed
