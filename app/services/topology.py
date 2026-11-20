from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from statistics import median

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.main import Event, NetworkMeasurement, PROVIDER_METADATA, as_utc
from app.services.correlation import candidate_correlations, observation_family
from app.v2_models import EvidenceArtifact, EventEvidence, Hypothesis, Investigation, InvestigationEvent


def display_label(value: str, limit: int = 46) -> str:
    normalized = " ".join(value.split())
    return normalized if len(normalized) <= limit else normalized[: limit - 1].rstrip() + "…"


def relationship_presentation(relationship: str, basis: str) -> tuple[str, str]:
    readable = relationship.replace("_", " ")
    if relationship == "confirmed_dependency":
        return "confirmed_dependency", "confirmed dependency"
    if relationship == "independent_corroboration":
        return "independently_corroborated", "independent corroboration"
    if basis == "hypothesis":
        return "unverified_hypothesis", f"hypothesis · {readable}"
    if basis == "inferred":
        return "inferred_candidate_not_causal", f"candidate · {readable}"
    return "direct_observation", readable


def telemetry_coverage(db: Session, events: list[Event], *, start: datetime, end: datetime) -> dict:
    rows = db.execute(
        select(
            NetworkMeasurement.source,
            NetworkMeasurement.resource,
            NetworkMeasurement.provider,
            NetworkMeasurement.asn,
            NetworkMeasurement.signal_type,
            NetworkMeasurement.detail,
            func.count(NetworkMeasurement.id),
            func.min(NetworkMeasurement.observed_at),
            func.max(NetworkMeasurement.observed_at),
        )
        .where(NetworkMeasurement.observed_at >= start, NetworkMeasurement.observed_at <= end)
        .group_by(
            NetworkMeasurement.source,
            NetworkMeasurement.resource,
            NetworkMeasurement.provider,
            NetworkMeasurement.asn,
            NetworkMeasurement.signal_type,
            NetworkMeasurement.detail,
        )
    ).all()
    resources: dict[tuple[str, str, str | None, str | None], dict] = {}
    source_counts: defaultdict[str, int] = defaultdict(int)
    family_counts: defaultdict[str, int] = defaultdict(int)
    interval_estimates: list[float] = []
    for source, resource, provider, asn, signal_type, detail, count, first, last in rows:
        key = (source, resource, provider, asn)
        family = observation_family(source, signal_type, detail)
        try:
            metadata = json.loads(detail or "{}")
        except (TypeError, ValueError):
            metadata = {}
        target = metadata.get("target") if isinstance(metadata.get("target"), dict) else {}
        entry = resources.setdefault(
            key,
            {
                "source": source,
                "resource": resource,
                "provider": provider,
                "asn": asn,
                "signal_types": [],
                "observation_families": [],
                "target_selection_reasons": [],
                "incident_aware": False,
                "sample_count": 0,
                "first_observed_at": as_utc(first).isoformat(),
                "last_observed_at": as_utc(last).isoformat(),
                "observation_interval_seconds": None,
                "_intervals": [],
            },
        )
        entry["signal_types"].append(signal_type)
        entry["observation_families"].append(family)
        if target.get("selection_reason"):
            entry["target_selection_reasons"].append(target["selection_reason"])
        entry["incident_aware"] = entry["incident_aware"] or bool(target.get("incident_aware"))
        entry["sample_count"] += count
        source_counts[source] += count
        family_counts[family] += count
        if count > 1:
            interval = (as_utc(last) - as_utc(first)).total_seconds() / (count - 1)
            entry["_intervals"].append(interval)
            interval_estimates.append(interval)

    for entry in resources.values():
        estimates = entry.pop("_intervals")
        entry["signal_types"].sort()
        entry["signal_types"] = sorted(set(entry["signal_types"]))
        entry["observation_families"] = sorted(set(entry["observation_families"]))
        entry["target_selection_reasons"] = sorted(set(entry["target_selection_reasons"]))
        entry["observation_interval_seconds"] = round(median(estimates)) if estimates else None

    event_asns = {event.asn for event in events if event.asn}
    event_providers = {event.provider for event in events if event.provider}
    monitored_asns = {entry["asn"] for entry in resources.values() if entry["asn"]}
    monitored_providers = {entry["provider"] for entry in resources.values() if entry["provider"]}
    expected_sources = ("ripe_stat", "ioda")
    configured_prefixes = sorted(
        {
            metadata["prefix"]
            for metadata in PROVIDER_METADATA.values()
            if metadata.get("prefix")
        }
    )
    configured_asns = sorted(
        {
            metadata["asn"]
            for metadata in PROVIDER_METADATA.values()
            if metadata.get("asn")
        }
    )
    observed_prefixes = sorted(
        {entry["resource"] for entry in resources.values() if "/" in entry["resource"]}
    )
    return {
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "configured_prefixes": configured_prefixes,
        "configured_asns": configured_asns,
        "observed_prefixes": observed_prefixes,
        "monitored_prefix_count": len(observed_prefixes),
        "incident_aware_prefix_count": len(
            {entry["resource"] for entry in resources.values() if entry["incident_aware"]}
        ),
        "monitored_asn_count": len(monitored_asns),
        "incident_asn_count": len(event_asns),
        "covered_incident_asn_count": len(event_asns & monitored_asns),
        "asn_coverage_ratio": round(len(event_asns & monitored_asns) / len(event_asns), 3) if event_asns else None,
        "incident_provider_count": len(event_providers),
        "covered_incident_provider_count": len(event_providers & monitored_providers),
        "provider_coverage_ratio": round(len(event_providers & monitored_providers) / len(event_providers), 3) if event_providers else None,
        "observation_interval_seconds": round(median(interval_estimates)) if interval_estimates else None,
        "sources": [
            {
                "source": source,
                "sample_count": source_counts.get(source, 0),
                "status": "observed" if source_counts.get(source, 0) else "no_observations",
            }
            for source in expected_sources
        ],
        "observation_families": [
            {"family": family, "sample_count": count}
            for family, count in sorted(family_counts.items())
        ],
        "observation_family_count": len(family_counts),
        "missing_event_asns": sorted(event_asns - monitored_asns),
        "missing_event_providers": sorted(event_providers - monitored_providers),
        "resources": sorted(resources.values(), key=lambda item: (item["source"], item["provider"] or "", item["resource"]))[:50],
        "scope_note": (
            "Coverage describes bounded ASN-derived prefix targets, observation modalities, and intervals. "
            "Repeated samples from one observation family are not independent corroboration, and this "
            "does not establish visibility across an entire provider network or prove incident impact."
        ),
    }


def incident_node(event: Event) -> dict:
    return {
        "data": {
            "id": f"incident:{event.id}",
            "entity_id": event.id,
            "type": "incident",
            "label": event.title,
            "display_label": display_label(event.title),
            "record_kind": event.category,
            "source": event.source,
            "provider": event.provider,
            "asn": event.asn,
            "region": event.region,
            "service": event.service,
            "severity": event.severity,
            "category": event.category,
            "confidence": event.confidence,
            "cause_classification": event.cause_classification,
            "observed_at": as_utc(event.observed_at).isoformat(),
            "url": event.url,
            "is_future": as_utc(event.observed_at) > datetime.now(timezone.utc),
            "is_scheduled": event.category == "scheduled_maintenance",
        }
    }


def topology(
    db: Session,
    *,
    days: int = 30,
    provider: str | None = None,
    region: str | None = None,
    severity: str | None = None,
    minimum_confidence: float = 0,
    edge_types: list[str] | None = None,
    include_inferred: bool = False,
    include_hypotheses: bool = False,
    page: int = 1,
    page_size: int = 100,
    focus: str | None = None,
    cutoff: datetime | None = None,
) -> dict:
    now = as_utc(cutoff or datetime.now(timezone.utc))
    window_start = now - timedelta(days=days)
    conditions = [
        Event.observed_at >= window_start,
        Event.observed_at <= now,
        Event.category != "scheduled_maintenance",
        Event.confidence >= minimum_confidence,
        func.coalesce(Event.publisher_reported_at, Event.first_observed_at, Event.ingested_at, Event.observed_at) <= now,
    ]
    if provider:
        conditions.append(func.lower(Event.provider) == provider.casefold())
    if region:
        conditions.append(func.lower(Event.region) == region.casefold())
    if severity:
        conditions.append(Event.severity == severity)
    if focus and focus.startswith("incident:"):
        try:
            focused_id = int(focus.split(":", 1)[1])
        except ValueError:
            focused_id = -1
        focused = db.get(Event, focused_id)
        if focused:
            conditions.append(
                or_(
                    Event.id == focused_id,
                    Event.provider == focused.provider if focused.provider else False,
                    Event.asn == focused.asn if focused.asn else False,
                    Event.region == focused.region if focused.region else False,
                )
            )
    elif focus and focus.startswith("investigation_cluster:"):
        try:
            investigation_id = int(focus.split(":", 1)[1])
        except ValueError:
            investigation_id = -1
        member_ids = select(InvestigationEvent.event_id).where(InvestigationEvent.investigation_id == investigation_id)
        conditions.append(Event.id.in_(member_ids))

    total = db.scalar(select(func.count()).select_from(Event).where(*conditions)) or 0
    events = db.scalars(
        select(Event)
        .where(*conditions)
        .order_by(Event.observed_at.desc(), Event.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    event_by_id = {event.id: event for event in events}
    nodes: dict[str, dict] = {f"incident:{event.id}": incident_node(event) for event in events}
    edges: dict[str, dict] = {}

    def add_entity(kind: str, value: str | None) -> str | None:
        if not value:
            return None
        stable = f"{kind}:{value.casefold()}"
        nodes.setdefault(stable, {"data": {"id": stable, "type": kind, "label": value, "display_label": display_label(value)}})
        return stable

    for event in events:
        incident_id = f"incident:{event.id}"
        provider_kind = "cloud_platform" if event.provider and "cloud" in event.provider.casefold() else "provider"
        for kind, value in ((provider_kind, event.provider), ("asn", event.asn), ("region", event.region), ("service", event.service), ("datacenter", event.datacenter)):
            entity_id = add_entity(kind, value)
            if entity_id:
                edge_id = f"scope:{incident_id}:{entity_id}"
                edges[edge_id] = {
                    "data": {
                        "id": edge_id,
                        "source": incident_id,
                        "target": entity_id,
                        "relationship_type": "observed_on",
                        "semantic_status": "direct_source_observation",
                        "visual_label": "",
                        "causal_claim": False,
                        "evidence_refs": [],
                        "source_provenance": {"publisher": event.source, "url": event.url},
                        "evidence_basis": "observed",
                        "confidence": event.confidence,
                        "confidence_assessment": "source_reported",
                        "explanation": f"The source record identifies {value} as the affected {kind}.",
                        "first_observed_at": as_utc(event.observed_at).isoformat(),
                        "last_observed_at": as_utc(event.observed_at).isoformat(),
                        "assessment_status": "source_reported",
                        "updated_at": as_utc(event.collected_at or event.ingested_at).isoformat(),
                    }
                }

    selected_ids = set(event_by_id)
    candidates = candidate_correlations(db, days=days, cutoff=now, limit=1000)
    evidence_summary = {
        "direct_observations": 0,
        "confirmed_dependencies": 0,
        "inferred_relationships": 0,
        "temporal_associations": 0,
        "hypotheses": 0,
        "independent_technical_corroboration": 0,
        "visible_edges": 0,
        "hidden_inferred_edges": 0,
    }
    for candidate in candidates:
        if candidate.left_event_id not in selected_ids or candidate.right_event_id not in selected_ids:
            continue
        if candidate.independent_technical_corroboration:
            evidence_summary["independent_technical_corroboration"] += 1
        for relationship in candidate.relationship_types:
            relationship_basis = (
                "observed"
                if relationship == "confirmed_dependency"
                or (relationship == "independent_corroboration" and candidate.independent_technical_corroboration)
                else candidate.evidence_basis
            )
            if relationship == "confirmed_dependency":
                evidence_summary["confirmed_dependencies"] += 1
            if relationship == "temporal_coincidence":
                evidence_summary["temporal_associations"] += 1
            if relationship_basis == "inferred":
                evidence_summary["inferred_relationships"] += 1
            if edge_types is not None and relationship not in edge_types:
                continue
            if relationship_basis == "inferred" and not include_inferred:
                evidence_summary["hidden_inferred_edges"] += 1
                continue
            semantic_status, visual_label = relationship_presentation(relationship, relationship_basis)
            edge_id = f"correlation:{candidate.left_event_id}:{candidate.right_event_id}:{relationship}"
            edges[edge_id] = {
                "data": {
                    "id": edge_id,
                    "source": f"incident:{candidate.left_event_id}",
                    "target": f"incident:{candidate.right_event_id}",
                    "relationship_type": relationship,
                    "semantic_status": semantic_status,
                    "visual_label": visual_label,
                    "causal_claim": False,
                    "evidence_refs": candidate.evidence_ids,
                    "source_provenance": {
                        "independent_publishers": candidate.independent_publishers,
                        "independent_technical_corroboration": candidate.independent_technical_corroboration,
                    },
                    "first_observed_at": as_utc(candidate.first_observed_at).isoformat(),
                    "last_observed_at": as_utc(candidate.last_observed_at).isoformat(),
                    "confidence": candidate.strength,
                    "confidence_assessment": candidate.confidence_assessment,
                    "explanation": candidate.explanation,
                    "assessment_status": "candidate",
                    "evidence_basis": relationship_basis,
                    "contradictory_factors": candidate.contradictory_factors,
                    "updated_at": now.isoformat(),
                }
            }

    measurements = db.scalars(
        select(NetworkMeasurement).where(
            NetworkMeasurement.observed_at >= window_start,
            NetworkMeasurement.observed_at <= now,
            or_(func.abs(NetworkMeasurement.z_score) >= 2, NetworkMeasurement.source == "ioda"),
        ).limit(page_size * 5)
    ).all()
    for measurement in measurements:
        matching_events = [
            event for event in events
            if any(
                left and right and left.casefold() == right.casefold()
                for left, right in ((event.provider, measurement.provider), (event.asn, measurement.asn), (event.region, measurement.region))
            )
            and abs((as_utc(event.observed_at) - as_utc(measurement.observed_at)).total_seconds()) <= 7200
        ]
        if not matching_events:
            continue
        node_id = f"network_anomaly:{measurement.id}"
        nodes[node_id] = {
            "data": {
                "id": node_id,
                "entity_id": measurement.id,
                "type": "network_anomaly",
                "label": f"{measurement.signal_type}: {measurement.resource}",
                "display_label": display_label(f"{measurement.signal_type}: {measurement.resource}"),
                "source": measurement.source,
                "provider": measurement.provider,
                "asn": measurement.asn,
                "resource": measurement.resource,
                "observed_at": as_utc(measurement.observed_at).isoformat(),
                "z_score": measurement.z_score,
                "url": measurement.url,
            }
        }
        for event in matching_events:
            edge_id = f"measurement:{measurement.id}:{event.id}"
            edges[edge_id] = {
                "data": {
                    "id": edge_id,
                    "source": node_id,
                    "target": f"incident:{event.id}",
                    "relationship_type": "observed_network_anomaly",
                    "semantic_status": "direct_technical_observation",
                    "visual_label": "network observation",
                    "causal_claim": False,
                    "evidence_refs": [f"network_measurement:{measurement.id}"],
                    "source_provenance": {"publisher": measurement.source, "url": measurement.url},
                    "evidence_basis": "observed",
                    "confidence": measurement.confidence,
                    "confidence_assessment": "source_reported",
                    "explanation": "A passive public network measurement overlaps the incident's technical scope and time window.",
                    "first_observed_at": as_utc(measurement.observed_at).isoformat(),
                    "last_observed_at": as_utc(measurement.observed_at).isoformat(),
                    "assessment_status": "source_reported",
                    "updated_at": as_utc(measurement.ingested_at).isoformat(),
                }
            }

    evidence_rows = db.execute(
        select(EventEvidence.event_id, EventEvidence.role, EvidenceArtifact)
        .join(EvidenceArtifact, EvidenceArtifact.id == EventEvidence.evidence_id)
        .where(EventEvidence.event_id.in_(selected_ids))
    ).all() if selected_ids else []
    for event_id, role, artifact in evidence_rows:
        node_id = f"evidence:{artifact.id}"
        nodes[node_id] = {
            "data": {
                "id": node_id,
                "entity_id": artifact.id,
                "type": "evidence",
                "label": f"Evidence from {artifact.publisher}",
                "display_label": display_label(f"Evidence · {artifact.publisher}"),
                "publisher": artifact.publisher,
                "url": artifact.original_url,
                "verification_status": artifact.verification_status,
                "reliability": artifact.reliability,
            }
        }
        edge_id = f"evidence-link:{artifact.id}:{event_id}:{role}"
        edges[edge_id] = {
            "data": {
                "id": edge_id,
                "source": node_id,
                "target": f"incident:{event_id}",
                "relationship_type": "contradicts_hypothesis" if role.startswith("contradict") else "supports_observation",
                "semantic_status": "documented_evidence",
                "visual_label": "contradicts" if role.startswith("contradict") else "source evidence",
                "causal_claim": False,
                "evidence_refs": [artifact.id],
                "source_provenance": {"publisher": artifact.publisher, "upstream_source": artifact.upstream_source, "url": artifact.original_url},
                "evidence_basis": "observed",
                "confidence": artifact.reliability,
                "confidence_assessment": artifact.verification_status,
                "explanation": f"Evidence is linked with role: {role}.",
                "first_observed_at": as_utc(artifact.observed_at or artifact.ingested_at).isoformat(),
                "last_observed_at": as_utc(artifact.retrieved_at).isoformat(),
                "assessment_status": artifact.verification_status,
                "updated_at": as_utc(artifact.retrieved_at).isoformat(),
            }
        }

    hypotheses = db.execute(
        select(Hypothesis, InvestigationEvent.event_id)
        .join(InvestigationEvent, InvestigationEvent.investigation_id == Hypothesis.investigation_id)
        .where(InvestigationEvent.event_id.in_(selected_ids))
    ).all() if selected_ids else []
    evidence_summary["hypotheses"] = len(hypotheses)
    if not include_hypotheses:
        hypotheses = []
    for hypothesis, event_id in hypotheses:
        node_id = f"hypothesis:{hypothesis.id}"
        nodes[node_id] = {
            "data": {
                "id": node_id,
                "entity_id": hypothesis.id,
                "type": "hypothesis",
                "label": hypothesis.statement,
                "display_label": display_label(hypothesis.statement),
                "status": hypothesis.status,
                "confidence": hypothesis.confidence,
            }
        }
        edge_id = f"hypothesis-link:{hypothesis.id}:{event_id}"
        edges[edge_id] = {
            "data": {
                "id": edge_id,
                "source": node_id,
                "target": f"incident:{event_id}",
                "relationship_type": "suspected_common_cause",
                "semantic_status": "unverified_hypothesis",
                "visual_label": "hypothesis · unverified",
                "causal_claim": False,
                "evidence_refs": [],
                "source_provenance": {"type": "investigator_assertion", "author": hypothesis.created_by},
                "evidence_basis": "hypothesis",
                "confidence": hypothesis.confidence,
                "confidence_assessment": hypothesis.status,
                "explanation": hypothesis.rationale or "Investigator-entered hypothesis; not an established dependency.",
                "first_observed_at": as_utc(hypothesis.created_at).isoformat(),
                "last_observed_at": as_utc(hypothesis.updated_at).isoformat(),
                "assessment_status": hypothesis.status,
                "updated_at": as_utc(hypothesis.updated_at).isoformat(),
            }
        }

    investigation_rows = db.execute(
        select(Investigation, InvestigationEvent.event_id)
        .join(InvestigationEvent, InvestigationEvent.investigation_id == Investigation.id)
        .where(InvestigationEvent.event_id.in_(selected_ids))
    ).all() if selected_ids else []
    for investigation, event_id in investigation_rows:
        node_id = f"investigation_cluster:{investigation.id}"
        nodes[node_id] = {
            "data": {
                "id": node_id,
                "entity_id": investigation.id,
                "type": "investigation_cluster",
                "label": investigation.title,
                "display_label": display_label(investigation.title),
                "state": investigation.state,
                "public": investigation.public,
            }
        }
        edge_id = f"investigation-member:{investigation.id}:{event_id}"
        edges[edge_id] = {
            "data": {
                "id": edge_id,
                "source": f"incident:{event_id}",
                "target": node_id,
                "relationship_type": "member_of_cluster",
                "semantic_status": "explicit_investigator_membership",
                "visual_label": "investigation member",
                "causal_claim": False,
                "evidence_refs": [],
                "source_provenance": {"type": "investigator_workspace", "created_by": investigation.created_by},
                "evidence_basis": "observed",
                "confidence": 1.0,
                "confidence_assessment": "explicit_membership",
                "explanation": "An investigator explicitly attached this incident to the workspace.",
                "first_observed_at": as_utc(investigation.created_at).isoformat(),
                "last_observed_at": as_utc(investigation.updated_at).isoformat(),
                "assessment_status": investigation.state,
                "updated_at": as_utc(investigation.updated_at).isoformat(),
            }
        }
    edge_values = list(edges.values())
    evidence_summary["direct_observations"] = sum(
        item["data"].get("evidence_basis") == "observed" for item in edge_values
    )
    evidence_summary["visible_edges"] = len(edge_values)
    return {
        "nodes": list(nodes.values()),
        "edges": edge_values,
        "evidence_summary": evidence_summary,
        "telemetry_coverage": telemetry_coverage(db, events, start=window_start, end=now),
        "view": {
            "mode": "evidence_first",
            "include_inferred": include_inferred,
            "include_hypotheses": include_hypotheses,
            "default_layout": "investigation",
        },
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_incidents": total,
            "has_next": page * page_size < total,
        },
        "replay_cutoff": now.isoformat() if cutoff else None,
        "score_semantics": "Edge confidence is a heuristic evidence-strength assessment, not a probability.",
    }
