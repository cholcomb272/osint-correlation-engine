from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.main import Base, EventIn, insert_event
from app.services.fusion import discover_clusters, materialize_relationships
from app.v2_models import EventCluster, InvestigationCandidate, KnowledgeRelationship


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def event(source: str, title: str, observed_at: datetime, **values) -> EventIn:
    return EventIn(
        source=source,
        title=title,
        url=f"https://{source}.example/events/{title.casefold().replace(' ', '-')}",
        observed_at=observed_at,
        source_reliability=0.85,
        extraction_confidence=0.9,
        raw_metadata={
            "publisher_name": source.title(),
            "source_role": values.pop("source_role", "official_report"),
        },
        **values,
    )


def test_shared_vulnerability_is_relevant_but_not_causal():
    engine = database()
    now = datetime(2026, 11, 28, tzinfo=timezone.utc)
    with Session(engine) as db:
        for index, source in enumerate(("cert-a", "cert-b")):
            item = event(
                source,
                f"Report {index} involving CVE-2026-1234",
                now - timedelta(days=index),
                category="reported_incident",
                domain="cybersecurity",
                event_type="reported_compromise",
            )
            item.raw_metadata["cve_ids"] = ["CVE-2026-1234"]
            insert_event(db, item)
        result = materialize_relationships(db, days=90, cutoff=now)
        assert result["relationship_types"]["SHARES_VULNERABILITY"] == 1
        relationship = db.scalar(
            select(KnowledgeRelationship).where(
                KnowledgeRelationship.predicate == "SHARES_VULNERABILITY",
                KnowledgeRelationship.subject_ref.like("event:%"),
                KnowledgeRelationship.object_ref.like("event:%"),
            )
        )
        assert relationship.semantic_tier == "supported_inference"
        assert relationship.causal_confidence is None
        assert relationship.attributes["causal_claim"] is False


def test_shared_publisher_alone_does_not_create_event_relationship():
    engine = database()
    now = datetime(2026, 11, 28, tzinfo=timezone.utc)
    with Session(engine) as db:
        insert_event(db, event("same-publisher", "Unrelated flood", now, domain="environmental_hazard", event_type="flood"))
        insert_event(db, event("same-publisher", "Unrelated policy", now, domain="geopolitical_policy", event_type="policy_announcement"))
        materialize_relationships(db, days=30, cutoff=now)
        event_edges = db.scalar(
            select(func.count()).select_from(KnowledgeRelationship).where(
                KnowledgeRelationship.subject_ref.like("event:%"),
                KnowledgeRelationship.object_ref.like("event:%"),
            )
        )
        assert event_edges == 0


def test_cross_domain_cluster_creates_explainable_investigation_candidate():
    engine = database()
    now = datetime(2026, 11, 28, tzinfo=timezone.utc)
    with Session(engine) as db:
        items = [
            event("hazard-agency", "Flood near Test Region", now - timedelta(hours=6), category="natural_hazard", domain="environmental_hazard", event_type="flood", region="test-region", significance="high"),
            event("grid-operator", "Power disruption in Test Region", now - timedelta(hours=3), category="service_incident", domain="critical_infrastructure", event_type="power_disruption", region="test-region", significance="high"),
            event("transport-operator", "Rail service disruption in Test Region", now - timedelta(hours=1), category="service_incident", domain="transportation_logistics", event_type="rail_disruption", region="test-region", significance="moderate"),
        ]
        for item in items:
            insert_event(db, item)
        materialize_relationships(db, days=30, cutoff=now)
        result = discover_clusters(db, days=30, cutoff=now)
        assert result["clusters"] == 1
        cluster = db.scalar(select(EventCluster))
        assert cluster.cluster_type == "cross_domain"
        assert cluster.anomaly_score is None
        candidate = db.scalar(select(InvestigationCandidate))
        assert candidate is not None
        assert len(candidate.competing_explanations) >= 3
        assert "not a common cause" in cluster.explanation


def test_fusion_replay_excludes_events_not_known_at_cutoff():
    engine = database()
    now = datetime(2026, 11, 28, tzinfo=timezone.utc)
    cutoff = now - timedelta(hours=2)
    with Session(engine) as db:
        known = event("source-a", "Known regional outage", cutoff - timedelta(minutes=30), category="service_incident", domain="infrastructure", event_type="outage", region="test-region")
        known.publisher_reported_at = cutoff - timedelta(minutes=20)
        delayed = event("source-b", "Delayed regional outage report", cutoff - timedelta(minutes=25), category="service_incident", domain="infrastructure", event_type="outage", region="test-region")
        delayed.publisher_reported_at = cutoff + timedelta(minutes=20)
        insert_event(db, known)
        insert_event(db, delayed)
        result = materialize_relationships(db, days=1, cutoff=cutoff)
        assert result["events_considered"] == 1
        assert result["relationships_evaluated"] == 0
