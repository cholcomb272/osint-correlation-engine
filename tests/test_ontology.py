from datetime import datetime, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.main import Base, EventIn, insert_event
from app.v2_models import (
    EventClassification,
    EventEntity,
    EventFieldAssessment,
    IntelligenceEntity,
    KnowledgeRelationship,
    RelationshipRevision,
)


def test_reconcile_materializes_entities_classifications_and_field_uncertainty():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    event = EventIn(
        source="structured-test",
        title="Example Gateway exploitation observed",
        url="https://example.org/events/1",
        observed_at=datetime(2026, 11, 28, tzinfo=timezone.utc),
        category="vulnerability_exploitation",
        domain="cybersecurity",
        event_type="known_exploited_vulnerability",
        service="Example Gateway",
        confidence=0.9,
        source_reliability=0.9,
        extraction_confidence=0.95,
        source_event_id="CVE-2026-1234",
        raw_metadata={
            "publisher_name": "National CERT",
            "source_role": "official_advisory",
            "vendor": "Example Vendor",
            "cve_ids": ["CVE-2026-1234"],
            "entity_mentions": ["Example Vendor", "Example Gateway"],
            "fingerprint_strategy": "source_event_id",
        },
    )
    with Session(engine) as db:
        record, created, _ = insert_event(db, event)
        assert created
        assert db.scalar(select(func.count()).select_from(IntelligenceEntity)) >= 4
        assert db.scalar(select(func.count()).select_from(EventEntity)) >= 4
        labels = set(
            db.scalars(
                select(EventClassification.label).where(
                    EventClassification.event_id == record.id
                )
            ).all()
        )
        assert {"cybersecurity", "known_exploited_vulnerability"} <= labels
        fields = {
            item.field_name: item
            for item in db.scalars(
                select(EventFieldAssessment).where(
                    EventFieldAssessment.event_id == record.id
                )
            ).all()
        }
        assert fields["what_happened"].knowledge_status == "reported"
        assert fields["cause"].knowledge_status == "not_applicable"
        assert fields["attribution"].knowledge_status == "not_applicable"
        predicates = set(db.scalars(select(KnowledgeRelationship.predicate)).all())
        assert {"REPORTED_BY", "AFFECTS", "SHARES_VULNERABILITY", "PRODUCES"} <= predicates
        assert db.scalar(select(func.count()).select_from(RelationshipRevision)) >= 4


def test_reconcile_is_idempotent_for_unchanged_event():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    event = EventIn(
        source="direct-test",
        title="Observed flood",
        url="https://example.org/events/flood",
        observed_at=datetime(2026, 11, 28, tzinfo=timezone.utc),
        category="natural_hazard",
        domain="environmental_hazard",
        event_type="flood",
        location_name="Test Valley",
        raw_metadata={
            "publisher_name": "Hydrology Agency",
            "source_role": "direct_observation",
        },
    )
    with Session(engine) as db:
        record, _, _ = insert_event(db, event)
        before = {
            "classifications": db.scalar(select(func.count()).select_from(EventClassification)),
            "fields": db.scalar(select(func.count()).select_from(EventFieldAssessment)),
            "relationships": db.scalar(select(func.count()).select_from(KnowledgeRelationship)),
            "revisions": db.scalar(select(func.count()).select_from(RelationshipRevision)),
        }
        _, created, changed = insert_event(db, event, refresh_existing=True)
        assert not created and not changed
        after = {
            "classifications": db.scalar(select(func.count()).select_from(EventClassification)),
            "fields": db.scalar(select(func.count()).select_from(EventFieldAssessment)),
            "relationships": db.scalar(select(func.count()).select_from(KnowledgeRelationship)),
            "revisions": db.scalar(select(func.count()).select_from(RelationshipRevision)),
        }
        assert before == after
        assert record.domain == "environmental_hazard"
