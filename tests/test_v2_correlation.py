from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.main import Base, Event, NetworkMeasurement
from app.services.correlation import candidate_correlations, evaluate_pair
from app.v2_models import EvidenceArtifact, EventEvidence, ProviderDependency


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def incident(identifier: int, title: str, at: datetime, **values) -> Event:
    defaults = {
        "fingerprint": f"f{identifier:063d}",
        "source": f"source-{identifier}",
        "title": title,
        "url": f"https://example.org/{identifier}",
        "observed_at": at,
        "ingested_at": at + timedelta(minutes=5),
        "first_observed_at": at,
        "publisher_reported_at": at,
        "category": "service_incident",
        "confidence": 0.8,
        "detail": "",
    }
    defaults.update(values)
    return Event(id=identifier, **defaults)


def test_simultaneous_unrelated_outages_are_not_candidates():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "API latency in Tokyo", now, provider="alpha", region="asia-northeast1")
        right = incident(2, "Email delivery failure in Virginia", now, provider="beta", region="us-east4")
        db.add_all([left, right])
        db.commit()
        assert evaluate_pair(db, left, right) is None


def test_common_provider_is_inferred_but_not_called_causal():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "DNS service unavailable", now, provider="shared-cloud")
        right = incident(2, "DNS queries timing out", now + timedelta(minutes=10), provider="shared-cloud")
        db.add_all([left, right])
        db.commit()
        result = evaluate_pair(db, left, right)
        assert result is not None
        assert "shares_provider" in result.relationship_types
        assert result.evidence_basis == "inferred"
        assert "not a causal" in result.explanation


def test_provider_and_asn_scope_are_not_double_counted():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "API unavailable", now, provider="example", asn="AS64500")
        right = incident(2, "API requests failing", now + timedelta(minutes=5), provider="example", asn="AS64500")
        db.add_all([left, right])
        db.commit()
        result = evaluate_pair(db, left, right)
        assert result is not None
        assert result.score_components["shared_provider"] == 0.30
        assert result.score_components["shared_asn"] == 0.35
        assert result.score_components["overlapping_provider_asn_discount"] == -0.30
        assert result.additional_observations["overlapping_evidence_dimensions"] == [["provider", "asn"]]
        assert any("scored once" in factor for factor in result.contradictory_factors)


def test_confirmed_dependency_is_distinct_from_shared_branding():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "Application unavailable", now, provider="downstream")
        right = incident(2, "Edge routing disruption", now, provider="upstream")
        db.add_all([left, right, ProviderDependency(consumer="downstream", dependency="upstream", status="confirmed", confidence=0.9, evidence_ids=[1], explanation="Contract and route evidence")])
        db.commit()
        result = evaluate_pair(db, left, right)
        assert result is not None
        assert "confirmed_dependency" in result.relationship_types


def test_different_publishers_with_same_upstream_are_not_independent_technical_evidence():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "Resolver outage", now, provider="dns-co")
        right = incident(2, "Resolver outage update", now + timedelta(minutes=3), provider="dns-co")
        artifact_a = EvidenceArtifact(stable_id="ev_a", original_url="https://a.example/report", publisher="Publisher A", upstream_source="Status Vendor", content_hash="a" * 64)
        artifact_b = EvidenceArtifact(stable_id="ev_b", original_url="https://b.example/report", publisher="Publisher B", upstream_source="Status Vendor", content_hash="b" * 64)
        db.add_all([left, right, artifact_a, artifact_b])
        db.flush()
        db.add_all([EventEvidence(event_id=1, evidence_id=artifact_a.id, role="supports"), EventEvidence(event_id=2, evidence_id=artifact_b.id, role="supports")])
        db.commit()
        result = evaluate_pair(db, left, right)
        assert result is not None
        assert result.independent_publishers is True
        assert result.independent_technical_corroboration is False
        assert result.score_components["shared_upstream_discount"] < 0


def test_independent_network_observations_raise_technical_corroboration():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "Routing outage", now, asn="AS64500")
        right = incident(2, "Network unreachable", now + timedelta(minutes=4), asn="AS64500")
        measurements = [
            NetworkMeasurement(fingerprint="m" * 64, source="ripe", signal_type="bgp_withdrawals", observed_at=now, provider=None, asn="AS64500", region=None, resource="prefix", value=20, unit="count", z_score=5, confidence=0.9, url="https://stat.ripe.net/x", detail=""),
            NetworkMeasurement(fingerprint="n" * 64, source="ioda", signal_type="reachability_loss", observed_at=now, provider=None, asn="AS64500", region=None, resource="asn", value=12, unit="score", z_score=4, confidence=0.8, url="https://ioda.inetintel.cc/x", detail=""),
        ]
        db.add_all([left, right, *measurements])
        db.commit()
        result = evaluate_pair(db, left, right, measurements=measurements)
        assert result is not None
        assert result.independent_technical_corroboration is True
        assert "observed_network_anomaly" in result.relationship_types


def test_contradictory_evidence_reduces_strength():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "Database unavailable", now, provider="cloud")
        right = incident(2, "Database errors", now, provider="cloud")
        db.add_all([left, right])
        db.commit()
        baseline = evaluate_pair(db, left, right)
        artifact = EvidenceArtifact(stable_id="ev_c", original_url="https://example.org/root-cause", publisher="Operator", content_hash="c" * 64)
        db.add(artifact)
        db.flush()
        db.add(EventEvidence(event_id=1, evidence_id=artifact.id, role="contradicts"))
        db.commit()
        contradicted = evaluate_pair(db, left, right)
        assert contradicted.strength < baseline.strength
        assert contradicted.contradictory_factors


def test_scheduled_maintenance_and_policy_news_are_excluded():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        maintenance = incident(1, "Scheduled cloud maintenance", now, provider="cloud", category="scheduled_maintenance")
        outage = incident(2, "Cloud outage", now, provider="cloud")
        policy = incident(3, "CISA reporting form announced", now, provider="cloud", category="policy_announcement")
        db.add_all([maintenance, outage, policy])
        db.commit()
        assert evaluate_pair(db, maintenance, outage) is None
        assert evaluate_pair(db, policy, outage) is None


def test_security_advisories_do_not_form_operational_dependency_candidates():
    engine = database()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        left = incident(1, "CISA advisory for product A", now, provider="example", asn="AS64500", category="security_advisory")
        right = incident(2, "CISA advisory for product B", now + timedelta(minutes=5), provider="example", asn="AS64500", category="security_advisory")
        db.add_all([left, right])
        db.commit()
        assert evaluate_pair(db, left, right) is None


def test_replay_excludes_delayed_reports_and_future_knowledge():
    engine = database()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=1)
    with Session(engine) as db:
        known = incident(1, "Known outage", cutoff - timedelta(minutes=20), provider="cloud", publisher_reported_at=cutoff - timedelta(minutes=10))
        delayed = incident(2, "Delayed outage report", cutoff - timedelta(minutes=15), provider="cloud", publisher_reported_at=cutoff + timedelta(minutes=20))
        db.add_all([known, delayed])
        db.commit()
        assert candidate_correlations(db, days=1, cutoff=cutoff) == []
