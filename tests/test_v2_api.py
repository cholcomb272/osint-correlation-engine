from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main


def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    monkeypatch.setattr(main, "engine", engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(engine, expire_on_commit=False))
    monkeypatch.setenv("API_TOKEN", "test-admin-token")
    return TestClient(main.app)


def test_public_dashboard_apis_need_no_token_and_admin_rejects_anonymous(monkeypatch):
    with client(monkeypatch) as api:
        assert api.get("/api/public/incidents").status_code == 200
        topology = api.get("/api/public/topology")
        assert topology.status_code == 200
        assert topology.json()["view"]["mode"] == "evidence_first"
        assert "evidence_summary" in topology.json()
        assert "telemetry_coverage" in topology.json()
        assert api.get("/api/public/correlations").status_code == 200
        assert api.post("/api/admin/investigations", json={"title": "Test investigation"}).status_code == 401


def test_topology_hides_inferred_candidates_until_requested(monkeypatch):
    headers = {"Authorization": "Bearer test-admin-token"}
    now = datetime.now(timezone.utc)
    with client(monkeypatch) as api:
        for index, title in enumerate(("API outage", "API requests failing")):
            created = api.post("/api/events", headers=headers, json={
                "source": "provider-status",
                "title": title,
                "url": f"https://example.org/incidents/topology-{index}",
                "observed_at": (now - timedelta(minutes=2) + timedelta(seconds=index * 10)).isoformat(),
                "category": "service_incident",
                "provider": "example-cloud",
                "asn": "AS64500",
            })
            assert created.status_code == 201

        default_graph = api.get("/api/public/topology?days=1").json()
        assert default_graph["evidence_summary"]["inferred_relationships"] >= 2
        assert not any(
            edge["data"]["relationship_type"] in {"shares_provider", "shares_asn"}
            for edge in default_graph["edges"]
        )

        expanded_graph = api.get("/api/public/topology?days=1&include_inferred=true").json()
        candidate_edges = [
            edge["data"] for edge in expanded_graph["edges"]
            if edge["data"]["relationship_type"] in {"shares_provider", "shares_asn"}
        ]
        assert candidate_edges
        assert all(edge["semantic_status"] == "inferred_candidate_not_causal" for edge in candidate_edges)
        assert all(edge["causal_claim"] is False for edge in candidate_edges)


def test_request_size_limit_is_enforced(monkeypatch):
    headers = {"Authorization": "Bearer test-admin-token"}
    monkeypatch.setenv("MAX_REQUEST_BYTES", "1024")
    with client(monkeypatch) as api:
        response = api.post("/api/admin/investigations", headers=headers, json={"title": "Large request", "summary": "x" * 2000})
        assert response.status_code == 413


def test_assessment_history_is_immutable_and_exports_work(monkeypatch):
    headers = {"Authorization": "Bearer test-admin-token"}
    now = datetime.now(timezone.utc)
    with client(monkeypatch) as api:
        created = api.post("/api/events", headers=headers, json={
            "source": "manual_verified", "title": "Defensive patch disruption",
            "url": "https://example.org/incidents/patch", "observed_at": now.isoformat(),
            "category": "service_incident", "provider": "example-cloud",
        })
        event_id = created.json()["id"]
        first = api.post(f"/api/admin/incidents/{event_id}/assessments", headers=headers, json={
            "cause_classification": "unknown", "rationale": "Initial evidence is incomplete",
        })
        second = api.post(f"/api/admin/incidents/{event_id}/assessments", headers=headers, json={
            "cause_classification": "defensive_remediation_disruption", "severity": "moderate",
            "evidence_confidence": 0.8, "rationale": "Operator confirmed emergency defensive patching",
        })
        assert first.status_code == second.status_code == 201
        history = api.get(f"/api/admin/incidents/{event_id}/assessments", headers=headers).json()["items"]
        assert len(history) == 2
        assert history[0]["supersedes_id"] == history[1]["id"]

        investigation = api.post("/api/admin/investigations", headers=headers, json={"title": "Patch disruption review", "public": True}).json()
        investigation_id = investigation["id"]
        assert api.post(f"/api/admin/investigations/{investigation_id}/events/{event_id}", headers=headers).status_code == 201
        graph = api.get("/api/public/topology?days=1").json()
        assert any(node["data"]["type"] == "investigation_cluster" for node in graph["nodes"])
        assert any(edge["data"]["relationship_type"] == "member_of_cluster" for edge in graph["edges"])
        assert api.get(f"/api/public/investigations/{investigation_id}/export?format=json").status_code == 200
        csv_export = api.get(f"/api/public/investigations/{investigation_id}/export?format=csv")
        assert csv_export.status_code == 200
        assert "cause_classification" in csv_export.text
        report = api.get(f"/api/public/investigations/{investigation_id}/export?format=report")
        assert report.status_code == 200
        assert "Evidence-backed incident timeline" in report.text


def test_replay_does_not_use_future_report(monkeypatch):
    headers = {"Authorization": "Bearer test-admin-token"}
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=2)
    with client(monkeypatch) as api:
        for index, reported in enumerate((cutoff - timedelta(minutes=5), cutoff + timedelta(minutes=30))):
            response = api.post("/api/events", headers=headers, json={
                "source": f"source-{index}", "title": "Shared cloud outage",
                "url": f"https://example.org/incidents/{index}",
                "observed_at": (cutoff - timedelta(minutes=10)).isoformat(),
                "publisher_reported_at": reported.isoformat(), "provider": "cloud",
            })
            assert response.status_code == 201
        replay = api.get("/api/public/replay", params={"cutoff": cutoff.isoformat(), "days": 1})
        assert replay.status_code == 200
        assert len(replay.json()["incidents"]) == 1
        assert replay.json()["correlations"] == []


def test_public_intelligence_graph_map_and_uncertainty_endpoints(monkeypatch):
    headers = {"Authorization": "Bearer test-admin-token"}
    now = datetime.now(timezone.utc)
    with client(monkeypatch) as api:
        created = api.post(
            "/api/events",
            headers=headers,
            json={
                "source": "hazard-observer",
                "title": "Significant flood in Test Valley",
                "url": "https://example.org/events/test-flood",
                "observed_at": now.isoformat(),
                "occurrence_at": (now - timedelta(minutes=10)).isoformat(),
                "category": "natural_hazard",
                "domain": "environmental_hazard",
                "event_type": "flood",
                "significance": "high",
                "latitude": 40.1,
                "longitude": -75.2,
                "location_name": "Test Valley",
                "raw_metadata": {
                    "publisher_name": "Hazard Observer",
                    "source_role": "direct_observation",
                },
            },
        )
        assert created.status_code == 201
        event_id = created.json()["id"]
        intelligence = api.get(f"/api/public/events/{event_id}/intelligence")
        assert intelligence.status_code == 200
        assert intelligence.json()["classifications"]["event_type"]["label"] == "flood"
        assert intelligence.json()["field_assessments"]["attribution"]["knowledge_status"] == "not_applicable"

        graph = api.get("/api/public/knowledge-graph", params={"focus": f"event:{event_id}"})
        assert graph.status_code == 200
        assert any(edge["predicate"] == "REPORTED_BY" for edge in graph.json()["edges"])
        assert all(edge["causal_confidence"] is None for edge in graph.json()["edges"])

        mapped = api.get("/api/public/map?days=1&minimum_significance=moderate")
        assert mapped.status_code == 200
        assert any(item["id"] == event_id for item in mapped.json()["items"])
        coverage = api.get("/api/public/coverage")
        assert coverage.status_code == 200
        assert len(coverage.json()["items"]) >= 17
        assert coverage.json()["known_global_gaps"]


def test_intelligence_requirements_are_structured_and_admin_only(monkeypatch):
    payload = {
        "name": "Cross-domain European infrastructure",
        "description": "Prioritize meaningful cross-domain developments.",
        "priority": "high",
        "scope": {
            "domains": ["critical_infrastructure", "cybersecurity"],
            "regions": ["Europe"],
            "relationship_types": ["SHARES_INFRASTRUCTURE"],
        },
        "trigger_policy": {
            "minimum_significance": "high",
            "minimum_relevance": 0.75,
            "minimum_independent_sources": 2,
            "require_cross_domain": True,
            "create_investigation_candidate": True,
        },
    }
    with client(monkeypatch) as api:
        assert api.post("/api/admin/intelligence-requirements", json=payload).status_code == 401
        created = api.post(
            "/api/admin/intelligence-requirements",
            headers={"Authorization": "Bearer test-admin-token"},
            json=payload,
        )
        assert created.status_code == 201
        public = api.get("/api/public/intelligence-requirements").json()["items"]
        assert public[0]["scope"]["domains"] == ["critical_infrastructure", "cybersecurity"]
        assert public[0]["trigger_policy"]["minimum_independent_sources"] == 2
