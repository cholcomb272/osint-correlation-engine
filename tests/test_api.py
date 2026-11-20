from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main


def test_authenticated_event_workflow_and_explainable_correlation(monkeypatch):
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(main, "engine", test_engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(test_engine, expire_on_commit=False))
    monkeypatch.setenv("API_TOKEN", "test-token")
    monkeypatch.setenv("POLL_MINUTES", "60")

    headers = {"Authorization": "Bearer test-token"}
    now = datetime.now(timezone.utc)
    first = {
        "source": "manual_verified",
        "title": "Verified incident A",
        "url": "https://example.org/incidents/a",
        "observed_at": (now - timedelta(hours=2)).isoformat(),
        "provider": "example-cloud",
        "confidence": 0.8,
    }
    second = {
        **first,
        "source": "independent_source",
        "title": "Verified incident B",
        "url": "https://example.net/incidents/b",
        "observed_at": (now - timedelta(hours=1, minutes=30)).isoformat(),
    }

    with TestClient(main.app) as client:
        assert client.get("/health").json() == {
            "ok": True,
            "events": 0,
            "measurements": 0,
        }
        public_events = client.get("/api/events")
        assert public_events.status_code == 200
        assert public_events.json() == []

        unauthorized = client.post("/api/collect?days=1")
        assert unauthorized.status_code == 401
        assert unauthorized.headers["www-authenticate"] == "Bearer"

        created = client.post("/api/events", headers=headers, json=first)
        assert created.status_code == 201
        assert created.json()["created"] is True

        duplicate = client.post("/api/events", headers=headers, json=first)
        assert duplicate.status_code == 200
        assert duplicate.json() == {"id": created.json()["id"], "created": False}

        assert client.post("/api/events", headers=headers, json=second).status_code == 201
        events = client.get("/api/events?days=30", headers=headers).json()
        assert len(events) == 2

        candidates = client.get(
            "/api/correlations?days=30&hours=24", headers=headers
        ).json()
        assert len(candidates) == 1
        assert candidates[0]["score"] > 0.4
        assert candidates[0]["left"]["title"]
        assert candidates[0]["independent_sources"] is True
        assert "shared provider" in " ".join(candidates[0]["reasons"])

        scheduled_a = {
            **first,
            "source": "maintenance_source_a",
            "title": "Future maintenance A",
            "url": "https://status.example.org/maintenance/a",
            "observed_at": (now + timedelta(days=2)).isoformat(),
            "category": "scheduled_maintenance",
        }
        scheduled_b = {
            **scheduled_a,
            "source": "maintenance_source_b",
            "title": "Future maintenance B",
            "url": "https://status.example.net/maintenance/b",
        }
        assert client.post("/api/events", headers=headers, json=scheduled_a).status_code == 201
        assert client.post("/api/events", headers=headers, json=scheduled_b).status_code == 201

        default_candidates = client.get(
            "/api/correlations?days=30&hours=24", headers=headers
        ).json()
        assert all(
            edge["left"]["category"] != "scheduled_maintenance"
            and edge["right"]["category"] != "scheduled_maintenance"
            for edge in default_candidates
        )

        expanded_candidates = client.get(
            "/api/correlations?days=30&hours=24"
            "&include_scheduled=true&include_future=true",
            headers=headers,
        ).json()
        assert any(
            edge["left"]["category"] == "scheduled_maintenance"
            or edge["right"]["category"] == "scheduled_maintenance"
            for edge in expanded_candidates
        )

        measurement = {
            "source": "manual_verified_measurement",
            "signal_type": "dns_failure",
            "observed_at": (now - timedelta(hours=1)).isoformat(),
            "provider": "example-cloud",
            "resource": "public-passive-dataset",
            "value": 42,
            "unit": "failures",
            "baseline_mean": 5,
            "baseline_stddev": 4,
            "z_score": 9.25,
            "confidence": 0.8,
            "url": "https://example.org/public-measurements/1",
        }
        created_measurement = client.post(
            "/api/measurements", headers=headers, json=measurement
        )
        assert created_measurement.status_code == 201
        anomaly_records = client.get(
            "/api/measurements?days=30&anomalies_only=true", headers=headers
        ).json()
        assert len(anomaly_records) == 1
        assert anomaly_records[0]["signal_type"] == "dns_failure"
        supported_candidates = client.get(
            "/api/correlations?days=30&hours=24", headers=headers
        ).json()
        assert supported_candidates[0]["network_evidence"]["left"]
        assert supported_candidates[0]["network_evidence"]["right"]


def test_invalid_manual_url_is_rejected(monkeypatch):
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(main, "engine", test_engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(test_engine, expire_on_commit=False))
    monkeypatch.setenv("API_TOKEN", "test-token")

    with TestClient(main.app) as client:
        response = client.post(
            "/api/events",
            headers={"Authorization": "Bearer test-token"},
            json={
                "source": "manual",
                "title": "Invalid event",
                "url": "javascript:alert(1)",
                "observed_at": "2026-11-17T12:00:00Z",
            },
        )
        assert response.status_code == 422
