"""Deterministic correlation-regression benchmark runner.

The benchmark is an engineering regression suite, not a claim of real-world
statistical calibration.  Fixtures are synthetic and versioned so scoring
changes produce reviewable, reproducible results.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.main import Base, Event, NetworkMeasurement, as_utc
from app.services.correlation import candidate_correlations, evaluate_pair
from app.v2_models import EvidenceArtifact, EventEvidence, ProviderDependency


DEFAULT_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "benchmarks"
    / "correlation_v1.json"
)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return as_utc(parsed)


def _event(index: int, values: dict[str, Any]) -> Event:
    observed_at = _timestamp(values["observed_at"])
    publisher_reported_at = _timestamp(
        values.get("publisher_reported_at", values["observed_at"])
    )
    return Event(
        id=index,
        fingerprint=f"benchmark-{index:054d}",
        source=values.get("source", f"source-{index}"),
        title=values["title"],
        url=values.get("url", f"https://benchmark.invalid/events/{index}"),
        observed_at=observed_at,
        ingested_at=_timestamp(values.get("ingested_at", values["observed_at"])),
        first_observed_at=_timestamp(
            values.get("first_observed_at", values["observed_at"])
        ),
        publisher_reported_at=publisher_reported_at,
        category=values.get("category", "service_incident"),
        provider=values.get("provider"),
        asn=values.get("asn"),
        region=values.get("region"),
        confidence=values.get("confidence", 0.8),
        detail=values.get("detail", ""),
        cause_classification=values.get("cause_classification", "unknown"),
        severity=values.get("severity", "unknown"),
        investigation_status="unreviewed",
        raw_metadata={"synthetic_benchmark": True},
    )


def _measurement(index: int, values: dict[str, Any]) -> NetworkMeasurement:
    detail = values.get("detail", {})
    if isinstance(detail, dict):
        detail = json.dumps(detail, sort_keys=True)
    return NetworkMeasurement(
        fingerprint=f"measurement-{index:052d}",
        source=values["source"],
        signal_type=values["signal_type"],
        observed_at=_timestamp(values["observed_at"]),
        provider=values.get("provider"),
        asn=values.get("asn"),
        region=values.get("region"),
        resource=values.get("resource", f"benchmark/{index}"),
        value=values.get("value", 1.0),
        unit=values.get("unit", "score"),
        z_score=values.get("z_score", 3.0),
        confidence=values.get("confidence", 0.8),
        url=values.get("url", f"https://benchmark.invalid/measurements/{index}"),
        detail=detail,
    )


def _assertions(expected: dict[str, Any], result: Any | None) -> list[str]:
    failures: list[str] = []
    candidate = result is not None
    if candidate != expected["candidate"]:
        failures.append(f"expected candidate={expected['candidate']}, got {candidate}")
    if not result:
        return failures

    if "independent_technical" in expected and (
        result.independent_technical_corroboration
        != expected["independent_technical"]
    ):
        failures.append(
            "independent technical corroboration did not match expectation"
        )
    for relationship in expected.get("required_relationships", []):
        if relationship not in result.relationship_types:
            failures.append(f"missing relationship: {relationship}")
    for relationship in expected.get("forbidden_relationships", []):
        if relationship in result.relationship_types:
            failures.append(f"unexpected relationship: {relationship}")
    for component in expected.get("required_components", []):
        if component not in result.score_components:
            failures.append(f"missing score component: {component}")
    if result.strength < expected.get("minimum_strength", 0):
        failures.append(
            f"strength {result.strength} below {expected['minimum_strength']}"
        )
    if result.strength > expected.get("maximum_strength", 1):
        failures.append(
            f"strength {result.strength} above {expected['maximum_strength']}"
        )
    return failures


def _run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        events = [_event(index + 1, item) for index, item in enumerate(scenario["events"])]
        measurements = [
            _measurement(index + 1, item)
            for index, item in enumerate(scenario.get("measurements", []))
        ]
        db.add_all([*events, *measurements])
        for item in scenario.get("dependencies", []):
            db.add(ProviderDependency(**item))
        db.flush()

        for index, item in enumerate(scenario.get("evidence", []), 1):
            artifact = EvidenceArtifact(
                stable_id=f"{scenario['id']}-evidence-{index}",
                original_url=item.get(
                    "original_url", f"https://benchmark.invalid/evidence/{index}"
                ),
                publisher=item.get("publisher", "Benchmark publisher"),
                upstream_source=item.get("upstream_source"),
                content_hash=f"{index:064x}",
                excerpt=item.get("excerpt", "Synthetic benchmark evidence"),
                structured_observation={"synthetic_benchmark": True},
                verification_status=item.get("verification_status", "verified"),
            )
            db.add(artifact)
            db.flush()
            db.add(
                EventEvidence(
                    event_id=item["event_id"],
                    evidence_id=artifact.id,
                    role=item.get("role", "supports"),
                )
            )
        db.commit()

        if scenario.get("mode") == "replay":
            cutoff = _timestamp(scenario["cutoff"])
            results = candidate_correlations(
                db,
                days=scenario.get("days", 1),
                window_hours=scenario.get("window_hours", 24),
                cutoff=cutoff,
            )
            result = results[0] if results else None
        else:
            result = evaluate_pair(
                db,
                events[0],
                events[1],
                measurements=measurements,
                window_hours=scenario.get("window_hours", 24),
            )

        expected = scenario["expected"]
        failures = _assertions(expected, result)
        actual = {
            "candidate": result is not None,
            "strength": result.strength if result else None,
            "relationships": result.relationship_types if result else [],
            "independent_technical": (
                result.independent_technical_corroboration if result else False
            ),
        }
        return {
            "id": scenario["id"],
            "description": scenario["description"],
            "expected_candidate": expected["candidate"],
            "actual": actual,
            "passed": not failures,
            "failures": failures,
        }


def run_benchmark(path: str | Path = DEFAULT_FIXTURE) -> dict[str, Any]:
    fixture_path = Path(path)
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    scenarios = [_run_scenario(item) for item in fixture["scenarios"]]

    true_positive = sum(
        item["expected_candidate"] and item["actual"]["candidate"]
        for item in scenarios
    )
    false_positive = sum(
        not item["expected_candidate"] and item["actual"]["candidate"]
        for item in scenarios
    )
    true_negative = sum(
        not item["expected_candidate"] and not item["actual"]["candidate"]
        for item in scenarios
    )
    false_negative = sum(
        item["expected_candidate"] and not item["actual"]["candidate"]
        for item in scenarios
    )

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    precision = ratio(true_positive, true_positive + false_positive)
    recall = ratio(true_positive, true_positive + false_negative)
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "benchmark": fixture["name"],
        "fixture_version": fixture["version"],
        "fixture_path": str(fixture_path),
        "semantics": (
            "Synthetic deterministic regression metrics; not real-world calibration "
            "or a probability claim."
        ),
        "passed": all(item["passed"] for item in scenarios),
        "scenario_count": len(scenarios),
        "scenario_pass_rate": ratio(
            sum(item["passed"] for item in scenarios), len(scenarios)
        ),
        "confusion_matrix": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "specificity": ratio(true_negative, true_negative + false_positive),
            "f1": f1,
        },
        "scenarios": scenarios,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
