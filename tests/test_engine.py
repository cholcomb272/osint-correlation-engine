from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.main import (
    EventIn,
    classify_feed_item,
    extract_region,
    fingerprint,
    incident_types_compatible,
    ioda_measurements_from_payload,
    pair_score,
    parse_feed,
    ripe_measurements_from_payload,
    semantic_relevance,
)


def event(at, *, provider=None, asn=None, region=None, source="source-a"):
    return SimpleNamespace(
        observed_at=at,
        provider=provider,
        asn=asn,
        region=region,
        source=source,
    )


def test_fingerprint_is_stable_and_ignores_fragment_and_default_port():
    first = fingerprint("A", "https://EXAMPLE.org:443/incident#details", "x")
    second = fingerprint("a", "https://example.org/incident", "different title")
    assert first == second


def test_temporal_overlap_is_not_attribution():
    now = datetime.now(timezone.utc)
    score, reasons = pair_score(event(now), event(now + timedelta(minutes=5), source="source-b"))
    assert 0 < score <= 0.1
    assert reasons == ["temporal proximity: 0.1h"]


def test_shared_provider_is_explained():
    now = datetime.now(timezone.utc)
    score, reasons = pair_score(
        event(now, provider="cloud"),
        event(now, provider="CLOUD", source="source-b"),
    )
    assert score == 0.5
    assert "shared provider: cloud" in reasons


def test_same_source_is_discounted():
    now = datetime.now(timezone.utc)
    score, reasons = pair_score(
        event(now, provider="cloud"),
        event(now, provider="cloud"),
    )
    assert score == 0.35
    assert any("not independent" in reason for reason in reasons)


def test_timezone_offsets_representing_same_instant_score_as_simultaneous():
    utc_time = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)
    offset_time = datetime(2026, 11, 17, 4, tzinfo=timezone(timedelta(hours=-8)))
    score, reasons = pair_score(event(utc_time), event(offset_time, source="source-b"))
    assert score == 0.1
    assert reasons == ["temporal proximity: 0.0h"]


def test_outside_window_has_no_candidate_score():
    now = datetime.now(timezone.utc)
    assert pair_score(event(now), event(now - timedelta(hours=25)), 24) == (0, [])


def test_feed_parsing_filters_old_and_insecure_entries():
    xml = b"""<rss><channel>
      <item><title>Current outage</title><link>https://example.org/a</link><pubDate>Tue, 17 Nov 2026 12:00:00 GMT</pubDate></item>
      <item><title>Old outage</title><link>https://example.org/old</link><pubDate>Fri, 17 Nov 2023 12:00:00 GMT</pubDate></item>
      <item><title>Insecure URL</title><link>http://example.org/b</link><pubDate>Tue, 17 Nov 2026 12:00:00 GMT</pubDate></item>
    </channel></rss>"""
    parsed = parse_feed("test", xml, 365, now=datetime(2026, 11, 18, tzinfo=timezone.utc))
    assert [item.title for item in parsed] == ["Current outage"]
    assert parsed[0].category == "service_incident"


def test_scheduled_maintenance_is_classified_from_statuspage_metadata():
    xml = b"""<rss><channel><item>
      <title>SJC (San Jose) on 2026-11-27</title>
      <description>&lt;strong&gt;Scheduled&lt;/strong&gt; - Scheduled maintenance window.</description>
      <link>https://status.example.org/incidents/maintenance</link>
      <pubDate>Fri, 27 Nov 2026 10:00:00 GMT</pubDate>
      <maintenanceEndDate>Fri, 27 Nov 2026 14:00:00 GMT</maintenanceEndDate>
    </item></channel></rss>"""
    parsed = parse_feed(
        "cloudflare", xml, 365, now=datetime(2026, 11, 18, tzinfo=timezone.utc)
    )
    assert parsed[0].category == "scheduled_maintenance"
    assert parsed[0].observed_at == datetime(2026, 11, 27, 10, tzinfo=timezone.utc)


def test_cisa_items_are_security_advisories():
    item = {"title": "Advisory", "summary": "An advisory"}
    assert classify_feed_item("cisa", item) == "security_advisory"


def test_cisa_policy_news_is_not_an_operational_incident():
    item = {
        "title": "CISA Announces Enhanced Reporting Form for Cyber Incidents",
        "summary": "A new reporting policy and form is available.",
    }
    assert classify_feed_item("cisa", item) == "policy_announcement"


def test_google_cloud_region_is_extracted_from_title():
    title = "RESOLVED: Multiple services were experiencing issues in europe-west2 region"
    assert extract_region(title) == "europe-west2"


def test_policy_and_service_incident_types_are_incompatible():
    policy = SimpleNamespace(category="policy_announcement")
    outage = SimpleNamespace(category="service_incident")
    compatible, reason = incident_types_compatible(policy, outage)
    assert compatible is False
    assert "policy" in reason


def test_semantic_relevance_requires_meaningful_shared_terms():
    left = SimpleNamespace(title="DNS resolution failures", detail="Resolvers unavailable")
    right = SimpleNamespace(title="Regional DNS outage", detail="Resolution errors")
    unrelated = SimpleNamespace(title="New reporting policy", detail="Updated form")
    score, terms = semantic_relevance(left, right)
    assert score > 0
    assert "dns" in terms
    assert semantic_relevance(left, unrelated) == (0.0, [])


def test_ripe_measurements_include_withdrawals_and_baselines():
    payload = {
        "data": {
            "updates": [
                {"starttime": "2026-11-17T00:00:00", "announcements": 1, "withdrawals": 0},
                {"starttime": "2026-11-17T01:00:00", "announcements": 2, "withdrawals": 1},
                {"starttime": "2026-11-17T02:00:00", "announcements": 12, "withdrawals": 9},
            ]
        }
    }
    records = ripe_measurements_from_payload(
        "cloudflare",
        "AS13335",
        "1.1.1.0/24",
        payload,
        "https://stat.ripe.net/data/bgp-update-activity/data.json",
    )
    assert len(records) == 6
    assert {record.signal_type for record in records} == {
        "bgp_announcements",
        "bgp_withdrawals",
    }
    assert all(record.baseline_mean is not None for record in records)
    assert max(record.z_score for record in records) > 1
    assert {
        json.loads(record.detail)["observation_family"] for record in records
    } == {"bgp_control_plane"}


def test_ioda_events_map_public_signals_without_local_probing():
    payload = {
        "data": [
            {
                "start": 1794990000,
                "duration": 900,
                "datasource": "bgp",
                "method": "median",
                "score": 12.5,
                "location_name": "AS13335 (CLOUDFLARENET)",
            },
            {
                "start": 1794993600,
                "duration": 600,
                "datasource": "merit-nt",
                "method": "median",
                "score": 8.0,
                "location_name": "AS13335 (CLOUDFLARENET)",
            },
        ]
    }
    records = ioda_measurements_from_payload(
        "cloudflare",
        "AS13335",
        payload,
        "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events",
    )
    assert [record.signal_type for record in records] == [
        "bgp_visibility_drop",
        "traffic_anomaly",
    ]
    assert all("did not probe" in record.detail for record in records)
    assert [json.loads(record.detail)["observation_family"] for record in records] == [
        "bgp_control_plane",
        "network_telescope",
    ]


def test_manual_event_url_must_be_absolute_http_url():
    with pytest.raises(ValidationError):
        EventIn(
            source="manual",
            title="Incident",
            url="javascript:alert(1)",
            observed_at=datetime.now(timezone.utc),
        )
