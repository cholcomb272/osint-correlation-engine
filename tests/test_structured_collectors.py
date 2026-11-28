import json
from datetime import datetime, timezone

from app.collector_sources import load_feed_sources
from app.collectors.structured import parse_structured_source


NOW = datetime(2026, 11, 28, 4, 0, tzinfo=timezone.utc)
SOURCES = load_feed_sources()


def parse(source_id: str, payload: dict | list):
    return parse_structured_source(
        SOURCES[source_id], json.dumps(payload).encode(), 30, NOW
    )


def test_usgs_preserves_occurrence_geography_and_observation_semantics():
    events = parse(
        "usgs_significant_earthquakes",
        {
            "features": [
                {
                    "id": "us-test-1",
                    "properties": {
                        "title": "M 6.2 - Test region",
                        "place": "Test region",
                        "time": 1795831200000,
                        "updated": 1795831800000,
                        "mag": 6.2,
                        "alert": "orange",
                        "status": "reviewed",
                        "url": "https://earthquake.usgs.gov/earthquakes/eventpage/us-test-1",
                        "net": "us",
                    },
                    "geometry": {"type": "Point", "coordinates": [140.2, 35.1, 20]},
                }
            ]
        },
    )
    assert len(events) == 1
    event = events[0]
    assert event["domain"] == "environmental_hazard"
    assert event["event_type"] == "earthquake"
    assert event["severity"] == "high"
    assert event["latitude"] == 35.1
    assert event["longitude"] == 140.2
    assert event["occurrence_at"] < event["publisher_reported_at"]
    assert event["raw_metadata"]["source_role"] == "direct_observation"


def test_gdacs_retains_country_lineage_and_alert_level():
    events = parse(
        "gdacs_global_hazards",
        {
            "features": [
                {
                    "geometry": {"type": "Point", "coordinates": [-70.2, -18.9]},
                    "properties": {
                        "eventtype": "EQ",
                        "eventid": 123,
                        "episodeid": 456,
                        "name": "Earthquake in Chile",
                        "description": "Earthquake in Chile",
                        "htmldescription": "Orange earthquake in Chile",
                        "fromdate": "2026-11-28T02:55:35",
                        "todate": "2026-11-28T02:55:35",
                        "datemodified": "2026-11-28T03:35:45",
                        "iscurrent": "true",
                        "alertlevel": "Orange",
                        "country": "Chile",
                        "source": "NEIC",
                        "url": {"report": "https://www.gdacs.org/report.aspx?eventid=123"},
                        "affectedcountries": [
                            {"countryname": "Chile", "iso3": "CHL"}
                        ],
                    },
                }
            ]
        },
    )
    event = events[0]
    assert event["event_type"] == "earthquake"
    assert event["significance"] == "high"
    assert event["raw_metadata"]["country_codes"] == ["CHL"]
    assert event["raw_metadata"]["upstream_source"] == "NEIC"


def test_eonet_keeps_curated_upstream_sources_distinct_from_direct_observation():
    events = parse(
        "nasa_eonet",
        {
            "events": [
                {
                    "id": "EONET_TEST",
                    "title": "Wildfire test",
                    "link": "https://eonet.gsfc.nasa.gov/api/v3/events/EONET_TEST",
                    "categories": [{"id": "wildfires", "title": "Wildfires"}],
                    "sources": [{"id": "InciWeb", "url": "https://example.org/fire"}],
                    "geometry": [
                        {"date": "2026-11-27T00:00:00Z", "type": "Point", "coordinates": [-120, 40]}
                    ],
                }
            ]
        },
    )
    event = events[0]
    assert event["event_type"] == "wildfire"
    assert event["raw_metadata"]["source_role"] == "curated_aggregator"
    assert event["raw_metadata"]["upstream_source"] == "InciWeb"


def test_noaa_space_weather_separates_threshold_time_from_publication():
    events = parse(
        "noaa_space_weather",
        [
            {
                "product_id": "K04A",
                "issue_datetime": "2026-11-28 01:17:48.273",
                "message": "ALERT: Geomagnetic K-index of 4\nThreshold Reached: 2026 Nov 28 0105 UTC\nNOAA Scale G2",
            }
        ],
    )
    event = events[0]
    assert event["event_type"] == "geomagnetic_storm"
    assert event["occurrence_at"].minute == 5
    assert event["publisher_reported_at"].minute == 17


def test_cisa_kev_is_actionable_without_claiming_incident_cause():
    events = parse(
        "cisa_kev",
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1234",
                    "vendorProject": "Example Vendor",
                    "product": "Example Gateway",
                    "vulnerabilityName": "Example Gateway Injection Vulnerability",
                    "dateAdded": "2026-11-27",
                    "shortDescription": "Observed exploitation of the vulnerability.",
                    "knownRansomwareCampaignUse": "Unknown",
                }
            ]
        },
    )
    event = events[0]
    assert event["event_type"] == "known_exploited_vulnerability"
    assert event["category"] == "vulnerability_exploitation"
    assert event.get("cause_classification", "unknown") == "unknown"
    assert event["raw_metadata"]["cve_ids"] == ["CVE-2026-1234"]
