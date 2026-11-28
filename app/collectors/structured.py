"""Structured public-source adapters.

Adapters return normalized event dictionaries and never fetch URLs themselves.
The caller owns the outbound allowlist, retry, size, and timeout policy. Keeping
parsing pure makes live collectors replayable and unit-testable without network
access.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode


UTC = timezone.utc


def _time(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000 if float(value) > 10_000_000_000 else float(value)
        return datetime.fromtimestamp(seconds, UTC)
    if isinstance(value, date) and not isinstance(value, datetime):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y %b %d %H%M %Z", "%Y %b %d %H:%M %Z"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d")
        except ValueError:
            return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _recent(value: datetime | None, collected_at: datetime, days: int) -> bool:
    return bool(value and collected_at - timedelta(days=days) <= value <= collected_at + timedelta(minutes=5))


def _coordinates(geometry: dict | None) -> tuple[float | None, float | None]:
    if not geometry or geometry.get("type") != "Point":
        return None, None
    values = geometry.get("coordinates") or []
    if len(values) < 2:
        return None, None
    try:
        longitude, latitude = float(values[0]), float(values[1])
    except (TypeError, ValueError):
        return None, None
    if not (-180 <= longitude <= 180 and -90 <= latitude <= 90):
        return None, None
    return latitude, longitude


def _source_metadata(definition) -> dict:
    return {
        "publisher_name": definition.publisher,
        "feed_kind": definition.kind,
        "source_role": definition.source_role,
        "source_domains": definition.domains,
        "geographic_scope": definition.geographic_scope,
        "languages": definition.languages,
        "is_primary_source": definition.source_role in {"direct_observation", "official_report"},
        "collection_method": "structured_public_api",
        "fingerprint_strategy": "source_event_id",
    }


def parse_usgs(payload: dict, definition, collected_at: datetime, days: int) -> list[dict]:
    results: list[dict] = []
    for feature in payload.get("features") or []:
        properties = feature.get("properties") or {}
        occurrence = _time(properties.get("time"))
        updated = _time(properties.get("updated")) or occurrence
        if not _recent(updated or occurrence, collected_at, days):
            continue
        event_id = str(feature.get("id") or "").strip()
        if not event_id:
            continue
        magnitude = properties.get("mag")
        alert = str(properties.get("alert") or "").casefold()
        if alert in {"red", "orange", "yellow", "green"}:
            severity = {"red": "critical", "orange": "high", "yellow": "moderate", "green": "low"}[alert]
        else:
            try:
                numeric_magnitude = float(magnitude)
            except (TypeError, ValueError):
                numeric_magnitude = 0
            severity = "critical" if numeric_magnitude >= 7 else "high" if numeric_magnitude >= 6 else "moderate" if numeric_magnitude >= 5 else "low"
        latitude, longitude = _coordinates(feature.get("geometry"))
        place = str(properties.get("place") or "Unknown location").strip()
        raw = _source_metadata(definition)
        raw.update(
            {
                "magnitude": magnitude,
                "magnitude_type": properties.get("magType"),
                "alert_level": properties.get("alert"),
                "significance_score": properties.get("sig"),
                "felt_reports": properties.get("felt"),
                "tsunami_flag": bool(properties.get("tsunami")),
                "review_status": properties.get("status"),
                "upstream_source": properties.get("net") or "USGS/ANSS",
                "entity_mentions": [place],
            }
        )
        results.append(
            {
                "source": definition.id,
                "title": str(properties.get("title") or f"Earthquake near {place}")[:500],
                "url": str(properties.get("url") or feature.get("id") or definition.url),
                "observed_at": occurrence or updated,
                "occurrence_at": occurrence,
                "first_observed_at": occurrence,
                "publisher_reported_at": updated,
                "collected_at": collected_at,
                "retrieval_at": collected_at,
                "category": "natural_hazard",
                "domain": "environmental_hazard",
                "event_type": "earthquake",
                "severity": severity,
                "significance": severity,
                "confidence": definition.reliability,
                "source_reliability": definition.reliability,
                "detail": f"Magnitude {magnitude}; {place}; status {properties.get('status') or 'unknown'}",
                "latitude": latitude,
                "longitude": longitude,
                "location_name": place,
                "language": "en",
                "extraction_confidence": 0.98,
                "source_event_id": event_id,
                "raw_metadata": raw,
            }
        )
    return results


GDACS_TYPES = {
    "EQ": "earthquake",
    "TC": "tropical_cyclone",
    "FL": "flood",
    "WF": "wildfire",
    "VO": "volcanic_activity",
    "DR": "drought",
}


def parse_gdacs(payload: dict, definition, collected_at: datetime, days: int) -> list[dict]:
    results: list[dict] = []
    for feature in payload.get("features") or []:
        properties = feature.get("properties") or {}
        occurrence = _time(properties.get("fromdate"))
        updated = _time(properties.get("datemodified")) or _time(properties.get("todate")) or occurrence
        if not _recent(updated or occurrence, collected_at, days):
            continue
        event_id = str(properties.get("eventid") or "").strip()
        episode_id = str(properties.get("episodeid") or "").strip()
        if not event_id:
            continue
        event_code = str(properties.get("eventtype") or "").upper()
        event_type = GDACS_TYPES.get(event_code, f"gdacs_{event_code.casefold() or 'hazard'}")
        alert = str(properties.get("alertlevel") or "unknown").casefold()
        significance = {"red": "critical", "orange": "high", "green": "low"}.get(alert, "unknown")
        latitude, longitude = _coordinates(feature.get("geometry"))
        countries = [
            item.get("countryname")
            for item in properties.get("affectedcountries") or []
            if item.get("countryname")
        ]
        country_codes = [
            item.get("iso3")
            for item in properties.get("affectedcountries") or []
            if item.get("iso3")
        ]
        location = str(properties.get("country") or ", ".join(countries) or "Unknown location")
        urls = properties.get("url") or {}
        raw = _source_metadata(definition)
        raw.update(
            {
                "gdacs_event_type": event_code,
                "episode_id": episode_id,
                "alert_level": properties.get("alertlevel"),
                "alert_score": properties.get("alertscore"),
                "affected_countries": countries,
                "country_codes": country_codes,
                "severity_data": properties.get("severitydata") or {},
                "upstream_source": properties.get("source"),
                "entity_mentions": countries,
            }
        )
        results.append(
            {
                "source": definition.id,
                "title": str(properties.get("name") or properties.get("description") or f"GDACS {event_type}")[:500],
                "url": str(urls.get("report") or urls.get("details") or definition.url),
                "observed_at": occurrence or updated,
                "occurrence_at": occurrence,
                "first_observed_at": occurrence,
                "publisher_reported_at": updated,
                "collected_at": collected_at,
                "retrieval_at": collected_at,
                "resolved_at": _time(properties.get("todate")) if str(properties.get("iscurrent")).casefold() == "false" else None,
                "category": "natural_hazard",
                "domain": "environmental_hazard",
                "event_type": event_type,
                "severity": significance,
                "significance": significance,
                "confidence": definition.reliability,
                "source_reliability": definition.reliability,
                "detail": str(properties.get("htmldescription") or properties.get("description") or "")[:4000],
                "latitude": latitude,
                "longitude": longitude,
                "location_name": location,
                "language": "en",
                "extraction_confidence": 0.95,
                "source_event_id": f"{event_code}:{event_id}:{episode_id}",
                "raw_metadata": raw,
            }
        )
    return results


EONET_TYPES = {
    "drought": "drought",
    "dustHaze": "dust_haze",
    "earthquakes": "earthquake",
    "floods": "flood",
    "landslides": "landslide",
    "manmade": "human_caused_environmental_event",
    "seaLakeIce": "sea_lake_ice",
    "severeStorms": "severe_storm",
    "snow": "extreme_snow",
    "tempExtremes": "temperature_extreme",
    "volcanoes": "volcanic_activity",
    "waterColor": "water_quality_anomaly",
    "wildfires": "wildfire",
}


def parse_eonet(payload: dict, definition, collected_at: datetime, days: int) -> list[dict]:
    results: list[dict] = []
    for item in payload.get("events") or []:
        geometries = item.get("geometry") or []
        dated = [(value, _time(value.get("date"))) for value in geometries]
        dated = [(value, stamp) for value, stamp in dated if stamp]
        if not dated:
            continue
        dated.sort(key=lambda pair: pair[1])
        first_geometry, occurrence = dated[0]
        latest_geometry, latest = dated[-1]
        if not _recent(latest, collected_at, days):
            continue
        event_id = str(item.get("id") or "").strip()
        if not event_id:
            continue
        categories = item.get("categories") or []
        category_ids = [str(value.get("id")) for value in categories if value.get("id")]
        event_type = EONET_TYPES.get(category_ids[0], category_ids[0] if category_ids else "natural_event")
        latitude, longitude = _coordinates(latest_geometry)
        sources = item.get("sources") or []
        source_urls = [value.get("url") for value in sources if value.get("url")]
        source_names = [value.get("id") for value in sources if value.get("id")]
        raw = _source_metadata(definition)
        raw.update(
            {
                "categories": categories,
                "upstream_sources": source_names,
                "upstream_source": source_names[0] if len(source_names) == 1 else None,
                "source_urls": source_urls,
                "geometry_observation_count": len(dated),
                "magnitude_value": latest_geometry.get("magnitudeValue"),
                "magnitude_unit": latest_geometry.get("magnitudeUnit"),
                "entity_mentions": [value.get("title") for value in categories if value.get("title")],
            }
        )
        results.append(
            {
                "source": definition.id,
                "title": str(item.get("title") or event_type.replace("_", " ").title())[:500],
                "url": str(item.get("link") or (source_urls[0] if source_urls else definition.url)),
                "observed_at": occurrence,
                "occurrence_at": occurrence,
                "first_observed_at": occurrence,
                "publisher_reported_at": latest,
                "collected_at": collected_at,
                "retrieval_at": collected_at,
                "resolved_at": _time(item.get("closed")),
                "category": "natural_hazard",
                "domain": "environmental_hazard",
                "event_type": event_type,
                "severity": "unknown",
                "significance": "unknown",
                "confidence": definition.reliability,
                "source_reliability": definition.reliability,
                "detail": str(item.get("description") or "")[:4000],
                "latitude": latitude,
                "longitude": longitude,
                "language": "en",
                "extraction_confidence": 0.9,
                "source_event_id": event_id,
                "raw_metadata": raw,
            }
        )
    return results


NOAA_THRESHOLD = re.compile(r"Threshold Reached:\s*([^\r\n]+)", re.IGNORECASE)
NOAA_SCALE = re.compile(r"\b([GRS][1-5])\b")


def parse_noaa_swpc(payload: list, definition, collected_at: datetime, days: int) -> list[dict]:
    results: list[dict] = []
    for item in payload:
        issued = _time(item.get("issue_datetime"))
        if not _recent(issued, collected_at, days):
            continue
        message = str(item.get("message") or "")
        threshold_match = NOAA_THRESHOLD.search(message)
        occurrence = _time(threshold_match.group(1).strip()) if threshold_match else issued
        scale_match = NOAA_SCALE.search(message)
        scale = scale_match.group(1) if scale_match else None
        numeric = int(scale[1]) if scale else 0
        severity = "critical" if numeric >= 5 else "high" if numeric >= 4 else "moderate" if numeric >= 3 else "low" if numeric else "unknown"
        lowered = message.casefold()
        event_type = (
            "geomagnetic_storm" if "geomagnetic" in lowered or "k-index" in lowered
            else "solar_radiation_storm" if "solar radiation" in lowered
            else "radio_blackout" if "radio blackout" in lowered or "x-ray" in lowered
            else "space_weather_alert"
        )
        product_id = str(item.get("product_id") or "unknown")
        source_event_id = f"{product_id}:{issued.isoformat() if issued else 'unknown'}"
        raw = _source_metadata(definition)
        raw.update({"product_id": product_id, "noaa_scale": scale, "entity_mentions": ["GNSS", "satellite communications", "power grid"]})
        results.append(
            {
                "source": definition.id,
                "title": f"NOAA {event_type.replace('_', ' ')} {scale or product_id}"[:500],
                "url": definition.url + "?" + urlencode({"product": product_id, "issued": issued.isoformat() if issued else "unknown"}),
                "observed_at": occurrence or issued,
                "occurrence_at": occurrence,
                "first_observed_at": occurrence or issued,
                "publisher_reported_at": issued,
                "collected_at": collected_at,
                "retrieval_at": collected_at,
                "category": "environmental_condition",
                "domain": "space_weather",
                "event_type": event_type,
                "severity": severity,
                "significance": severity,
                "confidence": definition.reliability,
                "source_reliability": definition.reliability,
                "detail": message[:4000],
                "language": "en",
                "extraction_confidence": 0.95,
                "source_event_id": source_event_id,
                "raw_metadata": raw,
            }
        )
    return results


def parse_cisa_kev(payload: dict, definition, collected_at: datetime, days: int) -> list[dict]:
    results: list[dict] = []
    for item in payload.get("vulnerabilities") or []:
        added = _time(item.get("dateAdded"))
        if not _recent(added, collected_at, days):
            continue
        cve = str(item.get("cveID") or "").upper().strip()
        if not cve:
            continue
        vendor = str(item.get("vendorProject") or "Unknown vendor").strip()
        product = str(item.get("product") or "Unknown product").strip()
        ransomware = str(item.get("knownRansomwareCampaignUse") or "Unknown")
        raw = _source_metadata(definition)
        raw.update(
            {
                "cve_ids": [cve],
                "vendor": vendor,
                "product": product,
                "required_action": item.get("requiredAction"),
                "due_date": item.get("dueDate"),
                "known_ransomware_campaign_use": ransomware,
                "notes": item.get("notes"),
                "entity_mentions": [vendor, product, cve],
            }
        )
        results.append(
            {
                "source": definition.id,
                "title": str(item.get("vulnerabilityName") or f"{cve} added to CISA KEV")[:500],
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?" + urlencode({"search_api_fulltext": cve}),
                "observed_at": added,
                "occurrence_at": None,
                "first_observed_at": added,
                "publisher_reported_at": added,
                "collected_at": collected_at,
                "retrieval_at": collected_at,
                "category": "vulnerability_exploitation",
                "domain": "cybersecurity",
                "event_type": "known_exploited_vulnerability",
                "severity": "high",
                "significance": "high" if ransomware.casefold() == "known" else "moderate",
                "confidence": definition.reliability,
                "source_reliability": definition.reliability,
                "detail": str(item.get("shortDescription") or "")[:4000],
                "service": product,
                "language": "en",
                "extraction_confidence": 0.98,
                "source_event_id": cve,
                "raw_metadata": raw,
            }
        )
    return results


ADAPTERS = {
    "usgs_geojson": parse_usgs,
    "gdacs_geojson": parse_gdacs,
    "nasa_eonet": parse_eonet,
    "noaa_swpc_alerts": parse_noaa_swpc,
    "cisa_kev": parse_cisa_kev,
}


def parse_structured_source(definition, content: bytes, backfill_days: int, collected_at: datetime) -> list[dict]:
    parser = ADAPTERS.get(definition.adapter)
    if parser is None:
        raise ValueError(f"unsupported structured adapter: {definition.adapter}")
    payload = json.loads(content.decode("utf-8-sig"))
    return parser(payload, definition, collected_at.astimezone(UTC), backfill_days)
