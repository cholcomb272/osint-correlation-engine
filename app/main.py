import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from calendar import timegm
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import fmean, pstdev
from urllib.parse import urljoin, urlsplit, urlunsplit

import feedparser
import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field, field_validator
from tenacity import retry, stop_after_attempt, wait_exponential
from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, UniqueConstraint, create_engine, func, or_, select, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

logger = logging.getLogger(__name__)

from app.logging_config import configure_logging

configure_logging()

REQUEST_COUNT = Counter(
    "osint_http_requests_total", "HTTP requests", ("method", "route", "status")
)
REQUEST_LATENCY = Histogram(
    "osint_http_request_duration_seconds", "HTTP request duration", ("method", "route")
)
_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_RATE_LOCK = threading.Lock()


class RequestBodyTooLarge(Exception):
    pass

def configured_database_url() -> str | URL:
    explicit_url = os.getenv("DATABASE_URL")
    if explicit_url:
        return explicit_url
    if os.getenv("DB_HOST"):
        return URL.create(
            drivername="postgresql+psycopg",
            username=os.getenv("DB_USER", "osint"),
            password=os.getenv("DB_PASSWORD", os.getenv("POSTGRES_PASSWORD")),
            host=os.environ["DB_HOST"],
            port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME", "osint"),
        )
    return "sqlite:///./osint.db"


DATABASE_URL = configured_database_url()
IS_SQLITE = isinstance(DATABASE_URL, str) and DATABASE_URL.startswith("sqlite")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if IS_SQLITE else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(100), index=True)
    title: Mapped[str] = mapped_column(String(500))
    url: Mapped[str] = mapped_column(String(2000))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    category: Mapped[str] = mapped_column(String(60), index=True)
    provider: Mapped[str | None] = mapped_column(String(100), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(30), nullable=True)
    region: Mapped[str | None] = mapped_column(String(100), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    detail: Mapped[str] = mapped_column(String(4000), default="")
    occurrence_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    first_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    publisher_reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retrieval_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scheduled_start_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    scheduled_end_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    original_timezone: Mapped[str | None] = mapped_column(String(80), nullable=True)
    cause_classification: Mapped[str] = mapped_column(String(60), default="unknown", index=True)
    severity: Mapped[str] = mapped_column(String(30), default="unknown", index=True)
    investigation_status: Mapped[str] = mapped_column(String(40), default="unreviewed", index=True)
    source_reliability: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    service: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    datacenter: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    source_event_id: Mapped[str | None] = mapped_column(String(300), nullable=True, index=True)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    left_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"))
    right_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"))
    score: Mapped[float] = mapped_column(Float)
    reasons: Mapped[str] = mapped_column(String(1000))
    __table_args__ = (UniqueConstraint("left_id", "right_id", name="uq_evidence_pair"),)


class NetworkMeasurement(Base):
    __tablename__ = "network_measurements"

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(100), index=True)
    signal_type: Mapped[str] = mapped_column(String(60), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    provider: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    asn: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    region: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    resource: Mapped[str] = mapped_column(String(200), index=True)
    value: Mapped[float] = mapped_column(Float)
    unit: Mapped[str] = mapped_column(String(30), default="count")
    baseline_mean: Mapped[float | None] = mapped_column(Float, nullable=True)
    baseline_stddev: Mapped[float | None] = mapped_column(Float, nullable=True)
    z_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    url: Mapped[str] = mapped_column(String(2000))
    detail: Mapped[str] = mapped_column(String(2000), default="")


class EventIn(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    url: str = Field(min_length=1, max_length=2000)
    observed_at: datetime
    category: str = Field(default="reported_incident", min_length=1, max_length=60)
    provider: str | None = Field(default=None, max_length=100)
    asn: str | None = Field(default=None, max_length=30)
    region: str | None = Field(default=None, max_length=100)
    confidence: float = Field(default=0.5, ge=0, le=1)
    detail: str = Field(default="", max_length=4000)
    occurrence_at: datetime | None = None
    first_observed_at: datetime | None = None
    publisher_reported_at: datetime | None = None
    collected_at: datetime | None = None
    retrieval_at: datetime | None = None
    scheduled_start_at: datetime | None = None
    scheduled_end_at: datetime | None = None
    resolved_at: datetime | None = None
    original_timezone: str | None = Field(default=None, max_length=80)
    cause_classification: str = Field(default="unknown", pattern="^(confirmed_intrusion|defensive_remediation_disruption|unrelated_operational_failure|unknown)$")
    severity: str = Field(default="unknown", max_length=30)
    investigation_status: str = Field(default="unreviewed", max_length=40)
    source_reliability: float | None = Field(default=None, ge=0, le=1)
    raw_metadata: dict = Field(default_factory=dict)
    service: str | None = Field(default=None, max_length=200)
    datacenter: str | None = Field(default=None, max_length=200)
    source_event_id: str | None = Field(default=None, max_length=300)

    @field_validator("source", "title", "category")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("provider", "asn", "region", "original_timezone", "service", "datacenter", "source_event_id")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("url")
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("URL credentials are not allowed")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("URL port is invalid") from exc
        return value

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at(cls, value: datetime) -> datetime:
        return as_utc(value)

    @field_validator(
        "occurrence_at", "first_observed_at", "publisher_reported_at", "collected_at",
        "retrieval_at", "scheduled_start_at", "scheduled_end_at", "resolved_at"
    )
    @classmethod
    def normalize_optional_times(cls, value: datetime | None) -> datetime | None:
        return as_utc(value) if value else None


class MeasurementIn(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    signal_type: str = Field(min_length=1, max_length=60)
    observed_at: datetime
    provider: str | None = Field(default=None, max_length=100)
    asn: str | None = Field(default=None, max_length=30)
    region: str | None = Field(default=None, max_length=100)
    resource: str = Field(min_length=1, max_length=200)
    value: float
    unit: str = Field(default="count", min_length=1, max_length=30)
    baseline_mean: float | None = None
    baseline_stddev: float | None = Field(default=None, ge=0)
    z_score: float | None = None
    confidence: float = Field(default=0.8, ge=0, le=1)
    url: str = Field(min_length=1, max_length=2000)
    detail: str = Field(default="", max_length=2000)

    @field_validator("source", "signal_type", "resource", "unit")
    @classmethod
    def strip_measurement_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("signal_type")
    @classmethod
    def validate_signal_type(cls, value: str) -> str:
        if value not in MEASUREMENT_SIGNAL_TYPES:
            raise ValueError(
                f"must be one of: {', '.join(sorted(MEASUREMENT_SIGNAL_TYPES))}"
            )
        return value

    @field_validator("provider", "asn", "region")
    @classmethod
    def normalize_measurement_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("observed_at")
    @classmethod
    def normalize_measurement_time(cls, value: datetime) -> datetime:
        return as_utc(value)

    @field_validator("url")
    @classmethod
    def validate_measurement_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("must be an absolute HTTPS URL")
        return value


SOURCES = {
    "cisa": "https://www.cisa.gov/news.xml",
    "cloudflare": "https://www.cloudflarestatus.com/history.rss",
    "github": "https://www.githubstatus.com/history.rss",
    "google_cloud": "https://status.cloud.google.com/en/feed.atom",
}

PROVIDER_METADATA = {
    "cloudflare": {"asn": "AS13335", "prefix": "1.1.1.0/24"},
    "github": {"asn": "AS36459", "prefix": "140.82.112.0/24"},
    "google_cloud": {"asn": "AS15169", "prefix": "8.8.8.0/24"},
}

RIPESTAT_BGP_ACTIVITY_URL = "https://stat.ripe.net/data/bgp-update-activity/data.json"
IODA_OUTAGE_EVENTS_URL = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events"
OUTBOUND_ALLOWED_HOSTS = {
    *(urlsplit(url).hostname for url in SOURCES.values()),
    urlsplit(RIPESTAT_BGP_ACTIVITY_URL).hostname,
    urlsplit(IODA_OUTAGE_EVENTS_URL).hostname,
}
MEASUREMENT_SIGNAL_TYPES = {
    "bgp_announcements",
    "bgp_withdrawals",
    "bgp_visibility_drop",
    "traffic_anomaly",
    "dns_failure",
    "reachability_loss",
}

REGION_PATTERN = re.compile(
    r"\b(?:africa|asia|australia|europe|me|northamerica|southamerica|us|ca|sa|ap|eu|cn|il|mx)"
    r"(?:-[a-z]+)+-?\d\b",
    re.IGNORECASE,
)
WORD_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{2,}", re.IGNORECASE)
SEMANTIC_STOPWORDS = {
    "about", "after", "before", "cloud", "could", "during", "event", "from",
    "general", "incident", "increased", "issue", "issues", "multiple", "resolved",
    "service", "services", "status", "the", "their", "this", "with", "were",
}

COLLECT_LOCK = threading.Lock()
MEASUREMENT_COLLECT_LOCK = threading.Lock()


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def validate_collector_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in OUTBOUND_ALLOWED_HOSTS:
        raise ValueError("collector URL is outside the fixed HTTPS allowlist")
    if parsed.username or parsed.password:
        raise ValueError("collector URL credentials are forbidden")


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=0.5, min=0.5, max=4), reraise=True)
def fetch_public_source(client: httpx.Client, url: str, *, params: dict | None = None) -> httpx.Response:
    """Fetch a configured public source with bounded, allowlisted redirects."""
    validate_collector_url(url)
    next_url = url
    next_params = params
    for _ in range(4):
        response = client.get(next_url, params=next_params)
        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                response.raise_for_status()
            next_url = urljoin(str(response.url), location)
            validate_collector_url(next_url)
            next_params = None
            continue
        response.raise_for_status()
        declared = int(response.headers.get("content-length", "0") or 0)
        if declared > 10_000_000 or len(response.content) > 10_000_000:
            raise ValueError("collector response exceeds 10 MB limit")
        return response
    raise ValueError("collector redirect limit exceeded")


def canonical_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    hostname = (parsed.hostname or "").casefold()
    port = parsed.port
    default_port = (parsed.scheme.casefold() == "https" and port == 443) or (
        parsed.scheme.casefold() == "http" and port == 80
    )
    netloc = hostname if not port or default_port else f"{hostname}:{port}"
    return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, ""))


def fingerprint(source: str, url: str, title: str) -> str:
    identity = canonical_url(url) if url else " ".join(title.casefold().split())
    return hashlib.sha256(f"{source.strip().casefold()}|{identity}".encode()).hexdigest()


def extract_region(*values: str) -> str | None:
    for value in values:
        match = REGION_PATTERN.search(value or "")
        if match:
            return match.group(0).casefold()
    return None


def semantic_terms(event: Event) -> set[str]:
    return {
        term.casefold()
        for term in WORD_PATTERN.findall(event.title)
        if term.casefold() not in SEMANTIC_STOPWORDS and not term.isdigit()
    }


def semantic_relevance(a: Event, b: Event) -> tuple[float, list[str]]:
    left_terms = semantic_terms(a)
    right_terms = semantic_terms(b)
    shared = sorted(left_terms & right_terms)
    if not shared:
        return 0.0, []
    overlap = len(shared) / max(1, min(len(left_terms), len(right_terms)))
    return round(overlap, 3), shared[:8]


def incident_types_compatible(a: Event, b: Event) -> tuple[bool, str]:
    categories = {a.category, b.category}
    if "scheduled_maintenance" in categories:
        return False, "scheduled maintenance is not incident evidence"
    if "policy_announcement" in categories:
        return False, "policy announcements are not operational incidents"
    if "security_advisory" in categories:
        return False, "security advisories are context, not operational disruption evidence"
    if "service_notice" in categories and len(categories) > 1:
        return False, "service notices require like-for-like evidence"
    return True, "incident types compatible"


def shared_infrastructure(a: Event, b: Event) -> list[str]:
    shared = []
    for field in ("provider", "asn", "region"):
        left, right = getattr(a, field), getattr(b, field)
        if left and right and left.casefold() == right.casefold():
            shared.append(field)
    return shared


def insert_event(
    db: Session, event: EventIn, *, refresh_existing: bool = False
) -> tuple[Event, bool, bool]:
    key = fingerprint(event.source, event.url, event.title)
    existing = db.scalar(select(Event).where(Event.fingerprint == key))
    if existing:
        changed = False
        if refresh_existing:
            for field, value in event.model_dump().items():
                if getattr(existing, field) != value:
                    setattr(existing, field, value)
                    changed = True
            if changed:
                db.commit()
                db.refresh(existing)
        ensure_event_evidence(db, existing, event)
        return existing, False, changed

    values = event.model_dump()
    collected_at = values.get("collected_at") or datetime.now(timezone.utc)
    values["collected_at"] = collected_at
    values["retrieval_at"] = values.get("retrieval_at") or collected_at
    values["first_observed_at"] = values.get("first_observed_at") or event.observed_at
    values["publisher_reported_at"] = values.get("publisher_reported_at") or event.observed_at
    if event.category == "scheduled_maintenance":
        values["scheduled_start_at"] = values.get("scheduled_start_at") or event.observed_at
    elif values.get("occurrence_at") is None and event.source.startswith("manual"):
        values["occurrence_at"] = event.observed_at
    record = Event(fingerprint=key, **values)
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        # A scheduler/manual collection race may insert the same fingerprint first.
        db.rollback()
        existing = db.scalar(select(Event).where(Event.fingerprint == key))
        if existing:
            return existing, False, False
        raise
    db.refresh(record)
    ensure_event_evidence(db, record, event)
    return record, True, False


def ensure_event_evidence(db: Session, record: Event, event: EventIn) -> None:
    """Preserve provenance for every normalized source record idempotently."""
    from app.v2_models import EvidenceArtifact, EventEvidence

    content_hash = hashlib.sha256(
        json.dumps(
            {
                "title": event.title,
                "detail": event.detail,
                "observed_at": as_utc(event.observed_at).isoformat(),
                "raw_metadata": event.raw_metadata,
            },
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()
    stable_id = "ev_" + hashlib.sha256(f"{canonical_url(event.url)}|{content_hash}".encode()).hexdigest()[:24]
    artifact = db.scalar(select(EvidenceArtifact).where(EvidenceArtifact.stable_id == stable_id))
    if artifact is None:
        artifact = EvidenceArtifact(
            stable_id=stable_id,
            original_url=event.url,
            publisher=event.source,
            upstream_source=event.raw_metadata.get("upstream_source") or event.source,
            published_at=event.publisher_reported_at or event.observed_at,
            observed_at=event.first_observed_at or event.observed_at,
            ingested_at=record.ingested_at,
            retrieved_at=event.retrieval_at or event.collected_at or datetime.now(timezone.utc),
            content_hash=content_hash,
            excerpt=event.detail,
            structured_observation={
                "category": event.category,
                "provider": event.provider,
                "asn": event.asn,
                "region": event.region,
                "service": event.service,
            },
            raw_metadata=event.raw_metadata,
            collection_method="manual_verified" if event.source.startswith("manual") else "public_feed",
            reliability=event.source_reliability if event.source_reliability is not None else event.confidence,
            verification_status="verified" if event.source.startswith("manual_verified") else "unverified",
            is_primary_source=event.source != "cisa",
        )
        db.add(artifact)
        db.flush()
    if db.get(EventEvidence, (record.id, artifact.id, "supports")) is None:
        db.add(EventEvidence(event_id=record.id, evidence_id=artifact.id, role="supports", added_by="collector"))
    db.commit()


def measurement_fingerprint(measurement: MeasurementIn) -> str:
    identity = "|".join(
        (
            measurement.source.casefold(),
            measurement.signal_type.casefold(),
            measurement.resource.casefold(),
            as_utc(measurement.observed_at).isoformat(),
        )
    )
    return hashlib.sha256(identity.encode()).hexdigest()


def insert_measurement(
    db: Session, measurement: MeasurementIn, *, refresh_existing: bool = False
) -> tuple[NetworkMeasurement, bool, bool]:
    key = measurement_fingerprint(measurement)
    existing = db.scalar(
        select(NetworkMeasurement).where(NetworkMeasurement.fingerprint == key)
    )
    if existing:
        changed = False
        if refresh_existing:
            for field, value in measurement.model_dump().items():
                if getattr(existing, field) != value:
                    setattr(existing, field, value)
                    changed = True
            if changed:
                db.commit()
                db.refresh(existing)
        return existing, False, changed

    record = NetworkMeasurement(fingerprint=key, **measurement.model_dump())
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(NetworkMeasurement).where(NetworkMeasurement.fingerprint == key)
        )
        if existing:
            return existing, False, False
        raise
    db.refresh(record)
    return record, True, False


def upsert_measurements(
    db: Session, measurements: list[MeasurementIn]
) -> tuple[int, int]:
    keyed = {measurement_fingerprint(item): item for item in measurements}
    existing = {
        record.fingerprint: record
        for record in db.scalars(
            select(NetworkMeasurement).where(
                NetworkMeasurement.fingerprint.in_(keyed.keys())
            )
        ).all()
    }
    added = 0
    updated = 0
    for key, measurement in keyed.items():
        record = existing.get(key)
        if record is None:
            db.add(NetworkMeasurement(fingerprint=key, **measurement.model_dump()))
            added += 1
            continue
        changed = False
        for field, value in measurement.model_dump().items():
            if getattr(record, field) != value:
                setattr(record, field, value)
                changed = True
        updated += int(changed)
    db.commit()
    return added, updated


def measurement_dict(measurement: NetworkMeasurement) -> dict:
    return {
        "id": measurement.id,
        "source": measurement.source,
        "signal_type": measurement.signal_type,
        "observed_at": as_utc(measurement.observed_at).isoformat(),
        "provider": measurement.provider,
        "asn": measurement.asn,
        "region": measurement.region,
        "resource": measurement.resource,
        "value": measurement.value,
        "unit": measurement.unit,
        "baseline_mean": measurement.baseline_mean,
        "baseline_stddev": measurement.baseline_stddev,
        "z_score": measurement.z_score,
        "confidence": measurement.confidence,
        "url": measurement.url,
        "detail": measurement.detail,
    }


def ripe_measurements_from_payload(
    provider: str,
    asn: str,
    prefix: str,
    payload: dict,
    source_url: str,
) -> list[MeasurementIn]:
    updates = payload.get("data", {}).get("updates", [])
    results: list[MeasurementIn] = []
    for field, signal_type in (
        ("announcements", "bgp_announcements"),
        ("withdrawals", "bgp_withdrawals"),
    ):
        samples = [sample for sample in updates if sample.get(field) is not None]
        values = [float(sample[field]) for sample in samples]
        if not values:
            continue
        baseline_mean = fmean(values)
        baseline_stddev = pstdev(values)
        for sample in samples:
            value = float(sample[field])
            z_score = (
                (value - baseline_mean) / baseline_stddev
                if baseline_stddev > 0
                else 0.0
            )
            results.append(
                MeasurementIn(
                    source="ripe_stat",
                    signal_type=signal_type,
                    observed_at=as_utc(datetime.fromisoformat(sample["starttime"])),
                    provider=provider,
                    asn=asn,
                    resource=prefix,
                    value=value,
                    unit="updates_per_interval",
                    baseline_mean=round(baseline_mean, 3),
                    baseline_stddev=round(baseline_stddev, 3),
                    z_score=round(z_score, 3),
                    confidence=0.9,
                    url=source_url,
                    detail=json.dumps(
                        {
                            "representative_prefix": True,
                            "interpretation": (
                                "Routing activity for a representative provider prefix; "
                                "not proof of provider-wide impact."
                            ),
                        }
                    ),
                )
            )
    return results


def ioda_measurements_from_payload(
    provider: str,
    asn: str,
    payload: dict,
    source_url: str,
) -> list[MeasurementIn]:
    results = []
    for event in payload.get("data", []):
        datasource = str(event.get("datasource") or "unknown")
        if datasource == "bgp":
            signal_type = "bgp_visibility_drop"
        elif datasource.startswith("ping"):
            signal_type = "reachability_loss"
        else:
            signal_type = "traffic_anomaly"
        start = event.get("start")
        if start is None:
            continue
        score = float(event.get("score") or 0)
        results.append(
            MeasurementIn(
                source="ioda",
                signal_type=signal_type,
                observed_at=datetime.fromtimestamp(int(start), timezone.utc),
                provider=provider,
                asn=asn,
                resource=f"asn/{asn.removeprefix('AS')}:{datasource}",
                value=score,
                unit="ioda_anomaly_score",
                confidence=0.85,
                url=source_url,
                detail=json.dumps(
                    {
                        "datasource": datasource,
                        "duration_seconds": event.get("duration"),
                        "method": event.get("method"),
                        "location_name": event.get("location_name"),
                        "interpretation": (
                            "Public IODA outage event retrieved passively; the local "
                            "engine did not probe the affected network."
                        ),
                    }
                ),
            )
        )
    return results


def collect_network_measurements(
    days: int = 7, *, now: datetime | None = None
) -> dict[str, dict[str, int | str]]:
    if not MEASUREMENT_COLLECT_LOCK.acquire(blocking=False):
        return {"collection": {"status": "already_running"}}

    current_time = as_utc(now or datetime.now(timezone.utc))
    start_time = current_time - timedelta(days=days)
    summary: dict[str, dict[str, int | str]] = {}
    try:
        with httpx.Client(
            timeout=httpx.Timeout(30, connect=10),
            follow_redirects=False,
            headers={"User-Agent": "OSINT-Correlation-Research/1.0"},
        ) as client:
            with SessionLocal() as db:
                for provider, metadata in PROVIDER_METADATA.items():
                    try:
                        response = fetch_public_source(
                            client,
                            RIPESTAT_BGP_ACTIVITY_URL,
                            params={
                                "resource": metadata["prefix"],
                                "starttime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "endtime": current_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "max_samples": 0,
                                "min_sampling_period": 3600,
                                "hide_empty_samples": "false",
                            },
                        )
                        payload = response.json()
                        if payload.get("status") != "ok":
                            raise ValueError(payload.get("messages") or "RIPEstat error")
                        parsed = ripe_measurements_from_payload(
                            provider,
                            metadata["asn"],
                            metadata["prefix"],
                            payload,
                            str(response.url),
                        )
                        added, updated = upsert_measurements(db, parsed)
                        summary[provider] = {
                            "added": added,
                            "updated": updated,
                            "parsed": len(parsed),
                        }
                    except Exception as exc:
                        logger.warning(
                            "Network measurement collection failed for %s: %s",
                            provider,
                            exc,
                        )
                        summary[provider] = {"error": str(exc)[:250]}
                for provider, metadata in PROVIDER_METADATA.items():
                    summary_key = f"ioda:{provider}"
                    try:
                        response = fetch_public_source(
                            client,
                            IODA_OUTAGE_EVENTS_URL,
                            params={
                                "entityType": "asn",
                                "entityCode": metadata["asn"].removeprefix("AS"),
                                "from": int(start_time.timestamp()),
                                "until": int(current_time.timestamp()),
                                "limit": 1000,
                            },
                        )
                        payload = response.json()
                        if payload.get("error"):
                            raise ValueError(payload["error"])
                        parsed = ioda_measurements_from_payload(
                            provider,
                            metadata["asn"],
                            payload,
                            str(response.url),
                        )
                        added, updated = upsert_measurements(db, parsed)
                        summary[summary_key] = {
                            "added": added,
                            "updated": updated,
                            "parsed": len(parsed),
                        }
                    except Exception as exc:
                        logger.warning(
                            "IODA collection failed for %s: %s", provider, exc
                        )
                        summary[summary_key] = {"error": str(exc)[:250]}
        return summary
    finally:
        MEASUREMENT_COLLECT_LOCK.release()


def classify_feed_item(source: str, item) -> str:
    if source == "cisa":
        title = item.get("title", "")
        detail = item.get("summary", "") or item.get("description", "")
        searchable = f"{title} {detail}".casefold()
        if any(
            marker in searchable
            for marker in (
                "advisory",
                "alert",
                "exploited vulnerabilities",
                "malware",
                "ransomware",
                "vulnerability",
            )
        ):
            return "security_advisory"
        return "policy_announcement"

    title = item.get("title", "")
    detail = item.get("summary", "") or item.get("description", "")
    searchable = f"{title} {detail}".casefold()
    maintenance_end = item.get("maintenanceenddate") or item.get("maintenance_end_date")
    if maintenance_end or any(
        marker in searchable
        for marker in ("scheduled maintenance", ">scheduled<", " maintenance window")
    ):
        return "scheduled_maintenance"

    if any(
        marker in searchable
        for marker in (
            "incident",
            "outage",
            "disruption",
            "degraded",
            "investigating",
            "identified",
            "monitoring",
            "resolved",
        )
    ):
        return "service_incident"
    return "service_notice"


def parse_feed(
    source: str,
    content: bytes,
    backfill_days: int,
    *,
    now: datetime | None = None,
) -> list[EventIn]:
    parsed = feedparser.parse(content)
    cutoff = as_utc(now or datetime.now(timezone.utc)) - timedelta(days=backfill_days)
    results: list[EventIn] = []

    for item in parsed.entries:
        stamp = item.get("published_parsed") or item.get("updated_parsed")
        if not stamp:
            continue
        observed_at = datetime.fromtimestamp(timegm(stamp), timezone.utc)
        if observed_at < cutoff:
            continue

        url = item.get("link", "").strip()
        parsed_url = urlsplit(url)
        if parsed_url.scheme != "https" or not parsed_url.hostname:
            continue

        category = classify_feed_item(source, item)
        maintenance_end_stamp = item.get("maintenanceenddate_parsed") or item.get("maintenance_end_date_parsed")
        scheduled_end_at = (
            datetime.fromtimestamp(timegm(maintenance_end_stamp), timezone.utc)
            if maintenance_end_stamp
            else None
        )

        results.append(
            EventIn(
                source=source,
                title=item.get("title", "Untitled")[:500],
                url=url,
                observed_at=observed_at,
                category=category,
                # Vendor status feeds identify the affected provider. CISA is a
                # publisher, not necessarily the provider affected by an advisory.
                provider=None if source == "cisa" else source,
                asn=PROVIDER_METADATA.get(source, {}).get("asn"),
                region=extract_region(
                    item.get("title", ""), item.get("summary", "")
                ),
                confidence=0.8,
                detail=item.get("summary", "")[:4000],
                publisher_reported_at=observed_at,
                first_observed_at=observed_at,
                scheduled_start_at=observed_at if category == "scheduled_maintenance" else None,
                scheduled_end_at=scheduled_end_at,
                source_event_id=str(item.get("id") or item.get("guid") or "")[:300] or None,
                raw_metadata={
                    "feed_source": source,
                    "published": item.get("published"),
                    "updated": item.get("updated"),
                    "author": item.get("author"),
                    "tags": [tag.get("term") for tag in item.get("tags", []) if tag.get("term")][:20],
                },
            )
        )
    return results


def collect(backfill_days: int = 30) -> dict[str, dict[str, int | str]]:
    if not COLLECT_LOCK.acquire(blocking=False):
        return {"collection": {"status": "already_running"}}

    summary: dict[str, dict[str, int | str]] = {}
    try:
        with httpx.Client(
            timeout=httpx.Timeout(20, connect=10),
            follow_redirects=False,
            headers={"User-Agent": "OSINT-Correlation-Research/1.0"},
        ) as client:
            with SessionLocal() as db:
                for name, url in SOURCES.items():
                    try:
                        response = fetch_public_source(client, url)
                        parsed_events = parse_feed(name, response.content, backfill_days)
                        added = 0
                        updated = 0
                        for event in parsed_events:
                            _, created, changed = insert_event(
                                db, event, refresh_existing=True
                            )
                            added += int(created)
                            updated += int(changed)
                        summary[name] = {
                            "added": added,
                            "updated": updated,
                            "parsed": len(parsed_events),
                        }
                    except Exception as exc:  # Keep one failed publisher from stopping others.
                        logger.warning("Collection failed for %s: %s", name, exc)
                        summary[name] = {"error": str(exc)[:250]}
        return summary
    finally:
        COLLECT_LOCK.release()


def pair_score(a: Event, b: Event, window_hours: float = 24) -> tuple[float, list[str]]:
    if window_hours <= 0:
        return 0, []
    hours = abs((as_utc(a.observed_at) - as_utc(b.observed_at)).total_seconds()) / 3600
    if hours > window_hours:
        return 0, []

    reasons = [f"temporal proximity: {hours:.1f}h"]
    score = 0.10 * (1 - hours / window_hours)
    for field, weight in (("provider", 0.40), ("asn", 0.35), ("region", 0.10)):
        left, right = getattr(a, field), getattr(b, field)
        if left and right and left.casefold() == right.casefold():
            score += weight
            reasons.append(f"shared {field}: {left}")

    if a.source.casefold() == b.source.casefold():
        reasons.append("same reporting source (not independent corroboration)")
        score *= 0.7
    return round(min(score, 1), 3), reasons


def event_reference(event: Event) -> dict[str, int | str]:
    return {
        "id": event.id,
        "title": event.title,
        "source": event.source,
        "observed_at": as_utc(event.observed_at).isoformat(),
        "category": event.category,
        "url": event.url,
    }


def measurement_support(
    event: Event,
    measurements: list[NetworkMeasurement],
    window_hours: float = 2,
) -> list[dict]:
    support = []
    for measurement in measurements:
        same_infrastructure = any(
            left and right and left.casefold() == right.casefold()
            for left, right in (
                (event.provider, measurement.provider),
                (event.asn, measurement.asn),
                (event.region, measurement.region),
            )
        )
        if not same_infrastructure:
            continue
        hours = abs(
            (
                as_utc(event.observed_at) - as_utc(measurement.observed_at)
            ).total_seconds()
        ) / 3600
        if hours <= window_hours:
            item = measurement_dict(measurement)
            item["distance_hours"] = round(hours, 2)
            support.append(item)
    return sorted(
        support, key=lambda item: abs(item.get("z_score") or 0), reverse=True
    )[:5]


def correlate(
    db: Session,
    days: int = 30,
    window_hours: float = 24,
    minimum: float = 0.08,
    include_scheduled: bool = False,
    include_future: bool = False,
    independent_only: bool = True,
    *,
    now: datetime | None = None,
) -> list[dict]:
    current_time = as_utc(now or datetime.now(timezone.utc))
    cutoff = current_time - timedelta(days=days)
    conditions = [Event.observed_at >= cutoff]
    if not include_future:
        conditions.append(Event.observed_at <= current_time)
    if not include_scheduled:
        conditions.append(Event.category != "scheduled_maintenance")
    events = db.scalars(
        select(Event)
        .where(*conditions)
        .order_by(Event.observed_at.desc())
        .limit(2000)
    ).all()
    anomalous_measurements = db.scalars(
        select(NetworkMeasurement)
        .where(
            NetworkMeasurement.observed_at >= cutoff - timedelta(hours=2),
            NetworkMeasurement.observed_at <= current_time + timedelta(hours=2),
            or_(
                func.abs(NetworkMeasurement.z_score) >= 2.0,
                NetworkMeasurement.source == "ioda",
            ),
        )
        .order_by(NetworkMeasurement.observed_at.desc())
        .limit(5000)
    ).all()

    edges = []
    for index, left in enumerate(events):
        for right in events[index + 1 :]:
            # Records are descending, so every later record will be farther away.
            if (as_utc(left.observed_at) - as_utc(right.observed_at)).total_seconds() > window_hours * 3600:
                break
            independent_sources = left.source.casefold() != right.source.casefold()
            if independent_only and not independent_sources:
                continue
            if include_scheduled and "scheduled_maintenance" in {
                left.category,
                right.category,
            }:
                compatible = True
                compatibility_reason = "scheduled comparison explicitly included"
            else:
                compatible, compatibility_reason = incident_types_compatible(left, right)
            if not compatible:
                continue
            infrastructure = shared_infrastructure(left, right)
            semantic_score, shared_terms = semantic_relevance(left, right)
            if not infrastructure and not shared_terms:
                continue
            score, reasons = pair_score(left, right, window_hours)
            if semantic_score:
                score += min(0.15, 0.15 * semantic_score)
                reasons.append(
                    "semantic overlap: " + ", ".join(shared_terms)
                )
            reasons.append(compatibility_reason)
            left_measurements = measurement_support(left, anomalous_measurements)
            right_measurements = measurement_support(right, anomalous_measurements)
            if left_measurements:
                score += 0.05
                reasons.append("anomalous network measurement near left event")
            if right_measurements:
                score += 0.05
                reasons.append("anomalous network measurement near right event")
            score = round(min(score, 1), 3)
            if score >= minimum:
                edges.append(
                    {
                        "a": left.id,
                        "b": right.id,
                        "left": event_reference(left),
                        "right": event_reference(right),
                        "independent_sources": independent_sources,
                        "semantic_score": semantic_score,
                        "shared_terms": shared_terms,
                        "shared_infrastructure": infrastructure,
                        "network_evidence": {
                            "left": left_measurements,
                            "right": right_measurements,
                        },
                        "score": score,
                        "reasons": reasons,
                    }
                )
    return sorted(edges, key=lambda edge: edge["score"], reverse=True)[:500]


def poll_minutes() -> int:
    try:
        return max(1, int(os.getenv("POLL_MINUTES", "15")))
    except ValueError:
        logger.warning("Invalid POLL_MINUTES; falling back to 15")
        return 15


def measurement_poll_minutes() -> int:
    try:
        return max(15, int(os.getenv("MEASUREMENT_POLL_MINUTES", "60")))
    except ValueError:
        logger.warning("Invalid MEASUREMENT_POLL_MINUTES; falling back to 60")
        return 60


@asynccontextmanager
async def lifespan(application: FastAPI):
    from app.config import get_settings

    get_settings()
    # SQLite/unit-test bootstrapping remains convenient. Production Compose runs
    # Alembic before API and worker startup and disables this compatibility path.
    if IS_SQLITE or os.getenv("AUTO_CREATE_SCHEMA", "false").casefold() == "true":
        Base.metadata.create_all(engine)
    yield


app = FastAPI(
    title="OSINT Correlation Engine",
    version="0.1.0-beta.2",
    description="Evidence-driven public infrastructure disruption intelligence. Correlation scores are explainable heuristics, not attribution probabilities.",
    lifespan=lifespan,
)
cors_origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "").split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
security = HTTPBearer(auto_error=False)


@app.middleware("http")
async def operational_safeguards(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:80]
    request.state.request_id = request_id
    max_bytes = max(1024, int(os.getenv("MAX_REQUEST_BYTES", "1048576")))
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                return Response("request body too large", status_code=413)
        except ValueError:
            return Response("invalid content-length", status_code=400)

    received = 0
    original_receive = request._receive

    async def limited_receive():
        nonlocal received
        message = await original_receive()
        received += len(message.get("body", b""))
        if received > max_bytes:
            raise RequestBodyTooLarge
        return message

    request._receive = limited_receive

    if request.url.path.startswith("/api/public/"):
        limit = max(10, int(os.getenv("PUBLIC_RATE_LIMIT_PER_MINUTE", "120")))
        address = request.client.host if request.client else "unknown"
        key = hashlib.sha256(address.encode()).hexdigest()
        now = time.monotonic()
        with _RATE_LOCK:
            bucket = _RATE_BUCKETS[key]
            while bucket and bucket[0] < now - 60:
                bucket.popleft()
            if len(bucket) >= limit:
                return Response("rate limit exceeded", status_code=429, headers={"Retry-After": "60"})
            bucket.append(now)

    started = time.perf_counter()
    try:
        response = await call_next(request)
    except RequestBodyTooLarge:
        return Response("request body too large", status_code=413)
    route = request.scope.get("route")
    route_path = getattr(route, "path", request.url.path)
    REQUEST_COUNT.labels(request.method, route_path, str(response.status_code)).inc()
    REQUEST_LATENCY.labels(request.method, route_path).observe(time.perf_counter() - started)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'"
    )
    return response


def authorize(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> None:
    expected = os.getenv("API_TOKEN", "")
    provided = credentials.credentials if credentials else ""
    if not expected or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_db():
    with SessionLocal() as db:
        yield db


def write_compatibility_audit(db: Session, request: Request, action: str, object_type: str, object_id: int | None = None) -> None:
    from app.v2_models import AuditLog

    remote = request.client.host if request.client else "unknown"
    salt = os.getenv("AUDIT_HASH_SALT", os.getenv("API_TOKEN", "local-audit"))
    db.add(
        AuditLog(
            actor="admin_api",
            action=action,
            object_type=object_type,
            object_id=str(object_id) if object_id is not None else None,
            request_id=getattr(request.state, "request_id", None),
            remote_address_hash=hashlib.sha256(f"{salt}|{remote}".encode()).hexdigest(),
            details={"compatibility_endpoint": True},
        )
    )
    db.commit()


@app.get("/", include_in_schema=False)
def dashboard():
    root = Path(__file__).resolve().parent.parent
    built = root / "static" / "app" / "index.html"
    return FileResponse(built if built.exists() else root / "static" / "index.html")


@app.get("/health")
def health(db: Session = Depends(get_db)):
    return {
        "ok": True,
        "events": db.scalar(select(func.count()).select_from(Event)),
        "measurements": db.scalar(
            select(func.count()).select_from(NetworkMeasurement)
        ),
    }


@app.get("/ready")
def readiness(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"ready": True, "database": "ok"}


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/events")
def events(
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(90, ge=1, le=3650),
    db: Session = Depends(get_db),
):
    current_time = datetime.now(timezone.utc)
    cutoff = current_time - timedelta(days=days)
    records = db.scalars(
        select(Event)
        .where(Event.observed_at >= cutoff)
        .order_by(Event.observed_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": event.id,
            "source": event.source,
            "title": event.title,
            "url": event.url,
            "observed_at": as_utc(event.observed_at).isoformat(),
            "category": event.category,
            "time_semantics": (
                "scheduled_window_start"
                if event.category == "scheduled_maintenance"
                else "publisher_event_timestamp"
            ),
            "is_future": as_utc(event.observed_at) > current_time,
            "provider": event.provider,
            "asn": event.asn,
            "region": event.region,
            "confidence": event.confidence,
        }
        for event in records
    ]


@app.post("/api/events", dependencies=[Depends(authorize)], status_code=status.HTTP_201_CREATED)
def add_event(event: EventIn, request: Request, response: Response, db: Session = Depends(get_db)):
    record, created, _ = insert_event(db, event)
    if not created:
        response.status_code = status.HTTP_200_OK
    write_compatibility_audit(db, request, "event.create" if created else "event.deduplicate", "event", record.id)
    return {"id": record.id, "created": created}


@app.post("/api/collect", dependencies=[Depends(authorize)])
def trigger_collect(request: Request, days: int = Query(30, ge=1, le=3650), db: Session = Depends(get_db)):
    result = collect(days)
    write_compatibility_audit(db, request, "collectors.run", "feed_collectors")
    return result


@app.get("/api/measurements")
def measurements(
    limit: int = Query(500, ge=1, le=5000),
    days: int = Query(30, ge=1, le=3650),
    anomalies_only: bool = Query(False),
    db: Session = Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    conditions = [NetworkMeasurement.observed_at >= cutoff]
    if anomalies_only:
        conditions.append(
            or_(
                func.abs(NetworkMeasurement.z_score) >= 2.0,
                NetworkMeasurement.source == "ioda",
            )
        )
    records = db.scalars(
        select(NetworkMeasurement)
        .where(*conditions)
        .order_by(NetworkMeasurement.observed_at.desc())
        .limit(limit)
    ).all()
    return [measurement_dict(measurement) for measurement in records]


@app.post(
    "/api/measurements",
    dependencies=[Depends(authorize)],
    status_code=status.HTTP_201_CREATED,
)
def add_measurement(
    measurement: MeasurementIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    record, created, _ = insert_measurement(db, measurement)
    if not created:
        response.status_code = status.HTTP_200_OK
    write_compatibility_audit(db, request, "measurement.create" if created else "measurement.deduplicate", "network_measurement", record.id)
    return {"id": record.id, "created": created}


@app.post("/api/collect/measurements", dependencies=[Depends(authorize)])
def trigger_measurement_collect(request: Request, days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db)):
    result = collect_network_measurements(days)
    write_compatibility_audit(db, request, "collectors.run", "measurement_collectors")
    return result


@app.get("/api/correlations")
def correlations(
    days: int = Query(30, ge=1, le=3650),
    hours: float = Query(24, gt=0, le=720),
    minimum: float = Query(0.08, ge=0, le=1),
    include_scheduled: bool = Query(False),
    include_future: bool = Query(False),
    independent_only: bool = Query(True),
    db: Session = Depends(get_db),
):
    return correlate(
        db,
        days,
        hours,
        minimum,
        include_scheduled,
        include_future,
        independent_only,
    )


# Register additive models before lifespan schema bootstrap in tests, then mount
# the v2 public/admin API. Imports stay here so the compatibility symbols above
# remain available to existing deployments and collector code.
from app import v2_models as _v2_models  # noqa: E402,F401
from app.api_v2 import router as v2_router  # noqa: E402

app.include_router(v2_router)

_built_assets = Path(__file__).resolve().parent.parent / "static" / "app" / "assets"
if _built_assets.exists():
    app.mount("/assets", StaticFiles(directory=_built_assets), name="frontend-assets")
