"""Additive v2 persistence models.

This module intentionally uses the existing declarative registry so Alembic and
the compatibility API see one schema.  Legacy tables remain untouched.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.main import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    stable_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    original_url: Mapped[str] = mapped_column(String(2000))
    publisher: Mapped[str] = mapped_column(String(200), index=True)
    upstream_source: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    excerpt: Mapped[str] = mapped_column(Text, default="")
    structured_observation: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    collection_method: Mapped[str] = mapped_column(String(100), default="public_feed")
    reliability: Mapped[float] = mapped_column(Float, default=0.5)
    verification_status: Mapped[str] = mapped_column(String(40), default="unverified", index=True)
    is_primary_source: Mapped[bool] = mapped_column(Boolean, default=False)


class EventEvidence(Base):
    __tablename__ = "event_evidence"

    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence_artifacts.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(30), default="supports", primary_key=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    added_by: Mapped[str] = mapped_column(String(100), default="system")


class IncidentAssessment(Base):
    __tablename__ = "incident_assessments"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    cause_classification: Mapped[str] = mapped_column(String(60), default="unknown", index=True)
    severity: Mapped[str] = mapped_column(String(30), default="unknown", index=True)
    evidence_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    investigation_status: Mapped[str] = mapped_column(String(40), default="unreviewed", index=True)
    rationale: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    assessed_by: Mapped[str] = mapped_column(String(100), default="system")
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    supersedes_id: Mapped[int | None] = mapped_column(ForeignKey("incident_assessments.id"), nullable=True)


class CorrelationRecord(Base):
    __tablename__ = "correlations"

    id: Mapped[int] = mapped_column(primary_key=True)
    stable_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    left_event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    right_event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(60), index=True)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    source_provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    strength: Mapped[float] = mapped_column(Float, index=True)
    confidence_assessment: Mapped[str] = mapped_column(String(30), index=True)
    explanation: Mapped[str] = mapped_column(Text)
    supporting_factors: Mapped[list] = mapped_column(JSON, default=list)
    contradictory_factors: Mapped[list] = mapped_column(JSON, default=list)
    independence: Mapped[dict] = mapped_column(JSON, default=dict)
    additional_observations: Mapped[dict] = mapped_column(JSON, default=dict)
    score_components: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_basis: Mapped[str] = mapped_column(String(30), default="inferred", index=True)
    assessment_status: Mapped[str] = mapped_column(String(30), default="candidate", index=True)
    replay_cutoff: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    __table_args__ = (
        UniqueConstraint("left_event_id", "right_event_id", "relationship_type", name="uq_correlation_pair_type"),
        Index("ix_correlations_strength_updated", "strength", "updated_at"),
    )


class ProviderDependency(Base):
    __tablename__ = "provider_dependencies"

    id: Mapped[int] = mapped_column(primary_key=True)
    consumer: Mapped[str] = mapped_column(String(200), index=True)
    dependency: Mapped[str] = mapped_column(String(200), index=True)
    relationship_type: Mapped[str] = mapped_column(String(60), default="depends_on")
    status: Mapped[str] = mapped_column(String(30), default="unverified")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    explanation: Mapped[str] = mapped_column(Text, default="")
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("consumer", "dependency", "relationship_type", name="uq_provider_dependency"),)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[str] = mapped_column(String(40), default="Open", index=True)
    public: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[str] = mapped_column(String(100), default="admin")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class InvestigationEvent(Base):
    __tablename__ = "investigation_events"

    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    added_by: Mapped[str] = mapped_column(String(100), default="admin")


class InvestigationEvidence(Base):
    __tablename__ = "investigation_evidence"

    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence_artifacts.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(30), default="context", primary_key=True)


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="unverified", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(100), default="admin")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class HypothesisEvidence(Base):
    __tablename__ = "hypothesis_evidence"

    hypothesis_id: Mapped[int] = mapped_column(ForeignKey("hypotheses.id", ondelete="CASCADE"), primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence_artifacts.id", ondelete="CASCADE"), primary_key=True)
    stance: Mapped[str] = mapped_column(String(30), primary_key=True)
    explanation: Mapped[str] = mapped_column(Text, default="")


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    body: Mapped[str] = mapped_column(Text)
    assertion_type: Mapped[str] = mapped_column(String(30), default="investigator_assertion")
    author: Mapped[str] = mapped_column(String(100), default="admin")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorRun(Base):
    __tablename__ = "collector_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    collector: Mapped[str] = mapped_column(String(100), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="running", index=True)
    fetched: Mapped[int] = mapped_column(Integer, default=0)
    inserted: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    deduplicated: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_freshness_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)


class CollectorCheckpoint(Base):
    __tablename__ = "collector_checkpoints"

    collector: Mapped[str] = mapped_column(String(100), primary_key=True)
    cursor: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class BaselineSnapshot(Base):
    __tablename__ = "baseline_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    dimension_type: Mapped[str] = mapped_column(String(40), index=True)
    dimension_value: Mapped[str] = mapped_column(String(200), index=True)
    period: Mapped[str] = mapped_column(String(40), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    sample_count: Mapped[int] = mapped_column(Integer)
    median: Mapped[float] = mapped_column(Float)
    mad: Mapped[float] = mapped_column(Float)
    current_value: Mapped[float] = mapped_column(Float)
    robust_z_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    coverage_ratio: Mapped[float] = mapped_column(Float, default=1.0)
    change_point: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[list] = mapped_column(JSON, default=list)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(100), default="admin")
    action: Mapped[str] = mapped_column(String(100), index=True)
    object_type: Mapped[str] = mapped_column(String(80))
    object_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    remote_address_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
