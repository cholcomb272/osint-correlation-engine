"""Add the v2 evidence and investigation schema without replacing legacy data."""

from alembic import op
import sqlalchemy as sa

revision = "20261119_0001"
down_revision = None
branch_labels = None
depends_on = None


EVENT_COLUMNS = {
    "occurrence_at": sa.Column("occurrence_at", sa.DateTime(timezone=True), nullable=True),
    "first_observed_at": sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=True),
    "publisher_reported_at": sa.Column("publisher_reported_at", sa.DateTime(timezone=True), nullable=True),
    "collected_at": sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
    "retrieval_at": sa.Column("retrieval_at", sa.DateTime(timezone=True), nullable=True),
    "scheduled_start_at": sa.Column("scheduled_start_at", sa.DateTime(timezone=True), nullable=True),
    "scheduled_end_at": sa.Column("scheduled_end_at", sa.DateTime(timezone=True), nullable=True),
    "resolved_at": sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    "original_timezone": sa.Column("original_timezone", sa.String(80), nullable=True),
    "cause_classification": sa.Column("cause_classification", sa.String(60), nullable=False, server_default="unknown"),
    "severity": sa.Column("severity", sa.String(30), nullable=False, server_default="unknown"),
    "investigation_status": sa.Column("investigation_status", sa.String(40), nullable=False, server_default="unreviewed"),
    "source_reliability": sa.Column("source_reliability", sa.Float(), nullable=True),
    "raw_metadata": sa.Column("raw_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    "service": sa.Column("service", sa.String(200), nullable=True),
    "datacenter": sa.Column("datacenter", sa.String(200), nullable=True),
    "source_event_id": sa.Column("source_event_id", sa.String(300), nullable=True),
}


NEW_TABLES = [
    "audit_log",
    "baseline_snapshots",
    "collector_checkpoints",
    "collector_runs",
    "hypothesis_evidence",
    "investigation_notes",
    "hypotheses",
    "investigation_evidence",
    "investigation_events",
    "investigations",
    "provider_dependencies",
    "correlations",
    "incident_assessments",
    "event_evidence",
    "evidence_artifacts",
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    # A clean installation is created from the single metadata registry. An
    # installed prototype already has events/measurements, so only missing
    # columns and additive v2 tables are introduced.
    if "events" in tables:
        existing = {column["name"] for column in inspector.get_columns("events")}
        for name, column in EVENT_COLUMNS.items():
            if name not in existing:
                op.add_column("events", column)

    from app.main import Base
    import app.v2_models  # noqa: F401

    Base.metadata.create_all(bind=bind, checkfirst=True)

    if "events" in sa.inspect(bind).get_table_names():
        op.execute(
            sa.text(
                "UPDATE events SET "
                "first_observed_at = COALESCE(first_observed_at, observed_at), "
                "publisher_reported_at = COALESCE(publisher_reported_at, observed_at), "
                "collected_at = COALESCE(collected_at, ingested_at), "
                "retrieval_at = COALESCE(retrieval_at, ingested_at), "
                "scheduled_start_at = CASE WHEN category = 'scheduled_maintenance' "
                "THEN COALESCE(scheduled_start_at, observed_at) ELSE scheduled_start_at END"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    existing_tables = set(sa.inspect(bind).get_table_names())
    for table in NEW_TABLES:
        if table in existing_tables:
            op.drop_table(table)
    if "events" in existing_tables:
        existing_columns = {column["name"] for column in sa.inspect(bind).get_columns("events")}
        for name in reversed(list(EVENT_COLUMNS)):
            if name in existing_columns:
                op.drop_column("events", name)
