"""Add the global fusion ontology and persistent knowledge graph.

The revision is additive: legacy events, evidence, correlations, and
investigations remain in place. Existing rows receive only conservative domain
and event-type defaults derived from their current category.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261128_0002"
down_revision = "20261119_0001"
branch_labels = None
depends_on = None


EVENT_COLUMNS = {
    "domain": sa.Column("domain", sa.String(60), nullable=False, server_default="general"),
    "event_type": sa.Column("event_type", sa.String(100), nullable=False, server_default="unclassified"),
    "significance": sa.Column("significance", sa.String(30), nullable=False, server_default="unknown"),
    "latitude": sa.Column("latitude", sa.Float(), nullable=True),
    "longitude": sa.Column("longitude", sa.Float(), nullable=True),
    "location_name": sa.Column("location_name", sa.String(300), nullable=True),
    "language": sa.Column("language", sa.String(20), nullable=True),
    "extraction_confidence": sa.Column("extraction_confidence", sa.Float(), nullable=True),
    "ontology_version": sa.Column("ontology_version", sa.String(30), nullable=False, server_default="fusion-v1"),
}


NEW_TABLES = [
    "intelligence_entities",
    "entity_aliases",
    "event_entities",
    "event_classifications",
    "event_field_assessments",
    "knowledge_relationships",
    "relationship_evidence",
    "relationship_revisions",
    "event_clusters",
    "cluster_events",
    "investigation_candidates",
    "intelligence_requirements",
    "source_coverage_snapshots",
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "events" in tables:
        existing = {column["name"] for column in inspector.get_columns("events")}
        for name, column in EVENT_COLUMNS.items():
            if name not in existing:
                op.add_column("events", column)

    from app.main import Base
    import app.v2_models  # noqa: F401

    for name in NEW_TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)

    if "events" in sa.inspect(bind).get_table_names():
        op.execute(
            sa.text(
                "UPDATE events SET event_type = CASE "
                "WHEN event_type = 'unclassified' THEN category ELSE event_type END, "
                "domain = CASE "
                "WHEN domain <> 'general' THEN domain "
                "WHEN category IN ('service_incident', 'service_notice', 'scheduled_maintenance') THEN 'infrastructure' "
                "WHEN category IN ('security_advisory', 'vulnerability_exploitation') THEN 'cybersecurity' "
                "WHEN category = 'policy_announcement' THEN 'geopolitical_policy' "
                "ELSE domain END"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    existing_tables = set(sa.inspect(bind).get_table_names())
    for table in reversed(NEW_TABLES):
        if table in existing_tables:
            op.drop_table(table)
    if "events" in existing_tables:
        existing_columns = {column["name"] for column in sa.inspect(bind).get_columns("events")}
        for name in reversed(list(EVENT_COLUMNS)):
            if name in existing_columns:
                op.drop_column("events", name)
