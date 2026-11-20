from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_existing_prototype_row_survives_upgrade(tmp_path, monkeypatch):
    database = tmp_path / "prototype.db"
    url = f"sqlite:///{database}"
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY, fingerprint VARCHAR(64) UNIQUE NOT NULL,
                source VARCHAR(100) NOT NULL, title VARCHAR(500) NOT NULL,
                url VARCHAR(2000) NOT NULL, observed_at DATETIME NOT NULL,
                ingested_at DATETIME NOT NULL, category VARCHAR(60) NOT NULL,
                provider VARCHAR(100), asn VARCHAR(30), region VARCHAR(100),
                confidence FLOAT NOT NULL, detail VARCHAR(4000) NOT NULL
            )
        """))
        connection.execute(text("""
            INSERT INTO events (id, fingerprint, source, title, url, observed_at, ingested_at, category, confidence, detail)
            VALUES (1, 'legacy', 'legacy', 'Preserved event', 'https://example.org/legacy', '2026-11-18T00:00:00Z', '2026-11-18T00:01:00Z', 'service_incident', 0.5, '')
        """))
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config("alembic.ini")
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT title FROM events WHERE id=1")) == "Preserved event"
        assert connection.scalar(text("SELECT cause_classification FROM events WHERE id=1")) == "unknown"
    tables = set(inspect(engine).get_table_names())
    assert {"evidence_artifacts", "investigations", "correlations", "alembic_version"} <= tables
