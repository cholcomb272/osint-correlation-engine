from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main


def test_one_failed_collector_does_not_stop_others(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    main.Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(engine, expire_on_commit=False))
    monkeypatch.setattr(main, "SOURCES", {
        "failed": "https://www.cisa.gov/failed.xml",
        "healthy": "https://www.cisa.gov/healthy.xml",
    })
    xml = b"""<rss><channel><item><title>Service outage</title>
      <link>https://example.org/synthetic/outage</link>
      <pubDate>Wed, 18 Nov 2026 12:00:00 GMT</pubDate>
    </item></channel></rss>"""

    def fetch(_client, url, **_kwargs):
        if url.endswith("failed.xml"):
            raise RuntimeError("synthetic source failure")
        return SimpleNamespace(content=xml)

    monkeypatch.setattr(main, "fetch_public_source", fetch)
    result = main.collect(30)
    assert "error" in result["failed"]
    assert result["healthy"]["added"] == 1
