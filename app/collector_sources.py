"""Validated, environment-configurable public feed registry.

The bundled registry is deliberately data, not incident-specific code. Operators
can supply a replacement registry with ``FEED_SOURCE_REGISTRY``. The configured
URLs become the collector's complete outbound feed allowlist.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
from urllib.parse import urlsplit


VALID_KINDS = {
    "provider_status",
    "publisher_disclosure",
    "official_advisory",
    "official_news",
}
VALID_POLICIES = {"all", "incidents_only"}
DEFAULT_REGISTRY = Path(__file__).with_name("data") / "sources.json"


@dataclass(frozen=True)
class FeedSource:
    id: str
    name: str
    url: str
    kind: str
    publisher: str
    ingest_policy: str = "all"
    reliability: float = 0.7
    provider: str | None = None
    asn: str | None = None


def _source_from_dict(value: dict) -> FeedSource:
    required = {"id", "name", "url", "kind", "publisher"}
    missing = required - value.keys()
    if missing:
        raise ValueError(f"feed source is missing fields: {', '.join(sorted(missing))}")
    source = FeedSource(**value)
    parsed = urlsplit(source.url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"feed source {source.id!r} must use an absolute credential-free HTTPS URL")
    if source.kind not in VALID_KINDS:
        raise ValueError(f"feed source {source.id!r} has unsupported kind {source.kind!r}")
    if source.ingest_policy not in VALID_POLICIES:
        raise ValueError(f"feed source {source.id!r} has unsupported ingest policy")
    if not 0 <= source.reliability <= 1:
        raise ValueError(f"feed source {source.id!r} reliability must be between zero and one")
    return source


def load_feed_sources(path: str | Path | None = None) -> dict[str, FeedSource]:
    registry_path = Path(path or os.getenv("FEED_SOURCE_REGISTRY", DEFAULT_REGISTRY))
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("feed source registry must contain a JSON array")
    sources: dict[str, FeedSource] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("each feed source must be a JSON object")
        source = _source_from_dict(item)
        if source.id in sources:
            raise ValueError(f"duplicate feed source id: {source.id}")
        sources[source.id] = source
    if not sources:
        raise ValueError("feed source registry must not be empty")
    return sources
