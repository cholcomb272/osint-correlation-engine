"""Collector contracts used by the worker.

Collectors return source-specific records but share retry-safe run metadata,
checkpointing, and health semantics.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


@dataclass
class CollectorResult:
    collector: str
    fetched: int = 0
    inserted: int = 0
    updated: int = 0
    deduplicated: int = 0
    source_freshness_at: datetime | None = None
    errors: list[str] = field(default_factory=list)
    checkpoint: dict = field(default_factory=dict)


class Collector(Protocol):
    name: str

    def collect(self, *, days: int, checkpoint: dict | None = None) -> CollectorResult:
        """Collect idempotently and return a replayable checkpoint."""
        ...
