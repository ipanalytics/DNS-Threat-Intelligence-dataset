from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from dnsintel.models import Evidence


@dataclass(slots=True)
class SourceResult:
    name: str
    evidence: list[Evidence] = field(default_factory=list)
    skipped: bool = False
    reason: str | None = None


class SourceAdapter(Protocol):
    name: str

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        """Collect evidence from a fixture, local file, or configured live source."""
