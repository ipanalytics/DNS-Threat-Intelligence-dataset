from __future__ import annotations

from dnsintel.sources.base import SourceResult


class FeodoTrackerAdapter:
    name = "feodotracker"

    def collect(self) -> SourceResult:
        return SourceResult(name=self.name, evidence=[], skipped=False, reason="fixture feed empty")
