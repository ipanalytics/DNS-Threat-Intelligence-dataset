from __future__ import annotations

from dnsintel.sources.base import SourceResult


class OTXAdapter:
    name = "otx"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        _ = (live, limit)
        return SourceResult(
            name=self.name, skipped=True, reason="requires token; disabled by default"
        )
