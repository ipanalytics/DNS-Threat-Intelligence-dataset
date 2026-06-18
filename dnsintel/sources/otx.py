from __future__ import annotations

from dnsintel.sources.base import SourceResult


class OTXAdapter:
    name = "otx"

    def collect(self) -> SourceResult:
        return SourceResult(
            name=self.name, skipped=True, reason="requires token; disabled by default"
        )
