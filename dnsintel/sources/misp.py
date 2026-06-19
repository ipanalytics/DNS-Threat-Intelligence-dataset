from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class MISPAdapter:
    name = "misp"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        _ = limit
        if live:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason="live MISP export requires configured instance credentials",
            )
        return SourceResult(
            name=self.name,
            evidence=[evidence("misp", "domain", "misp-ioc.bad", ["malware"], 76, event="fixture")],
        )
