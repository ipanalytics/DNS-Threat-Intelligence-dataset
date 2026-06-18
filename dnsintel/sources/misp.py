from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class MISPAdapter:
    name = "misp"

    def collect(self) -> SourceResult:
        return SourceResult(
            name=self.name,
            evidence=[evidence("misp", "domain", "misp-ioc.bad", ["malware"], 76, event="fixture")],
        )
