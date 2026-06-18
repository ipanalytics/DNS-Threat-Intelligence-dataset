from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class ThreatFoxAdapter:
    name = "threatfox"

    def collect(self) -> SourceResult:
        return SourceResult(
            name=self.name,
            evidence=[
                evidence(
                    "threatfox",
                    "domain",
                    "c2-control.evil",
                    ["c2", "malware"],
                    95,
                    malware_family="ExampleLoader",
                ),
                evidence(
                    "threatfox", "ip", "203.0.113.50", ["c2"], 80, malware_family="ExampleLoader"
                ),
            ],
        )
