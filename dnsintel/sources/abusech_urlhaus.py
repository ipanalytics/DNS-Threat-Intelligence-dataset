from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class URLhausAdapter:
    name = "urlhaus"

    def collect(self) -> SourceResult:
        records = [
            evidence(
                "urlhaus",
                "url",
                "hxxp://malware-download.bad/payload.exe",
                ["malware"],
                92,
                tags=["exe", "payload"],
            ),
            evidence(
                "urlhaus", "domain", "malware-download.bad", ["malware"], 88, threat="payload"
            ),
        ]
        return SourceResult(name=self.name, evidence=records)
