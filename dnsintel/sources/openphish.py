from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class OpenPhishAdapter:
    name = "openphish"

    def collect(self) -> SourceResult:
        return SourceResult(
            name=self.name,
            evidence=[
                evidence(
                    "openphish",
                    "url",
                    "http://wallet-verify.bad/login",
                    ["phishing"],
                    84,
                    campaign_hint="wallet",
                ),
            ],
        )
