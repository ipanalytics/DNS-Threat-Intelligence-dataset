from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class PhishTankAdapter:
    name = "phishtank"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        _ = limit
        if live:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason="live feed requires a configured PhishTank data source",
            )
        return SourceResult(
            name=self.name,
            evidence=[
                evidence(
                    "phishtank",
                    "url",
                    "https://login-paypal-security.example.net/signin",
                    ["phishing"],
                    86,
                    verified=True,
                ),
            ],
        )
