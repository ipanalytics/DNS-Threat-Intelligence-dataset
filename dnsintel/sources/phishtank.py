from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class PhishTankAdapter:
    name = "phishtank"

    def collect(self) -> SourceResult:
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
