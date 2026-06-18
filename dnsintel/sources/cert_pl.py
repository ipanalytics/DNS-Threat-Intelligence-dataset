from __future__ import annotations

from dnsintel.sources.base import SourceResult


class CertPLAdapter:
    name = "cert_pl"

    def collect(self) -> SourceResult:
        return SourceResult(
            name=self.name, skipped=True, reason="public/auth policy dependent; disabled by default"
        )
