from __future__ import annotations

import httpx

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class OpenPhishAdapter:
    name = "openphish"
    url = "https://openphish.com/feed.txt"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        if live:
            return self._collect_live(limit=limit)
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

    def _collect_live(self, limit: int | None = None) -> SourceResult:
        try:
            response = httpx.get(self.url, timeout=30, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason=f"live fetch failed: {exc.__class__.__name__}: {exc}",
            )
        records = []
        for line in response.text.splitlines():
            url = line.strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            records.append(
                evidence(
                    self.name,
                    "url",
                    url,
                    ["phishing"],
                    82,
                    tags=["openphish"],
                    source_type="feed",
                    reference_url=self.url,
                )
            )
            if limit is not None and len(records) >= limit:
                break
        return SourceResult(name=self.name, evidence=records)
