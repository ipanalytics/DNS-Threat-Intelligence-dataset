from __future__ import annotations

from json import JSONDecodeError

import httpx

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class URLhausAdapter:
    name = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        if live:
            return self._collect_live(limit=limit)
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

    def _collect_live(self, limit: int | None = None) -> SourceResult:
        try:
            response = httpx.get(
                self.url,
                timeout=30,
                follow_redirects=True,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, JSONDecodeError, ValueError) as exc:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason=f"live fetch failed: {exc.__class__.__name__}: {exc}",
            )
        records = []
        seen_domains: set[str] = set()
        rows = payload.values() if isinstance(payload, dict) else payload
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = row.get("url")
            host = row.get("host") or row.get("domain")
            tags = row.get("tags") if isinstance(row.get("tags"), list) else []
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                records.append(
                    evidence(
                        self.name,
                        "url",
                        url,
                        ["malware"],
                        90,
                        tags=tags,
                        source_type="feed",
                        source_status=row.get("url_status"),
                        threat=row.get("threat"),
                        reference_url=row.get("urlhaus_reference"),
                    )
                )
            if isinstance(host, str) and host not in seen_domains:
                seen_domains.add(host)
                records.append(
                    evidence(
                        self.name,
                        "domain",
                        host,
                        ["malware"],
                        85,
                        tags=tags,
                        source_type="feed",
                        threat=row.get("threat"),
                        reference_url=row.get("urlhaus_reference"),
                    )
                )
            if limit is not None and len(records) >= limit:
                break
        return SourceResult(name=self.name, evidence=records[:limit] if limit else records)
