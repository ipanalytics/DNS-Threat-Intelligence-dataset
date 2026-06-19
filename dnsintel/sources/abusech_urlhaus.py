from __future__ import annotations

from json import JSONDecodeError

import httpx

from dnsintel.normalize import normalize_domain
from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class URLhausAdapter:
    name = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    hostfile_url = "https://urlhaus.abuse.ch/downloads/hostfile/"

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
        records = []
        seen_domains: set[str] = set()

        json_result = self._collect_json_recent(limit=limit)
        records.extend(json_result.evidence)
        for record in json_result.evidence:
            if record.indicator_type == "domain":
                seen_domains.add(record.value)

        if limit is None or len(records) < limit:
            host_limit = None if limit is None else max(0, limit - len(records))
            host_result = self._collect_hostfile(limit=host_limit, seen_domains=seen_domains)
            records.extend(host_result.evidence)

        if records:
            return SourceResult(name=self.name, evidence=records[:limit] if limit else records)
        reasons = [json_result.reason, locals().get("host_result", SourceResult(self.name)).reason]
        reason = "; ".join(reason for reason in reasons if reason)
        return SourceResult(name=self.name, skipped=True, reason=reason or "empty live feed")

    def _collect_json_recent(self, limit: int | None = None) -> SourceResult:
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
        rows = _flatten_rows(payload)
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

    def _collect_hostfile(
        self, limit: int | None = None, seen_domains: set[str] | None = None
    ) -> SourceResult:
        seen_domains = seen_domains or set()
        try:
            response = httpx.get(self.hostfile_url, timeout=30, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason=f"hostfile fetch failed: {exc.__class__.__name__}: {exc}",
            )

        records = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            host = parts[-1] if parts else ""
            try:
                domain = normalize_domain(host)
            except ValueError:
                continue
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            records.append(
                evidence(
                    self.name,
                    "domain",
                    domain,
                    ["malware"],
                    86,
                    tags=["urlhaus-hostfile"],
                    source_type="feed",
                    reference_url=self.hostfile_url,
                )
            )
            if limit is not None and len(records) >= limit:
                break
        return SourceResult(name=self.name, evidence=records)


def _flatten_rows(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        iterable = payload.values()
    elif isinstance(payload, list):
        iterable = payload
    else:
        return []

    rows: list[dict] = []
    for item in iterable:
        if isinstance(item, dict):
            rows.append(item)
        elif isinstance(item, list):
            rows.extend(row for row in item if isinstance(row, dict))
    return rows
