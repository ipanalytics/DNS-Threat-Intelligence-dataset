from __future__ import annotations

import csv
from io import StringIO

import httpx

from dnsintel.normalize import normalize_ip
from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class FeodoTrackerAdapter:
    name = "feodotracker"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        if live:
            return self._collect_live(limit=limit)
        _ = limit
        return SourceResult(name=self.name, evidence=[], skipped=False, reason="fixture feed empty")

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

        csv_text = "\n".join(
            line for line in response.text.splitlines() if line.strip() and not line.startswith("#")
        )
        records = []
        seen_ips: set[str] = set()
        for row in csv.DictReader(StringIO(csv_text)):
            ip_raw = row.get("dst_ip") or row.get("ip_address") or row.get("ip")
            if not ip_raw:
                continue
            try:
                ip = normalize_ip(ip_raw)
            except ValueError:
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            records.append(
                evidence(
                    self.name,
                    "ip",
                    ip,
                    ["c2", "malware"],
                    88,
                    source_type="feed",
                    malware_family=row.get("malware") or row.get("malware_family"),
                    first_seen=row.get("first_seen_utc"),
                    reference_url=self.url,
                )
            )
            if limit is not None and len(records) >= limit:
                break
        return SourceResult(name=self.name, evidence=records)
