from __future__ import annotations

import csv
from io import StringIO

import httpx

from dnsintel.normalize import is_public_ip, normalize_ip
from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class PublicDNSInfoAdapter:
    name = "public-dns-info"
    url = "https://public-dns.info/nameservers.csv"
    plaintext_url = "https://public-dns.info/nameservers.txt"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        if live:
            return self._collect_live(limit=limit)
        _ = limit
        return SourceResult(name=self.name, evidence=[], skipped=False, reason="fixture feed empty")

    def _collect_live(self, limit: int | None = None) -> SourceResult:
        csv_result = self._collect_csv(limit=limit)
        if csv_result.evidence:
            return csv_result
        text_result = self._collect_plaintext(limit=limit)
        if text_result.evidence:
            return text_result
        reasons = "; ".join(reason for reason in [csv_result.reason, text_result.reason] if reason)
        return SourceResult(name=self.name, skipped=True, reason=reasons or "empty live feed")

    def _collect_csv(self, limit: int | None = None) -> SourceResult:
        try:
            response = httpx.get(self.url, timeout=45, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason=f"live fetch failed: {exc.__class__.__name__}: {exc}",
            )

        records = []
        seen: set[str] = set()
        for row in csv.DictReader(StringIO(response.text)):
            ip_raw = row.get("ip_address")
            if not ip_raw:
                continue
            try:
                ip = normalize_ip(ip_raw)
            except ValueError:
                continue
            if ip in seen or not is_public_ip(ip):
                continue
            seen.add(ip)
            records.append(
                evidence(
                    self.name,
                    "resolver",
                    ip,
                    ["open_resolver"],
                    70,
                    source_type="feed",
                    reference_url=self.url,
                    as_number=row.get("as_number"),
                    as_org=row.get("as_org"),
                    country_code=row.get("country_code"),
                    city=row.get("city"),
                    dnssec=row.get("dnssec"),
                    reliability=row.get("reliability"),
                    checked_at=row.get("checked_at"),
                )
            )
            if limit is not None and len(records) >= limit:
                break
        if not records:
            return SourceResult(
                name=self.name, skipped=True, reason="CSV export produced no records"
            )
        return SourceResult(name=self.name, evidence=records)

    def _collect_plaintext(self, limit: int | None = None) -> SourceResult:
        try:
            response = httpx.get(self.plaintext_url, timeout=45, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason=f"plaintext fetch failed: {exc.__class__.__name__}: {exc}",
            )

        records = []
        seen: set[str] = set()
        for line in response.text.splitlines():
            ip_raw = line.strip()
            if not ip_raw or ip_raw.startswith("#"):
                continue
            try:
                ip = normalize_ip(ip_raw)
            except ValueError:
                continue
            if ip in seen or not is_public_ip(ip):
                continue
            seen.add(ip)
            records.append(
                evidence(
                    self.name,
                    "resolver",
                    ip,
                    ["open_resolver"],
                    68,
                    source_type="feed",
                    reference_url=self.plaintext_url,
                )
            )
            if limit is not None and len(records) >= limit:
                break
        if not records:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason="plaintext export produced no records",
            )
        return SourceResult(name=self.name, evidence=records)
