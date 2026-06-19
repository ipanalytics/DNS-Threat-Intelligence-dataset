from __future__ import annotations

import httpx

from dnsintel.normalize import is_public_ip, normalize_ip
from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class TrickestResolversAdapter:
    name = "trickest-resolvers"
    extended_url = (
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-extended.txt"
    )
    plaintext_url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        if live:
            return self._collect_live(limit=limit)
        _ = limit
        return SourceResult(name=self.name, evidence=[], skipped=False, reason="fixture feed empty")

    def _collect_live(self, limit: int | None = None) -> SourceResult:
        extended = self._collect_extended(limit=limit)
        if extended.evidence:
            return extended
        plain = self._collect_plaintext(limit=limit)
        if plain.evidence:
            return plain
        reasons = "; ".join(reason for reason in [extended.reason, plain.reason] if reason)
        return SourceResult(name=self.name, skipped=True, reason=reasons or "empty live feed")

    def _collect_extended(self, limit: int | None = None) -> SourceResult:
        try:
            response = httpx.get(self.extended_url, timeout=45, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason=f"extended fetch failed: {exc.__class__.__name__}: {exc}",
            )
        records = []
        seen: set[str] = set()
        for line in response.text.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            ip = _public_ip_or_none(parts[0])
            if ip is None or ip in seen:
                continue
            seen.add(ip)
            records.append(
                evidence(
                    self.name,
                    "resolver",
                    ip,
                    ["open_resolver"],
                    72,
                    source_type="feed",
                    reference_url=self.extended_url,
                    organization=parts[1] if len(parts) > 1 else None,
                    country_code=parts[2] if len(parts) > 2 else None,
                    validation_count=parts[3] if len(parts) > 3 else None,
                )
            )
            if limit is not None and len(records) >= limit:
                break
        if not records:
            return SourceResult(
                name=self.name, skipped=True, reason="extended feed produced no records"
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
            ip = _public_ip_or_none(line.strip())
            if ip is None or ip in seen:
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
                    reference_url=self.plaintext_url,
                )
            )
            if limit is not None and len(records) >= limit:
                break
        if not records:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason="plaintext feed produced no records",
            )
        return SourceResult(name=self.name, evidence=records)


def _public_ip_or_none(value: str) -> str | None:
    try:
        ip = normalize_ip(value)
    except ValueError:
        return None
    return ip if is_public_ip(ip) else None
