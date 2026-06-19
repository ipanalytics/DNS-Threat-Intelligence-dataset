from __future__ import annotations

import os
from json import JSONDecodeError

import httpx

from dnsintel.normalize import normalize_ip
from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class ThreatFoxAdapter:
    name = "threatfox"
    url = "https://threatfox.abuse.ch/export/json/recent/"
    api_url = "https://threatfox-api.abuse.ch/api/v1/"

    def collect(self, live: bool = False, limit: int | None = None) -> SourceResult:
        if live:
            return self._collect_live(limit=limit)
        return SourceResult(
            name=self.name,
            evidence=[
                evidence(
                    "threatfox",
                    "domain",
                    "c2-control.evil",
                    ["c2", "malware"],
                    95,
                    malware_family="ExampleLoader",
                ),
                evidence(
                    "threatfox", "ip", "203.0.113.50", ["c2"], 80, malware_family="ExampleLoader"
                ),
            ],
        )

    def _collect_live(self, limit: int | None = None) -> SourceResult:
        try:
            payload = self._fetch_payload()
        except (httpx.HTTPError, JSONDecodeError, ValueError) as exc:
            return SourceResult(
                name=self.name,
                skipped=True,
                reason=f"live fetch failed: {exc.__class__.__name__}: {exc}",
            )
        rows = _flatten_rows(payload)
        records = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = row.get("ioc_value") or row.get("ioc")
            ioc_type = str(row.get("ioc_type", "")).lower()
            if not isinstance(value, str):
                continue
            if "url" in ioc_type:
                indicator_type = "url"
                category = ["malware"]
            elif "domain" in ioc_type or "hostname" in ioc_type:
                indicator_type = "domain"
                category = ["c2", "malware"]
            elif "ip" in ioc_type:
                indicator_type = "ip"
                category = ["c2"]
                value = str(value).split(":", 1)[0]
                try:
                    value = normalize_ip(value)
                except ValueError:
                    continue
            else:
                continue
            confidence_raw = row.get("confidence_level")
            try:
                confidence = float(confidence_raw)
            except (TypeError, ValueError):
                confidence = 80.0
            records.append(
                evidence(
                    self.name,
                    indicator_type,
                    value,
                    category,
                    max(0, min(100, confidence)),
                    tags=row.get("tags") if isinstance(row.get("tags"), list) else [],
                    source_type="feed",
                    malware_family=row.get("malware"),
                    reference_url=row.get("reference"),
                )
            )
            if limit is not None and len(records) >= limit:
                break
        return SourceResult(name=self.name, evidence=records)

    def _fetch_payload(self) -> object:
        auth_key = os.environ.get("ABUSECH_AUTH_KEY")
        if auth_key:
            response = httpx.post(
                self.api_url,
                json={"query": "get_iocs", "days": 7},
                timeout=30,
                headers={"Accept": "application/json", "Auth-Key": auth_key},
            )
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict) and isinstance(payload.get("data"), list):
                return payload["data"]
            return payload

        response = httpx.get(
            self.url,
            timeout=30,
            follow_redirects=True,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()


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
