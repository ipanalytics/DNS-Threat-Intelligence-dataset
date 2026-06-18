from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator

Confidence = Literal["low", "medium", "high", "critical"]
RecommendedAction = Literal[
    "monitor",
    "block_domain",
    "block_url",
    "block_ip",
    "do_not_block_shared_infra",
    "needs_review",
]


def now_utc() -> datetime:
    return datetime.now(UTC)


class Evidence(BaseModel):
    source_name: str
    source_type: str
    indicator_type: Literal["domain", "url", "ip", "asn", "hash", "certificate", "resolver"]
    value: str
    category: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    reference_url: str | None = None
    raw: dict[str, Any] | None = None


class DomainIndicator(BaseModel):
    domain: str
    etld1: str | None = None
    category: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=now_utc)
    last_seen: datetime = Field(default_factory=now_utc)
    confidence: Confidence = "low"
    score: float = Field(default=0, ge=0, le=100)
    recommended_action: RecommendedAction = "monitor"
    shared_infrastructure_hint: bool = False

    @field_validator("domain")
    @classmethod
    def domain_is_lower(cls, value: str) -> str:
        return value.rstrip(".").lower()


class URLIndicator(BaseModel):
    url: str
    domain: str
    category: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=now_utc)
    last_seen: datetime = Field(default_factory=now_utc)
    confidence: Confidence = "low"
    score: float = Field(default=0, ge=0, le=100)
    recommended_action: RecommendedAction = "monitor"


class IPEnrichment(BaseModel):
    ip: str
    asn: int | None = None
    as_name: str | None = None
    bgp_prefix: str | None = None
    rir: str | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    rdap_org: str | None = None
    rdap_abuse_email: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=now_utc)
    last_seen: datetime = Field(default_factory=now_utc)
    sources: list[str] = Field(default_factory=list)


class DomainIPLink(BaseModel):
    domain: str
    ip: str
    record_type: Literal["A", "AAAA"]
    ttl: int | None = None
    resolver: str
    observed_at: datetime = Field(default_factory=now_utc)
    asn: int | None = None
    bgp_prefix: str | None = None
    country: str | None = None


class ResolverRisk(BaseModel):
    ip: str
    asn: int | None = None
    country: str | None = None
    resolver_type: Literal[
        "open_resolver",
        "public_resolver",
        "malicious_resolver",
        "amplification_risk",
        "unknown",
    ] = "unknown"
    amplification_risk_score: float = Field(default=0, ge=0, le=100)
    evidence: list[Evidence] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=now_utc)
    last_seen: datetime = Field(default_factory=now_utc)
    recommended_action: Literal[
        "monitor",
        "report_to_abuse_contact",
        "block_as_resolver",
        "do_not_block",
    ] = "monitor"


class CTCandidate(BaseModel):
    domain: str
    brand: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    fingerprint: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    recommended_action: RecommendedAction = "needs_review"


class PublicOSINTEvidence(BaseModel):
    indicator: str
    indicator_type: str
    platform: Literal["github", "gitlab", "gist", "other_public"]
    source_url: str
    repository: str | None = None
    file_path: str | None = None
    matched_terms: list[str] = Field(default_factory=list)
    evidence_snippet: str | None = None
    published_or_indexed_at: datetime | None = None
    confidence: float = Field(default=0, ge=0, le=100)


class MalwareReport(BaseModel):
    report_id: str
    title: str
    source_name: str
    source_url: HttpUrl | str
    published_at: datetime | None = None
    fetched_at: datetime = Field(default_factory=now_utc)
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    iocs: list[Evidence] = Field(default_factory=list)


class FastFluxScore(BaseModel):
    domain: str
    flux_score: float = Field(ge=0, le=100)
    flux_type: Literal["none", "single_flux", "double_flux"] = "none"
    flux_confidence: Literal["low", "medium", "high"] = "low"
    reason_codes: list[str] = Field(default_factory=list)
