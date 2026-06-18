from __future__ import annotations

from dnsintel.models import FastFluxScore


def score_flux(
    domain: str,
    features: dict[str, float | int],
    shared_cdn: bool = False,
    malicious_overlap: bool = False,
) -> FastFluxScore:
    score = 0.0
    reasons: list[str] = []
    if features.get("unique_ips", 0) >= 5:
        score += 25
        reasons.append("many_ips")
    if features.get("unique_asns", 0) >= 3:
        score += 20
        reasons.append("many_asns")
    if features.get("unique_countries", 0) >= 3:
        score += 15
        reasons.append("many_countries")
    if 0 < features.get("ttl_min", 0) <= 300:
        score += 15
        reasons.append("low_ttl")
    if features.get("ns_churn", 0) >= 3:
        score += 20
        reasons.append("ns_churn")
    if malicious_overlap:
        score += 20
        reasons.append("malicious_overlap")
    if shared_cdn and not malicious_overlap:
        score -= 45
        reasons.append("shared_cdn_penalty")
    score = max(0, min(100, score))
    flux_type = "none"
    if score >= 55:
        flux_type = "double_flux" if features.get("ns_churn", 0) >= 3 else "single_flux"
    confidence = "high" if score >= 75 else "medium" if score >= 45 else "low"
    return FastFluxScore(
        domain=domain,
        flux_score=score,
        flux_type=flux_type,
        flux_confidence=confidence,
        reason_codes=reasons,
    )
