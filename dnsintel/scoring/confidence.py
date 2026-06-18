from __future__ import annotations

from dnsintel.models import DomainIndicator

HIGH_VALUE_CATEGORIES = {"c2", "malware", "phishing", "confirmed_dga_domain"}
WEAK_ONLY = {"ct_candidate", "nrd", "suspected_dga_domain", "public_osint"}


def score_domain(indicator: DomainIndicator, popularity_score: float = 0) -> DomainIndicator:
    evidence_score = sum(item.confidence for item in indicator.evidence)
    category_bonus = 25 if HIGH_VALUE_CATEGORIES.intersection(indicator.category) else 0
    weak_only = set(indicator.category).issubset(WEAK_ONLY) if indicator.category else False
    penalty = 35 if indicator.shared_infrastructure_hint else 0
    penalty += min(popularity_score, 30)
    score = max(
        0, min(100, evidence_score / max(len(indicator.evidence), 1) + category_bonus - penalty)
    )
    indicator.score = round(score, 2)
    if score >= 90:
        indicator.confidence = "critical"
    elif score >= 70:
        indicator.confidence = "high"
    elif score >= 45:
        indicator.confidence = "medium"
    else:
        indicator.confidence = "low"
    if indicator.shared_infrastructure_hint:
        indicator.recommended_action = "do_not_block_shared_infra"
    elif weak_only:
        indicator.recommended_action = "needs_review"
    elif score >= 70:
        indicator.recommended_action = "block_domain"
    elif score >= 20:
        indicator.recommended_action = "monitor"
    else:
        indicator.recommended_action = "needs_review"
    return indicator
