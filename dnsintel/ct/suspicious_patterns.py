from __future__ import annotations

from dnsintel.models import CTCandidate

SUSPICIOUS_KEYWORDS = {
    "login",
    "secure",
    "verify",
    "wallet",
    "support",
    "account",
    "auth",
    "mfa",
    "2fa",
    "payment",
    "invoice",
    "update",
    "reset",
    "customer",
    "helpdesk",
}


def find_ct_candidates(
    domains: list[str], brand_keywords: dict[str, list[str]]
) -> list[CTCandidate]:
    candidates: list[CTCandidate] = []
    for domain in domains:
        lowered = domain.lower()
        reasons = [f"keyword:{kw}" for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
        brand = None
        for name, keywords in brand_keywords.items():
            if any(keyword.lower() in lowered for keyword in keywords):
                brand = name
                reasons.append(f"brand:{name}")
        if reasons:
            candidates.append(
                CTCandidate(domain=domain, brand=brand, reason_codes=sorted(set(reasons)))
            )
    return candidates
