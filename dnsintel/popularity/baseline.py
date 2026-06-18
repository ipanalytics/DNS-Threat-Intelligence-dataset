from __future__ import annotations

POPULAR_FIXTURES = {"google.com": 30, "microsoft.com": 30, "cloudflare.com": 30, "github.com": 25}


def benign_popularity_score(domain: str) -> float:
    return float(POPULAR_FIXTURES.get(domain.lower(), 0))
