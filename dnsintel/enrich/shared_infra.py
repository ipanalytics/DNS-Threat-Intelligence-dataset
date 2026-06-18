from __future__ import annotations

SHARED_PATTERNS = (
    "cloudflare",
    "amazonaws.com",
    "azureedge.net",
    "googleusercontent.com",
    "fastly.net",
    "akamai",
    "cloudfront.net",
    "github.io",
    "vercel.app",
    "netlify.app",
)


def is_shared_infrastructure(value: str) -> bool:
    lowered = value.lower()
    return any(pattern in lowered for pattern in SHARED_PATTERNS)
