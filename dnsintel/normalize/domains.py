from __future__ import annotations

import re

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
COMMON_MULTI_SUFFIXES = {"co.uk", "com.au", "co.jp", "com.br", "com.tr", "co.in"}


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    if not domain:
        raise ValueError("empty domain")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDN domain: {value}") from exc
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"invalid domain: {value}")
    return domain


def etld1(domain: str) -> str | None:
    normalized = normalize_domain(domain)
    parts = normalized.split(".")
    if len(parts) < 2:
        return None
    suffix2 = ".".join(parts[-2:])
    suffix3 = ".".join(parts[-3:])
    if suffix2 in COMMON_MULTI_SUFFIXES and len(parts) >= 3:
        return suffix3
    return suffix2
