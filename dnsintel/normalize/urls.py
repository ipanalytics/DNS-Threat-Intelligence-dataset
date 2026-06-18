from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from dnsintel.normalize.domains import normalize_domain


def defang_to_url(value: str) -> str:
    cleaned = (
        value.strip()
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
    )
    return cleaned


def normalize_url(value: str) -> str:
    refanged = defang_to_url(value)
    parsed = urlsplit(refanged)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"unsupported URL: {value}")
    host = normalize_domain(parsed.hostname or "")
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def extract_domain(value: str) -> str:
    parsed = urlsplit(defang_to_url(value))
    if not parsed.hostname:
        raise ValueError(f"URL has no hostname: {value}")
    return normalize_domain(parsed.hostname)
