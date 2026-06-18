from __future__ import annotations

FORBIDDEN_TERMS = {
    "password",
    "credential",
    "secret",
    "token",
    "apikey",
    "private_key",
    "stealer log",
}


def validate_public_ioc_query(query: str) -> str:
    lowered = query.lower()
    if any(term in lowered for term in FORBIDDEN_TERMS):
        raise ValueError("credential or secret hunting queries are not allowed")
    if not any(
        term in lowered
        for term in ("ioc", "c2", "phishing", "malware", "yara", "sigma", "misp", "ransomware")
    ):
        raise ValueError("query must target public IOC or security report context")
    return query
