from __future__ import annotations


def fixture_rdap(ip: str) -> dict[str, object]:
    return {
        "ip": ip,
        "rir": "TEST",
        "org": "Fixture Network",
        "abuse_emails": ["abuse@example.net"],
    }
