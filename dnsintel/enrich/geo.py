from __future__ import annotations


def fixture_geo(ip: str) -> dict[str, object]:
    return {"ip": ip, "country": "ZZ", "city": "Fixture City", "latitude": 0.0, "longitude": 0.0}
