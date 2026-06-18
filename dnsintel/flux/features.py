from __future__ import annotations

from statistics import median, pstdev


def flux_features(snapshots: list[dict]) -> dict[str, float | int]:
    ips = {item["ip"] for item in snapshots if item.get("ip")}
    asns = {item["asn"] for item in snapshots if item.get("asn") is not None}
    countries = {item["country"] for item in snapshots if item.get("country")}
    ttls = [int(item["ttl"]) for item in snapshots if item.get("ttl") is not None]
    ns_values = {item["value"] for item in snapshots if item.get("record_type") == "NS"}
    return {
        "unique_ips": len(ips),
        "unique_asns": len(asns),
        "unique_countries": len(countries),
        "ttl_min": min(ttls) if ttls else 0,
        "ttl_median": median(ttls) if ttls else 0,
        "ttl_std": pstdev(ttls) if len(ttls) > 1 else 0,
        "ns_churn": len(ns_values),
    }
