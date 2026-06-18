from __future__ import annotations

from dnsintel.models import IPEnrichment

FIXTURE_ASN = {
    "198.51.100.10": IPEnrichment(
        ip="198.51.100.10",
        asn=64501,
        as_name="Fixture CDN",
        bgp_prefix="198.51.100.0/24",
        country="US",
        sources=["fixture"],
    ),
    "203.0.113.50": IPEnrichment(
        ip="203.0.113.50",
        asn=64550,
        as_name="Fixture Threat Network",
        bgp_prefix="203.0.113.0/24",
        country="ZZ",
        sources=["fixture"],
    ),
}


def enrich_ip(ip: str) -> IPEnrichment:
    return FIXTURE_ASN.get(ip, IPEnrichment(ip=ip, sources=["unknown"]))
