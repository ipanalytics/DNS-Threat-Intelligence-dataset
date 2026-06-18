from __future__ import annotations

from dnsintel.dns.resolver import DNSRecord, SafeResolver


def snapshot_domain(domain: str, resolver: SafeResolver | None = None) -> list[DNSRecord]:
    safe_resolver = resolver or SafeResolver()
    records: list[DNSRecord] = []
    for record_type in ("A", "AAAA", "NS", "MX", "CNAME", "TXT", "SOA"):
        records.extend(safe_resolver.resolve(domain, record_type))
    return records
