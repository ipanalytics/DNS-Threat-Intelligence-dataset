from __future__ import annotations

from dataclasses import dataclass
from time import monotonic, sleep

import dns.resolver

from dnsintel.dns.record_types import SUPPORTED_RECORD_TYPES


@dataclass(frozen=True)
class DNSRecord:
    name: str
    record_type: str
    value: str
    ttl: int | None = None


class SafeResolver:
    def __init__(
        self,
        nameserver: str = "1.1.1.1",
        timeout: float = 3,
        max_rounds: int = 2,
        rate_limit_per_second: float = 0.5,
    ) -> None:
        self.nameserver = nameserver
        self.timeout = timeout
        self.max_rounds = max_rounds
        self.rate_limit_per_second = rate_limit_per_second
        self._last_query = 0.0
        self._resolver = dns.resolver.Resolver(configure=True)
        self._resolver.nameservers = [nameserver]
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def resolve(self, domain: str, record_type: str) -> list[DNSRecord]:
        rtype = record_type.upper()
        if rtype not in SUPPORTED_RECORD_TYPES:
            raise ValueError(f"unsupported record type: {record_type}")
        elapsed = monotonic() - self._last_query
        min_interval = 1 / self.rate_limit_per_second if self.rate_limit_per_second > 0 else 0
        if elapsed < min_interval:
            sleep(min_interval - elapsed)
        self._last_query = monotonic()
        for _ in range(self.max_rounds):
            try:
                answers = self._resolver.resolve(domain, rtype)
                ttl = getattr(answers.rrset, "ttl", None)
                return [DNSRecord(domain, rtype, str(item).rstrip("."), ttl) for item in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except dns.exception.DNSException:
                continue
        return []
