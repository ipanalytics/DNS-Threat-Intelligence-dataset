from __future__ import annotations

from dnsintel.models import ResolverRisk
from dnsintel.normalize.ips import is_public_ip


def classify_resolver(
    ip: str, amplification_score: float = 0, malicious: bool = False
) -> ResolverRisk:
    if not is_public_ip(ip):
        raise ValueError("resolver risk requires a public IP")
    if malicious:
        return ResolverRisk(
            ip=ip,
            resolver_type="malicious_resolver",
            amplification_risk_score=amplification_score,
            recommended_action="block_as_resolver",
        )
    if amplification_score >= 70:
        return ResolverRisk(
            ip=ip,
            resolver_type="amplification_risk",
            amplification_risk_score=amplification_score,
            recommended_action="report_to_abuse_contact",
        )
    if amplification_score > 0:
        return ResolverRisk(
            ip=ip,
            resolver_type="open_resolver",
            amplification_risk_score=amplification_score,
            recommended_action="monitor",
        )
    return ResolverRisk(ip=ip, resolver_type="unknown", recommended_action="do_not_block")
