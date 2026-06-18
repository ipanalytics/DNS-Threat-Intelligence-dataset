from __future__ import annotations

from dnsintel.models import DomainIndicator, DomainIPLink


def build_evidence_graph(
    domains: list[DomainIndicator], links: list[DomainIPLink]
) -> dict[str, list[dict]]:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for domain in domains:
        nodes[f"domain:{domain.domain}"] = {
            "id": f"domain:{domain.domain}",
            "type": "domain",
            "score": domain.score,
        }
        for ev in domain.evidence:
            evidence_id = f"evidence:{ev.source_name}:{ev.value}"
            nodes[evidence_id] = {"id": evidence_id, "type": "evidence", "source": ev.source_name}
            edges.append(
                {"source": f"domain:{domain.domain}", "target": evidence_id, "type": "has_evidence"}
            )
    for link in links:
        domain_id = f"domain:{link.domain}"
        ip_id = f"ip:{link.ip}"
        nodes.setdefault(ip_id, {"id": ip_id, "type": "ip", "asn": link.asn})
        edges.append({"source": domain_id, "target": ip_id, "type": "resolves_to"})
    return {"nodes": list(nodes.values()), "edges": edges}
