from __future__ import annotations

from pathlib import Path

from dnsintel.export.csv import write_csv
from dnsintel.export.plain import write_plain_list
from dnsintel.flux.reporting import render_flux_report
from dnsintel.flux.score import score_flux
from dnsintel.models import DomainIndicator, Evidence, URLIndicator
from dnsintel.normalize import (
    etld1,
    extract_domain,
    is_public_ip,
    normalize_domain,
    normalize_ip,
    normalize_url,
)
from dnsintel.scoring import score_domain
from dnsintel.sources import SourceResult, build_adapters
from dnsintel.stats import write_stats
from dnsintel.storage.jsonl_store import write_jsonl
from dnsintel.utils.time import iso_now


def evidence_to_indicators(
    evidence_records: list[Evidence],
) -> tuple[list[DomainIndicator], list[URLIndicator]]:
    by_domain: dict[str, DomainIndicator] = {}
    urls: list[URLIndicator] = []
    for ev in evidence_records:
        if ev.indicator_type == "url":
            try:
                url = normalize_url(ev.value)
                domain = extract_domain(url)
            except ValueError:
                continue
            urls.append(
                URLIndicator(
                    url=url,
                    domain=domain,
                    category=ev.category,
                    sources=[ev.source_name],
                    evidence=[ev],
                    score=ev.confidence,
                    recommended_action="block_url" if ev.confidence >= 70 else "monitor",
                )
            )
        elif ev.indicator_type == "domain":
            try:
                domain = normalize_domain(ev.value)
            except ValueError:
                continue
            current = by_domain.get(domain)
            if current is None:
                current = DomainIndicator(domain=domain, etld1=etld1(domain))
                by_domain[domain] = current
            current.category = sorted(set(current.category + ev.category))
            current.sources = sorted(set(current.sources + [ev.source_name]))
            current.evidence.append(ev)
    return [score_domain(item) for item in by_domain.values()], urls


def evidence_to_ips(evidence_records: list[Evidence]) -> list[str]:
    ips: set[str] = set()
    for ev in evidence_records:
        if ev.indicator_type != "ip":
            continue
        try:
            ip = normalize_ip(ev.value.split(":", 1)[0])
        except ValueError:
            continue
        if is_public_ip(ip):
            ips.add(ip)
    return sorted(ips)


def evidence_to_resolvers(evidence_records: list[Evidence]) -> list[str]:
    resolvers: set[str] = set()
    for ev in evidence_records:
        if ev.indicator_type != "resolver":
            continue
        try:
            ip = normalize_ip(ev.value)
        except ValueError:
            continue
        if is_public_ip(ip):
            resolvers.add(ip)
    return sorted(resolvers)


def source_summary(
    results: list[SourceResult],
    domains: list[DomainIndicator],
    urls: list[URLIndicator],
    ips: list[str],
    resolvers: list[str],
) -> list[dict[str, object]]:
    rows = []
    domain_sources = {domain.domain: set(domain.sources) for domain in domains}
    url_sources = {url.url: set(url.sources) for url in urls}
    ip_sources: dict[str, set[str]] = {}
    resolver_sources: dict[str, set[str]] = {}
    for result in results:
        for ev in result.evidence:
            if ev.indicator_type not in {"ip", "resolver"}:
                continue
            try:
                ip = normalize_ip(
                    ev.value.split(":", 1)[0] if ev.indicator_type == "ip" else ev.value
                )
            except ValueError:
                continue
            if ev.indicator_type == "ip":
                ip_sources.setdefault(ip, set()).add(result.name)
            else:
                resolver_sources.setdefault(ip, set()).add(result.name)

    for result in results:
        rows.append(
            {
                "source": result.name,
                "evidence_records": len(result.evidence),
                "domain_records": sum(
                    1 for domain, sources in domain_sources.items() if result.name in sources
                ),
                "url_records": sum(
                    1 for url, sources in url_sources.items() if result.name in sources
                ),
                "ip_records": sum(1 for ip in ips if result.name in ip_sources.get(ip, set())),
                "resolver_records": sum(
                    1 for ip in resolvers if result.name in resolver_sources.get(ip, set())
                ),
                "status": "skipped" if result.skipped else "ok",
                "reason": result.reason or "",
            }
        )
    return rows


def generate_dataset(
    output: Path, live: bool = False, limit_per_source: int | None = None
) -> dict[str, int]:
    output.mkdir(parents=True, exist_ok=True)
    results: list[SourceResult] = []
    for adapter in build_adapters():
        try:
            results.append(adapter.collect(live=live, limit=limit_per_source))
        except Exception as exc:  # pragma: no cover - defensive boundary for live feeds
            results.append(
                SourceResult(
                    name=getattr(adapter, "name", adapter.__class__.__name__),
                    skipped=True,
                    reason=f"collector error: {exc.__class__.__name__}: {exc}",
                )
            )
    evidence_records = [item for result in results for item in result.evidence]
    domains, urls = evidence_to_indicators(evidence_records)
    ips = evidence_to_ips(evidence_records)
    resolvers = evidence_to_resolvers(evidence_records)
    if live and any(result.name == "public-dns-info" for result in results) and not resolvers:
        public_dns = next(result for result in results if result.name == "public-dns-info")
        raise RuntimeError(
            "public-dns-info produced no open resolver records: "
            f"{public_dns.reason or 'empty live feed'}"
        )
    if live and not domains and not urls and not ips and not resolvers:
        skipped = [f"{result.name}: {result.reason or 'empty'}" for result in results]
        detail = "; ".join(skipped) if skipped else "no source output"
        raise RuntimeError(
            f"live mode produced no domain, URL, IP, or resolver indicators: {detail}"
        )

    write_jsonl(output / "normalized" / "domains.jsonl", domains)
    write_jsonl(output / "normalized" / "urls.jsonl", urls)
    write_csv(output / "normalized" / "domains.csv", [d.model_dump(mode="json") for d in domains])

    write_plain_list(
        output / "lists" / "malicious-domains.txt", [d.domain for d in domains], "malicious domains"
    )
    write_plain_list(
        output / "lists" / "phishing-domains.txt",
        [u.domain for u in urls if "phishing" in u.category],
        "phishing domains",
    )
    write_plain_list(
        output / "lists" / "malware-domains.txt",
        [d.domain for d in domains if "malware" in d.category],
        "malware domains",
    )
    write_plain_list(
        output / "lists" / "c2-domains.txt",
        [d.domain for d in domains if "c2" in d.category],
        "C2 domains",
    )
    write_plain_list(
        output / "lists" / "malicious-urls.txt", [u.url for u in urls], "malicious URLs"
    )
    write_plain_list(output / "lists" / "malicious-ips.txt", ips, "malicious IPs")
    write_plain_list(output / "lists" / "open-resolvers.txt", resolvers, "open resolvers")
    write_plain_list(
        output / "lists" / "c2-ips.txt",
        [
            ip
            for ip in ips
            if any(ev.value == ip and "c2" in ev.category for ev in evidence_records)
        ],
        "C2 IPs",
    )
    adguard_domains = sorted({d.domain for d in domains} | {u.domain for u in urls})
    write_plain_list(
        output / "lists" / "adguard-dns-filter.txt",
        [f"||{domain}^" for domain in adguard_domains],
        "AdGuard DNS filter rules generated from DNS threat intelligence indicators",
    )

    skipped = [result for result in results if result.skipped or result.reason]
    report = [
        "# Update Summary",
        "",
        f"- generated_at: {iso_now()}",
        f"- mode: {'live' if live else 'sample'}",
        f"- sources_seen: {len(results)}",
        f"- evidence_records: {len(evidence_records)}",
        f"- domains: {len(domains)}",
        f"- urls: {len(urls)}",
        f"- ips: {len(ips)}",
        f"- open_resolvers: {len(resolvers)}",
    ]
    if skipped:
        report.extend(["", "## Skipped Or Empty Sources"])
        report.extend(f"- {result.name}: {result.reason or 'empty'}" for result in skipped)
    report.extend(
        [
            "",
            "## Source Summary",
            "",
            "| Source | Evidence | Domains | URLs | IPs | Resolvers | Status | Reason |",
            "|---|---:|---:|---:|---:|---:|---|---|",
        ]
    )
    summary_rows = source_summary(results, domains, urls, ips, resolvers)
    report.extend(
        "| {source} | {evidence_records} | {domain_records} | {url_records} | "
        "{ip_records} | {resolver_records} | {status} | {reason} |".format(**row)
        for row in summary_rows
    )
    (output / "reports").mkdir(parents=True, exist_ok=True)
    (output / "reports" / "update-summary.md").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    write_csv(output / "enriched" / "source-summary.csv", summary_rows)
    generate_enrichment_outputs(output, domains=domains, live=live)
    write_stats(output)
    return {
        "evidence": len(evidence_records),
        "domains": len(domains),
        "urls": len(urls),
        "ips": len(ips),
        "resolvers": len(resolvers),
    }


def generate_sample_dataset(output: Path) -> dict[str, int]:
    return generate_dataset(output, live=False)


def generate_enrichment_outputs(
    output: Path, domains: list[DomainIndicator] | None = None, live: bool = False
) -> None:
    enriched = output / "enriched"
    reports = output / "reports"
    lists = output / "lists"
    enriched.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    lists.mkdir(parents=True, exist_ok=True)

    if live:
        for path in [
            enriched / "asn-abuse-summary.csv",
            enriched / "certificate-links.csv",
            enriched / "ct-candidates.csv",
            enriched / "domain-ip-links.csv",
            enriched / "domain-risk-features.csv",
            enriched / "fast-flux-domains.jsonl",
            enriched / "fast-flux-features.csv",
            enriched / "ip-asn-enrichment.csv",
            enriched / "public-malware-report-iocs.csv",
            enriched / "public-malware-report-iocs.jsonl",
            enriched / "public-osint-evidence.csv",
            enriched / "resolver-risk.csv",
            lists / "ct-brand-impersonation-candidates.txt",
            lists / "ct-suspicious-domains.txt",
            lists / "dga-confirmed-domains.txt",
            lists / "dga-suspected-domains.txt",
            lists / "dns-amplification-risk-resolvers.txt",
            lists / "double-flux-domains.txt",
            lists / "fast-flux-domains.txt",
            lists / "newly-registered-risk-domains.txt",
            reports / "ct-early-warning-report.md",
            reports / "dga-risk-report.md",
            reports / "fast-flux-report.md",
            reports / "nrd-risk-report.md",
            reports / "public-malware-report-summary.md",
            reports / "public-osint-report.md",
            reports / "resolver-abuse-report.md",
            reports / "top-flux-asns.md",
            reports / "top-malicious-asns.md",
            reports / "top-malicious-prefixes.md",
            reports / "top-open-resolver-asns.md",
        ]:
            path.unlink(missing_ok=True)
        return

    domain_ip_links = [
        {
            "domain": "c2-control.evil",
            "ip": "203.0.113.50",
            "record_type": "A",
            "ttl": 120,
            "resolver": "fixture",
            "asn": 64550,
            "bgp_prefix": "203.0.113.0/24",
            "country": "ZZ",
        },
        {
            "domain": "login-paypal-security.example.net",
            "ip": "198.51.100.10",
            "record_type": "A",
            "ttl": 300,
            "resolver": "fixture",
            "asn": 64501,
            "bgp_prefix": "198.51.100.0/24",
            "country": "US",
        },
    ]
    ip_asn = [
        {
            "ip": "203.0.113.50",
            "asn": 64550,
            "as_name": "Fixture Threat Network",
            "bgp_prefix": "203.0.113.0/24",
            "country": "ZZ",
            "shared_infrastructure_hint": False,
        },
        {
            "ip": "198.51.100.10",
            "asn": 64501,
            "as_name": "Fixture CDN",
            "bgp_prefix": "198.51.100.0/24",
            "country": "US",
            "shared_infrastructure_hint": True,
        },
    ]
    write_csv(enriched / "domain-ip-links.csv", domain_ip_links)
    write_csv(enriched / "ip-asn-enrichment.csv", ip_asn)
    write_csv(
        enriched / "asn-abuse-summary.csv",
        [{"asn": 64550, "domains": 1, "recommended_action": "monitor"}],
    )
    write_plain_list(
        lists / "dga-confirmed-domains.txt", ["confirmed-dga.bad"], "confirmed DGA domains"
    )
    write_plain_list(
        lists / "dga-suspected-domains.txt", ["xj29abqplm77.bad"], "suspected DGA domains"
    )
    write_plain_list(
        lists / "newly-registered-risk-domains.txt", ["fresh-wallet-login.bad"], "NRD risk domains"
    )
    write_plain_list(
        lists / "ct-suspicious-domains.txt",
        ["login-paypal-security.example.net"],
        "CT suspicious domains",
    )
    write_csv(
        enriched / "domain-risk-features.csv",
        [{"domain": "xj29abqplm77.bad", "dga_score": 75, "nrd": True}],
    )
    write_csv(
        enriched / "certificate-links.csv",
        [
            {
                "domain": "login-paypal-security.example.net",
                "issuer": "Fixture CA",
                "recommended_action": "needs_review",
            }
        ],
    )

    flux_score = score_flux(
        "flux.bad",
        {"unique_ips": 8, "unique_asns": 4, "unique_countries": 4, "ttl_min": 120, "ns_churn": 3},
    )
    write_plain_list(lists / "fast-flux-domains.txt", ["flux.bad"], "fast flux domains")
    write_plain_list(lists / "double-flux-domains.txt", ["flux.bad"], "double flux domains")
    write_csv(
        enriched / "fast-flux-features.csv",
        [{"domain": "flux.bad", "unique_ips": 8, "unique_asns": 4, "ttl_min": 120, "ns_churn": 3}],
    )
    write_jsonl(enriched / "fast-flux-domains.jsonl", [flux_score])

    write_plain_list(lists / "open-resolvers.txt", ["8.8.8.8"], "open resolver fixtures")
    write_plain_list(
        lists / "dns-amplification-risk-resolvers.txt",
        ["9.9.9.9"],
        "DNS amplification risk fixtures",
    )
    write_csv(
        enriched / "resolver-risk.csv",
        [
            {
                "ip": "9.9.9.9",
                "resolver_type": "amplification_risk",
                "recommended_action": "report_to_abuse_contact",
            }
        ],
    )

    write_plain_list(
        lists / "ct-brand-impersonation-candidates.txt",
        ["login-paypal-security.example.net"],
        "CT brand candidates",
    )
    write_csv(
        enriched / "ct-candidates.csv",
        [
            {
                "domain": "login-paypal-security.example.net",
                "brand": "paypal",
                "recommended_action": "needs_review",
            }
        ],
    )
    write_csv(
        enriched / "public-osint-evidence.csv",
        [
            {
                "indicator": "c2-control.evil",
                "platform": "github",
                "matched_terms": "IOC,C2",
                "confidence": 45,
            }
        ],
    )
    write_csv(
        enriched / "public-malware-report-iocs.csv",
        [
            {
                "indicator": "malware-download.bad",
                "indicator_type": "domain",
                "source_name": "Fixture Report",
            }
        ],
    )
    write_jsonl(
        enriched / "public-malware-report-iocs.jsonl",
        [
            {
                "indicator": "malware-download.bad",
                "indicator_type": "domain",
                "source_name": "Fixture Report",
            }
        ],
    )

    (reports / "top-malicious-asns.md").write_text(
        "# Top Malicious ASNs\n\n- AS64550 Fixture Threat Network: 1 domain\n", encoding="utf-8"
    )
    (reports / "top-malicious-prefixes.md").write_text(
        "# Top Malicious Prefixes\n\n- 203.0.113.0/24: 1 domain\n", encoding="utf-8"
    )
    (reports / "nrd-risk-report.md").write_text(
        "# NRD Risk Report\n\nNRD is treated as risk context only.\n", encoding="utf-8"
    )
    (reports / "dga-risk-report.md").write_text(
        "# DGA Risk Report\n\nConfirmed and suspected DGA domains are separated.\n",
        encoding="utf-8",
    )
    (reports / "fast-flux-report.md").write_text(render_flux_report([flux_score]), encoding="utf-8")
    (reports / "top-flux-asns.md").write_text(
        "# Top Flux ASNs\n\n- AS64550: fixture flux activity\n", encoding="utf-8"
    )
    (reports / "resolver-abuse-report.md").write_text(
        "# Resolver Abuse Report\n\nNo internet-wide scanning is performed.\n", encoding="utf-8"
    )
    (reports / "top-open-resolver-asns.md").write_text(
        "# Top Open Resolver ASNs\n\n- Fixture data only.\n", encoding="utf-8"
    )
    (reports / "ct-early-warning-report.md").write_text(
        "# CT Early Warning Report\n\nCT candidates require review without corroboration.\n",
        encoding="utf-8",
    )
    (reports / "public-osint-report.md").write_text(
        "# Public OSINT Report\n\nOnly public IOC/security-report contexts are allowed.\n",
        encoding="utf-8",
    )
    (reports / "public-malware-report-summary.md").write_text(
        "# Public Malware Report Summary\n\nStores metadata, IOC, and short snippets only.\n",
        encoding="utf-8",
    )
