from __future__ import annotations

import json
from pathlib import Path

from dnsintel.utils.time import iso_now

STATS_START = "<!-- DNSINTEL_STATS_START -->"
STATS_END = "<!-- DNSINTEL_STATS_END -->"


def count_list_file(path: Path) -> int:
    if not path.exists():
        return 0
    return len(
        [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    )


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    return len([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()])


def collect_dataset_stats(data_dir: Path) -> dict[str, int | str]:
    lists = data_dir / "lists"
    normalized = data_dir / "normalized"
    enriched = data_dir / "enriched"
    reports = data_dir / "reports"
    stats: dict[str, int | str] = {
        "generated_at": iso_now(),
        "malicious_domains": count_list_file(lists / "malicious-domains.txt"),
        "phishing_domains": count_list_file(lists / "phishing-domains.txt"),
        "malware_domains": count_list_file(lists / "malware-domains.txt"),
        "c2_domains": count_list_file(lists / "c2-domains.txt"),
        "malicious_urls": count_list_file(lists / "malicious-urls.txt"),
        "adguard_rules": count_list_file(lists / "adguard-dns-filter.txt"),
        "dga_confirmed_domains": count_list_file(lists / "dga-confirmed-domains.txt"),
        "dga_suspected_domains": count_list_file(lists / "dga-suspected-domains.txt"),
        "fast_flux_domains": count_list_file(lists / "fast-flux-domains.txt"),
        "double_flux_domains": count_list_file(lists / "double-flux-domains.txt"),
        "open_resolvers": count_list_file(lists / "open-resolvers.txt"),
        "dns_amplification_risk_resolvers": count_list_file(
            lists / "dns-amplification-risk-resolvers.txt"
        ),
        "normalized_domain_records": count_jsonl(normalized / "domains.jsonl"),
        "normalized_url_records": count_jsonl(normalized / "urls.jsonl"),
        "enriched_files": len(list(enriched.glob("*"))),
        "reports": len(list(reports.glob("*.md"))),
    }
    return stats


def render_stats_markdown(stats: dict[str, int | str]) -> str:
    rows = [
        ("Malicious domains", "malicious_domains"),
        ("Phishing domains", "phishing_domains"),
        ("Malware domains", "malware_domains"),
        ("C2 domains", "c2_domains"),
        ("Malicious URLs", "malicious_urls"),
        ("AdGuard DNS rules", "adguard_rules"),
        ("DGA confirmed domains", "dga_confirmed_domains"),
        ("DGA suspected domains", "dga_suspected_domains"),
        ("Fast-flux domains", "fast_flux_domains"),
        ("Double-flux domains", "double_flux_domains"),
        ("Open resolvers", "open_resolvers"),
        ("DNS amplification-risk resolvers", "dns_amplification_risk_resolvers"),
        ("Normalized domain records", "normalized_domain_records"),
        ("Normalized URL records", "normalized_url_records"),
        ("Enriched files", "enriched_files"),
        ("Reports", "reports"),
    ]
    lines = [
        f"_Generated: `{stats['generated_at']}`_",
        "",
        "| Dataset metric | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {label} | {stats[key]} |" for label, key in rows)
    return "\n".join(lines) + "\n"


def write_stats(data_dir: Path) -> dict[str, int | str]:
    stats = collect_dataset_stats(data_dir)
    dashboard_dir = data_dir / "dashboard"
    reports_dir = data_dir / "reports"
    dashboard_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    (dashboard_dir / "dataset-stats.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8"
    )
    (reports_dir / "dataset-stats.md").write_text(render_stats_markdown(stats), encoding="utf-8")
    return stats


def update_readme_stats(readme_path: Path, stats: dict[str, int | str]) -> None:
    block = f"{STATS_START}\n{render_stats_markdown(stats)}{STATS_END}"
    text = readme_path.read_text(encoding="utf-8")
    if STATS_START not in text or STATS_END not in text:
        text = text.rstrip() + "\n\n## Dataset Stats\n\n" + block + "\n"
    else:
        before, rest = text.split(STATS_START, 1)
        _, after = rest.split(STATS_END, 1)
        text = before + block + after
    readme_path.write_text(text, encoding="utf-8")
