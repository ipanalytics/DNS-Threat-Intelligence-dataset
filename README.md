# DNS-Threat-Intelligence-dataset

`DNS-Threat-Intelligence-dataset` is a legal OSINT project for collecting,
normalizing, enriching, scoring, and publishing DNS threat intelligence.

The project models the chain:

```text
domain -> URL -> IPs -> ASN -> CIDR -> Geo -> RDAP -> CT -> source evidence -> score -> recommended action
```

It ships a Python CLI, source adapters, safe DNS enrichment, scoring rules,
exporters, sample datasets, reports, and a static dashboard.

## Legal And Ethical Policy

Allowed inputs are public OSINT feeds, open APIs, official reports, public
GitHub/GitLab/Gist security material, Certificate Transparency, licensed NRD
or zone-file sources when configured by the user, and user-supplied datasets.

The project must not use stolen logs, credential dumps, stealer logs, closed
forums, botnet panels, unauthorized DNS logs, private repositories, or any
source that violates terms of service. GitHub Actions must not run aggressive
internet-wide scans.

Active DNS behavior is limited to safe DNS lookups with conservative timeouts,
retry limits, caching, and rate limiting.

## False-Positive Policy

Weak signals such as CT candidates, NRD, DGA-like lexical score, or public-code
mentions default to `needs_review` unless corroborated by stronger evidence.
Shared infrastructure such as CDN, cloud hosting, Pages platforms, and global
load balancers is never recommended for broad IP/ASN/CIDR blocking by default.

## Quickstart

```bash
uv sync --all-groups
uv run dnsintel config validate
uv run dnsintel sample-data --output data
uv run dnsintel dashboard build --data-dir data --output docs/dashboard
uv run pytest
```

## Outputs

- Plain DNS blocklists for Pi-hole, AdGuard Home, Unbound/RPZ-style consumers,
  Blocky, and simple resolver tooling.
- `data/lists/adguard-dns-filter.txt` for AdGuard DNS filtering and release assets.
- CSV and JSONL for SIEM and data engineering workflows.
- Parquet/DuckDB-friendly data for analytics.
- MISP/STIX/TAXII-oriented schemas are represented by normalized evidence and
  can be extended through exporters.

## Dataset Stats

<!-- DNSINTEL_STATS_START -->
_Generated: `2026-06-18T13:43:43.609460+00:00`_

| Dataset metric | Count |
|---|---:|
| Malicious domains | 3 |
| Phishing domains | 2 |
| Malware domains | 3 |
| C2 domains | 1 |
| Malicious URLs | 3 |
| AdGuard DNS rules | 5 |
| DGA confirmed domains | 1 |
| DGA suspected domains | 1 |
| Fast-flux domains | 1 |
| Double-flux domains | 1 |
| Open resolvers | 1 |
| DNS amplification-risk resolvers | 1 |
| Normalized domain records | 3 |
| Normalized URL records | 3 |
| Enriched files | 13 |
| Reports | 13 |
<!-- DNSINTEL_STATS_END -->

## Adding A Source Adapter

Adapters subclass `dnsintel.sources.base.SourceAdapter`, implement `fetch()` or
fixture loading, and return normalized `Evidence` records. Live adapters must
support timeouts, rate limits, disabled defaults for authenticated/licensed
sources, and fixture tests.

