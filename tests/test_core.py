from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from dnsintel.cli import app
from dnsintel.config import validate_config_dir
from dnsintel.ct.suspicious_patterns import find_ct_candidates
from dnsintel.dga import score_dga
from dnsintel.flux.score import score_flux
from dnsintel.models import DomainIndicator, Evidence
from dnsintel.normalize import extract_domain, normalize_domain, normalize_url
from dnsintel.osint.github_search import validate_public_ioc_query
from dnsintel.osint.ioc_extractor import extract_iocs
from dnsintel.pipeline import generate_sample_dataset, should_emit_adguard_dns_rule
from dnsintel.resolvers.risk import classify_resolver
from dnsintel.scoring import score_domain


def test_config_validation() -> None:
    paths = validate_config_dir(Path("configs"))
    assert len(paths) == 4


def test_domain_url_normalization() -> None:
    assert normalize_domain("ExAmPlE.COM.") == "example.com"
    assert normalize_domain("bücher.example").startswith("xn--")
    assert normalize_url("hxxp://Bad[.]Example/path") == "http://bad.example/path"
    assert extract_domain("https://Login.Example/a") == "login.example"
    with pytest.raises(ValueError):
        normalize_domain("not a domain")


def test_scoring_shared_infra_and_weak_signal() -> None:
    weak = DomainIndicator(
        domain="login-brand.example",
        category=["ct_candidate"],
        evidence=[
            Evidence(
                source_name="ct",
                source_type="fixture",
                indicator_type="domain",
                value="login-brand.example",
                category=["ct_candidate"],
                confidence=80,
            )
        ],
    )
    assert score_domain(weak).recommended_action == "needs_review"
    shared = DomainIndicator(
        domain="site.github.io",
        category=["malware"],
        shared_infrastructure_hint=True,
        evidence=[
            Evidence(
                source_name="fixture",
                source_type="fixture",
                indicator_type="domain",
                value="site.github.io",
                category=["malware"],
                confidence=95,
            )
        ],
    )
    assert score_domain(shared).recommended_action == "do_not_block_shared_infra"


def test_adguard_dns_export_excludes_shared_code_hosts() -> None:
    assert not should_emit_adguard_dns_rule("github.com")
    assert not should_emit_adguard_dns_rule("codeload.github.com")
    assert not should_emit_adguard_dns_rule("raw.githubusercontent.com")
    assert should_emit_adguard_dns_rule("malware.example.net")


def test_dga_ct_flux_and_resolver_rules() -> None:
    assert score_dga("xj29abqplm77zzzz.bad")["dga_score"] >= 40
    candidates = find_ct_candidates(["login-paypal-security.example.net"], {"paypal": ["paypal"]})
    assert candidates[0].recommended_action == "needs_review"
    flux = score_flux(
        "flux.bad",
        {"unique_ips": 8, "unique_asns": 4, "unique_countries": 4, "ttl_min": 120, "ns_churn": 3},
    )
    assert flux.flux_type == "double_flux"
    cdn = score_flux(
        "cdn.example",
        {"unique_ips": 8, "unique_asns": 4, "unique_countries": 4, "ttl_min": 120, "ns_churn": 0},
        shared_cdn=True,
    )
    assert cdn.flux_type == "none"
    with pytest.raises(ValueError):
        classify_resolver("192.168.1.1")


def test_public_osint_safety_and_ioc_extraction() -> None:
    assert validate_public_ioc_query('"example.com" "IOC"') == '"example.com" "IOC"'
    with pytest.raises(ValueError):
        validate_public_ioc_query('"password" "token"')
    iocs = extract_iocs("hxxp://malware[.]bad/a.exe CVE-2024-12345 " + "b" * 64)
    assert "malware.bad" in iocs["domains"]
    assert "CVE-2024-12345" in iocs["cves"]
    assert "b" * 64 in iocs["hashes"]


def test_sample_pipeline_and_cli(tmp_path: Path) -> None:
    counts = generate_sample_dataset(tmp_path)
    assert counts["domains"] >= 2
    assert (tmp_path / "lists" / "malicious-domains.txt").exists()
    assert (tmp_path / "enriched" / "fast-flux-features.csv").exists()
    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate"])
    assert result.exit_code == 0
