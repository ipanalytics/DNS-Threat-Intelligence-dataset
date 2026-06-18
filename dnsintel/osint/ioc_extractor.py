from __future__ import annotations

import re

from dnsintel.normalize.urls import defang_to_url

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\[\.\]|[a-zA-Z0-9-]+\.)(?:[a-zA-Z0-9-]+\.)*[a-zA-Z]{2,}\b"
)
URL_RE = re.compile(r"hxxps?://[^\s'\"<>]+|https?://[^\s'\"<>]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
FALSE_POSITIVE_DOMAINS = {"example.com", "example.org", "test.com", "localhost"}


def extract_iocs(text: str) -> dict[str, list[str]]:
    refanged = defang_to_url(text)
    domains = {match.group(0).replace("[.]", ".") for match in DOMAIN_RE.finditer(text)}
    domains |= {item.split("/")[2].split(":")[0] for item in URL_RE.findall(refanged)}
    domains = {domain.lower() for domain in domains if domain.lower() not in FALSE_POSITIVE_DOMAINS}
    return {
        "domains": sorted(domains),
        "urls": sorted(set(URL_RE.findall(refanged))),
        "ips": sorted(set(IP_RE.findall(refanged))),
        "hashes": sorted(set(HASH_RE.findall(refanged))),
        "cves": sorted({item.upper() for item in CVE_RE.findall(refanged)}),
    }
