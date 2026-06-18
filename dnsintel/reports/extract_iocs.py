from __future__ import annotations

from dnsintel.osint.ioc_extractor import extract_iocs


def extract_report_iocs(text: str) -> dict[str, list[str]]:
    return extract_iocs(text)
