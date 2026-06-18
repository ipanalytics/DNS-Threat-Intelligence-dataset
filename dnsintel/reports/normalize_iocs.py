from __future__ import annotations

from dnsintel.osint.ioc_extractor import extract_iocs


def normalize_report_text(text: str) -> dict[str, list[str]]:
    return extract_iocs(text)
