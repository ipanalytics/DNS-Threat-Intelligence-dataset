from __future__ import annotations

from dnsintel.utils.hashing import stable_id


def report_id(source_name: str, source_url: str) -> str:
    return stable_id(source_name, source_url)
