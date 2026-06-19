from __future__ import annotations

from dnsintel.models import Evidence


def evidence(
    source: str,
    indicator_type: str,
    value: str,
    category: list[str],
    confidence: float,
    **raw: object,
) -> Evidence:
    source_type = raw.pop("source_type", "fixture")
    return Evidence(
        source_name=source,
        source_type=source_type if isinstance(source_type, str) else "fixture",
        indicator_type=indicator_type,  # type: ignore[arg-type]
        value=value,
        category=category,
        tags=list(raw.get("tags", [])) if isinstance(raw.get("tags", []), list) else [],
        confidence=confidence,
        reference_url=raw.get("reference_url")
        if isinstance(raw.get("reference_url"), str)
        else None,
        raw=raw or None,
    )
