from __future__ import annotations

from dnsintel.normalize import normalize_domain


def normalize_san_names(names: list[str]) -> list[str]:
    normalized: list[str] = []
    for name in names:
        clean = name.removeprefix("*.").strip()
        try:
            normalized.append(normalize_domain(clean))
        except ValueError:
            continue
    return sorted(set(normalized))
