from __future__ import annotations

from pathlib import Path


def write_plain_list(path: Path, values: list[str], header: str | None = None) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted(set(values))
    with path.open("w", encoding="utf-8") as handle:
        if header:
            handle.write(f"# {header}\n")
        for value in unique:
            handle.write(f"{value}\n")
    return len(unique)
