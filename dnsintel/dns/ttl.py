from __future__ import annotations


def ttl_stats(ttls: list[int]) -> dict[str, float | int | None]:
    if not ttls:
        return {"min": None, "median": None, "count": 0}
    values = sorted(ttls)
    mid = len(values) // 2
    median = values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2
    return {"min": values[0], "median": median, "count": len(values)}
