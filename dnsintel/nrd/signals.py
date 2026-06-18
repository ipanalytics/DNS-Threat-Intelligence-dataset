from __future__ import annotations


def nrd_signal(domain: str, age_days: int | None) -> dict[str, object]:
    if age_days is None:
        return {"domain": domain, "nrd": False, "risk_signal_only": True}
    return {"domain": domain, "nrd": age_days <= 30, "risk_signal_only": True}
