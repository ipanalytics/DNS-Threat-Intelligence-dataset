from __future__ import annotations

from dnsintel.models import FastFluxScore


def render_flux_report(scores: list[FastFluxScore]) -> str:
    lines = ["# Fast Flux Report", ""]
    for item in scores:
        reasons = ",".join(item.reason_codes)
        lines.append(f"- {item.domain}: {item.flux_type} score={item.flux_score} reasons={reasons}")
    return "\n".join(lines) + "\n"
