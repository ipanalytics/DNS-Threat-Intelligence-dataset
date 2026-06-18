from __future__ import annotations

import math
import re
from collections import Counter

VOWELS = set("aeiou")


def _entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value) or 1
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def score_dga(domain: str) -> dict[str, object]:
    label = domain.split(".")[0].lower()
    digits = sum(ch.isdigit() for ch in label)
    vowels = sum(ch in VOWELS for ch in label)
    hyphens = label.count("-")
    entropy = _entropy(label)
    reasons: list[str] = []
    score = 0.0
    if len(label) >= 16:
        score += 20
        reasons.append("long_label")
    if entropy >= 3.5:
        score += 25
        reasons.append("high_entropy")
    if digits / max(len(label), 1) > 0.25:
        score += 15
        reasons.append("digit_heavy")
    if vowels / max(len(label), 1) < 0.18:
        score += 15
        reasons.append("low_vowel_ratio")
    if hyphens >= 2:
        score += 10
        reasons.append("many_hyphens")
    if re.search(r"(.)\1\1", label):
        score += 10
        reasons.append("repeated_chars")
    score = min(100, score)
    confidence = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return {"dga_score": score, "dga_confidence": confidence, "dga_reason_codes": reasons}
