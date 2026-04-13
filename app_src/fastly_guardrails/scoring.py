from __future__ import annotations
from typing import Dict, List, Tuple

from .utils import clamp, confidence_level


def score_to_level(score: float) -> str:
    return confidence_level(score)


def level_to_severity(severity_map: Dict[str, str], level: str) -> str:
    return severity_map.get(level, "info")


def finalize_score(base: float, increments: List[float], decrements: List[float]) -> Tuple[float, str]:
    score = base + sum(increments) - sum(decrements)
    score = clamp(score)
    return score, score_to_level(score)
