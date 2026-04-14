from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..models import Signal
from .validation import validate_signal_dict, validate_unique_ids

DEFAULT_CUSTOM_DETECTORS = {
    "SEC001": "sec001",
    "SEC002": "sec002",
    "SEC005": "sec005",
}


def _normalize_signal(data: Dict[str, Any]) -> Dict[str, Any]:
    params = dict(data.get("params") or {})
    params.setdefault("patterns", list(data.get("patterns") or []))
    params.setdefault("boosters", list(data.get("boosters") or []))
    params.setdefault("suppressors", list(data.get("suppressors") or []))

    detector_type = data.get("detector_type") or "pattern_context"
    if detector_type == "absence_heuristic":
        params.setdefault("presence_markers", list(data.get("patterns") or []))
        params.setdefault("expected_absent", [])
    else:
        params.setdefault("triggers", list(data.get("patterns") or []))

    if data.get("signal_id") == "BKG002" and not params.get("triggers"):
        params["triggers"] = ["address", "hostname", "host"]

    if data.get("signal_id") in DEFAULT_CUSTOM_DETECTORS:
        detector_type = "custom"
        data.setdefault("custom_detector", DEFAULT_CUSTOM_DETECTORS[data["signal_id"]])

    normalized = dict(data)
    normalized["detector_type"] = detector_type
    normalized["params"] = params
    return normalized


def load_signals() -> List[Signal]:
    data_path = Path(__file__).resolve().parents[1] / "data" / "signals.json"
    raw = json.loads(data_path.read_text())
    normalized = [_normalize_signal(item) for item in raw]
    validate_unique_ids(normalized)
    for item in normalized:
        validate_signal_dict(item)
    return [Signal(**item) for item in normalized]
