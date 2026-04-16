from __future__ import annotations

from typing import Any, Iterable, Mapping

VALID_CATEGORIES = {"backend", "security", "observability"}
VALID_DETECTOR_TYPES = {"pattern", "pattern_context", "absence_heuristic", "block_summary", "custom"}
VALID_CONFIDENCE_LEVELS = {"low", "medium", "high"}
VALID_SEVERITIES = {"info", "warn", "error"}


class SignalValidationError(ValueError):
    pass


def _require(value: Mapping[str, Any], key: str) -> Any:
    if key not in value:
        raise SignalValidationError(f"Signal is missing required field: {key}")
    return value[key]


def validate_severity_map(severity_map: Mapping[str, Any]) -> None:
    missing = VALID_CONFIDENCE_LEVELS - set(severity_map)
    if missing:
        raise SignalValidationError(f"severity_map missing keys: {', '.join(sorted(missing))}")
    invalid = {str(v) for v in severity_map.values()} - VALID_SEVERITIES
    if invalid:
        raise SignalValidationError(f"severity_map contains invalid severities: {', '.join(sorted(invalid))}")


def validate_template_params(detector_type: str, params: Mapping[str, Any]) -> None:
    if detector_type in {"pattern", "pattern_context", "block_summary"}:
        triggers = params.get("triggers") or params.get("patterns") or []
        if not isinstance(triggers, list) or not triggers:
            raise SignalValidationError(f"{detector_type} detector requires non-empty params.triggers")
    if detector_type == "absence_heuristic":
        presence = params.get("presence_markers") or params.get("patterns") or []
        if not isinstance(presence, list) or not presence:
            raise SignalValidationError("absence_heuristic detector requires non-empty params.presence_markers")
        expected_absent = params.get("expected_absent") or []
        if not isinstance(expected_absent, list):
            raise SignalValidationError("absence_heuristic params.expected_absent must be a list")


def validate_signal_dict(data: Mapping[str, Any]) -> None:
    signal_id = _require(data, "signal_id")
    category = _require(data, "category")
    detector_type = _require(data, "detector_type")
    _require(data, "title")
    _require(data, "description")
    _require(data, "targets")
    _require(data, "base_confidence")
    severity_map = _require(data, "severity_map")
    _require(data, "message")
    _require(data, "remediation")

    if not isinstance(signal_id, str) or not signal_id.strip():
        raise SignalValidationError("signal_id must be a non-empty string")
    if category not in VALID_CATEGORIES:
        raise SignalValidationError(f"Invalid category: {category}")
    if detector_type not in VALID_DETECTOR_TYPES:
        raise SignalValidationError(f"Invalid detector_type: {detector_type}")
    validate_severity_map(severity_map)

    params = data.get("params") or {}
    if detector_type == "custom":
        if not data.get("custom_detector"):
            raise SignalValidationError("custom detector requires custom_detector field")
    else:
        validate_template_params(detector_type, params)


def validate_unique_ids(items: Iterable[Mapping[str, Any]]) -> None:
    seen: set[str] = set()
    for item in items:
        signal_id = str(item.get("signal_id"))
        if signal_id in seen:
            raise SignalValidationError(f"Duplicate signal_id: {signal_id}")
        seen.add(signal_id)
