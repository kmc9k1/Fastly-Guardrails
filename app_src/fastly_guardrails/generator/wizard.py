from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DetectorSpec:
    signal_id: str
    category: str
    title: str
    description: str
    message: str
    remediation: str
    detector_type: str
    targets: List[str]
    base_confidence: float
    severity_map: Dict[str, str]
    params: Dict[str, object] = field(default_factory=dict)
    create_positive_fixture: bool = True
    create_negative_fixture: bool = True
    create_suppressed_fixture: bool = False
    create_test_file: bool = True

    def to_signal_dict(self) -> Dict[str, object]:
        payload = {
            "signal_id": self.signal_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "targets": self.targets,
            "detector_type": self.detector_type,
            "base_confidence": self.base_confidence,
            "severity_map": self.severity_map,
            "message": self.message,
            "remediation": self.remediation,
            "params": self.params,
            "boosters": list(self.params.get("boosters", [])),
            "suppressors": list(self.params.get("suppressors", [])),
        }
        if self.detector_type == "absence_heuristic":
            payload["patterns"] = list(self.params.get("presence_markers", []))
        else:
            payload["patterns"] = list(self.params.get("triggers", []))
        return payload


def _prompt(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def _prompt_list(prompt: str) -> List[str]:
    raw = input(f"{prompt} (comma-separated): ").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def _prompt_bool(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def run_wizard() -> DetectorSpec:
    signal_id = _prompt("Signal ID").upper()
    category = _prompt("Category", "security")
    title = _prompt("Title")
    description = _prompt("Description")
    message = _prompt("Finding message")
    remediation = _prompt("Remediation hint")
    detector_type = _prompt("Detector type (pattern, pattern_context, absence_heuristic)", "pattern_context")
    targets = _prompt_list("Targets (terraform, vcl)") or ["vcl"]
    base_confidence = float(_prompt("Base confidence", "0.55"))
    severity_map = {
        "low": _prompt("Low severity", "info"),
        "medium": _prompt("Medium severity", "warn"),
        "high": _prompt("High severity", "error"),
    }
    params: Dict[str, object] = {
        "boosters": _prompt_list("Confidence boosters"),
        "suppressors": _prompt_list("Suppressors"),
        "radius": int(_prompt("Context radius", "5")),
        "case_insensitive": _prompt_bool("Case-insensitive matching?", True),
    }
    if detector_type == "absence_heuristic":
        params["presence_markers"] = _prompt_list("Presence markers")
        params["expected_absent"] = _prompt_list("Expected-absent markers")
    else:
        params["triggers"] = _prompt_list("Primary trigger patterns")

    return DetectorSpec(
        signal_id=signal_id,
        category=category,
        title=title,
        description=description,
        message=message,
        remediation=remediation,
        detector_type=detector_type,
        targets=targets,
        base_confidence=base_confidence,
        severity_map=severity_map,
        params=params,
        create_positive_fixture=_prompt_bool("Create positive fixture?", True),
        create_negative_fixture=_prompt_bool("Create negative fixture?", True),
        create_suppressed_fixture=_prompt_bool("Create suppressed fixture?", detector_type == "pattern_context"),
        create_test_file=_prompt_bool("Create test file?", True),
    )
