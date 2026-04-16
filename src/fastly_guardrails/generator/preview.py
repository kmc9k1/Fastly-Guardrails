from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..runtime import workspace_generated_fixtures_dir, workspace_manifests_dir, workspace_signals_path
from .wizard import DetectorSpec


def planned_paths(spec: DetectorSpec) -> List[Path]:
    ext = "tf" if "terraform" in spec.targets else "vcl"
    paths: List[Path] = [workspace_signals_path()]
    if spec.create_positive_fixture:
        paths.append(workspace_generated_fixtures_dir() / f"{spec.signal_id.lower()}_positive.{ext}")
    if spec.create_negative_fixture:
        paths.append(workspace_generated_fixtures_dir() / f"{spec.signal_id.lower()}_negative.{ext}")
    if spec.create_suppressed_fixture:
        paths.append(workspace_generated_fixtures_dir() / f"{spec.signal_id.lower()}_suppressed.{ext}")
    paths.append(workspace_manifests_dir() / f"{spec.signal_id.lower()}.json")
    if spec.create_test_file:
        paths.append(workspace_manifests_dir().parent / f"test_{spec.signal_id.lower()}.py")
    return paths


def _summary_lines(spec: DetectorSpec) -> List[str]:
    lines = ["You are about to create:", ""]
    lines.append(f"Rule ID: {spec.signal_id}")
    lines.append(f"Purpose: {spec.title}")
    lines.append(f"Applies to: {', '.join(target.upper() for target in spec.targets)}")
    lines.append(f"Behavior: {spec.preview_behavior or spec.detector_type}")
    if spec.preview_intent:
        lines.append(f"Intent: {spec.preview_intent}")
    if spec.preview_risk_label:
        lines.append(f"Risk level: {spec.preview_risk_label} ({spec.preview_risk_explanation})")
    boosters = list(spec.params.get("boosters", []))
    suppressors = list(spec.params.get("suppressors", []))
    if boosters:
        lines.append("")
        lines.append("More suspicious when nearby text includes:")
        for item in boosters:
            lines.append(f"- {item}")
    if suppressors:
        lines.append("")
        lines.append("Usually harmless when nearby text includes:")
        for item in suppressors:
            lines.append(f"- {item}")
    lines.append("")
    lines.append("Files to write:")
    for path in planned_paths(spec):
        lines.append(f"- {path}")
    return lines


def render_preview(spec: DetectorSpec) -> str:
    lines = _summary_lines(spec)
    lines.extend([
        "",
        "Technical details:",
        json.dumps(spec.to_signal_dict(), indent=2),
    ])
    return "\n".join(lines)
