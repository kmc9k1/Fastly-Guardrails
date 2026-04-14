from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .wizard import DetectorSpec


def planned_paths(project_root: Path, spec: DetectorSpec) -> List[Path]:
    ext = "tf" if "terraform" in spec.targets else "vcl"
    generated = project_root / "tests" / "fixtures" / "generated"
    paths: List[Path] = [project_root / "fastly_guardrails" / "data" / "signals.json"]
    if spec.create_positive_fixture:
        paths.append(generated / f"{spec.signal_id.lower()}_positive.{ext}")
    if spec.create_negative_fixture:
        paths.append(generated / f"{spec.signal_id.lower()}_negative.{ext}")
    if spec.create_suppressed_fixture:
        paths.append(generated / f"{spec.signal_id.lower()}_suppressed.{ext}")
    if spec.create_test_file:
        paths.append(project_root / "tests" / f"test_{spec.signal_id.lower()}.py")
    return paths


def render_preview(project_root: Path, spec: DetectorSpec) -> str:
    lines = ["Planned changes:", "", "Signal definition:", json.dumps(spec.to_signal_dict(), indent=2), "", "Files to write:"]
    for path in planned_paths(project_root, spec):
        lines.append(f"  - {path}")
    return "\n".join(lines)
