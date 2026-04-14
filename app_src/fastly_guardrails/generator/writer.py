from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from .fixture_builder import build_fixtures
from .test_builder import build_test_module
from .wizard import DetectorSpec


class GeneratorError(ValueError):
    pass


def _signals_path(project_root: Path) -> Path:
    return project_root / "fastly_guardrails" / "data" / "signals.json"


def write_detector_spec(project_root: Path, spec: DetectorSpec) -> Dict[str, Path]:
    signals_path = _signals_path(project_root)
    signals = json.loads(signals_path.read_text())
    if any(item.get("signal_id") == spec.signal_id for item in signals):
        raise GeneratorError(f"Signal ID already exists: {spec.signal_id}")
    signals.append(spec.to_signal_dict())
    signals_path.write_text(json.dumps(signals, indent=2) + "\n")

    written: Dict[str, Path] = {"signals": signals_path}
    fixture_dir = project_root / "tests" / "fixtures" / "generated"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    fixtures = build_fixtures(spec)
    ext = "tf" if "terraform" in spec.targets else "vcl"
    for name, content in fixtures.items():
        if name == "positive" and not spec.create_positive_fixture:
            continue
        if name == "negative" and not spec.create_negative_fixture:
            continue
        if name == "suppressed" and not spec.create_suppressed_fixture:
            continue
        path = fixture_dir / f"{spec.signal_id.lower()}_{name}.{ext}"
        path.write_text(content)
        written[name] = path
    if spec.create_test_file:
        test_path = project_root / "tests" / f"test_{spec.signal_id.lower()}.py"
        test_path.write_text(build_test_module(spec))
        written["test"] = test_path
    return written
