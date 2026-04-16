from __future__ import annotations

from pathlib import Path
from typing import Dict

from ..engine.registry import load_signals
from ..runtime import (
    dump_json,
    ensure_workspace_layout,
    load_json,
    workspace_generated_fixtures_dir,
    workspace_manifests_dir,
    workspace_signals_path,
    workspace_tests_root,
)
from .fixture_builder import build_fixtures
from .manifest_builder import build_test_manifest, build_test_module
from .wizard import DetectorSpec


class GeneratorError(ValueError):
    pass


def write_detector_spec(spec: DetectorSpec) -> Dict[str, Path]:
    ensure_workspace_layout()

    existing_ids = {signal.signal_id for signal in load_signals()}
    if spec.signal_id in existing_ids:
        raise GeneratorError(f"Signal ID already exists: {spec.signal_id}")

    signals_path = workspace_signals_path()
    signals = load_json(signals_path, [])
    signals.append(spec.to_signal_dict())
    dump_json(signals_path, signals)

    written: Dict[str, Path] = {"signals": signals_path}
    fixture_dir = workspace_generated_fixtures_dir()
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

    manifest = build_test_manifest(spec)
    manifest_path = workspace_manifests_dir() / f"{spec.signal_id.lower()}.json"
    dump_json(manifest_path, manifest)
    written["manifest"] = manifest_path

    if spec.create_test_file:
        test_path = workspace_tests_root() / f"test_{spec.signal_id.lower()}.py"
        test_path.write_text(build_test_module(spec))
        written["test"] = test_path
    return written
