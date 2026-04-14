import json
import shutil
from pathlib import Path

from fastly_guardrails.generator.preview import render_preview
from fastly_guardrails.generator.wizard import DetectorSpec
from fastly_guardrails.generator.writer import write_detector_spec


def test_generator_writes_signal_and_fixtures(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    shutil.copytree(Path(__file__).resolve().parents[1], project_root)
    spec = DetectorSpec(
        signal_id="OBS010",
        category="observability",
        title="Debug response header exposed",
        description="Flags debug response headers that appear to be delivered to clients.",
        message="Debug response header detected.",
        remediation="Confirm debug headers are intentional and appropriately scoped.",
        detector_type="pattern_context",
        targets=["vcl"],
        base_confidence=0.55,
        severity_map={"low": "info", "medium": "warn", "high": "warn"},
        params={
            "triggers": ["resp.http.x-debug"],
            "boosters": ["deliver", "debug"],
            "suppressors": ["example"],
            "radius": 5,
            "case_insensitive": True,
        },
    )
    preview = render_preview(project_root, spec)
    assert "OBS010" in preview
    written = write_detector_spec(project_root, spec)
    assert "signals" in written
    payload = json.loads((project_root / "fastly_guardrails" / "data" / "signals.json").read_text())
    assert any(item.get("signal_id") == "OBS010" for item in payload)
    assert (project_root / "tests" / "fixtures" / "generated" / "obs010_positive.vcl").exists()
    assert (project_root / "tests" / "test_obs010.py").exists()
