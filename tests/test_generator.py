import json

from fastly_guardrails.generator.preview import render_preview
from fastly_guardrails.generator.wizard import DetectorSpec
from fastly_guardrails.generator.writer import write_detector_spec
from fastly_guardrails.runtime import workspace_generated_fixtures_dir, workspace_manifests_dir, workspace_signals_path


def test_generator_writes_signal_and_workspace_artifacts() -> None:
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
        preview_intent="Match a debug header and inspect nearby context.",
        preview_behavior="Match the pattern and inspect nearby context.",
        preview_risk_label="Worth review",
        preview_risk_explanation="shows up as something a reviewer should look at because it may indicate risky or unusual behavior",
    )
    preview = render_preview(spec)
    assert "You are about to create:" in preview
    assert "Worth review" in preview
    written = write_detector_spec(spec)
    assert "signals" in written
    payload = json.loads(workspace_signals_path().read_text())
    assert any(item.get("signal_id") == "OBS010" for item in payload)
    assert (workspace_generated_fixtures_dir() / "obs010_positive.vcl").exists()
    assert (workspace_manifests_dir() / "obs010.json").exists()
