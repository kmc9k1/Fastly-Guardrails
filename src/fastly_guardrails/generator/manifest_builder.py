from __future__ import annotations

from .wizard import DetectorSpec


def build_test_manifest(spec: DetectorSpec) -> dict:
    ext = "tf" if "terraform" in spec.targets else "vcl"
    cases = []
    if spec.create_positive_fixture:
        cases.append({"name": "positive", "expected_present": True})
    if spec.create_negative_fixture:
        cases.append({"name": "negative", "expected_present": False})
    if spec.create_suppressed_fixture:
        cases.append({"name": "suppressed", "expected_present": True})
    return {"signal_id": spec.signal_id, "extension": ext, "cases": cases}


def build_test_module(spec: DetectorSpec) -> str:
    signal = spec.signal_id
    stem = spec.signal_id.lower()
    return (
        f"# Generated detector validation note for {signal}\n"
        f"# Validate with: fastly_guardrails test --signal {signal}\n"
        f"# Manifest: tests/manifests/{stem}.json\n"
    )
