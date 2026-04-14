from __future__ import annotations

from .wizard import DetectorSpec


def build_test_module(spec: DetectorSpec) -> str:
    signal = spec.signal_id
    stem = spec.signal_id.lower()
    ext = "tf" if "terraform" in spec.targets else "vcl"
    return f'''from pathlib import Path

from fastly_guardrails.scanner import FastlyGuardrails


def test_{stem}_positive_fixture_triggers() -> None:
    repo = Path(__file__).parent / "fixtures" / "generated"
    scanner = FastlyGuardrails(str(repo))
    findings = scanner.scan()
    assert any(f.signal_id == "{signal}" and f.file.endswith("{stem}_positive.{ext}") for f in findings)


def test_{stem}_negative_fixture_does_not_trigger() -> None:
    repo = Path(__file__).parent / "fixtures" / "generated"
    scanner = FastlyGuardrails(str(repo))
    findings = scanner.scan()
    assert not any(f.signal_id == "{signal}" and f.file.endswith("{stem}_negative.{ext}") for f in findings)
'''
