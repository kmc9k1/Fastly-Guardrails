from pathlib import Path

from fastly_guardrails.scanner import FastlyGuardrails


def test_sample_repo_produces_expected_signals() -> None:
    repo = Path(__file__).parent / "fixtures" / "sample_repo"
    scanner = FastlyGuardrails(str(repo))
    findings = scanner.scan()
    signal_ids = {finding.signal_id for finding in findings}
    assert "BKG001" in signal_ids
    assert "BKG002" in signal_ids
    assert "BKG003" in signal_ids
    assert "SEC001" in signal_ids
    assert "SEC002" in signal_ids
    assert "SEC005" in signal_ids
    assert "OBS001" in signal_ids
