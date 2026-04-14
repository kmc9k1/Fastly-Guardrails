from pathlib import Path

from fastly_guardrails.scanner import FastlyGuardrails


def test_template_backed_signals_still_fire() -> None:
    repo = Path(__file__).parent / "fixtures" / "sample_repo"
    scanner = FastlyGuardrails(str(repo))
    findings = scanner.scan(categories={"backend", "observability"})
    signal_ids = {finding.signal_id for finding in findings}
    assert "BKG001" in signal_ids
    assert "BKG002" in signal_ids
    assert "BKG003" in signal_ids
    assert "OBS001" in signal_ids
