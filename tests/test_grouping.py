from pathlib import Path

from fastly_guardrails.grouping import consolidate_findings
from fastly_guardrails.scanner import FastlyGuardrails


def test_consolidation_collapses_overlapping_security_findings() -> None:
    repo = Path(__file__).parent / "fixtures" / "sample_repo"
    scanner = FastlyGuardrails(str(repo))
    findings = scanner.scan(categories={"security"})
    grouped = consolidate_findings(findings)

    account_security = [f for f in grouped if f.file == "services/account/edge.vcl"]
    signal_ids = {(f.signal_id, f.line) for f in account_security}

    assert ("SEC001", 2) in signal_ids
    assert ("SEC005", 8) in signal_ids
    assert ("SEC002", 14) in signal_ids
    assert len(account_security) == 3

    rate_limit = next(f for f in account_security if f.signal_id == "SEC005")
    supporting = rate_limit.metadata.get("supporting_findings", [])
    assert len(supporting) >= 1
    assert any(item["signal_id"] == "SEC001" for item in supporting)
