from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import json

from .runtime import workspace_generated_fixtures_dir, workspace_manifests_dir
from .scanner import FastlyGuardrails


@dataclass
class TestResult:
    signal_id: str
    fixture_name: str
    expected_present: bool
    passed: bool
    detail: str


def _iter_manifests(signal_filter: Optional[str] = None) -> list[Path]:
    base = workspace_manifests_dir()
    if not base.exists():
        return []
    manifests = sorted(base.glob('*.json'))
    if signal_filter:
        signal_filter = signal_filter.upper()
        manifests = [path for path in manifests if path.stem.upper() == signal_filter]
    return manifests


def run_workspace_tests(signal_filter: Optional[str] = None) -> list[TestResult]:
    manifests = _iter_manifests(signal_filter)
    if not manifests:
        return []

    scan_root = workspace_generated_fixtures_dir()
    scanner = FastlyGuardrails(str(scan_root))
    findings = scanner.scan()
    results: list[TestResult] = []

    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_text())
        signal_id = manifest['signal_id']
        ext = manifest['extension']
        for case in manifest['cases']:
            fixture_name = f"{signal_id.lower()}_{case['name']}.{ext}"
            present = any(f.signal_id == signal_id and Path(f.file).name == fixture_name for f in findings)
            expected_present = bool(case['expected_present'])
            passed = present == expected_present
            detail = 'matched expected outcome' if passed else f'expected present={expected_present}, observed present={present}'
            results.append(TestResult(signal_id=signal_id, fixture_name=fixture_name, expected_present=expected_present, passed=passed, detail=detail))
    return results
