from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from .generator.preview import render_preview
from .generator.wizard import run_wizard
from .generator.writer import write_detector_spec
from .reporter import findings_to_json, findings_to_text
from .runtime import ensure_workspace_layout, workspace_generated_fixtures_dir, workspace_named_fixture
from .scanner import FastlyGuardrails
from .testing import run_workspace_tests

VALID_CATEGORIES = {"backend", "security", "observability"}
VALID_SEVERITIES = {"info", "warn", "error"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Heuristic Fastly safety scanner for Terraform and VCL")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a directory for Terraform and VCL findings")
    scan.add_argument("path", help="Directory or repository path to scan")
    scan.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan.add_argument("--category", action="append", choices=sorted(VALID_CATEGORIES), help="Restrict results to one or more categories")
    scan.add_argument("--min-severity", choices=sorted(VALID_SEVERITIES), default="info", help="Hide findings below this severity")
    scan.add_argument("--fail-on", action="append", default=[], help="Signal ID(s) that should trigger a non-zero exit code when present")
    scan.add_argument("--no-color", action="store_true", help="Disable ANSI colors in text output")

    fixture = subparsers.add_parser("scan-fixture", help="Scan a managed workspace fixture")
    fixture.add_argument("name", help="Fixture name, such as sample_repo or generated")
    fixture.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    fixture.add_argument("--category", action="append", choices=sorted(VALID_CATEGORIES), help="Restrict results to one or more categories")
    fixture.add_argument("--min-severity", choices=sorted(VALID_SEVERITIES), default="info", help="Hide findings below this severity")
    fixture.add_argument("--no-color", action="store_true", help="Disable ANSI colors in text output")

    report = subparsers.add_parser("report", help="Generate a styled PDF report")
    report.add_argument("path", help="Directory or repository path to scan")
    report.add_argument("--output", required=True, help="Output PDF path")
    report.add_argument("--title", default="Fastly Guardrails Report", help="Report title")
    report.add_argument("--category", action="append", choices=sorted(VALID_CATEGORIES), help="Restrict results to one or more categories")
    report.add_argument("--min-severity", choices=sorted(VALID_SEVERITIES), default="info", help="Hide findings below this severity")

    create = subparsers.add_parser("create-detector", help="Guided detector scaffold generator")
    create.add_argument("--yes", action="store_true", help="Write changes without confirmation")

    test = subparsers.add_parser("test", help="Run generated detector validation cases in the managed workspace")
    test.add_argument("--signal", help="Only validate a specific signal ID")

    return parser


def _render_scan(findings, output_format: str, use_color: bool) -> int:
    if output_format == "json":
        print(findings_to_json(findings))
    else:
        print(findings_to_text(findings, use_color=use_color))
    return 0


def _scan_path(path: Path, categories, min_severity: str):
    scanner = FastlyGuardrails(str(path))
    return scanner.scan(categories=categories, min_severity=min_severity)


def _resolve_fixture(name: str) -> Path:
    ensure_workspace_layout()
    if name == 'generated':
        target = workspace_generated_fixtures_dir()
        if target.exists():
            return target
    target = workspace_named_fixture(name)
    if target.exists():
        return target
    raise FileNotFoundError(f"Workspace fixture not found: {name}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "create-detector":
        spec = run_wizard()
        print(render_preview(spec))
        if not args.yes:
            confirm = input("Write these changes? [y/N]: ").strip().lower()
            if confirm not in {"y", "yes"}:
                print("Aborted.")
                return 1
        written = write_detector_spec(spec)
        print("Created detector files:")
        for key, path in written.items():
            print(f"  - {key}: {path}")
        return 0

    if args.command == "test":
        results = run_workspace_tests(signal_filter=args.signal)
        if not results:
            print("No generated detector tests were found in the managed workspace.")
            return 1
        failed = [result for result in results if not result.passed]
        for result in results:
            prefix = "PASS" if result.passed else "FAIL"
            print(f"{prefix}  {result.signal_id:<8} {result.fixture_name}  {result.detail}")
        print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
        return 1 if failed else 0

    categories = set(args.category) if getattr(args, "category", None) else None

    if args.command == "scan-fixture":
        try:
            target = _resolve_fixture(args.name)
        except FileNotFoundError as exc:
            parser.error(str(exc))
        findings = _scan_path(target, categories, args.min_severity)
        return _render_scan(findings, args.format, not args.no_color)

    target = Path(args.path)
    if not target.exists():
        parser.error(f"Path does not exist: {target}")

    findings = _scan_path(target, categories, args.min_severity)

    if args.command == "scan":
        rc = _render_scan(findings, args.format, not args.no_color)
        fail_on = {item.upper() for item in args.fail_on}
        if fail_on and any(f.signal_id.upper() in fail_on for f in findings):
            return 1
        return rc

    try:
        from .reporting import build_pdf_report
    except ModuleNotFoundError as exc:
        if exc.name == "reportlab":
            raise SystemExit("PDF reporting is not available in this environment. Reinstall with report support enabled.")
        raise

    output = build_pdf_report(findings, args.output, str(target), title=args.title)
    print(output)
    return 0
