from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from .reporter import findings_to_json, findings_to_text
from .scanner import FastlyGuardrails


VALID_CATEGORIES = {"backend", "security", "observability"}
VALID_SEVERITIES = {"info", "warn", "error"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Heuristic Fastly safety scanner for Terraform and VCL")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a directory for Terraform and VCL findings")
    scan.add_argument("path", help="Directory or repository path to scan")
    scan.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan.add_argument(
        "--category",
        action="append",
        choices=sorted(VALID_CATEGORIES),
        help="Restrict results to one or more categories",
    )
    scan.add_argument(
        "--min-severity",
        choices=sorted(VALID_SEVERITIES),
        default="info",
        help="Hide findings below this severity",
    )
    scan.add_argument(
        "--fail-on",
        action="append",
        default=[],
        help="Signal ID(s) that should trigger a non-zero exit code when present",
    )
    scan.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in text output",
    )

    report = subparsers.add_parser("report", help="Generate a styled PDF report")
    report.add_argument("path", help="Directory or repository path to scan")
    report.add_argument("--output", required=True, help="Output PDF path")
    report.add_argument("--title", default="Fastly Guardrails Report", help="Report title")
    report.add_argument(
        "--category",
        action="append",
        choices=sorted(VALID_CATEGORIES),
        help="Restrict results to one or more categories",
    )
    report.add_argument(
        "--min-severity",
        choices=sorted(VALID_SEVERITIES),
        default="info",
        help="Hide findings below this severity",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command not in {"scan", "report"}:
        parser.print_help()
        return 2

    target = Path(args.path)
    if not target.exists():
        parser.error(f"Path does not exist: {target}")

    scanner = FastlyGuardrails(str(target))
    categories = set(args.category) if getattr(args, "category", None) else None
    findings = scanner.scan(categories=categories, min_severity=args.min_severity)

    if args.command == "scan":
        if args.format == "json":
            print(findings_to_json(findings))
        else:
            print(findings_to_text(findings, use_color=not args.no_color))

        fail_on = {item.upper() for item in args.fail_on}
        if fail_on and any(f.signal_id.upper() in fail_on for f in findings):
            return 1
        return 0

    try:
        from .reporting import build_pdf_report
    except ModuleNotFoundError as exc:
        if exc.name == "reportlab":
            raise SystemExit(
                "PDF reporting requires the optional dependency 'reportlab'.\n"
                "If you used the bootstrap installer, rerun 'fastly_guardrails doctor' to verify the managed install.\n"
                "If you are running from source, create and activate a virtual environment, then install it:\n\n"
                "  python3 -m venv .venv\n"
                "  source .venv/bin/activate\n"
                "  python3 -m pip install reportlab\n"
            )
        raise

    output = build_pdf_report(findings, args.output, str(target), title=args.title)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
