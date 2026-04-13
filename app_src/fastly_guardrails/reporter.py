from __future__ import annotations

import json
import os
import sys
from collections import Counter
from typing import Iterable, List

from .grouping import consolidate_findings
from .models import Finding
from .utils import severity_rank


class Ansi:
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"
    red = "\033[31m"
    yellow = "\033[33m"
    green = "\033[32m"
    blue = "\033[34m"
    magenta = "\033[35m"
    cyan = "\033[36m"
    white = "\033[97m"
    bright_black = "\033[90m"


def _should_use_color(explicit: bool | None = None) -> bool:
    if explicit is not None:
        return explicit
    if os.environ.get("NO_COLOR"):
        return False
    term = os.environ.get("TERM", "")
    if term.lower() == "dumb":
        return False
    return sys.stdout.isatty()


def _color(text: str, *styles: str, use_color: bool) -> str:
    if not use_color or not styles:
        return text
    return "".join(styles) + text + Ansi.reset


def findings_to_json(findings: Iterable[Finding]) -> str:
    payload = [finding.to_dict() for finding in findings]
    return json.dumps(payload, indent=2)


def findings_to_text(findings: list[Finding], use_color: bool | None = None) -> str:
    use_color = _should_use_color(use_color)
    findings = consolidate_findings(findings)
    counts = Counter(f.severity for f in findings)
    category_counts = Counter(f.category for f in findings)

    header_rule = _color("═" * 78, Ansi.cyan, use_color=use_color)
    faint_rule = _color("─" * 78, Ansi.bright_black, use_color=use_color)

    if not findings:
        title = _color("Fastly Guardrails", Ansi.bold, Ansi.cyan, use_color=use_color)
        ok = _color("✓ No findings", Ansi.bold, Ansi.green, use_color=use_color)
        return "\n".join([header_rule, title, faint_rule, ok])

    severity_styles = {
        "error": ("✖ ERROR", (Ansi.bold, Ansi.red)),
        "warn": ("▲ WARN ", (Ansi.bold, Ansi.yellow)),
        "info": ("• INFO ", (Ansi.bold, Ansi.blue)),
    }
    confidence_styles = {
        "high": (Ansi.bold, Ansi.green),
        "medium": (Ansi.bold, Ansi.yellow),
        "low": (Ansi.bold, Ansi.blue),
    }
    category_styles = {
        "backend": (Ansi.magenta,),
        "security": (Ansi.red,),
        "observability": (Ansi.cyan,),
    }

    lines: list[str] = []
    title = _color("Fastly Guardrails", Ansi.bold, Ansi.cyan, use_color=use_color)
    subtitle = _color("heuristic Fastly safety scanner", Ansi.dim, use_color=use_color)
    lines.append(header_rule)
    lines.append(f"{title}  {subtitle}")
    lines.append(faint_rule)

    summary_bits = [
        _color(f"errors {counts.get('error', 0)}", Ansi.bold, Ansi.red, use_color=use_color),
        _color(f"warnings {counts.get('warn', 0)}", Ansi.bold, Ansi.yellow, use_color=use_color),
        _color(f"info {counts.get('info', 0)}", Ansi.bold, Ansi.blue, use_color=use_color),
    ]
    lines.append("Summary  " + "  •  ".join(summary_bits))

    if category_counts:
        cat_parts = []
        for category in ("backend", "security", "observability"):
            if category in category_counts:
                cat_parts.append(
                    _color(f"{category} {category_counts[category]}", *category_styles.get(category, ()), use_color=use_color)
                )
        lines.append("Categories  " + "  •  ".join(cat_parts))

    lines.append("")

    ordered = sorted(findings, key=lambda f: (-severity_rank(f.severity), f.file, f.line or 0, f.signal_id))
    for idx, finding in enumerate(ordered, start=1):
        sev_label, sev_styles = severity_styles.get(finding.severity, (finding.severity.upper(), (Ansi.bold,)))
        conf_styles = confidence_styles.get(finding.confidence_level, (Ansi.bold,))
        cat_styles = category_styles.get(finding.category, tuple())

        lines.append(faint_rule)
        lines.append(
            f"{_color(sev_label, *sev_styles, use_color=use_color)}  "
            f"{_color(finding.signal_id, Ansi.bold, Ansi.white, use_color=use_color)}  "
            f"{_color('[' + finding.category + ']', *cat_styles, use_color=use_color)}  "
            f"{_color(f'confidence {finding.confidence_score:.2f}', *conf_styles, use_color=use_color)}  "
            f"{_color(finding.confidence_level.upper(), *conf_styles, use_color=use_color)}"
        )

        location = f"{finding.file}:{finding.line}" if finding.line is not None else finding.file
        lines.append(f"  {_color('↳', Ansi.cyan, use_color=use_color)} {_color(location, Ansi.bold, Ansi.cyan, use_color=use_color)}")
        if finding.block_name:
            lines.append(f"  {_color('block', Ansi.dim, use_color=use_color)}  {_color(finding.block_name, Ansi.magenta, use_color=use_color)}")

        lines.append(f"  {_color('message', Ansi.dim, use_color=use_color)}  {finding.message}")
        if finding.evidence:
            lines.append(f"  {_color('evidence', Ansi.dim, use_color=use_color)}")
            for evidence in finding.evidence:
                lines.append(f"    {_color('│', Ansi.bright_black, use_color=use_color)} {evidence}")

        context = finding.metadata.get('context') if isinstance(finding.metadata, dict) else None
        if isinstance(context, dict):
            context_lines = context.get('lines') or []
            start_line = context.get('start_line')
            focus_line = context.get('focus_line')
            focus_lines = set(context.get('focus_lines') or ([focus_line] if focus_line is not None else []))
            truncated = context.get('truncated')
            if context_lines:
                lines.append(f"  {_color('context', Ansi.dim, use_color=use_color)}")
                if truncated:
                    lines.append(f"    {_color('⋮', Ansi.bright_black, use_color=use_color)} {_color('trimmed to nearby block context', Ansi.dim, use_color=use_color)}")
                for offset, snippet_line in enumerate(context_lines):
                    current_line = (start_line + offset) if isinstance(start_line, int) else None
                    gutter = f"{current_line:>4}" if current_line is not None else "   ·"
                    is_focus = current_line in focus_lines
                    marker = '▶' if is_focus else ' '
                    gutter_colored = _color(gutter, Ansi.bright_black, use_color=use_color)
                    marker_colored = _color(marker, Ansi.cyan if is_focus else Ansi.bright_black, use_color=use_color)
                    code_colored = _color(snippet_line, Ansi.white if is_focus else Ansi.dim, use_color=use_color)
                    lines.append(f"    {marker_colored} {gutter_colored} {_color('│', Ansi.bright_black, use_color=use_color)} {code_colored}")
                if truncated:
                    lines.append(f"    {_color('⋮', Ansi.bright_black, use_color=use_color)}")


        related = finding.metadata.get("supporting_findings") if isinstance(finding.metadata, dict) else None
        if isinstance(related, list) and related:
            label = f"related signals ({len(related)})"
            lines.append(f"  {_color(label, Ansi.dim, use_color=use_color)}")
            for item in related:
                rel_line = item.get("line")
                rel_loc = f"line {rel_line}" if rel_line is not None else "line ?"
                rel_sig = item.get("signal_id", "?")
                rel_sev = item.get("severity", "info").upper()
                rel_conf = item.get("confidence_score", 0.0)
                rel_msg = item.get("message", "")
                lines.append(
                    f"    {_color('•', Ansi.bright_black, use_color=use_color)} "
                    f"{_color(str(rel_sig), Ansi.bold, Ansi.white, use_color=use_color)} "
                    f"{_color(str(rel_sev), Ansi.yellow if str(rel_sev).lower() == 'warn' else Ansi.red if str(rel_sev).lower() == 'error' else Ansi.blue, use_color=use_color)} "
                    f"{_color(rel_loc, Ansi.dim, use_color=use_color)} "
                    f"{_color(f'({float(rel_conf):.2f})', Ansi.dim, use_color=use_color)}"
                )
                if rel_msg:
                    lines.append(f"      {_color('↳', Ansi.bright_black, use_color=use_color)} {rel_msg}")

        lines.append(f"  {_color('hint', Ansi.dim, use_color=use_color)}  {finding.hint}")
        if idx != len(ordered):
            lines.append("")

    lines.append(faint_rule)
    return "\n".join(lines).rstrip()
