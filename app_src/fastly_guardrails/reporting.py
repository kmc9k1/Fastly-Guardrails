from __future__ import annotations

import datetime as _dt
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, List, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, StyleSheet1, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .grouping import consolidate_findings
from .models import Finding
from .utils import severity_rank

ACCENT = colors.HexColor("#0f766e")
ACCENT_DARK = colors.HexColor("#115e59")
TEXT = colors.HexColor("#102a43")
MUTED = colors.HexColor("#5b7083")
RULE = colors.HexColor("#d8e1eb")
PANEL = colors.HexColor("#f6f8fb")
PANEL_STRONG = colors.HexColor("#eef4fb")
CODE_BG = colors.HexColor("#f4f6f8")
ERROR = colors.HexColor("#b42318")
WARN = colors.HexColor("#b54708")
INFO = colors.HexColor("#175cd3")
SEV_COLORS = {"error": ERROR, "warn": WARN, "info": INFO}
CAT_COLORS = {
    "backend": colors.HexColor("#7a1fa2"),
    "security": colors.HexColor("#b42318"),
    "observability": colors.HexColor("#0f766e"),
}


def _build_styles() -> StyleSheet1:
    styles = getSampleStyleSheet()
    styles["Normal"].fontName = "Helvetica"
    styles["Normal"].fontSize = 9.6
    styles["Normal"].leading = 13
    styles["Normal"].textColor = TEXT

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=21,
            leading=26,
            textColor=ACCENT_DARK,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Subtitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=MUTED,
            spaceAfter=10,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=ACCENT_DARK,
            spaceBefore=10,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SubHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=14,
            textColor=TEXT,
            spaceBefore=8,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Meta",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11,
            textColor=MUTED,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Callout",
            parent=styles["Normal"],
            fontSize=9.3,
            leading=13,
            textColor=TEXT,
            leftIndent=0,
            rightIndent=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=TEXT,
            spaceAfter=3,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Label",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.3,
            leading=10,
            textColor=MUTED,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Small",
            parent=styles["Normal"],
            fontSize=8.6,
            leading=11,
            textColor=TEXT,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CodeCaption",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.3,
            leading=10,
            textColor=MUTED,
            spaceAfter=2,
        )
    )
    return styles


def _escape(text: str) -> str:
    return escape(text, {'"': '&quot;'})


def _severity_badge(severity: str, styles: StyleSheet1) -> Table:
    color = SEV_COLORS.get(severity, INFO)
    label = severity.upper()
    badge = Table([[Paragraph(f'<font color="white"><b>{_escape(label)}</b></font>', styles["Small"])]])
    badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("BOX", (0, 0), (-1, -1), 0, color),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return badge


def _summary_table(findings: List[Finding], styles: StyleSheet1) -> Table:
    sev_counts = Counter(f.severity for f in findings)
    cat_counts = Counter(f.category for f in findings)
    total = len(findings)
    rows = [
        [
            Paragraph("<b>Total findings</b>", styles["Small"]),
            Paragraph(str(total), styles["Small"]),
            Paragraph("<b>Errors</b>", styles["Small"]),
            Paragraph(str(sev_counts.get("error", 0)), styles["Small"]),
        ],
        [
            Paragraph("<b>Warnings</b>", styles["Small"]),
            Paragraph(str(sev_counts.get("warn", 0)), styles["Small"]),
            Paragraph("<b>Info</b>", styles["Small"]),
            Paragraph(str(sev_counts.get("info", 0)), styles["Small"]),
        ],
        [
            Paragraph("<b>Backend</b>", styles["Small"]),
            Paragraph(str(cat_counts.get("backend", 0)), styles["Small"]),
            Paragraph("<b>Security</b>", styles["Small"]),
            Paragraph(str(cat_counts.get("security", 0)), styles["Small"]),
        ],
        [
            Paragraph("<b>Observability</b>", styles["Small"]),
            Paragraph(str(cat_counts.get("observability", 0)), styles["Small"]),
            Paragraph("<b>Highest severity</b>", styles["Small"]),
            Paragraph(_escape(_highest_severity(findings).upper() if findings else "NONE"), styles["Small"]),
        ],
    ]
    tbl = Table(rows, colWidths=[1.55 * inch, 0.82 * inch, 1.60 * inch, 0.95 * inch])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("BOX", (0, 0), (-1, -1), 0.75, RULE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return tbl


def _top_files_table(findings: List[Finding], styles: StyleSheet1) -> Optional[Table]:
    counts = Counter(f.file for f in findings)
    if not counts:
        return None
    rows = [[Paragraph("<b>Most affected files</b>", styles["Small"]), Paragraph("<b>Findings</b>", styles["Small"])]]
    for file_path, count in counts.most_common(5):
        rows.append([Paragraph(_escape(file_path), styles["Small"]), Paragraph(str(count), styles["Small"])])
    tbl = Table(rows, colWidths=[4.7 * inch, 1.0 * inch])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PANEL_STRONG),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.75, RULE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return tbl


def _highest_severity(findings: List[Finding]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda f: severity_rank(f.severity)).severity


def _category_summary_text(findings: List[Finding]) -> str:
    by_category = Counter(f.category for f in findings)
    bits = []
    for category in ("security", "backend", "observability"):
        if by_category.get(category):
            bits.append(f"{category}: {by_category[category]}")
    if not bits:
        return "No findings were recorded."
    return "Category mix - " + ", ".join(bits) + "."


def _finding_context(finding: Finding) -> str:
    context = finding.metadata.get("context") if isinstance(finding.metadata, dict) else None
    if not isinstance(context, dict):
        joined = "\n".join(finding.evidence)
        return joined or "No code context available."
    lines = context.get("lines") or []
    start_line = context.get("start_line")
    focus_line = context.get("focus_line")
    focus_lines = set(context.get("focus_lines") or ([focus_line] if focus_line is not None else []))
    rendered = []
    for offset, text in enumerate(lines):
        line_no = (start_line + offset) if isinstance(start_line, int) else None
        marker = ">" if line_no in focus_lines else " "
        gutter = f"{line_no:>4}" if line_no is not None else "   ."
        rendered.append(f"{marker} {gutter} | {text}")
    return "\n".join(rendered) if rendered else ("\n".join(finding.evidence) or "No code context available.")


def _supporting_findings_panel(finding: Finding, styles: StyleSheet1) -> Optional[Table]:
    supporting = finding.metadata.get("supporting_findings") if isinstance(finding.metadata, dict) else None
    if not isinstance(supporting, list) or not supporting:
        return None

    rows = [[Paragraph("<b>Related signals consolidated into this finding</b>", styles["Small"]), Paragraph("", styles["Small"])] ]
    for item in supporting:
        sig = _escape(str(item.get("signal_id", "?")))
        sev = _escape(str(item.get("severity", "info")).upper())
        line = item.get("line")
        loc = f"line {line}" if line is not None else "line ?"
        conf = float(item.get("confidence_score", 0.0))
        msg = _escape(str(item.get("message", "")))
        left = Paragraph(f"<b>{sig}</b> - {msg}", styles["Small"])
        right = Paragraph(f"{sev}<br/>{_escape(loc)}<br/>{conf:.2f}", styles["Small"])
        rows.append([left, right])

    tbl = Table(rows, colWidths=[4.9 * inch, 1.1 * inch])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PANEL),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.6, RULE),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return tbl


def _finding_card(finding: Finding, styles: StyleSheet1) -> KeepTogether:
    sev_color = SEV_COLORS.get(finding.severity, INFO)
    cat_color = CAT_COLORS.get(finding.category, ACCENT)
    location = finding.file if finding.line is None else f"{finding.file}:{finding.line}"
    title = Paragraph(
        f'<b>{_escape(finding.signal_id)}</b> - {_escape(finding.message)}',
        styles["FindingTitle"],
    )
    meta_rows = [
        [Paragraph("Severity", styles["Label"]), _severity_badge(finding.severity, styles), Paragraph("Confidence", styles["Label"]), Paragraph(f"{finding.confidence_level.title()} ({finding.confidence_score:.2f})", styles["Small"])],
        [Paragraph("Category", styles["Label"]), Paragraph(f'<font color="{cat_color.hexval()}"><b>{_escape(finding.category.title())}</b></font>', styles["Small"]), Paragraph("Location", styles["Label"]), Paragraph(_escape(location), styles["Small"])],
    ]
    if finding.block_name:
        meta_rows.append([Paragraph("Block", styles["Label"]), Paragraph(_escape(finding.block_name), styles["Small"]), Paragraph("", styles["Label"]), Paragraph("", styles["Small"])])

    meta = Table(meta_rows, colWidths=[0.75 * inch, 1.35 * inch, 0.85 * inch, 3.2 * inch])
    meta.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    rationale = Paragraph(
        f"<b>Why it was flagged.</b> {_escape(finding.message)}", styles["Callout"]
    )
    hint = Paragraph(f"<b>Reviewer note.</b> {_escape(finding.hint)}", styles["Callout"])

    supporting_panel = _supporting_findings_panel(finding, styles)

    context_caption = Paragraph("Code context", styles["CodeCaption"])
    context_text = _finding_context(finding)
    code = Preformatted(context_text, ParagraphStyle(
        name="CodeBlock",
        fontName="Courier",
        fontSize=8.1,
        leading=10.2,
        textColor=TEXT,
        leftIndent=0,
        rightIndent=0,
        spaceBefore=0,
        spaceAfter=0,
    ))
    code_panel = Table([[code]], colWidths=[6.0 * inch])
    code_panel.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("BOX", (0, 0), (-1, -1), 0.6, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    card_body = [title, Spacer(1, 4), meta, Spacer(1, 4), rationale]
    if supporting_panel is not None:
        card_body.extend([Spacer(1, 6), supporting_panel])
    card_body.extend([Spacer(1, 5), context_caption, code_panel, Spacer(1, 5), hint])
    card = Table([[card_body]], colWidths=[6.2 * inch])
    card.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.8, RULE),
                ("LINEBEFORE", (0, 0), (0, 0), 3, sev_color),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return KeepTogether([card])


def _draw_page_chrome(canvas, doc) -> None:
    canvas.saveState()
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.6)
    canvas.line(doc.leftMargin, doc.height + doc.topMargin + 8, doc.pagesize[0] - doc.rightMargin, doc.height + doc.topMargin + 8)
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(doc.leftMargin, 18, "Fastly Guardrails Report")
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 18, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def build_pdf_report(
    findings: List[Finding],
    output_path: str,
    scan_target: str,
    title: str = "Fastly Guardrails Report",
    scanner_version: str = "0.2.0",
) -> str:
    output = str(Path(output_path).resolve())
    styles = _build_styles()
    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        leftMargin=0.78 * inch,
        rightMargin=0.78 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.55 * inch,
        title=title,
        author="Fastly Guardrails",
    )

    ordered = consolidate_findings(findings)
    ordered = sorted(ordered, key=lambda f: (-severity_rank(f.severity), f.category, f.file, f.line or 0, f.signal_id))
    by_category = defaultdict(list)
    for finding in ordered:
        by_category[finding.category].append(finding)

    story = []
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    story.append(Paragraph(_escape(title), styles["ReportTitle"]))
    story.append(Paragraph("Heuristic Fastly safety scan for Terraform and VCL", styles["Subtitle"]))

    meta_panel = Table(
        [[
            Paragraph(f"<b>Target</b><br/>{_escape(scan_target)}", styles["Small"]),
            Paragraph(f"<b>Generated</b><br/>{_escape(generated)}", styles["Small"]),
            Paragraph(f"<b>Scanner version</b><br/>{_escape(scanner_version)}", styles["Small"]),
        ]],
        colWidths=[2.4 * inch, 1.6 * inch, 1.7 * inch],
    )
    meta_panel.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("BOX", (0, 0), (-1, -1), 0.75, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend([meta_panel, Spacer(1, 16)])

    story.append(Paragraph("Executive summary", styles["SectionHeading"]))
    summary_text = (
        "This report presents heuristic findings from the Fastly Guardrails scanner. "
        "The output is intended to support review and prioritization rather than act as a hard compliance verdict. "
        + _category_summary_text(ordered)
    )
    callout = Table([[Paragraph(_escape(summary_text), styles["Callout"])]], colWidths=[6.15 * inch])
    callout.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("BOX", (0, 0), (-1, -1), 0.75, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.extend([callout, Spacer(1, 12), _summary_table(ordered, styles), Spacer(1, 12)])

    top_files = _top_files_table(ordered, styles)
    if top_files is not None:
        story.append(top_files)
        story.append(Spacer(1, 12))

    if ordered:
        story.append(Paragraph("Detailed findings", styles["SectionHeading"]))
        story.append(Paragraph(
            "Findings are grouped by category. Each entry includes its severity, confidence, location, a short explanation, and a nearby code or block context excerpt.",
            styles["Callout"],
        ))
        story.append(Spacer(1, 8))

        for category in ("security", "backend", "observability"):
            findings_in_cat = by_category.get(category, [])
            if not findings_in_cat:
                continue
            cat_color = CAT_COLORS.get(category, ACCENT)
            story.append(Spacer(1, 4))
            story.append(HRFlowable(width="100%", thickness=1, color=cat_color, spaceBefore=0, spaceAfter=6))
            story.append(Paragraph(f'{category.title()} findings', styles["SectionHeading"]))
            grouped = defaultdict(list)
            for finding in findings_in_cat:
                grouped[finding.file].append(finding)
            for file_path in sorted(grouped.keys()):
                story.append(Paragraph(_escape(file_path), styles["SubHeading"]))
                for finding in grouped[file_path]:
                    story.append(_finding_card(finding, styles))
                    story.append(Spacer(1, 9))
    else:
        story.append(Paragraph("No findings", styles["SectionHeading"]))
        story.append(Paragraph("The scan completed without any findings at the selected thresholds.", styles["Callout"]))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.8, color=RULE, spaceBefore=4, spaceAfter=8))
    story.append(Paragraph("Method note", styles["SubHeading"]))
    story.append(Paragraph(
        "Fastly Guardrails uses heuristic pattern matching and absence checks. A finding means the scanner found something that resembles a known pitfall or review concern; it does not automatically mean the configuration is wrong.",
        styles["Callout"],
    ))

    doc.build(story, onFirstPage=_draw_page_chrome, onLaterPages=_draw_page_chrome)
    return output
