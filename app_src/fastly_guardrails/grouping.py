from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding
from .utils import severity_rank

PRIMARY_SIGNAL_PREFERENCE = {
    "SEC005": 60,
    "SEC001": 45,
    "SEC002": 25,
    "BKG002": 45,
    "BKG001": 35,
    "BKG003": 15,
    "OBS001": 40,
    "OBS002": 20,
}


def _context_dict(finding: Finding) -> Optional[Dict[str, Any]]:
    if not isinstance(finding.metadata, dict):
        return None
    context = finding.metadata.get("context")
    return context if isinstance(context, dict) else None


def _line_range(finding: Finding) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    focus = finding.line
    if isinstance(focus, int):
        return focus, focus, focus

    context = _context_dict(finding)
    start = context.get("start_line") if context else None
    end = context.get("end_line") if context else None
    if isinstance(start, int) and isinstance(end, int):
        return start, end, None
    return None, None, None


def _cluster_key(finding: Finding) -> Tuple[str, str, str, str]:
    context = _context_dict(finding) or {}
    block_name = finding.block_name or context.get("block_name") or ""
    block_type = context.get("block_type") or ""
    return finding.file, finding.category, str(block_name), str(block_type)


def _should_merge(cluster: Dict[str, Any], finding: Finding) -> bool:
    start, end, focus = _line_range(finding)
    if start is None or end is None:
        return False

    cluster_start = cluster["start"]
    cluster_end = cluster["end"]
    gap = 0
    if start > cluster_end:
        gap = start - cluster_end
    elif end < cluster_start:
        gap = cluster_start - end

    overlapping = not (end < cluster_start or start > cluster_end)
    adjacent = gap <= 2
    focus_lines = cluster["focus_lines"] + ([focus] if isinstance(focus, int) else [])
    focus_span = max(focus_lines) - min(focus_lines) if focus_lines else 0

    return (overlapping or adjacent) and focus_span <= 8


def _primary_sort_key(finding: Finding) -> Tuple[int, int, float, int]:
    return (
        severity_rank(finding.severity),
        PRIMARY_SIGNAL_PREFERENCE.get(finding.signal_id, 0),
        finding.confidence_score,
        -(finding.line or 0),
    )


def _merge_context(findings: List[Finding], primary: Finding) -> Optional[Dict[str, Any]]:
    contexts = [_context_dict(f) for f in findings]
    contexts = [c for c in contexts if c]
    if not contexts:
        return _context_dict(primary)

    line_map: Dict[int, str] = {}
    block_name = primary.block_name
    block_type = None
    kind = None
    for context in contexts:
        start_line = context.get("start_line")
        lines = context.get("lines") or []
        if isinstance(start_line, int):
            for offset, text in enumerate(lines):
                line_map.setdefault(start_line + offset, text)
        block_name = block_name or context.get("block_name")
        block_type = block_type or context.get("block_type")
        kind = kind or context.get("kind")

    if not line_map:
        return _context_dict(primary)

    focus_lines = sorted({f.line for f in findings if isinstance(f.line, int)})
    min_focus = min(focus_lines) if focus_lines else min(line_map)
    max_focus = max(focus_lines) if focus_lines else max(line_map)
    desired_start = min_focus - 2
    desired_end = max_focus + 2

    selected_numbers = [ln for ln in sorted(line_map) if desired_start <= ln <= desired_end]
    if not selected_numbers:
        selected_numbers = sorted(line_map)

    if len(selected_numbers) > 18:
        selected_numbers = selected_numbers[:18]

    lines = [line_map[ln] for ln in selected_numbers]
    return {
        "kind": kind,
        "block_type": block_type,
        "block_name": block_name,
        "start_line": selected_numbers[0],
        "end_line": selected_numbers[-1],
        "focus_line": primary.line,
        "focus_lines": focus_lines,
        "truncated": selected_numbers[0] > min(line_map) or selected_numbers[-1] < max(line_map),
        "lines": lines,
    }


def consolidate_findings(findings: List[Finding]) -> List[Finding]:
    if not findings:
        return []

    buckets: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = {}
    for finding in sorted(findings, key=lambda f: (f.file, f.category, f.block_name or "", f.line or 0, -severity_rank(f.severity), -f.confidence_score)):
        key = _cluster_key(finding)
        buckets.setdefault(key, [])
        start, end, focus = _line_range(finding)
        if start is None or end is None:
            buckets[key].append({
                "findings": [finding],
                "start": -1,
                "end": -1,
                "focus_lines": [focus] if isinstance(focus, int) else [],
            })
            continue

        clusters = buckets[key]
        if clusters and _should_merge(clusters[-1], finding):
            cluster = clusters[-1]
            cluster["findings"].append(finding)
            cluster["start"] = min(cluster["start"], start)
            cluster["end"] = max(cluster["end"], end)
            if isinstance(focus, int):
                cluster["focus_lines"].append(focus)
        else:
            clusters.append({
                "findings": [finding],
                "start": start,
                "end": end,
                "focus_lines": [focus] if isinstance(focus, int) else [],
            })

    consolidated: List[Finding] = []
    for clusters in buckets.values():
        for cluster in clusters:
            members: List[Finding] = cluster["findings"]
            if len(members) == 1:
                consolidated.append(members[0])
                continue

            primary = max(members, key=_primary_sort_key)
            supporting = [f for f in members if f is not primary]
            supporting_payload = [
                {
                    "signal_id": f.signal_id,
                    "severity": f.severity,
                    "confidence_score": f.confidence_score,
                    "confidence_level": f.confidence_level,
                    "line": f.line,
                    "message": f.message,
                    "evidence": f.evidence,
                }
                for f in sorted(
                    supporting,
                    key=lambda item: (
                        -severity_rank(item.severity),
                        -item.confidence_score,
                        -(PRIMARY_SIGNAL_PREFERENCE.get(item.signal_id, 0)),
                        item.line or 0,
                        item.signal_id,
                    ),
                )
            ]
            related_signals = []
            seen = set()
            for sig in [primary.signal_id] + [item["signal_id"] for item in supporting_payload]:
                if sig not in seen:
                    related_signals.append(sig)
                    seen.add(sig)

            merged_metadata = dict(primary.metadata or {})
            merged_metadata["supporting_findings"] = supporting_payload
            merged_metadata["grouped_count"] = len(supporting_payload)
            merged_metadata["related_signals"] = related_signals
            merged_metadata["context"] = _merge_context(members, primary)
            merged_metadata["consolidated"] = True
            merged_metadata["cluster_range"] = {"start": cluster["start"], "end": cluster["end"]}

            consolidated.append(replace(primary, metadata=merged_metadata))

    consolidated.sort(key=lambda f: (-severity_rank(f.severity), f.file, f.line or 0, f.signal_id))
    return consolidated
