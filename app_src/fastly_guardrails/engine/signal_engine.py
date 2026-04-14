from __future__ import annotations

import importlib
from collections import defaultdict
from typing import Dict, Optional, Set

from ..models import Block, Finding, Signal
from ..parser import ParsedRepo
from ..scoring import level_to_severity
from .templates import (
    run_absence_heuristic_detector,
    run_block_summary_detector,
    run_pattern_context_detector,
    run_pattern_detector,
)


class SignalEngine:
    def __init__(self, parsed_repo: ParsedRepo, signals: list[Signal]) -> None:
        self.repo = parsed_repo
        self.signals = signals
        self.blocks_by_file = defaultdict(list)
        for block in parsed_repo.blocks:
            self.blocks_by_file[block.file_path].append(block)
        self.docs_by_path = {doc.path: doc for doc in parsed_repo.documents}
        self.template_detectors = {
            "pattern": run_pattern_detector,
            "pattern_context": run_pattern_context_detector,
            "absence_heuristic": run_absence_heuristic_detector,
            "block_summary": run_block_summary_detector,
        }

    def run(self, categories: Optional[Set[str]] = None) -> list[Finding]:
        findings: list[Finding] = []
        for signal in self.signals:
            if categories and signal.category not in categories:
                continue
            findings.extend(self._run_signal(signal))
        findings.sort(key=lambda f: (f.file, f.line or 0, f.signal_id))
        return findings

    def _run_signal(self, signal: Signal) -> list[Finding]:
        if signal.detector_type == "custom":
            return self._run_custom_signal(signal)
        runner = self.template_detectors.get(signal.detector_type)
        if runner is None:
            return []
        return runner(self, signal)

    def _run_custom_signal(self, signal: Signal) -> list[Finding]:
        if not signal.custom_detector:
            return []
        module = importlib.import_module(f"fastly_guardrails.detectors.custom.{signal.custom_detector}")
        return module.run(self, signal)

    def iter_line_scan_blocks(self, kinds: set[str]) -> list[Block]:
        selected: list[Block] = []
        for block in self.repo.blocks:
            if block.kind not in kinds:
                continue
            if block.kind == "vcl":
                if block.block_type == "sub":
                    selected.append(block)
            else:
                selected.append(block)
        return selected

    def find_context_block(self, file_path: str, line: Optional[int], block_name: Optional[str]) -> Optional[Block]:
        blocks = self.blocks_by_file.get(file_path, [])
        preferred: list[Block] = []
        for block in blocks:
            if block_name and block.name == block_name:
                if line is None or (block.start_line <= line <= block.end_line):
                    preferred.append(block)
        if preferred:
            preferred.sort(key=lambda b: ((b.end_line - b.start_line), b.start_line))
            return preferred[0]
        if line is not None:
            containing = [b for b in blocks if b.start_line <= line <= b.end_line]
            if containing:
                containing.sort(key=lambda b: ((b.end_line - b.start_line), b.start_line))
                return containing[0]
        return blocks[0] if blocks else None

    def context_snippet(self, file_path: str, line: Optional[int], block_name: Optional[str], max_lines: int = 18) -> Optional[Dict[str, object]]:
        block = self.find_context_block(file_path, line, block_name)
        if block is None:
            return None
        block_lines = block.text.splitlines()
        if not block_lines:
            return None
        rel_focus = None
        if line is not None and block.start_line <= line <= block.end_line:
            rel_focus = line - block.start_line
        if len(block_lines) <= max_lines:
            start_idx = 0
            end_idx = len(block_lines)
        elif rel_focus is None:
            start_idx = 0
            end_idx = max_lines
        else:
            before = max_lines // 2
            after = max_lines - before - 1
            start_idx = max(0, rel_focus - before)
            end_idx = min(len(block_lines), rel_focus + after + 1)
            if end_idx - start_idx < max_lines:
                if start_idx == 0:
                    end_idx = min(len(block_lines), max_lines)
                elif end_idx == len(block_lines):
                    start_idx = max(0, len(block_lines) - max_lines)
        snippet_lines = block_lines[start_idx:end_idx]
        return {
            "kind": block.kind,
            "block_type": block.block_type,
            "block_name": block.name,
            "start_line": block.start_line + start_idx,
            "end_line": block.start_line + end_idx - 1,
            "focus_line": line,
            "truncated": start_idx > 0 or end_idx < len(block_lines),
            "lines": snippet_lines,
        }

    def make_finding(self, signal: Signal, score: float, level: str, file_path: str, line: Optional[int], block_name: Optional[str], evidence: list[str], metadata: Optional[Dict[str, object]] = None) -> Finding:
        severity = level_to_severity(signal.severity_map, level)
        merged_metadata = dict(metadata or {})
        context = self.context_snippet(file_path, line, block_name)
        if context is not None:
            merged_metadata.setdefault("context", context)
        return Finding(
            signal_id=signal.signal_id,
            category=signal.category,
            severity=severity,
            confidence_score=round(score, 2),
            confidence_level=level,
            file=file_path,
            line=line,
            block_name=block_name,
            message=signal.message,
            evidence=evidence,
            hint=signal.remediation,
            metadata=merged_metadata,
        )
