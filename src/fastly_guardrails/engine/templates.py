from __future__ import annotations

import re
from collections import defaultdict
from typing import List

from ..models import Block, Finding, Signal
from ..scoring import finalize_score
from ..utils import (
    context_window,
    has_logging_tokens,
    has_non_prod_markers,
    has_observability_tokens,
    has_shield_tokens,
    is_direct_ip,
    is_probably_prod,
    normalize_text,
)


def _iter_target_blocks(engine, signal: Signal) -> List[Block]:
    targets = set(signal.targets or [])
    selected: List[Block] = []
    for block in engine.repo.blocks:
        if block.kind not in targets:
            continue
        if block.kind == "vcl" and block.block_type != "sub":
            continue
        selected.append(block)
    return selected


def run_pattern_detector(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    params = signal.params or {}
    triggers = [normalize_text(t) for t in (params.get("triggers") or params.get("patterns") or [])]
    for block in _iter_target_blocks(engine, signal):
        lines = block.text.splitlines()
        for idx, line in enumerate(lines):
            lowered = normalize_text(line)
            if not any(trigger in lowered for trigger in triggers):
                continue
            score, level = finalize_score(signal.base_confidence, [0.10], [])
            findings.append(
                engine.make_finding(
                    signal,
                    score,
                    level,
                    block.file_path,
                    block.start_line + idx,
                    block.name,
                    [line.strip()],
                    metadata={"kind": block.kind, "template": "pattern"},
                )
            )
    return findings


def run_pattern_context_detector(engine, signal: Signal) -> List[Finding]:
    if signal.signal_id == "BKG001":
        return _run_bkg001(engine, signal)
    if signal.signal_id == "BKG002":
        return _run_bkg002(engine, signal)
    return _run_generic_pattern_context(engine, signal)


def _run_bkg001(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    triggers = [normalize_text(t) for t in (signal.params.get("triggers") or signal.params.get("patterns") or [])]
    boosters = [normalize_text(t) for t in (signal.params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (signal.params.get("suppressors") or [])]
    for block in _iter_target_blocks(engine, signal):
        if block.kind != "terraform" or block.block_type != "resource":
            continue
        scope = normalize_text(block.name + "\n" + block.text)
        if "backend" not in scope:
            continue
        for idx, line in enumerate(block.text.splitlines()):
            lowered = normalize_text(line)
            if not any(pattern in lowered for pattern in triggers):
                continue
            increments = [0.20]
            decrements: list[float] = []
            if any(token in scope for token in boosters) or is_probably_prod(scope):
                increments.append(0.10)
            if any(token in scope for token in suppressors) or has_non_prod_markers(scope):
                decrements.append(0.20)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(engine.make_finding(signal, score, level, block.file_path, block.start_line + idx, block.name, [line.strip()], metadata={"kind": block.kind, "template": "pattern_context"}))
    return findings


def _run_bkg002(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    attr_re = re.compile(r'(?:address|hostname|override_host|host)\s*=\s*"([^"]+)"')
    boosters = [normalize_text(t) for t in (signal.params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (signal.params.get("suppressors") or [])]
    for block in _iter_target_blocks(engine, signal):
        if block.kind != "terraform" or block.block_type != "resource":
            continue
        scope = normalize_text(block.name + "\n" + block.text)
        if "backend" not in scope:
            continue
        for idx, line in enumerate(block.text.splitlines()):
            match = attr_re.search(line)
            if not match:
                continue
            value = match.group(1)
            if not is_direct_ip(value):
                continue
            increments = [0.12]
            decrements: list[float] = []
            if any(term in scope for term in boosters) or is_probably_prod(scope):
                increments.append(0.08)
            if any(term in scope for term in suppressors):
                decrements.append(0.20)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(engine.make_finding(signal, score, level, block.file_path, block.start_line + idx, block.name, [line.strip()], metadata={"origin_value": value, "kind": block.kind, "template": "pattern_context"}))
    return findings


def _run_generic_pattern_context(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    params = signal.params or {}
    triggers = [normalize_text(t) for t in (params.get("triggers") or params.get("patterns") or [])]
    boosters = [normalize_text(t) for t in (params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (params.get("suppressors") or [])]
    radius = int(params.get("radius", 5))
    for block in _iter_target_blocks(engine, signal):
        lines = block.text.splitlines()
        for idx, line in enumerate(lines):
            lowered = normalize_text(line)
            if not any(trigger in lowered for trigger in triggers):
                continue
            context_norm = normalize_text(context_window(lines, idx, radius=radius))
            increments = [0.10]
            decrements: list[float] = []
            if any(token in context_norm for token in boosters):
                increments.append(0.10)
            if any(token in context_norm for token in suppressors):
                decrements.append(0.20)
            if re.search(r"==|!=|~", line):
                increments.append(0.08)
            if "if (" in lowered or ("if" in context_norm and "{" in context_norm):
                increments.append(0.06)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(engine.make_finding(signal, score, level, block.file_path, block.start_line + idx, block.name, [line.strip()], metadata={"kind": block.kind, "template": "pattern_context"}))
    return findings


def run_absence_heuristic_detector(engine, signal: Signal) -> List[Finding]:
    if signal.signal_id == "BKG003":
        return _run_bkg003(engine, signal)
    if signal.signal_id == "OBS001":
        return _run_obs001(engine, signal)
    if signal.signal_id == "OBS002":
        return _run_obs002(engine, signal)
    return _run_generic_absence(engine, signal)


def _run_bkg003(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    file_backend_blocks = defaultdict(list)
    for block in engine.repo.blocks:
        if block.kind == "terraform" and block.block_type == "resource":
            lowered = normalize_text(block.name + "\n" + block.text)
            if "backend" in lowered or "origin" in lowered:
                file_backend_blocks[block.file_path].append(block)
    boosters = [normalize_text(t) for t in (signal.params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (signal.params.get("suppressors") or [])]
    for file_path, backend_blocks in file_backend_blocks.items():
        doc = engine.docs_by_path[file_path]
        lowered = normalize_text(doc.text)
        if not (is_probably_prod(lowered) or any(tok in lowered for tok in boosters)):
            continue
        if has_shield_tokens(lowered):
            continue
        increments = [0.10]
        decrements: list[float] = []
        if len(backend_blocks) > 1:
            increments.append(0.05)
        if has_non_prod_markers(lowered) or any(tok in lowered for tok in suppressors):
            decrements.append(0.20)
        score, level = finalize_score(signal.base_confidence, increments, decrements)
        evidence = [f"{len(backend_blocks)} backend block(s) found; no shield-related configuration detected in file context."]
        findings.append(engine.make_finding(signal, score, level, file_path, backend_blocks[0].start_line, backend_blocks[0].name, evidence, metadata={"backend_count": len(backend_blocks), "template": "absence_heuristic"}))
    return findings


def _run_obs001(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    presence = [normalize_text(t) for t in (signal.params.get("presence_markers") or signal.params.get("patterns") or [])]
    boosters = [normalize_text(t) for t in (signal.params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (signal.params.get("suppressors") or [])]
    for doc in engine.repo.documents:
        if doc.kind != "terraform":
            continue
        lowered = normalize_text(doc.text)
        if not any(tok in lowered for tok in presence):
            continue
        if has_logging_tokens(lowered):
            continue
        increments = [0.05]
        decrements: list[float] = []
        if is_probably_prod(lowered) or any(tok in lowered for tok in boosters):
            increments.append(0.10)
        if "custom_vcl" in lowered or "snippet" in lowered:
            increments.append(0.08)
        if any(tok in lowered for tok in suppressors):
            decrements.append(0.22)
        score, level = finalize_score(signal.base_confidence, increments, decrements)
        findings.append(engine.make_finding(signal, score, level, doc.path, 1, None, ["Service/backend/origin patterns found; no obvious logging configuration detected in file context."], metadata={"kind": doc.kind, "template": "absence_heuristic"}))
    return findings


def _run_obs002(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    presence = [normalize_text(t) for t in (signal.params.get("presence_markers") or signal.params.get("patterns") or [])]
    boosters = [normalize_text(t) for t in (signal.params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (signal.params.get("suppressors") or [])]
    for doc in engine.repo.documents:
        lowered = normalize_text(doc.text)
        token_hits = sum(lowered.count(tok) for tok in presence)
        if token_hits < 4:
            continue
        if any(tok in lowered for tok in suppressors):
            continue
        increments = [0.08]
        decrements: list[float] = []
        if any(tok in lowered for tok in boosters):
            increments.append(0.08)
        if doc.kind == "vcl":
            sub_count = sum(1 for block in engine.blocks_by_file[doc.path] if block.kind == "vcl" and block.block_type == "sub")
            if sub_count >= 2:
                increments.append(0.06)
        if has_observability_tokens(lowered):
            decrements.append(0.20)
        score, level = finalize_score(signal.base_confidence, increments, decrements)
        findings.append(engine.make_finding(signal, score, level, doc.path, 1, None, [f"Custom logic tokens detected: {token_hits}; no clear logging/debug/tracing signals found."], metadata={"kind": doc.kind, "token_hits": token_hits, "template": "absence_heuristic"}))
    return findings


def _run_generic_absence(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    params = signal.params or {}
    targets = set(signal.targets or [])
    presence = [normalize_text(t) for t in (params.get("presence_markers") or params.get("patterns") or [])]
    expected_absent = [normalize_text(t) for t in (params.get("expected_absent") or [])]
    boosters = [normalize_text(t) for t in (params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (params.get("suppressors") or [])]
    for doc in engine.repo.documents:
        if doc.kind not in targets:
            continue
        lowered = normalize_text(doc.text)
        if presence and not any(tok in lowered for tok in presence):
            continue
        if expected_absent and any(tok in lowered for tok in expected_absent):
            continue
        increments = [0.05]
        decrements: list[float] = []
        if any(tok in lowered for tok in boosters):
            increments.append(0.10)
        if any(tok in lowered for tok in suppressors):
            decrements.append(0.20)
        score, level = finalize_score(signal.base_confidence, increments, decrements)
        findings.append(engine.make_finding(signal, score, level, doc.path, 1, None, ["Expected pattern appears absent in relevant file context."], metadata={"kind": doc.kind, "template": "absence_heuristic"}))
    return findings


def run_block_summary_detector(engine, signal: Signal) -> List[Finding]:
    findings: List[Finding] = []
    params = signal.params or {}
    triggers = [normalize_text(t) for t in (params.get("triggers") or params.get("patterns") or [])]
    boosters = [normalize_text(t) for t in (params.get("boosters") or [])]
    suppressors = [normalize_text(t) for t in (params.get("suppressors") or [])]
    for block in _iter_target_blocks(engine, signal):
        lowered = normalize_text(block.text)
        if not any(token in lowered for token in triggers):
            continue
        increments = [0.08]
        decrements: list[float] = []
        if any(token in lowered for token in boosters):
            increments.append(0.10)
        if any(token in lowered for token in suppressors):
            decrements.append(0.18)
        score, level = finalize_score(signal.base_confidence, increments, decrements)
        evidence = [block.text.splitlines()[0].strip()] if block.text.splitlines() else [signal.message]
        findings.append(engine.make_finding(signal, score, level, block.file_path, block.start_line, block.name, evidence, metadata={"kind": block.kind, "template": "block_summary"}))
    return findings
