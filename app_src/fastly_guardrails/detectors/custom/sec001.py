from __future__ import annotations

import re

from ...scoring import finalize_score
from ...utils import context_window, normalize_text


def run(engine, signal):
    findings = []
    risky_header_re = re.compile(r"req\.http\.[A-Za-z0-9_-]+", re.IGNORECASE)
    for block in engine.iter_line_scan_blocks(kinds={"vcl", "terraform"}):
        lines = block.text.splitlines()
        doc = engine.docs_by_path[block.file_path]
        for idx, line in enumerate(lines):
            if not risky_header_re.search(line):
                continue
            lowered = normalize_text(line)
            nearby = normalize_text(context_window(lines, idx, radius=5))
            if any(s in nearby for s in ["unset req.http", "remove req.http", "log req.http", "example", "test"]):
                continue
            increments = [0.10]
            decrements = []
            if any(tok in nearby for tok in ["token", "auth", "acl", "allow", "deny", "trusted", "trust", "internal", "ratelimit", "bypass", "secret"]):
                increments.append(0.10)
            if "if (" in lowered or ("if" in nearby and "{" in nearby):
                increments.append(0.12)
            if re.search(r"==|!=|~", line):
                increments.append(0.18)
            if "log " in lowered:
                decrements.append(0.20)
            if doc.kind == "vcl" and block.block_type == "sub" and "recv" in normalize_text(block.name):
                increments.append(0.08)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(engine.make_finding(signal, score, level, block.file_path, block.start_line + idx, block.name, [line.strip()], metadata={"kind": block.kind, "template": "custom"}))
    return findings
