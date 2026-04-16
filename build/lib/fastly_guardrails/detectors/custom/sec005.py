from __future__ import annotations

from ...scoring import finalize_score
from ...utils import context_window, normalize_text


def run(engine, signal):
    findings = []
    rate_tokens = ["ratelimit", "penaltybox", "client_key", "bucket", "limit"]
    header_tokens = ["req.http", "x-forwarded-for", "true-client-ip", "header", "identity", "key"]
    trusted_tokens = ["client.ip", "fastly.client.ip", "trusted overwrite"]
    for block in engine.iter_line_scan_blocks(kinds={"vcl", "terraform"}):
        lines = block.text.splitlines()
        for idx, line in enumerate(lines):
            lowered = normalize_text(line)
            if not any(tok in lowered for tok in rate_tokens):
                continue
            nearby = normalize_text(context_window(lines, idx, radius=4))
            if not any(tok in nearby for tok in header_tokens):
                continue
            increments = [0.10]
            decrements = []
            if "req.http" in nearby:
                increments.append(0.16)
            if "x-forwarded-for" in nearby or "true-client-ip" in nearby:
                increments.append(0.12)
            if any(tok in nearby for tok in trusted_tokens):
                decrements.append(0.22)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(engine.make_finding(signal, score, level, block.file_path, block.start_line + idx, block.name, [line.strip()], metadata={"kind": block.kind, "template": "custom"}))
    return findings
