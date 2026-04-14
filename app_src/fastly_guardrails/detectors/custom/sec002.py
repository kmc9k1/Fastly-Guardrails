from __future__ import annotations

from ...scoring import finalize_score
from ...utils import context_window, normalize_text


def run(engine, signal):
    findings = []
    patterns = ["return(pass)", "bypass", "skip", "allow"]
    bypass_keywords = ["debug", "internal", "admin", "whitelist", "bypass", "skip", "user-agent", "bot", "crawler"]
    sensitive_header_hints = ["x-debug", "x-internal", "x-bypass", "x-whitelist", "x-test"]
    safe_path_markers = [
        'req.url.path == "/health"',
        'req.url.path == "/healthz"',
        'req.url.path == "/status"',
        'req.url.path ~ "^/health',
        'req.url.path ~ "^/status',
    ]
    for block in engine.iter_line_scan_blocks(kinds={"vcl", "terraform"}):
        lines = block.text.splitlines()
        for idx, line in enumerate(lines):
            lowered = normalize_text(line)
            if not any(p in lowered for p in patterns):
                continue
            nearby = normalize_text(context_window(lines, idx, radius=4))
            local_nearby = normalize_text(context_window(lines, idx, radius=2))
            context_source = local_nearby if "return(pass)" in lowered else nearby
            if any(s in context_source for s in ["client.ip ~", "trusted acl", "localhost", "example", "test"]):
                continue
            has_sensitive_path_context = "req.url.path" in context_source and any(tok in context_source for tok in ["admin", "internal", "debug", "whitelist"])
            has_header_toggle_context = any(tok in context_source for tok in sensitive_header_hints)
            has_user_agent_context = "user-agent" in context_source or "req.http.user-agent" in context_source
            has_cookie_toggle_context = "cookie" in context_source and any(tok in context_source for tok in ["debug", "internal", "bypass"])
            has_explicit_bypass_language = any(tok in context_source for tok in bypass_keywords)
            has_safe_health_pattern = any(marker in context_source for marker in safe_path_markers)
            if "return(pass)" in lowered and not (has_sensitive_path_context or has_header_toggle_context or has_user_agent_context or has_cookie_toggle_context or has_explicit_bypass_language):
                continue
            if has_safe_health_pattern and not (has_header_toggle_context or has_user_agent_context or has_cookie_toggle_context):
                continue
            increments = [0.08]
            decrements = []
            if has_sensitive_path_context:
                increments.append(0.12)
            if has_header_toggle_context:
                increments.append(0.12)
            if has_user_agent_context:
                increments.append(0.10)
            if has_cookie_toggle_context:
                increments.append(0.10)
            if has_explicit_bypass_language:
                increments.append(0.08)
            if "return(pass)" in lowered:
                increments.append(0.05)
            if "client.ip ~" in context_source:
                decrements.append(0.18)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(engine.make_finding(signal, score, level, block.file_path, block.start_line + idx, block.name, [line.strip()], metadata={"kind": block.kind, "template": "custom"}))
    return findings
