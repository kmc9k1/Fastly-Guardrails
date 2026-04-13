from __future__ import annotations

import re
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Set

from .models import Block, Finding, Signal
from .parser import ParsedRepo
from .scoring import finalize_score, level_to_severity
from .utils import (
    GENERIC_BACKEND_NAMES,
    context_window,
    has_logging_tokens,
    has_non_prod_markers,
    has_observability_tokens,
    has_shield_tokens,
    is_direct_ip,
    is_probably_prod,
    normalize_text,
)

DetectorFunc = Callable[[ParsedRepo, Signal], list[Finding]]


class SignalEngine:
    def __init__(self, parsed_repo: ParsedRepo, signals: list[Signal]) -> None:
        self.repo = parsed_repo
        self.signals = signals
        self.blocks_by_file = defaultdict(list)
        for block in parsed_repo.blocks:
            self.blocks_by_file[block.file_path].append(block)
        self.docs_by_path = {doc.path: doc for doc in parsed_repo.documents}
        self.detectors: dict[str, DetectorFunc] = {
            "BKG001": self.detect_bkg001,
            "BKG002": self.detect_bkg002,
            "BKG003": self.detect_bkg003,
            "SEC001": self.detect_sec001,
            "SEC002": self.detect_sec002,
            "SEC005": self.detect_sec005,
            "OBS001": self.detect_obs001,
            "OBS002": self.detect_obs002,
        }

    def run(self, categories: Optional[Set[str]] = None) -> list[Finding]:
        findings: list[Finding] = []
        for signal in self.signals:
            if categories and signal.category not in categories:
                continue
            detector = self.detectors.get(signal.signal_id)
            if detector is None:
                continue
            findings.extend(detector(self.repo, signal))
        findings.sort(key=lambda f: (f.file, f.line or 0, f.signal_id))
        return findings

    def detect_bkg001(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
        for block in repo.blocks:
            if block.kind != "terraform" or block.block_type != "resource":
                continue
            if "backend" not in normalize_text(block.name) and "backend" not in normalize_text(block.text):
                continue
            lines = block.text.splitlines()
            for offset, line in enumerate(lines):
                lowered = normalize_text(line)
                if not any(pattern in lowered for pattern in ["http://", "port = 80", "ssl = false", "use_ssl = false"]):
                    continue
                increments = [0.20]
                decrements: list[float] = []
                scope = normalize_text(block.name + "\n" + block.text)
                if is_probably_prod(scope):
                    increments.append(0.10)
                if has_non_prod_markers(scope):
                    decrements.append(0.20)
                score, level = finalize_score(signal.base_confidence, increments, decrements)
                findings.append(
                    self.make_finding(
                        signal,
                        score,
                        level,
                        block.file_path,
                        block.start_line + offset,
                        block.name,
                        [line.strip()],
                        metadata={"block_type": block.block_type},
                    )
                )
        return findings

    def detect_bkg002(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
        attr_re = re.compile(r'(?:address|hostname|override_host|host)\s*=\s*"([^"]+)"')
        for block in repo.blocks:
            if block.kind != "terraform" or block.block_type != "resource":
                continue
            if "backend" not in normalize_text(block.name) and "backend" not in normalize_text(block.text):
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
                scope = normalize_text(block.name + "\n" + block.text)
                if is_probably_prod(scope):
                    increments.append(0.08)
                if any(term in scope for term in ["lab", "example", "sample", "test"]):
                    decrements.append(0.20)
                score, level = finalize_score(signal.base_confidence, increments, decrements)
                findings.append(
                    self.make_finding(
                        signal,
                        score,
                        level,
                        block.file_path,
                        block.start_line + idx,
                        block.name,
                        [line.strip()],
                        metadata={"origin_value": value},
                    )
                )
        return findings

    def detect_bkg003(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
        file_backend_blocks: dict[str, list[Block]] = defaultdict(list)
        for block in repo.blocks:
            if block.kind == "terraform" and block.block_type == "resource":
                if "backend" in normalize_text(block.name) or "backend" in normalize_text(block.text):
                    file_backend_blocks[block.file_path].append(block)
        for file_path, backend_blocks in file_backend_blocks.items():
            doc = self.docs_by_path[file_path]
            lowered = normalize_text(doc.text)
            if not is_probably_prod(lowered):
                continue
            if has_shield_tokens(lowered):
                continue
            increments = [0.10]
            decrements: list[float] = []
            if len(backend_blocks) > 1:
                increments.append(0.05)
            if has_non_prod_markers(lowered):
                decrements.append(0.20)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            evidence = [
                f"{len(backend_blocks)} backend block(s) found; no shield-related configuration detected in file context."
            ]
            findings.append(
                self.make_finding(
                    signal,
                    score,
                    level,
                    file_path,
                    backend_blocks[0].start_line,
                    backend_blocks[0].name,
                    evidence,
                    metadata={"backend_count": len(backend_blocks)},
                )
            )
        return findings

    def detect_sec001(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
        risky_header_re = re.compile(r"req\.http\.[A-Za-z0-9_-]+", re.IGNORECASE)
        for block in self._iter_line_scan_blocks(repo, kinds={"vcl", "terraform"}):
            lines = block.text.splitlines()
            doc = self.docs_by_path[block.file_path]
            for idx, line in enumerate(lines):
                if not risky_header_re.search(line):
                    continue
                lowered = normalize_text(line)
                nearby = normalize_text(context_window(lines, idx, radius=5))
                if any(s in nearby for s in ["unset req.http", "remove req.http", "log req.http", "example", "test"]):
                    continue
                increments = [0.10]
                decrements: list[float] = []
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
                findings.append(
                    self.make_finding(
                        signal,
                        score,
                        level,
                        block.file_path,
                        block.start_line + idx,
                        block.name,
                        [line.strip()],
                        metadata={"kind": block.kind},
                    )
                )
        return findings

    def detect_sec002(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
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
        for block in self._iter_line_scan_blocks(repo, kinds={"vcl", "terraform"}):
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

                has_sensitive_path_context = (
                    "req.url.path" in context_source
                    and any(tok in context_source for tok in ["admin", "internal", "debug", "whitelist"])
                )
                has_header_toggle_context = any(tok in context_source for tok in sensitive_header_hints)
                has_user_agent_context = "user-agent" in context_source or "req.http.user-agent" in context_source
                has_cookie_toggle_context = "cookie" in context_source and any(tok in context_source for tok in ["debug", "internal", "bypass"])
                has_explicit_bypass_language = any(tok in context_source for tok in bypass_keywords)
                has_safe_health_pattern = any(marker in context_source for marker in safe_path_markers)

                if "return(pass)" in lowered and not (
                    has_sensitive_path_context
                    or has_header_toggle_context
                    or has_user_agent_context
                    or has_cookie_toggle_context
                    or has_explicit_bypass_language
                ):
                    continue

                if has_safe_health_pattern and not (
                    has_header_toggle_context or has_user_agent_context or has_cookie_toggle_context
                ):
                    continue

                increments = [0.08]
                decrements: list[float] = []
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
                findings.append(
                    self.make_finding(
                        signal,
                        score,
                        level,
                        block.file_path,
                        block.start_line + idx,
                        block.name,
                        [line.strip()],
                        metadata={"kind": block.kind},
                    )
                )
        return findings

    def detect_sec005(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
        rate_tokens = ["ratelimit", "penaltybox", "client_key", "bucket", "limit"]
        header_tokens = ["req.http", "x-forwarded-for", "true-client-ip", "header", "identity", "key"]
        trusted_tokens = ["client.ip", "fastly.client.ip", "trusted overwrite"]
        for block in self._iter_line_scan_blocks(repo, kinds={"vcl", "terraform"}):
            lines = block.text.splitlines()
            for idx, line in enumerate(lines):
                lowered = normalize_text(line)
                if not any(tok in lowered for tok in rate_tokens):
                    continue
                nearby = normalize_text(context_window(lines, idx, radius=4))
                if not any(tok in nearby for tok in header_tokens):
                    continue
                increments = [0.10]
                decrements: list[float] = []
                if "req.http" in nearby:
                    increments.append(0.16)
                if "x-forwarded-for" in nearby or "true-client-ip" in nearby:
                    increments.append(0.12)
                if any(tok in nearby for tok in trusted_tokens):
                    decrements.append(0.22)
                score, level = finalize_score(signal.base_confidence, increments, decrements)
                findings.append(
                    self.make_finding(
                        signal,
                        score,
                        level,
                        block.file_path,
                        block.start_line + idx,
                        block.name,
                        [line.strip()],
                        metadata={"kind": block.kind},
                    )
                )
        return findings

    def detect_obs001(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
        for doc in repo.documents:
            if doc.kind != "terraform":
                continue
            lowered = normalize_text(doc.text)
            has_backend_or_service = any(tok in lowered for tok in ["backend", "origin", "service"])
            if not has_backend_or_service:
                continue
            if has_logging_tokens(lowered):
                continue
            increments = [0.05]
            decrements: list[float] = []
            if is_probably_prod(lowered):
                increments.append(0.10)
            if "custom_vcl" in lowered or "snippet" in lowered:
                increments.append(0.08)
            if "shared logging module" in lowered or "central logging" in lowered:
                decrements.append(0.22)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(
                self.make_finding(
                    signal,
                    score,
                    level,
                    doc.path,
                    1,
                    None,
                    ["Service/backend/origin patterns found; no obvious logging configuration detected in file context."],
                    metadata={"kind": doc.kind},
                )
            )
        return findings

    def detect_obs002(self, repo: ParsedRepo, signal: Signal) -> list[Finding]:
        findings: list[Finding] = []
        custom_logic_tokens = ["if (", "elseif", "return", "set ", "header", "custom_vcl", "snippet"]
        visibility_tokens = ["syslog", "bigquery", "datadog", "splunk", "logging", "trace", "debug"]
        for doc in repo.documents:
            lowered = normalize_text(doc.text)
            token_hits = sum(lowered.count(tok) for tok in custom_logic_tokens)
            if token_hits < 4:
                continue
            if any(tok in lowered for tok in visibility_tokens):
                continue
            increments = [0.08]
            decrements: list[float] = []
            if any(tok in lowered for tok in ["auth", "redirect", "cache", "backend", "recv", "deliver"]):
                increments.append(0.08)
            if doc.kind == "vcl":
                sub_count = sum(1 for block in self.blocks_by_file[doc.path] if block.kind == "vcl" and block.block_type == "sub")
                if sub_count >= 2:
                    increments.append(0.06)
            if has_observability_tokens(lowered):
                decrements.append(0.20)
            score, level = finalize_score(signal.base_confidence, increments, decrements)
            findings.append(
                self.make_finding(
                    signal,
                    score,
                    level,
                    doc.path,
                    1,
                    None,
                    [f"Custom logic tokens detected: {token_hits}; no clear logging/debug/tracing signals found."],
                    metadata={"kind": doc.kind, "token_hits": token_hits},
                )
            )
        return findings


    def _iter_line_scan_blocks(self, repo: ParsedRepo, kinds: set[str]) -> list[Block]:
        selected: list[Block] = []
        for block in repo.blocks:
            if block.kind not in kinds:
                continue
            if block.kind == "vcl":
                if block.block_type == "sub":
                    selected.append(block)
            else:
                selected.append(block)
        return selected

    def _find_context_block(
        self,
        file_path: str,
        line: Optional[int],
        block_name: Optional[str],
    ) -> Optional[Block]:
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

    def _context_snippet(
        self,
        file_path: str,
        line: Optional[int],
        block_name: Optional[str],
        max_lines: int = 18,
    ) -> Optional[Dict[str, object]]:
        block = self._find_context_block(file_path, line, block_name)
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

    def make_finding(
        self,
        signal: Signal,
        score: float,
        level: str,
        file_path: str,
        line: Optional[int],
        block_name: Optional[str],
        evidence: list[str],
        metadata: Optional[Dict[str, object]] = None,
    ) -> Finding:
        severity = level_to_severity(signal.severity_map, level)
        merged_metadata = dict(metadata or {})
        context = self._context_snippet(file_path, line, block_name)
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
