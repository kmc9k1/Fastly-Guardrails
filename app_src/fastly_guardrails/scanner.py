from __future__ import annotations

from typing import Optional, Set

from .engine.registry import load_signals
from .engine.signal_engine import SignalEngine
from .models import Finding
from .parser import collect_documents
from .utils import severity_rank


class FastlyGuardrails:
    def __init__(self, root: str) -> None:
        self.root = root
        self.parsed = collect_documents(root)
        self.signals = load_signals()

    def scan(self, categories: Optional[Set[str]] = None, min_severity: str = "info") -> list[Finding]:
        engine = SignalEngine(self.parsed, self.signals)
        findings = engine.run(categories=categories)
        min_rank = severity_rank(min_severity)
        return [finding for finding in findings if severity_rank(finding.severity) >= min_rank]
