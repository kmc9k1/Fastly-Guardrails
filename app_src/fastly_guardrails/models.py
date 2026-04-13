from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class Document:
    path: str
    kind: str
    text: str
    lines: List[str]


@dataclass
class Block:
    file_path: str
    kind: str
    block_type: str
    name: str
    start_line: int
    end_line: int
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Signal:
    signal_id: str
    category: str
    title: str
    description: str
    targets: List[str]
    detector_type: str
    base_confidence: float
    severity_map: Dict[str, str]
    message: str
    remediation: str
    patterns: List[str] = field(default_factory=list)
    boosters: List[str] = field(default_factory=list)
    suppressors: List[str] = field(default_factory=list)


@dataclass
class Finding:
    signal_id: str
    category: str
    severity: str
    confidence_score: float
    confidence_level: str
    file: str
    line: Optional[int]
    block_name: Optional[str]
    message: str
    evidence: List[str]
    hint: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
