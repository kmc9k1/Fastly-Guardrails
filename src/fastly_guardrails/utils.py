from __future__ import annotations

import re
from pathlib import Path


PROD_LIKE_TERMS = {
    "prod", "production", "live", "primary", "public", "checkout", "account", "api", "edge"
}
NON_PROD_TERMS = {"dev", "test", "sandbox", "stage", "staging", "example", "sample", "lab", "local"}
LOGGING_TOKENS = {
    "logging",
    "logentries",
    "datadog",
    "splunk",
    "syslog",
    "s3",
    "kafka",
    "bigquery",
    "gcs",
    "https_endpoint",
    "papertrail",
    "newrelic",
    "sumologic",
    "elasticsearch",
}
SHIELD_TOKENS = {"shield", "request_setting", "shielding"}
OBSERVABILITY_TOKENS = LOGGING_TOKENS | {"debug", "trace", "x-debug", "x-trace"}


GENERIC_BACKEND_NAMES = {"backend1", "backend2", "origin1", "origin2", "temp", "test", "foo", "bar"}


def normalize_text(text: str) -> str:
    return text.lower()


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def confidence_level(score: float) -> str:
    if score >= 0.70:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


def severity_rank(severity: str) -> int:
    return {"info": 1, "warn": 2, "error": 3}.get(severity, 0)


def is_probably_prod(text: str) -> bool:
    lowered = normalize_text(text)
    return any(term in lowered for term in PROD_LIKE_TERMS) and not any(term in lowered for term in NON_PROD_TERMS)


def has_non_prod_markers(text: str) -> bool:
    lowered = normalize_text(text)
    return any(term in lowered for term in NON_PROD_TERMS)


def has_logging_tokens(text: str) -> bool:
    lowered = normalize_text(text)
    return any(token in lowered for token in LOGGING_TOKENS)


def has_shield_tokens(text: str) -> bool:
    lowered = normalize_text(text)
    return any(token in lowered for token in SHIELD_TOKENS)


def has_observability_tokens(text: str) -> bool:
    lowered = normalize_text(text)
    return any(token in lowered for token in OBSERVABILITY_TOKENS)


def is_direct_ip(value: str) -> bool:
    value = value.strip().strip('"').strip("'")
    ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    return bool(ipv4.match(value) or (":" in value and ipv6.match(value)))


def context_window(lines: list[str], line_index_zero_based: int, radius: int = 5) -> str:
    start = max(0, line_index_zero_based - radius)
    end = min(len(lines), line_index_zero_based + radius + 1)
    return "\n".join(lines[start:end])


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
