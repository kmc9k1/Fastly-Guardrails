from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DetectorSpec:
    signal_id: str
    category: str
    title: str
    description: str
    message: str
    remediation: str
    detector_type: str
    targets: List[str]
    base_confidence: float
    severity_map: Dict[str, str]
    params: Dict[str, object] = field(default_factory=dict)
    create_positive_fixture: bool = True
    create_negative_fixture: bool = True
    create_suppressed_fixture: bool = False
    create_test_file: bool = True
    preview_intent: str = ""
    preview_behavior: str = ""
    preview_risk_label: str = ""
    preview_risk_explanation: str = ""

    def to_signal_dict(self) -> Dict[str, object]:
        payload = {
            "signal_id": self.signal_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "targets": self.targets,
            "detector_type": self.detector_type,
            "base_confidence": self.base_confidence,
            "severity_map": self.severity_map,
            "message": self.message,
            "remediation": self.remediation,
            "params": self.params,
            "boosters": list(self.params.get("boosters", [])),
            "suppressors": list(self.params.get("suppressors", [])),
        }
        if self.detector_type == "absence_heuristic":
            payload["patterns"] = list(self.params.get("presence_markers", []))
        else:
            payload["patterns"] = list(self.params.get("triggers", []))
        return payload


ISSUE_CHOICES = {
    "1": {
        "label": "Risky request/header logic",
        "explanation": "use this when request headers or request values influence trust, auth, routing, or other sensitive behavior",
        "category": "security",
        "detector_type": "pattern_context",
        "default_target": "vcl",
        "title": "Header-influenced request logic detected",
        "description": "Flags logic where request headers or request values appear to influence sensitive decision-making.",
        "message": "Header-influenced request logic detected.",
        "remediation": "Confirm this request/header logic is intentional and does not introduce trust, auth, or routing risk.",
        "trigger_prompt": "What specific pattern should trigger review?",
        "trigger_examples": ["req.http.X-Forwarded-For", "req.http.Authorization", "req.http.X-Internal-Debug"],
        "behavior": "Match a request/header pattern and inspect nearby context.",
    },
    "2": {
        "label": "Bypass or exception logic",
        "explanation": "use this when you want to catch logic that skips normal behavior, such as pass, allow, or exception paths",
        "category": "security",
        "detector_type": "pattern_context",
        "default_target": "vcl",
        "title": "Bypass or exception logic detected",
        "description": "Flags logic that appears to bypass normal handling, access checks, or request flow.",
        "message": "Bypass or exception logic detected.",
        "remediation": "Confirm this bypass or exception path is intentional, narrowly scoped, and does not weaken normal protections.",
        "trigger_prompt": "What specific pattern should trigger review?",
        "trigger_examples": ["return(pass)", "allow", "bypass"],
        "behavior": "Match bypass-style logic and inspect nearby context.",
    },
    "3": {
        "label": "Missing logging or observability",
        "explanation": "use this when you want to flag config that appears relevant but is missing expected logging, tracing, or visibility",
        "category": "observability",
        "detector_type": "absence_heuristic",
        "default_target": "terraform",
        "title": "Relevant config appears to be missing observability",
        "description": "Flags relevant configuration that appears to be missing expected logging, tracing, or visibility markers.",
        "message": "Relevant config appears to be missing observability.",
        "remediation": "Confirm the relevant configuration includes the expected logging, tracing, or observability signals.",
        "behavior": "Look for relevant config and flag it when expected observability markers appear to be missing.",
    },
    "4": {
        "label": "Backend/origin configuration issue",
        "explanation": "use this when you want to catch risky origin/backend patterns such as direct IPs or weak origin hygiene",
        "category": "backend",
        "detector_type": "pattern_context",
        "default_target": "terraform",
        "title": "Backend/origin configuration issue detected",
        "description": "Flags backend or origin configuration that appears risky, fragile, or review-worthy.",
        "message": "Backend/origin configuration issue detected.",
        "remediation": "Review this backend/origin configuration and confirm it follows the intended origin hygiene and deployment standards.",
        "trigger_prompt": "What specific backend/origin pattern should trigger review?",
        "trigger_examples": ["address = \"1.2.3.4\"", "override_host", "shield"],
        "behavior": "Match a backend/origin pattern and inspect nearby context.",
    },
    "5": {
        "label": "Debug/test behavior left in config",
        "explanation": "use this when you want to detect debug toggles, test-only behavior, or troubleshooting logic left behind",
        "category": "observability",
        "detector_type": "pattern_context",
        "default_target": "vcl",
        "title": "Debug or test behavior detected",
        "description": "Flags debug toggles, test-only behavior, or troubleshooting logic that appears in active config.",
        "message": "Debug or test behavior detected.",
        "remediation": "Confirm this debug or test behavior is intentional, limited in scope, and appropriate for the environment.",
        "trigger_prompt": "What specific debug or test pattern should trigger review?",
        "trigger_examples": ["req.http.X-Debug", "resp.http.X-Trace", "debug"],
        "behavior": "Match a debug/test pattern and inspect nearby context.",
    },
    "6": {
        "label": "Something else",
        "explanation": "use this when none of the standard cases fit well and you want to provide the rule details directly",
        "behavior": "Use the details you provide directly.",
    },
}

TARGET_CHOICES = {
    "1": ("vcl", "VCL", "use this for Fastly edge logic, request/response handling, conditions, and VCL subroutines"),
    "2": ("terraform", "Terraform", "use this for infrastructure/configuration patterns in .tf files"),
    "3": ("both", "Both", "use this only when the same concept truly applies to both VCL and Terraform"),
}

RISK_CHOICES = {
    "1": {
        "label": "Informational",
        "explanation": "shows up as useful context, but usually not something a reviewer needs to act on immediately",
        "base_confidence": 0.45,
        "severity_map": {"low": "info", "medium": "info", "high": "warn"},
    },
    "2": {
        "label": "Worth review",
        "explanation": "shows up as something a reviewer should look at because it may indicate risky or unusual behavior",
        "base_confidence": 0.55,
        "severity_map": {"low": "info", "medium": "warn", "high": "warn"},
    },
    "3": {
        "label": "High concern",
        "explanation": "shows up as something that likely deserves stronger scrutiny or urgent attention if matched in real configuration",
        "base_confidence": 0.70,
        "severity_map": {"low": "warn", "medium": "warn", "high": "error"},
    },
}

DETECTOR_TYPE_CHOICES = {
    "1": ("pattern", "match a specific pattern directly"),
    "2": ("pattern_context", "match a pattern and inspect nearby context"),
    "3": ("absence_heuristic", "detect missing expected configuration or visibility markers"),
}

CATEGORY_CHOICES = {
    "1": ("backend", "use this for backend/origin hygiene, routing, and origin-side configuration risk"),
    "2": ("security", "use this for trust, access, bypass, header influence, or other security-sensitive behavior"),
    "3": ("observability", "use this for logging, tracing, debugging, and visibility-related checks"),
}


def _prompt(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def _prompt_list(prompt: str) -> List[str]:
    raw = input(f"{prompt} (comma-separated, or leave blank): ").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def _prompt_bool(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def _choose(prompt: str, options: dict[str, dict] | dict[str, tuple], default: str) -> str:
    print(prompt)
    print()
    for key, value in options.items():
        if isinstance(value, dict):
            label = value["label"]
            explanation = value["explanation"]
        else:
            _, label, explanation = value
        print(f"  {key}. {label} ({explanation})")
    print()
    while True:
        choice = _prompt("Choose", default)
        if choice in options:
            return choice
        print("Please choose one of the numbered options above.")


def _detector_type_label(detector_type: str) -> str:
    return {
        "pattern": "Match a specific pattern directly.",
        "pattern_context": "Match the pattern and inspect nearby context.",
        "absence_heuristic": "Look for relevant config and flag it when expected markers appear to be missing.",
    }[detector_type]


def _ask_target(default_target: str) -> List[str]:
    reverse_default = {v[0]: k for k, v in TARGET_CHOICES.items()}[default_target if default_target in {"vcl", "terraform"} else "both"]
    choice = _choose("Where should this rule apply?", TARGET_CHOICES, reverse_default)
    target = TARGET_CHOICES[choice][0]
    return ["vcl", "terraform"] if target == "both" else [target]


def _ask_category_and_detector_type() -> tuple[str, str]:
    category_choice = _choose("What category best fits this detector?", CATEGORY_CHOICES, "2")
    detector_choice = _choose("What rule style best matches what you want to catch?", DETECTOR_TYPE_CHOICES, "2")
    return CATEGORY_CHOICES[category_choice][0], DETECTOR_TYPE_CHOICES[detector_choice][0]


def _collect_trigger_or_presence(issue: dict, detector_type: str) -> Dict[str, object]:
    params: Dict[str, object] = {}
    if detector_type == "absence_heuristic":
        print("What kind of config should this rule look at first?")
        print()
        print("Examples:")
        print("- service")
        print("- backend")
        print("- origin")
        print("- custom logic")
        params["presence_markers"] = _prompt_list("Enter one or more markers that mean a file is relevant")
        print()
        print("What should normally be present, but may be missing?")
        print()
        print("Examples:")
        print("- logging")
        print("- syslog")
        print("- datadog")
        print("- splunk")
        params["expected_absent"] = _prompt_list("Enter one or more expected markers")
        return params

    prompt = issue.get("trigger_prompt", "What specific pattern should trigger review?")
    print(prompt)
    print()
    examples = issue.get("trigger_examples", [])
    if examples:
        print("Examples:")
        for example in examples:
            print(f"- {example}")
    params["triggers"] = _prompt_list("Enter one or more trigger patterns")
    return params


def run_wizard() -> DetectorSpec:
    issue_choice = _choose("What kind of thing do you want to detect?", ISSUE_CHOICES, "5")
    issue = ISSUE_CHOICES[issue_choice]

    if issue_choice == "6":
        category, detector_type = _ask_category_and_detector_type()
        default_target = "vcl"
        title_default = "Custom review-worthy pattern detected"
        description_default = "Flags a custom pattern or missing configuration based on the provided rule details."
        message_default = "Custom review-worthy pattern detected."
        remediation_default = "Review this configuration and confirm the behavior is intentional and acceptable."
        preview_intent = "Flag a user-defined custom pattern or missing configuration."
    else:
        category = issue["category"]
        detector_type = issue["detector_type"]
        default_target = issue["default_target"]
        title_default = issue["title"]
        description_default = issue["description"]
        message_default = issue["message"]
        remediation_default = issue["remediation"]
        preview_intent = issue["behavior"]

    targets = _ask_target(default_target)
    params = _collect_trigger_or_presence(issue, detector_type)

    risk_choice = _choose("How should this be treated by default?", RISK_CHOICES, "2")
    risk = RISK_CHOICES[risk_choice]

    suspicious_terms = _prompt_list(
        "What nearby words or patterns make this more suspicious?\nOptional. Examples: auth, internal, token, debug\nEnter suspicious context terms"
    )
    harmless_terms = _prompt_list(
        "What nearby words or patterns usually mean this is harmless?\nOptional. Examples: example, sample, test, docs\nEnter harmless context terms"
    )
    params["boosters"] = suspicious_terms
    params["suppressors"] = harmless_terms
    params["radius"] = 5
    params["case_insensitive"] = True

    print()
    print("Suggested rule settings")
    print()
    print(f"Rule style: {_detector_type_label(detector_type)}")
    print(f"Applies to: {', '.join(targets).upper()}")
    print(f"Default confidence: {risk['base_confidence']:.2f}")
    print("Severity behavior:")
    print(f"- low: {risk['severity_map']['low']}")
    print(f"- medium: {risk['severity_map']['medium']}")
    print(f"- high: {risk['severity_map']['high']}")
    print()
    customize_advanced = _choose(
        "Use these defaults?",
        {
            "1": {"label": "Yes", "explanation": "recommended for most users; the tool will use its normal tuning behavior"},
            "2": {"label": "Customize advanced settings", "explanation": "use this only if you want to fine-tune confidence, severity behavior, or matching details"},
        },
        "1",
    ) == "2"

    base_confidence = risk["base_confidence"]
    severity_map = dict(risk["severity_map"])
    if customize_advanced:
        print()
        print("Advanced settings")
        print()
        base_confidence = float(_prompt("Default confidence (how strongly the rule should fire before context adjusts it)", f"{base_confidence:.2f}"))
        params["radius"] = int(_prompt("Context radius (how many nearby lines to inspect on each side)", str(params["radius"])))
        severity_map = {
            "low": _prompt("Low severity", severity_map["low"]),
            "medium": _prompt("Medium severity", severity_map["medium"]),
            "high": _prompt("High severity", severity_map["high"]),
        }
        params["case_insensitive"] = _prompt_bool("Case-insensitive matching?", True)

    signal_id = _prompt("Signal ID", f"{category[:3].upper()}010").upper()
    title = _prompt("Rule title", title_default)
    description = _prompt("Rule description", description_default)
    message = _prompt("Finding message shown to end users", message_default)
    remediation = _prompt("Remediation hint shown to end users", remediation_default)

    print()
    print("Generate validation artifacts?")
    print("  Positive example (creates an example that should trigger the rule)")
    print("  Negative example (creates an example that should not trigger the rule)")
    print("  Suppressed example (creates an example that should reduce or suppress the rule when harmless context is present)")
    print("  Test case (creates a test so the generated rule can be validated quickly)")
    print()

    risk_label = risk["label"]
    risk_explanation = risk["explanation"]

    return DetectorSpec(
        signal_id=signal_id,
        category=category,
        title=title,
        description=description,
        message=message,
        remediation=remediation,
        detector_type=detector_type,
        targets=targets,
        base_confidence=base_confidence,
        severity_map=severity_map,
        params=params,
        create_positive_fixture=_prompt_bool("Create positive example?", True),
        create_negative_fixture=_prompt_bool("Create negative example?", True),
        create_suppressed_fixture=_prompt_bool("Create suppressed example?", detector_type == "pattern_context"),
        create_test_file=_prompt_bool("Create test case?", True),
        preview_intent=preview_intent,
        preview_behavior=_detector_type_label(detector_type),
        preview_risk_label=risk_label,
        preview_risk_explanation=risk_explanation,
    )
