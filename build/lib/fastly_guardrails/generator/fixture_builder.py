from __future__ import annotations

from typing import Dict

from .wizard import DetectorSpec

def _wrap_vcl(body: str) -> str:
    return f"sub vcl_recv {{\n{body}\n}}\n"


def _indent(lines):
    return "\n".join(f"  {line}" for line in lines)


def build_fixtures(spec: DetectorSpec) -> Dict[str, str]:
    return _build_terraform_fixtures(spec) if "terraform" in spec.targets else _build_vcl_fixtures(spec)


def _build_vcl_fixtures(spec: DetectorSpec) -> Dict[str, str]:
    triggers = list(spec.params.get("triggers", [])) or ["req.http.X-Example"]
    boosters = list(spec.params.get("boosters", []))
    suppressors = list(spec.params.get("suppressors", []))

    if spec.detector_type == "absence_heuristic":
        presence = list(spec.params.get("presence_markers", [])) or ["backend"]
        expected_absent = list(spec.params.get("expected_absent", [])) or ["logging"]
        return {
            "positive": _wrap_vcl(_indent([f"# presence: {presence[0]}", 'set req.http.X-Present = "1";'])),
            "negative": _wrap_vcl(_indent([f"# presence: {presence[0]}", f"# expected: {expected_absent[0]}", 'set req.http.X-Present = "1";'])),
        }

    primary = triggers[0]
    positive_lines = [f"if ({primary} == \"1\") {{"]
    if boosters:
        positive_lines.append(f"  # booster: {boosters[0]}")
    positive_lines.extend(["  return(pass);", "}"])
    fixtures = {
        "positive": _wrap_vcl(_indent(positive_lines)),
        "negative": _wrap_vcl(_indent(['if (req.url.path == "/safe") {', '  return(pass);', '}'])),
    }
    if suppressors:
        fixtures["suppressed"] = _wrap_vcl(_indent([f"if ({primary} == \"1\") {{", f"  # {suppressors[0]}", "  return(pass);", "}"]))
    return fixtures


def _build_terraform_fixtures(spec: DetectorSpec) -> Dict[str, str]:
    triggers = list(spec.params.get("triggers", [])) or ["http://origin.example.internal"]
    boosters = list(spec.params.get("boosters", []))
    suppressors = list(spec.params.get("suppressors", []))
    primary = triggers[0]
    lines = ['resource "fastly_backend" "example" {']
    if boosters:
        lines.append(f"  # booster: {boosters[0]}")
    lines.append(f'  address = "{primary}"')
    lines.append("}")
    fixtures = {
        "positive": "\n".join(lines),
        "negative": '\n'.join(['resource "fastly_backend" "safe" {', '  address = "origin.example.internal"', '}']),
    }
    if suppressors:
        fixtures["suppressed"] = "\n".join(['resource "fastly_backend" "suppressed" {', f"  # {suppressors[0]}", f'  address = "{primary}"', '}'])
    return fixtures
