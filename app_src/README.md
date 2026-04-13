# Fastly Guardrails v1

A heuristic Fastly safety scanner for Terraform and VCL.

This tool is designed as a **review assistant**, not a strict policy gate. It scans `.tf` and `.vcl` files for three categories of issues:

- backend / origin hygiene
- security anti-patterns
- observability gaps

It emits findings with:

- category
- signal id
- severity
- confidence score and level
- source file and line
- evidence
- remediation hint

## Why this exists

This is useful in environments that are:

- new to Fastly
- migrating from another CDN
- heavily Terraform-driven
- still converging on consistent edge patterns

The scanner is intentionally heuristic. Many findings are phrased as **"review this"** rather than **"this is definitively wrong"**.

## Signals in v1

Implemented signals:

- `BKG001` — Backend uses plain HTTP
- `BKG002` — Direct IP origin detected
- `BKG003` — Production-like backend with no obvious shield signal
- `SEC001` — Client-controlled header influences trust/access logic
- `SEC002` — Bypass-style conditional detected
- `SEC005` — Spoofable rate-limit identity source
- `OBS001` — No obvious logging configuration detected
- `OBS002` — Custom edge logic with weak visibility story

## Installation

No third-party dependencies are required.

```bash
python3 --version
python3 -m fastly_guardrails --help
```

Or run the entrypoint directly:

```bash
python3 fastly_guardrails/cli.py --help
```

## Usage

Scan a repository or directory:

```bash
python3 -m fastly_guardrails scan /path/to/repo
```

Emit JSON:

```bash
python3 -m fastly_guardrails scan /path/to/repo --format json
```

Restrict to certain categories:

```bash
python3 -m fastly_guardrails scan /path/to/repo --category security --category observability
```

Treat selected signals as blockers:

```bash
python3 -m fastly_guardrails scan /path/to/repo --fail-on SEC001 --fail-on BKG001
```

Hide informational findings:

```bash
python3 -m fastly_guardrails scan /path/to/repo --min-severity warn
```

## Output example

```text
ERROR [security] SEC001 confidence=0.88 high
  file: snippets/recv_security.vcl:42
  block: recv_security
  message: Client-controlled header appears to influence trust or access logic.
  evidence: if (req.http.X-Origin-Token == "expected") {
  hint: Do not trust client-supplied headers for origin trust or access control.
```

## Notes on implementation

- Terraform parsing is intentionally lightweight and heuristic.
- VCL scanning is line-oriented with block-aware context windows.
- Absence-based findings are generated at the service / module level and have lower default confidence.
- This project is meant to be easy to extend as your Fastly standards harden over time.


## PDF reports

Generate a styled PDF report from the same findings engine:

```bash
python3 -m fastly_guardrails report tests/fixtures/sample_repo --output sample_report.pdf
```

Optional filters work here too:

```bash
python3 -m fastly_guardrails report repo/ --min-severity warn --category security --output security_report.pdf
```
