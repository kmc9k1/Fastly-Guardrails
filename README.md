# Fastly Guardrails

Fastly Guardrails scans Terraform and VCL for risky, suspicious, or review-worthy Fastly patterns, then presents the results in terminal output or a styled PDF report.

It is designed to support both:

- **installed usage** for normal users
- **source development** for contributors

---

## What it does

Fastly Guardrails looks for findings in three main areas:

- **Backend / Origin Hygiene**
- **Security Anti-Patterns**
- **Observability Gaps**

It supports:

- terminal scan output
- JSON output
- styled PDF report generation
- grouped findings to reduce duplicate noise
- contextual code blocks so findings are easier to review

---

## Installed Usage

### Install

1. Download and extract the bootstrap bundle.
2. Open a terminal in the extracted folder.
3. Run:

```bash
./fastly_guardrails install
```

The installer will:

- verify a compatible Python version is available
- create a managed install under `~/.fastly_guardrails`
- create a launcher at `~/.local/bin/fastly_guardrails`
- optionally offer to add `~/.local/bin` to your shell `PATH`

### After install

Check that the tool is available:

```bash
fastly_guardrails doctor
```

If the command is not found yet, restart your shell or reload your shell profile.

For zsh:

```bash
source ~/.zshrc
```

If you chose not to let the installer add `~/.local/bin` to your `PATH`, add this line to your shell profile manually:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Basic Commands

### Scan a repository or directory

```bash
fastly_guardrails scan /path/to/repo
```

### JSON output

```bash
fastly_guardrails scan /path/to/repo --format json
```

### Limit to a category

```bash
fastly_guardrails scan /path/to/repo --category security
```

Available categories:

- `backend`
- `security`
- `observability`

### Hide lower-severity findings

```bash
fastly_guardrails scan /path/to/repo --min-severity warn
```

Severity levels:

- `info`
- `warn`
- `error`

### Disable color output

```bash
fastly_guardrails scan /path/to/repo --no-color
```

---

## PDF Reports

Create a styled PDF report from the scan results:

```bash
fastly_guardrails report /path/to/repo --output report.pdf
```

You can also filter reports:

```bash
fastly_guardrails report /path/to/repo --category security --min-severity warn --output security_report.pdf
```

---

## Doctor

Check whether the install is healthy:

```bash
fastly_guardrails doctor
```

This checks things like:

- launcher presence
- managed install root
- Python availability
- PDF report support
- whether the launcher directory is in `PATH`

---

## Uninstall

Preview what would be removed:

```bash
fastly_guardrails uninstall --dry-run
```

Remove the tool:

```bash
fastly_guardrails uninstall
```

The uninstall process is designed to remove only tool-managed files created by the installer.

---

## Managed Install Locations

Fastly Guardrails installs into user-owned paths under your home directory:

- managed root: `~/.fastly_guardrails`
- launcher: `~/.local/bin/fastly_guardrails`

It does not require you to manually activate a virtual environment during normal use.

---

## Example Installed Workflow

Install the tool:

```bash
./fastly_guardrails install
```

Run a scan:

```bash
fastly_guardrails scan /path/to/repo
```

Generate a report:

```bash
fastly_guardrails report /path/to/repo --output report.pdf
```

Check install health later:

```bash
fastly_guardrails doctor
```

Uninstall if needed:

```bash
fastly_guardrails uninstall --dry-run
fastly_guardrails uninstall
```

---

## Source Development

For source development, use an editable install once, then work from the repository root.

### Recommended setup

```bash
python3 -m venv .venv
source .venv/bin/activate
cd app_src
python3 -m pip install -e .
cd ..
```

After that, you can run development commands from the repository root.

### Run the test suite

```bash
python3 -m pytest -q app_src/tests
```

### Smoke-test the scanner

```bash
python3 -m fastly_guardrails scan app_src/tests/fixtures/sample_repo
```

### Generate a report from the sample repo

```bash
python3 -m fastly_guardrails report app_src/tests/fixtures/sample_repo --output sample_report.pdf
```

---

## Creating New Detectors with the Wizard

Fastly Guardrails includes a guided detector scaffold generator so you can add new detectors without manually wiring every file yourself.

From the repository root, run:

```bash
python3 -m fastly_guardrails create-detector --project-root app_src
```

### What the wizard asks for

The wizard will walk you through:

- signal ID
- category
- title
- description
- finding message
- remediation hint
- detector type
- targets (`terraform`, `vcl`, or both)
- base confidence
- severity mapping for `low`, `medium`, and `high`
- trigger patterns
- boosters
- suppressors
- fixture/test generation options

### Supported detector types

Current scaffolded detector types:

- `pattern`
- `pattern_context`
- `absence_heuristic`

These are template-backed detectors. More complex or highly specialized detectors can still live as custom Python detectors.

### What gets generated

After you answer the prompts, the wizard shows a preview of the planned changes and asks for confirmation before writing anything.

Depending on the options you choose, it will update or create:

- `app_src/fastly_guardrails/data/signals.json`
- generated fixtures under `app_src/tests/fixtures/generated/`
- a detector test file under `app_src/tests/`

### Example workflow

```bash
python3 -m fastly_guardrails create-detector --project-root app_src
```

Example prompt flow:

```text
Signal ID: OBS010
Category [security]: observability
Title: Debug response header exposed
Description: Flags debug response headers that appear to be delivered to clients.
Finding message: Debug response header detected.
Remediation hint: Confirm debug headers are intentional and appropriately scoped.
Detector type (pattern, pattern_context, absence_heuristic) [pattern_context]:
Targets (terraform, vcl) (comma-separated): vcl
Base confidence [0.55]:
Low severity [info]:
Medium severity [warn]:
High severity [error]: warn
Confidence boosters (comma-separated): deliver, debug
Suppressors (comma-separated): example
Context radius [5]:
Case-insensitive matching? [Y/n]:
Primary trigger patterns (comma-separated): resp.http.x-debug
Create positive fixture? [Y/n]:
Create negative fixture? [Y/n]:
Create suppressed fixture? [Y/n]:
Create test file? [Y/n]:
```

After that, the tool will print a preview similar to:

```text
Planned changes:

Signal definition:
{
  "signal_id": "OBS010",
  "category": "observability",
  "title": "Debug response header exposed",
  "description": "Flags debug response headers that appear to be delivered to clients.",
  "targets": [
    "vcl"
  ],
  "detector_type": "pattern_context",
  "base_confidence": 0.55,
  "severity_map": {
    "low": "info",
    "medium": "warn",
    "high": "warn"
  },
  "message": "Debug response header detected.",
  "remediation": "Confirm debug headers are intentional and appropriately scoped.",
  "params": {
    "boosters": [
      "deliver",
      "debug"
    ],
    "suppressors": [
      "example"
    ],
    "radius": 5,
    "case_insensitive": true,
    "triggers": [
      "resp.http.x-debug"
    ]
  },
  "boosters": [
    "deliver",
    "debug"
  ],
  "suppressors": [
    "example"
  ],
  "patterns": [
    "resp.http.x-debug"
  ]
}

Files to write:
  - app_src/fastly_guardrails/data/signals.json
  - app_src/tests/fixtures/generated/obs010_positive.vcl
  - app_src/tests/fixtures/generated/obs010_negative.vcl
  - app_src/tests/fixtures/generated/obs010_suppressed.vcl
  - app_src/tests/test_obs010.py
```

Then confirm:

```text
Write these changes? [y/N]:
```

---

## Generated Fixture Validation

The generator creates offline fixtures based on the detector definition you entered.

Typical outputs include:

- **positive fixture**: should trigger the detector
- **negative fixture**: should not trigger the detector
- **suppressed fixture**: should reduce or suppress the detector when suppressor terms are present

This is intentionally template-driven so detector creation and validation do not depend on internet access.

After generating a detector, run:

```bash
python3 -m pytest -q app_src/tests
```

If you want to scan the generated fixtures directly:

```bash
python3 -m fastly_guardrails scan app_src/tests/fixtures/generated
```

---

## Current Limitations

The current wizard scaffolds **template-backed detectors** by updating signal metadata and generating fixtures/tests.

It does **not yet** generate brand-new custom Python detector modules automatically for advanced signals. For more specialized checks, add a custom detector under:

```text
app_src/fastly_guardrails/detectors/custom/
```

and wire it through the engine/registry as needed.

---

## Troubleshooting

### `fastly_guardrails: command not found`

Your shell may not have reloaded yet, or `~/.local/bin` may not be in your `PATH`.

Reload your shell profile:

```bash
source ~/.zshrc
```

Or add this manually:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### PDF reporting is unavailable

Run:

```bash
fastly_guardrails doctor
```

If PDF support is missing, reinstall using the bootstrap installer so the managed environment can be rebuilt correctly.

### Development commands cannot import `fastly_guardrails`

Make sure you completed the editable install step under **Source Development**:

```bash
python3 -m venv .venv
source .venv/bin/activate
cd app_src
python3 -m pip install -e .
cd ..
```

---

## Notes

Fastly Guardrails is heuristic by design. Findings are intended to help reviewers spot risky or suspicious patterns quickly, not to act as a formal proof that a configuration is correct or incorrect.

---