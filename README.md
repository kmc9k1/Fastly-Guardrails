# Fastly Guardrails

Fastly Guardrails scans Terraform and VCL for risky, suspicious, or review-worthy Fastly patterns, then presents the results in either terminal output or a styled PDF report.

It is designed to be usable by non-developers after installation, without needing to manually manage Python virtual environments.

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

## Installation

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

---

## After install

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

## Basic usage

### Scan a repository or directory

```bash
fastly_guardrails scan /path/to/repo
```

Example:

```bash
fastly_guardrails scan tests/fixtures/sample_repo
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

## Generate a PDF report

Create a styled PDF report from the scan results:

```bash
fastly_guardrails report /path/to/repo --output report.pdf
```

Example:

```bash
fastly_guardrails report tests/fixtures/sample_repo --output sample_report.pdf
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

## Managed install locations

Fastly Guardrails installs into user-owned paths under your home directory:

- managed root: `~/.fastly_guardrails`
- launcher: `~/.local/bin/fastly_guardrails`

It does not require you to manually activate a virtual environment during normal use.

---

## Example workflow

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


---

## Notes

Fastly Guardrails is heuristic by design. Findings are intended to help reviewers spot risky or suspicious patterns quickly, not to act as a formal proof that a configuration is correct or incorrect.