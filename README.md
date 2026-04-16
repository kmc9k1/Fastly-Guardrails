# Fastly Guardrails

Fastly Guardrails is an installed product for scanning Terraform and VCL for risky, suspicious, or review-worthy Fastly patterns.

After installation, it is designed to work from anywhere without requiring a checkout, repo navigation, or Python-specific workflow knowledge.

## What install creates

Installation creates a managed Fastly Guardrails environment under your home directory. That managed environment includes:

- the application runtime
- the managed workspace
- built-in fixtures used for validation
- detector-generation output locations
- application state used by the launcher and doctor checks

In normal use, you do not need to interact with those internals directly. The application resolves them automatically.

## Install

Download the bundle, extract it, and run:

```bash
./fastly_guardrails_bootstrap install
```

After installation, the tool provides two commands on your `PATH`:

- `fastly_guardrails` — the application command for scanning, reporting, detector creation, and testing
- `fastly_guardrails_bootstrap` — the lifecycle command for install, doctor, uninstall, and bootstrap-specific help

## First-run validation

After install, validate the environment with:

```bash
fastly_guardrails_bootstrap doctor
fastly_guardrails -h
fastly_guardrails scan-fixture sample_repo
```

That sequence confirms:

- the launcher is working
- the managed runtime is healthy
- the application help is being served by the app, not bootstrap help
- the managed workspace and built-in sample fixture are available

## Normal usage

Scan any directory:

```bash
fastly_guardrails scan /path/to/repo
```

Generate a PDF report:

```bash
fastly_guardrails report /path/to/repo --output report.pdf
```

Create a new detector in the managed workspace:

```bash
fastly_guardrails create-detector
```

Run detector validation checks in the managed workspace:

```bash
fastly_guardrails test
```

Scan a managed fixture:

```bash
fastly_guardrails scan-fixture sample_repo
```

## Detector wizard

The detector wizard is designed to be intent-first. It asks:

- what kind of issue you want to detect
- where the rule should apply
- what pattern or missing configuration should trigger review
- how risky the rule should be by default

A typical workflow looks like this:

```bash
fastly_guardrails create-detector
fastly_guardrails test
fastly_guardrails scan-fixture generated
```

The wizard will:

- help you choose a rule style based on what you are trying to catch
- explain each selection in plain English
- suggest defaults for confidence and severity behavior
- generate validation artifacts such as positive, negative, and suppressed examples
- show a plain-English preview before anything is written

### What gets generated

When you create a detector, Fastly Guardrails writes generated detector content into the managed workspace. That includes detector definitions and any fixtures or tests you choose to generate.

The managed workspace exists so detector creation and validation work consistently from anywhere, without requiring a checkout or project-specific shell setup.

### How detector validation works

These three commands work together:

- `fastly_guardrails create-detector` — creates the detector and its generated validation artifacts
- `fastly_guardrails test` — runs validation checks in the managed workspace
- `fastly_guardrails scan-fixture generated` — lets you inspect findings produced by generated fixtures

### What the wizard is best at

The wizard currently works best for:

- pattern-based rules
- pattern-plus-context rules
- missing expected configuration rules

For more specialized detectors, custom detector logic may still be appropriate.

For a detailed walkthrough of the wizard flow, see `WIZARD_README.md`.

## Bootstrap support

Health check:

```bash
fastly_guardrails_bootstrap doctor
```

Bootstrap help:

```bash
fastly_guardrails_bootstrap --bootstrap-help
```

Uninstall:

```bash
fastly_guardrails_bootstrap uninstall
```

## Troubleshooting

### `fastly_guardrails: command not found`

Your shell may not have reloaded yet, or `~/.local/bin` may not be in your `PATH`.

For zsh:

```bash
source ~/.zshrc
```

### Reports fail to generate

Run:

```bash
fastly_guardrails_bootstrap doctor
```

If the doctor check reports a problem, reinstall the tool from a clean extracted bundle.

### Detector creation or tests behave unexpectedly

Run:

```bash
fastly_guardrails_bootstrap doctor
fastly_guardrails test
```

If needed, recreate the detector and rerun the validation flow.

## Notes

Fastly Guardrails is heuristic by design. Findings are intended to help reviewers spot risky or suspicious patterns quickly, not to act as a formal proof that a configuration is correct or incorrect.
