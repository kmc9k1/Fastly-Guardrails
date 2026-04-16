# Fastly Guardrails

Fastly Guardrails is an installed product for scanning Terraform and VCL for risky, suspicious, or review-worthy Fastly patterns. After installation, it is designed to work from anywhere without requiring a checkout, repo navigation, or Python-specific workflow knowledge.

## Install

Download the bundle, extract it, and run:

```bash
./fastly_guardrails_bootstrap install
```

After installation, the tool provides two commands on your PATH:

- `fastly_guardrails` - the application
- `fastly_guardrails_bootstrap` - install, doctor, and uninstall support

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

The detector wizard is designed to be intent-first. It asks what kind of issue you want to detect, where it should apply, what pattern or missing configuration should trigger review, and how risky the rule should be by default.

A typical workflow looks like this:

```bash
fastly_guardrails create-detector
fastly_guardrails test
fastly_guardrails scan-fixture generated
```

The wizard will:

- help you choose a rule style based on what you are trying to catch
- explain each selection in plain English
- suggest sensible defaults for confidence and severity behavior
- generate validation artifacts such as positive, negative, and suppressed examples
- show a plain-English preview before anything is written

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
