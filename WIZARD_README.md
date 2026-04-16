# Fastly Guardrails Wizard Guide

This guide explains the detector creation wizard in detail.

Start it with:

```bash
fastly_guardrails create-detector
```

The wizard is designed to be intent-first. Instead of expecting you to understand internal detector-engine terminology up front, it starts by asking what you are trying to catch and where the rule should apply.

## The high-level flow

The wizard walks through detector creation in this order:

1. what kind of issue you want to detect
2. where the rule should apply
3. what should trigger review
4. how risky the rule should be by default
5. what nearby context should make the match more or less concerning
6. whether to accept the suggested defaults or customize advanced settings
7. whether to generate validation artifacts
8. a plain-English preview before writing anything

## Step 1: Choose the kind of issue

The first prompt asks what kind of thing you want to detect.

Example menu:

```text
What kind of thing do you want to detect?

  1. Risky request/header logic (use this when request headers or request values influence trust, auth, routing, or other sensitive behavior)
  2. Bypass or exception logic (use this when you want to catch logic that skips normal behavior, such as pass, allow, or exception paths)
  3. Missing logging or observability (use this when you want to flag config that appears relevant but is missing expected logging, tracing, or visibility)
  4. Backend/origin configuration issue (use this when you want to catch risky origin/backend patterns such as direct IPs or weak origin hygiene)
  5. Debug/test behavior left in config (use this when you want to detect debug toggles, test-only behavior, or troubleshooting logic left behind)
  6. Something else (use this when none of the above fit well and you want to provide the rule details directly)
```

This choice helps the tool choose a sensible detector style and default behavior.

## Step 2: Choose where it should apply

The wizard then asks where the detector should run.

Example menu:

```text
Where should this rule apply?

  1. VCL (use this for Fastly edge logic, request/response handling, conditions, and VCL subroutines)
  2. Terraform (use this for infrastructure/configuration patterns in `.tf` files)
  3. Both (use this only when the same concept truly applies to both VCL and Terraform)
```

Pick the narrowest scope that makes sense. Narrower rules are usually easier to understand and validate.

## Step 3: Define what should trigger review

The next prompts depend on the kind of rule you are creating.

### Pattern-based rules

If the detector is looking for a token or line pattern, the wizard will ask for trigger patterns.

Example:

```text
What specific pattern should trigger review?

Examples:
- req.http.X-Debug
- req.http.X-Forwarded-For
- resp.http.X-Trace

Enter one or more trigger patterns (comma-separated):
```

### Missing-config rules

If the detector is about expected configuration being absent, the wizard asks two questions:

1. what markers mean a file is relevant
2. what should normally be present but may be missing

Example:

```text
What kind of config should this rule look at first?

Examples:
- service
- backend
- origin
- custom logic

Enter one or more markers that mean a file is relevant:
```

Then:

```text
What should normally be present, but may be missing?

Examples:
- logging
- syslog
- datadog
- splunk

Enter one or more expected markers:
```

## Step 4: Choose the default risk level

Instead of exposing a severity map immediately, the wizard asks how the rule should be treated by default.

Example:

```text
How should this be treated by default?

  1. Informational (shows up as useful context, but usually not something a reviewer needs to act on immediately)
  2. Worth review (shows up as something a reviewer should look at because it may indicate risky or unusual behavior)
  3. High concern (shows up as something that likely deserves stronger scrutiny or faster attention)
```

The tool maps that choice to internal severity behavior.

## Step 5: Help reduce false positives

The wizard then asks about nearby context.

### More suspicious nearby context

```text
What nearby words or patterns make this more suspicious?
Optional. Examples:
- auth
- internal
- token
- debug
```

These terms make the rule more confident when found near the trigger.

### Usually harmless nearby context

```text
What nearby words or patterns usually mean this is harmless?
Optional. Examples:
- example
- sample
- test
- docs
```

These terms help reduce false positives.

## Step 6: Review suggested defaults

The wizard summarizes the settings it plans to use.

Example:

```text
Suggested rule settings

Rule style: pattern + nearby context
Applies to: VCL
Default confidence: 0.55
Severity behavior:
- low: info
- medium: warn
- high: warn

Use these defaults?

  1. Yes (recommended for most users; the tool will use its normal tuning behavior)
  2. Customize advanced settings (use this only if you want to tune confidence or severity behavior directly)
```

Most users should be able to accept the defaults.

## Step 7: Advanced settings (optional)

If you choose to customize advanced settings, the wizard will expose options such as:

- default confidence
- context radius
- low/medium/high severity behavior
- case sensitivity

Example:

```text
Advanced settings

Default confidence [0.55]:
Context radius [5]:
Low severity [info]:
Medium severity [warn]:
High severity [warn]:
Case-insensitive matching? [Y/n]:
```

These are for users who want finer control over detector behavior.

## Step 8: Generate validation artifacts

The wizard then asks whether it should generate validation artifacts.

Example:

```text
Generate validation artifacts?

  [Y] Positive example (creates an example that should trigger the rule)
  [Y] Negative example (creates an example that should not trigger the rule)
  [Y] Suppressed example (creates an example that should reduce or suppress the rule when harmless context is present)
  [Y] Test case (creates a test so the generated rule can be validated quickly)
```

The defaults are usually the right choice.

## Step 9: Plain-English preview

Before writing anything, the wizard shows a plain-English summary of what it is about to create.

Typical summary content includes:

- rule ID
- what it will look for
- what kind of issue it represents
- where it applies
- what makes it more or less suspicious
- which files will be written

If you want, the wizard can also show technical details after the plain-English summary.

## Step 10: Confirm and write

Once you confirm, the wizard writes the detector definition and any selected validation artifacts into the managed workspace.

## Recommended validation flow

After creating a detector, validate it with:

```bash
fastly_guardrails test
fastly_guardrails scan-fixture generated
```

That confirms the generated detector and fixtures behave the way the wizard intended.

## A good first detector

A good first detector is a debug-header rule in VCL, because it fits the wizard well and produces understandable generated examples.

Conceptually, that might look like:

- kind of issue: debug/test behavior left in config
- applies to: VCL
- trigger pattern: `req.http.X-Debug`
- risk level: worth review
- more suspicious nearby context: `debug, internal, trace`
- usually harmless nearby context: `example, test, sample`

## Current limitations

The wizard currently works best for:

- pattern-based rules
- pattern-plus-context rules
- missing expected configuration rules

More specialized detectors may still require custom detector logic.
