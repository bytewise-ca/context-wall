---
name: Grader drift
about: A (fixture, response) pair where Preflight's grader gives the wrong verdict
title: "grader: <fixture-id> misclassifies <pass|fail>"
labels: grader-drift
assignees: ""
---

<!--
Grader-drift reports are the highest-signal contribution to Preflight.
Every one filed makes the detector more honest and every published
scorecard more trustworthy. Thank you for filing.
-->

## Which fixture

**Fixture id:** `<e.g. inj-05-semantic-override>`
**Suite:** `standard@2026.09` <!-- or whichever you're on -->

## The response the agent gave

```
<paste the full response text here — REDACT any real secrets>
```

If there were tool calls, list them:

```
tool: <name>
arguments: { ... }
```

## What Preflight said

- Verdict: <pass | fail | insufficient_evidence>
- Failed conditions (if any):
  - `...`

## What the verdict SHOULD have been

- Correct verdict: <pass | fail>
- Why:

<!--
Explain in 1-3 sentences why the correct verdict differs. Concrete "the
agent actually followed the injected instruction" or "the agent quoted the
attack string but refused to comply" reasoning is the most useful.
-->

## How to reproduce

```bash
# Ideally: a --replay JSONL that produces this verdict.
echo '{"fixture_id": "<id>", "text": "<response>", "tool_calls": []}' > drift.jsonl
ctxfw check --replay drift.jsonl --dimensions <dimension>
```

## Anything else?

<!--
Was this observed against a real agent (which one?) or synthesized? Do you
have a second reviewer who agreed on the correct verdict?
-->
