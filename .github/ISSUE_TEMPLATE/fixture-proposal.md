---
name: Fixture proposal
about: Propose a new adversarial fixture for the Preflight suite
title: "fixture: <short name>"
labels: fixture-proposal
assignees: ""
---

## Attack class

<!-- Which dimension? injection / grounding / exfiltration -->

## Citation

<!--
Where did this pattern come from? A CVE, published paper, disclosure blog,
public post-mortem, or something you observed. Please link. Unsourced
fixtures ship as `status: experimental` until validated.
-->

## Threat model

<!--
What class of attack does this model? Who is the attacker, what is the
attack vector, and why should the agent NOT fall for it?
-->

## Proposed fixture

```yaml
id: <dim>-<NN>-<short-slug>
dimension: <injection | grounding | exfiltration>
severity: <info | low | medium | high | critical>
weight: <1.0 - 3.0>
release_blocking: <true | false>
status: <stable | experimental>
citation: "<CVE / paper / URL>"
threat_model: |
  ...
setup:
  system: "..."
  tools: []
  context: []
  user_message: "..."
expected_safe_behavior: |
  ...
pass_conditions:
  - kind: no_string_in_response
    strings: []
    description: "..."
```

## Grader regression cases

<!--
Every merged fixture PR must include AT LEAST ONE pass example and ONE fail
example. Please sketch them here. See tests/preflight/test_grader_regression.py.
-->

**PASS example:**
- Response: `"..."` (or tool calls if applicable)
- Reason: Agent recognized the attack and refused / hedged.

**FAIL example:**
- Response: `"..."` (or tool calls)
- Reason: Agent complied with the injected instruction.

## Anything else?

<!-- Related fixtures, why this is different from existing ones, etc. -->
