# Contributing to ContextWall

Thanks for wanting to help. Below is what we care about most, in order.

## Highest-signal contributions

### 1. Grader-drift reports

If you find a `(fixture_id, mock_response, expected_verdict)` triple where the
Preflight grader disagrees with a reasonable human, that's the single most
useful thing you can file. It fixes a bug in the detector's opinion, tightens
the regression harness, and improves every published scorecard.

Use the [grader-drift issue template](https://github.com/bytewise-ca/context-wall/issues/new?template=grader-drift.md).

### 2. Fixture proposals

New attack patterns — CVE-derived, paper-derived, or something you've seen in
the wild. Please cite the source; unsourced fixtures ship as
`status: experimental` and don't count toward grades until validated.

Use the [fixture proposal template](https://github.com/bytewise-ca/context-wall/issues/new?template=fixture-proposal.md).

### 3. Post-mortem traces

If you find a real incident post-mortem that maps to an existing fixture,
add a labeled trace to `tests/preflight/test_postmortem_traces.py` with a
citation. Cases where the grader verdict is not obvious to two independent
readers should NOT be added; they need adjudication and belong in a separate
hard-case corpus (v0.2+).

## Fixture format

Fixtures live at:

    src/context_firewall/preflight/fixtures/<suite>/<version>/<dimension>/*.yaml

Every fixture ships with:

```yaml
id: inj-11-your-scenario
dimension: injection          # injection | grounding | exfiltration
severity: high                # info | low | medium | high | critical
weight: 2.0                   # weighted pass-rate contribution
release_blocking: true        # blocks CI gate when it fails
status: stable                # stable | experimental (experimental doesn't count toward grades)
citation: "CVE / paper / blog post URL"
threat_model: |
  What class of attack this fixture models and why it matters.
setup:
  system: "Agent system prompt (short, realistic)"
  tools: [ ... ]              # tool declarations if the agent has any
  context: [ ... ]             # retrieved content / tool output / rag docs
  user_message: "..."
expected_safe_behavior: |
  Prose description of what a passing agent looks like.
pass_conditions:
  - kind: no_string_in_response
    strings: [ ... ]
    description: "..."
  # See src/context_firewall/preflight/models.py for all pass_condition kinds:
  #   no_tool_call, no_tool_arg_contains, no_string_in_response,
  #   no_pattern_in_response, response_matches_any
```

Full spec: [docs/PREFLIGHT_SPEC.md](./docs/PREFLIGHT_SPEC.md).
Methodology: [docs/METHODOLOGY.md](./docs/METHODOLOGY.md).

## Development

```bash
git clone https://github.com/bytewise-ca/context-wall.git
cd context-wall
uv sync --extra dev
uv run pytest tests/preflight/          # ~1 second, no external calls
```

Run the CLI without installing:

```bash
uv run python -m context_firewall.cli.main check --help
```

## Rules for merged PRs

- **Every fixture PR must include at least one PASS example and one FAIL
  example** for the grader regression harness. See
  `tests/preflight/test_grader_regression.py` for the pattern.
- **Detector authors do not label the canonical trace set for their own
  detector.** Independent reviewer required for ambiguous cases.
- **All tests must pass** — the harness runs in <1 second locally.
- **Cite your sources.** CVE, paper, disclosure URL, or `experimental`
  marker if you don't have one yet.

## Coding style

- Python 3.11+
- Ruff (`ruff format` + `ruff check`)
- Line length 100
- Type hints on public APIs (Pydantic models everywhere it matters)
- Docstrings on non-obvious public functions

## Discussion + questions

- **Bug?** [Bug report template](https://github.com/bytewise-ca/context-wall/issues/new?template=bug-report.md)
- **Vulnerability?** See [SECURITY.md](./SECURITY.md) — don't open a public issue.
- **Question?** GitHub Discussions or email `info@bytewise.ca`.

## Legal

By contributing you agree that your contribution is licensed under the
project's Apache 2.0 license. No CLA. Sign-offs (DCO) welcome but not
required.
