# r/AI_Agents post

Post 2-3 days after Show HN. Different audience — this crowd is builders,
not spectators. Lead with the CI story since that's what they can ship
tomorrow.

## Title

> **Built a safety preflight for agents – gates PR merges on regression, runs offline in CI**

## Flair

`Resource` or `Discussion` (whichever the sub is currently allowing).

## Body

> **TL;DR** — Wrote a CLI (`ctxfw check`) that runs 35 pinned adversarial
> fixtures against your agent and returns a scorecard + a machine-readable
> release gate. Wires into GitHub Actions as a pre-merge check. Apache 2.0,
> offline against fixtures, no API keys required for the suite itself.
>
> Repo: https://github.com/bytewise-ca/context-wall
>
> ---
>
> **What it looks like in CI**
>
> ```yaml
> # .github/workflows/preflight.yml
> jobs:
>   safety:
>     runs-on: ubuntu-latest
>     steps:
>       - uses: actions/checkout@v4
>       - uses: astral-sh/setup-uv@v3
>       - run: |
>           uvx contextwall check --replay ./tests/preflight/responses.jsonl \
>             --gate --fail-below B- --sarif > preflight.sarif
>       - uses: github/codeql-action/upload-sarif@v3
>         if: always()
>         with: { sarif_file: preflight.sarif }
> ```
>
> Exit codes are stable: `0` pass · `10` safety failure · `11` insufficient
> evidence · `12` adapter error. So a broken endpoint doesn't look the same
> as a real safety regression, and CI can route them differently.
>
> **What it grades**
>
> - **Injection Resistance (10 fixtures)** — EchoLeak-shape, tool
>   poisoning, zero-width, spaced-letters, semantic override, indirect via
>   retrieval, +3 CVE-derived
> - **Grounding Under Attack (5)** — false attribution, fabricated event,
>   nonexistent API, conflicting sources, poisoned action recommendation
> - **Data Exfiltration (20)** — AWS/OpenAI/Anthropic/GitHub keys, SSH
>   keys, JWTs, bearer tokens, DB URLs, SSN, credit card, composite PII,
>   tool-arg exfiltration
>
> Every fixture cites its source (CVE, paper, disclosure URL). Full list +
> methodology: https://contextwall.io/methodology
>
> **How I actually use it in my own workflow**
>
> 1. Capture a JSONL of my agent's responses against each fixture once with
>    `ctxfw check --openai <my-endpoint>` and save the `--json` output.
> 2. Commit that JSONL to `tests/preflight/responses.jsonl`.
> 3. In CI, run `ctxfw check --replay ./tests/preflight/responses.jsonl
>    --gate` — grades identically to the live run but doesn't burn tokens.
> 4. If the grade drops or a `release_blocking` fixture starts failing,
>    the PR blocks. If someone updates the agent, they update the JSONL
>    as part of their PR (with real responses, not doctored ones).
>
> **What it does NOT do (honest scope)**
>
> Not evaluated: correctness, cost, latency, reliability, tool
> authorization semantics, tenant isolation, availability, data retention,
> human-in-loop policy. A passing Preflight means the agent resisted the
> pinned safety corpus — not that it's production-ready overall.
>
> **How this compares to things you've probably heard of**
>
> - Not competing with **Meta PromptGuard 2** — that's a classifier, this
>   is a scorecard. You could use both.
> - Not competing with **Snyk agent-scan** — that scans MCP servers as
>   components, this scores agent behavior. Preflight has an `--mcp`
>   adapter for the overlap, but it's conservative (static-only, never
>   invokes tools).
> - Not competing with **PromptFoo** — that's an eval framework for
>   iterating on prompts, this is a release decision.
> - Full honest comparison: https://contextwall.io/vs
>
> **Looking for feedback on**
>
> - The grader is rule/heuristic based, not an LLM judge. If you find a
>   response the grader classifies obviously wrong, please file a
>   grader-drift issue — highest-signal contribution.
> - The `--replay` UX. Is capturing JSONL by hand the right shape for CI,
>   or does an "automatically save on the first check" flag make more
>   sense?
>
> Full quickstart: https://contextwall.io/quickstart
> Ping me here or open an issue. Apache 2.0, PRs welcome, especially
> fixture proposals with citations.
