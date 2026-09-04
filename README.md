# ContextWall

**Safety preflight and runtime firewall for AI agents.**

Point Preflight at your agent, get a safety scorecard and a release decision
in about 60 seconds. Then, if you want it, run the same detection at runtime
between your agent and its context sources.

```bash
uvx contextwall check --openai http://localhost:11434/v1
```

```
ContextWall Preflight — my-agent-v3.2
Suite: standard@2026.09    Adapter: openai-compatible
Assessment mode: MODEL-BOUNDARY
Assessment scope: SAFETY ONLY

  Injection Resistance       B+   7/10 cases passed
  Grounding Under Attack     C    2/5 cases passed
  Data Exfiltration          A    0/20 detected emissions

Release gate: BLOCKED
  ✗ Grounding score below minimum grade
  ✗ Critical test inj-05 (semantic override) failed

Fix first:
  1. Semantic override bypass       → contextwall.io/fix/inj-05
  2. Poisoned document treated fact → contextwall.io/fix/gnd-02
```

[Full quickstart](https://contextwall.io/quickstart)
&nbsp;·&nbsp;
[Methodology](https://contextwall.io/methodology)
&nbsp;·&nbsp;
[vs LlamaFirewall / NeMo / Snyk agent-scan / PromptFoo](https://contextwall.io/vs)

---

## Get started

**Zero install, one command:**

```bash
uvx contextwall check --help
```

**Install into your env:**

```bash
pip install contextwall                    # CLI + Preflight + detectors + daemon
pip install "contextwall[anthropic]"       # + SafeAnthropic wrapper
pip install "contextwall[openai]"          # + SafeOpenAI wrapper (works with vLLM, Ollama, Mistral, ...)
pip install "contextwall[all]"             # everything
```

The client SDK ships as a submodule:

```python
from context_firewall.sdk import SafeAnthropic, ContextWallBlockedError
```

Users of the old `contextwall-sdk` package: keep working via a deprecation
shim (import from `context_firewall.sdk` when convenient).

**Point at your agent — four adapters:**

| Flag | For | Assessment mode |
|---|---|---|
| `--openai <url>` | OpenAI-compatible endpoints (OpenAI, vLLM, Ollama, LiteLLM, …) | model-boundary |
| `--anthropic <url>` | Anthropic Messages endpoints (direct, Bedrock proxies) | model-boundary |
| `--replay <file.jsonl>` | Prerecorded responses — grade offline, reproducible in CI | trace-boundary |
| `--mcp <config.json>` | MCP config — enumerates tools + scans descriptions (never invokes) | component-exposure |

**Gate CI on it:**

```bash
ctxfw check --replay ./tests/preflight/responses.jsonl \
            --gate --fail-below B- --sarif > preflight.sarif
# Exit codes: 0 pass · 10 safety failure · 11 insufficient evidence · 12 adapter error
```

## What Preflight measures

35 fixtures across three safety dimensions, pinned per suite version so
scorecards remain reproducible:

| Dimension | Fixtures | What it tests |
|---|---:|---|
| **Injection Resistance** | 10 | EchoLeak-shape, tool poisoning, zero-width, spaced-letters, semantic override, indirect-via-retrieval, +3 CVE-derived |
| **Grounding Under Attack** | 5 | False attribution, fabricated event, nonexistent API, conflicting sources, poisoned action recommendation |
| **Data Exfiltration** | 20 | AWS/OpenAI/Anthropic/GitHub keys, SSH keys, JWTs, bearer tokens, DB URLs, SSN, credit card, composite PII, tool-arg exfiltration |

Every fixture cites its source — CVE-2025-32711 (EchoLeak), GHSA-7g7f-ff96-5gcw
(AWS Q v1.84.0), Invariant Labs' 2025 disclosures, USENIX 2025 PoisonedRAG,
and more.

Grades and release gates are **independent outputs**. Letter grade is for
humans and README badges; the gate is machine truth for CI. They can disagree
by design — see [docs/METHODOLOGY.md](./docs/METHODOLOGY.md).

## What Preflight does NOT measure

Every scorecard states this explicitly:

- Correctness of the agent's answers
- Cost, latency, throughput, availability
- Tool authorization semantics (who is allowed to call which tool)
- Tenant isolation and multi-user access control
- Data retention and provider configuration
- Human-in-loop policy correctness

A passing Preflight means the agent resisted the pinned safety corpus —
not that it's production-ready overall. Honest scope beats false assurances.

## Runtime firewall (optional follow-up)

Preflight is the wedge; the runtime firewall is the product. Once you know
which classes your agent falls for, enforce the same detection at runtime
by pointing your SDK at the local daemon:

```bash
ctxfw start                                          # runs the daemon on :8080
export ANTHROPIC_BASE_URL=http://localhost:8080/proxy/anthropic
export ANTHROPIC_API_KEY=sk-ant-your-real-key        # unchanged
```

Prompts and documents never leave your host. The daemon inspects both
inbound context and outbound tool arguments using the same detectors as
Preflight. Source-tier trust model, per-source policy, tamper-evident
provenance chain. See [`ctxfw.oss.yaml`](./ctxfw.oss.yaml) for a config
example.

## Compliance

Compliance packs (HIPAA, SOC 2, FedRAMP) map violations to specific control
IDs, run in `baa_mode` for PHI-adjacent deployments, and export tamper-evident
audit bundles. See [contextwall.io/compliance](https://contextwall.io/compliance)
for enterprise scope, data residency, and policy-as-code details.

## Architecture

One paragraph: the CLI (`ctxfw`) hosts both the Preflight subcommand
(`ctxfw check`) and the daemon (`ctxfw start`). Preflight adapters
(OpenAI-compatible, Anthropic, replay, MCP-static) each declare a capability
manifest with observed/unobserved channels. The suite runner iterates
versioned fixtures, the grader combines pattern-based checks with
outcome-based checks, and the scorecard reports dimension grades + release
gate independently. The runtime daemon shares the same three-layer detector
(structural, regex, heuristic scoring) and pattern libraries; it proxies
LLM API calls through `/proxy/anthropic` and `/proxy/openai`, applying
source-tier-aware policy before content reaches the model.

## Contributing

Grader-drift reports are the highest-signal contribution. If you find an
`(input, response)` pair where the grader gives the wrong verdict, please
[open an issue](https://github.com/bytewise-ca/context-wall/issues).
Fixture proposals and independent-reviewer volunteers are also very welcome —
see [docs/METHODOLOGY.md](./docs/METHODOLOGY.md) for conventions.

## License

Apache 2.0. See [LICENSE](./LICENSE).
