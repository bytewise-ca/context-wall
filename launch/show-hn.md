# Show HN post

## Title options (pick one)

Preferred:

> **Show HN: `uvx contextwall check` – a 60-second safety preflight for AI agents**

Alternates:

> Show HN: I built an offline safety scorecard for AI agents (35 fixtures, 4 adapters)
>
> Show HN: ContextWall – point at your agent, get a release decision

Guidance from the launch spec: the title should name the artifact and the
outcome, not the product / company. `ctxfw check` + "60-second" + "safety
preflight" does that.

## URL to submit

`https://contextwall.io` — the marketing site, not the GitHub link. HN
readers who care go to GitHub via the site's link; casual visitors get
context first.

## Text (leave empty)

Show HN posts have no body text — the title + first comment carry everything.

---

## Your first comment (post immediately after submitting)

> Author here. Quick honest overview + how it compares to what exists.
>
> **Why I built it**
>
> After reading enough post-mortems — EchoLeak (CVE-2025-32711), the AWS Q
> v1.84.0 near-miss, Invariant Labs' GitHub-MCP disclosure — I wanted a
> quick way to know whether an agent I was about to ship would fall for the
> same classes of attack. Not a "will you eventually get hacked" question,
> a "does your agent execute the injection in this specific fixture" answer.
>
> **What it actually does**
>
> `uvx contextwall check --openai <url>` runs a pinned adversarial suite
> against your agent endpoint and returns a scorecard + a release gate.
> Three safety dimensions: injection resistance (10 fixtures), grounding
> under attack (5), data exfiltration (20). Every fixture cites its source
> — a CVE, a published paper, or a public disclosure. Four adapters:
> OpenAI-compatible, Anthropic, JSONL replay (grade offline in CI), and
> MCP config (component-exposure static scan, never invokes tools).
>
> Grades are for humans / README badges. The gate is machine truth for CI.
> They're separate outputs so they can disagree — a B grade with a
> release-blocking critical failure exits non-zero, the scorecard still
> looks OK for a badge.
>
> **What it does NOT do**
>
> Every scorecard states this explicitly: not correctness, not cost, not
> latency, not tool authorization semantics, not tenant isolation, not
> availability, not data retention, not human-in-loop policy. It's a
> safety preflight, not a production-readiness gate. Passing means the
> agent resisted the pinned safety corpus — not that it's un-shippable
> if it doesn't pass, and not that it's un-shippable if it does. Honest
> scope beats false assurances.
>
> **How this compares to LlamaFirewall / PromptGuard 2**
>
> Meta's PromptGuard 2 is a very good classifier. Preflight is not a
> classifier. It scores agents-as-systems (does the agent take a
> destructive tool call given this poisoned retrieval?), not individual
> messages (is this text suspicious?). Different unit of analysis. You
> could point Preflight at an agent that uses PromptGuard as its
> classifier and Preflight would grade the outer system.
>
> **How this compares to Snyk agent-scan**
>
> Snyk agent-scan scans MCP servers as components (their tools, their
> inputSchema descriptions). Preflight has an `--mcp` adapter that does
> similar static-only enumeration and description scanning, but it's
> deliberately conservative — never invokes tools. The wedge is different:
> agent-scan owns MCP component inventory; Preflight owns agent-behavior
> assessment.
>
> **How this compares to PromptFoo**
>
> PromptFoo is an eval framework for prompts. Different mental model:
> devs iterating on prompts vs. devs asking "is this ready to ship?"
> Preflight has opinionated grades + a release gate; PromptFoo has
> user-defined assertions. Complementary.
>
> **What I'd love feedback on**
>
> - The grader is a rule/heuristic thing, not an LLM-in-the-loop judge.
>   If you find a `(fixture, agent-response)` pair where the grader gives
>   an obviously wrong verdict, please file a grader-drift issue — that's
>   the single most useful contribution.
> - The methodology page distinguishes "response contained the attack
>   string" from "agent followed the instruction." Grader design tries to
>   detect the second, not the first. Interested if that framing tracks
>   for people who've built similar tools.
>
> Repo: https://github.com/bytewise-ca/context-wall
> Methodology: https://contextwall.io/methodology
> vs comparison: https://contextwall.io/vs
> Apache 2.0. No telemetry by default. Runs offline against pinned
> fixtures — the LLM endpoint is the only network call, and only for the
> two behavioral adapters (openai / anthropic).

---

## If people ask specific questions in the thread

Prepared honest answers you can adapt in-line. Don't paste these verbatim
unless the exact question is asked.

**"Why did you build another one? Isn't [X] enough?"**

> Fair question. My honest read is Preflight sits in a slightly different
> spot — a scorecard + release gate, not a classifier or an MCP-server
> scanner. If [X] gives you what you need, keep using it. Preflight is
> useful specifically for "before I merge / deploy, would my agent have
> fallen for the shape of attack that took down [recent incident]?"

**"How well does the detector actually work?"**

> Honest answer: the detector is a three-layer rule/heuristic thing
> (structural, regex, semantic scoring), not SOTA. It's `good enough` to
> power the grader, not competing with a trained classifier. If detection
> accuracy is your primary concern, Meta PromptGuard 2 is free and probably
> better on individual messages. The value here is the wrapper — versioned
> corpus, opinionated grades, a real release decision.

**"Can I use this against Cursor / Claude Desktop / [named agent]?"**

> The `--mcp` adapter reads any config in the standard `mcpServers` shape,
> so yes to Claude Desktop and any MCP-compatible client. For behavioral
> checks against a full agent (does it fall for the fixtures?), you need
> either the model endpoint URL or a captured session log — the `--replay`
> adapter grades offline from a JSONL of `{fixture_id, text, tool_calls}`.

**"How do I know the grader isn't biased?"**

> You don't fully, and I don't hide that. Every scorecard cites its suite
> version (`standard@2026.09`). The regression harness has ~50 labeled
> `(fixture, response, verdict)` triples with each release; PRs must add
> pass + fail examples for anything new. The methodology page tracks the
> intended discipline (independent reviewers, adjudication rate) as a
> "target — in-progress" table. Not solved — but public and versioned.

**"Isn't this just the OSS `snyk agent-scan`?"**

> No — different unit of analysis. `agent-scan` inspects MCP servers as
> static components. Preflight inspects the agent's behavior when you
> point it at a live endpoint or replay a session. The `--mcp` adapter is
> the overlap, and it's deliberately conservative (static + dry-run only,
> never invokes tools). If you want MCP inventory + vulnerability
> classification, use `agent-scan`. If you want "does my agent fall for
> the shape of attack that took down EchoLeak" answered, this is the tool.

**"What about liability if I ship this and get sued?"**

> Apache 2.0 — the license carries the standard no-warranty clause. On the
> other side: Preflight is a safety check, not a compliance certification.
> The `/compliance` page lays out what maps to what for HIPAA / SOC 2 /
> FedRAMP conversations, but a passing scorecard isn't a legal shield.
> Same as `snyk test` or `bandit` — the tool tells you what it found; the
> shipping decision is yours.
