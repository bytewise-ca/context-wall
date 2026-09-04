# X / Twitter launch thread

6 posts. Post the whole thread at once (or use the "add another post" flow
before publishing). Add a screenshot to the first post — the scorecard from
the Hero, or an asciinema of `ctxfw check` running.

Best time to post: whatever your audience's timezone actually is. Not
"marketing best practice" — the people you want to see this are probably
online when you are.

---

## Post 1 (with image)

> new: point `ctxfw check` at your agent — get a safety scorecard + release
> decision in ~60s. offline, no API keys for the suite, 35 pinned fixtures,
> Apache 2.0.
>
> uvx contextwall check --openai http://localhost:11434/v1
>
> details 🧵

*Image: scorecard screenshot from the hero, or asciinema recording of
`ctxfw check` running. This is the tweet that determines the thread's ceiling.*

---

## Post 2

> what it grades:
>
> — Injection Resistance (10 fixtures): EchoLeak-shape, tool poisoning,
> zero-width, spaced-letters, semantic override, +3 CVE-derived
> — Grounding Under Attack (5): false attribution, poisoned action recs
> — Data Exfiltration (20): AWS/OpenAI/Anthropic/GitHub keys, SSN, CC, PII
>
> every fixture cites its source

---

## Post 3

> what it does NOT grade — every scorecard states this explicitly:
>
> correctness, cost, latency, reliability, tool authorization semantics,
> tenant isolation, availability, data retention, human-in-loop policy.
>
> honest scope beats false assurances. passing ≠ production-ready.

---

## Post 4

> two independent outputs by design:
>
> — letter grade (for humans, badges, README)
> — release gate (for CI, machine truth)
>
> they can disagree. B+ overall with one critical `release_blocking`
> fixture failed → gate blocks. exit codes are stable (0/10/11/12) so CI
> routes different failure classes correctly.

---

## Post 5

> honest comparison:
>
> — meta PromptGuard 2: a classifier. preflight is a scorecard. different
> unit of analysis. use both.
> — snyk agent-scan: scans MCP servers as components. preflight scores
> agent behavior. overlap only in --mcp adapter (which is deliberately
> conservative, never invokes tools).
> — promptfoo: eval framework for prompt iteration. preflight is a
> release decision.
>
> full breakdown incl. where each wins: https://contextwall.io/vs

---

## Post 6

> repo, docs, and the honest methodology page (grader integrity, redaction,
> versioning, contribution rules):
>
> repo: https://github.com/bytewise-ca/context-wall
> quickstart: https://contextwall.io/quickstart
> methodology: https://contextwall.io/methodology
>
> highest-signal contribution: grader-drift reports. Apache 2.0. PRs
> welcome — especially fixture proposals with citations 🙏

---

## Notes on tone

- No caps. No hype words. No "revolutionary" / "game-changing" / etc.
- Include the honest-scope tweet — Twitter rewards honesty in a way LinkedIn
  doesn't, and it disarms the "what about correctness?" QT that will
  otherwise arrive within the hour.
- Skip emojis except one clear signal each (🧵 for thread, 🙏 for the
  contributor ask). Overuse looks marketing-y.
- If anyone QTs criticizing the accuracy — thank them for the concrete case,
  ask them to file a grader-drift issue with the response text. That defuses
  95% of arguments.

## If it takes off

Prepared quote-post to reply with:

> tools ContextWall is NOT trying to replace:
>
> — LlamaFirewall / PromptGuard 2 (classifier — better on individual messages)
> — Snyk agent-scan (MCP component inventory + vulns)
> — PromptFoo (prompt iteration)
> — LangSmith / Braintrust (LLM evals during training)
>
> use them all. these tools answer different questions.
