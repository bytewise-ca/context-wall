# ContextWall v0.1.5 — Preflight

Release notes for the "Preflight" release. See [CHANGELOG.md](./CHANGELOG.md)
for the full change list.

## What's new

**`ctxfw check`** — point Preflight at your agent, get a safety scorecard and
a release decision in about 60 seconds.

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

**35 pinned fixtures** across three safety dimensions, each with a citation
to a CVE, paper, or public disclosure. **Four adapters:** OpenAI-compatible,
Anthropic, JSONL replay (trace-boundary — grade offline in CI), and MCP
static (component-exposure — never invokes tools). **Stable exit codes**
(0 / 10 / 11 / 12) route different failure classes correctly in CI.

## Get it

```bash
# One-shot, no install
uvx contextwall check --help

# Install into your env
pip install --upgrade contextwall
```

## Breaking changes

None for users of the runtime firewall. The migration is transparent via
deprecation aliases:

- **Env vars:** `CRE_*` → `CONTEXTWALL_*` (aliases in place; `DeprecationWarning`
  on the old names)
- **DB path:** `.ctxfw/cre.db` → `.ctxfw/contextwall.db` (auto-migrated at
  daemon start)
- **Error type:** `cre_policy_violation` → `contextwall_policy_violation`
  (SDK accepts both; mixed deployments work either way)

**One thing that IS breaking**: Prometheus metrics renamed `cre_*` →
`contextwall_*`. If you have Grafana dashboards or Prometheus alerts on the
old names, update them.

## Under the hood

- Removed ~800 LOC of speculative in-daemon research code
  (`graph`, `entropy`, `runtime`, `analytics`, `lint` engines) that no
  production path referenced.
- Dropped 5 large deps (`kuzu`, `context-compiler-mcp`, `opentelemetry-*`,
  `grpcio`) — faster install, smaller image, cleaner surface.
- Test suite grew to 74 tests, all under a second wall-clock.

## Manual steps for maintainers

These are `gh`/PyPI/GitHub settings, not code:

1. **PyPI publish**: `python -m build && python -m twine upload dist/*` from
   `context-wall/`; same from `context-wall/sdk/python/` for the SDK.
2. **GitHub release**: `gh release create v0.1.5 --title "v0.1.5 — Preflight"
   --notes-file RELEASE_NOTES_v0.1.5.md`.
3. **Repo metadata** (via Settings or `gh repo edit`):
   - Description: `Safety preflight and runtime firewall for AI agents — point at your agent, get a scorecard and release decision.`
   - Website: `https://contextwall.io`
   - Topics: `llm-security`, `prompt-injection`, `ai-agents`, `ai-security`, `agent-security`, `rag`, `guardrails`, `llmops`, `mcp`, `preflight`
4. **README badges** (once PyPI reflects 0.1.5): PyPI version, download count,
   Python versions, license.

## Deferred

- **Preamble patent freedom-to-operate review** (US20250028969A1) — needs
  counsel signoff before broad public distribution.
- **Grader validation stats** (independent-reviewer agreement rate, etc.) —
  target lands in v0.2 once the labeled corpus grows past 50.
- **Hosted scorecard** (uploaded scorecards with shareable URLs) — v1.5 per
  the spec, weeks 10–14.
