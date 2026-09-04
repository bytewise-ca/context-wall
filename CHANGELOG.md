# Changelog

All notable changes to ContextWall are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-09

### Fixed

- **`uvx contextwall <command>` now runs the CLI.** Adds a `contextwall`
  script entry aliasing the existing `ctxfw` executable. Before 0.2.1,
  `uvx contextwall check` failed with `An executable named "contextwall"
  is not provided by package "contextwall"` because the executable
  (`ctxfw`) didn't match the package name. The `ctxfw` and `ctxfwd`
  entry points remain — nothing existing changes.

## [0.2.0] — 2026-09

The **consolidation** release. The SDK now ships inside the main `contextwall`
package as `context_firewall.sdk`. The separate `contextwall-sdk` package becomes
a thin deprecation shim that installs `contextwall>=0.2.0` and re-exports
from the new location.

### Added

- **`context_firewall.sdk` submodule** — hosts `SafeAnthropic`, `AsyncSafeAnthropic`,
  `SafeOpenAI`, `AsyncSafeOpenAI`, `ContextWallClient`, `AsyncContextWallClient`,
  and all response models. Same class contracts and method signatures as the
  old `contextwall_sdk` package.
- **Optional extras** on the main package for provider SDKs:
  - `pip install "contextwall[anthropic]"` — anthropic>=0.25
  - `pip install "contextwall[openai]"` — openai>=1.0
  - `pip install "contextwall[all]"` — both

### Changed

- **`contextwall-sdk` bumped to 0.2.0 as a deprecation shim.** Depends on
  `contextwall>=0.2.0` plus both provider SDKs (matches the old
  `contextwall-sdk[all]` behavior so pinned installs keep working). Emits a
  `DeprecationWarning` on import. Will be removed in v0.4.

### Migration

```diff
- pip install contextwall-sdk[all]
+ pip install "contextwall[all]"

- from contextwall_sdk import SafeAnthropic
+ from context_firewall.sdk import SafeAnthropic
```

Nothing about class contracts changed — only the import path and the extras
name.

### Why

The split between `contextwall` and `contextwall-sdk` caused version drift
(main went to 0.1.5, SDK stayed at 0.1.4 in the previous release) and
doubled the release surface. Single-package is the pattern most successful
OSS security tools follow (openai, anthropic, snyk agent-scan, semgrep,
trivy). See [contextwall.io/vs](https://contextwall.io/vs) for context.

## [0.1.5] — 2026-08

The **Preflight** release. Introduces the `ctxfw check` subcommand — a safety
preflight for AI agents that returns a scorecard and a release decision in
about 60 seconds. Reduces the daemon's surface, cleans up the `CRE→ContextWall`
naming, and ships fallback aliases so existing deployments keep working.

### Added

- **`ctxfw check` — Preflight subcommand.** Runs a pinned adversarial suite
  against an agent target and emits a scorecard + release gate.
  - Four adapters: `--openai` (OpenAI-compatible), `--anthropic`, `--replay`
    (JSONL trace-boundary), `--mcp` (component-exposure static scan; never
    invokes tools).
  - 35 fixtures across three dimensions in `standard@2026.09`: Injection
    Resistance (10), Grounding Under Attack (5), Data Exfiltration (20).
    Every fixture cites its source — CVE, paper, or public disclosure.
  - Independent letter grade (per dimension) and release gate (for CI).
    Configurable via `contextwall.yaml`; supports `dimension_overrides`.
  - Stable exit codes: `0` pass · `2` usage · `10` safety failure ·
    `11` insufficient evidence · `12` adapter error.
  - Outputs: terminal (Rich when TTY), JSON, SARIF 2.1.0, self-hosted HTML.
    Evidence redacted by default; opt out with `--no-redact`.
- **Grader regression harness** (`tests/preflight/`) with 40+ labeled
  `(fixture, response, verdict)` triples plus post-mortem-derived traces from
  EchoLeak, AWS Q v1.84.0, GitHub MCP exfil, and PoisonedRAG.
- **Methodology doc** at `docs/METHODOLOGY.md` — versioned per suite.
- **Full spec** at `docs/PREFLIGHT_SPEC.md`.
- **CI dep on nothing else** — Preflight runs standalone from `uvx contextwall check`.

### Changed

- **CLI naming: `CRE_*` → `CONTEXTWALL_*`.** All env vars renamed with
  `CRE_*` fallback aliases and a `DeprecationWarning`. Legacy names slated
  for removal in v0.3.
  - `CRE_API_TOKEN` → `CONTEXTWALL_API_TOKEN`
  - `CRE_COMPLIANCE_HMAC_KEY` → `CONTEXTWALL_COMPLIANCE_HMAC_KEY`
  - `CRE_CONTROL_PLANE_TOKEN` → `CONTEXTWALL_CONTROL_PLANE_TOKEN`
  - `CRE_URL`, `CRE_API_KEY`, `CRE_KEY` → `CONTEXTWALL_*` (SDK)
- **Prometheus metric prefix: `cre_*` → `contextwall_*`.** All 12 metrics
  renamed. **Breaking for Grafana dashboards referencing the old names.**
- **Error type in proxy responses: `cre_policy_violation` → `contextwall_policy_violation`.**
  SDK accepts both so mixed old-daemon / new-SDK deployments keep working.
- **Default DB path: `.ctxfw/cre.db` → `.ctxfw/contextwall.db`.** Daemon
  auto-migrates the legacy file at startup if it exists.
- **`ctxfw.oss.yaml` sample updated** with the new env-var and path defaults.

### Removed

- **Speculative in-daemon engines pruned** (~800 LOC removed, no external
  API impact): `graph/`, `entropy/`, `runtime/`, `analytics/`, `lint/`. Their
  routes now consistently return 503 for the affected `/analytics/*` and
  `/v1/lint/*` endpoints. These were daemon-only research code; nothing in
  the SDK or proxy path referenced them.
- **Dependencies dropped:** `kuzu`, `context-compiler-mcp`,
  `opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-grpc`, `grpcio`.
- **`contextwall-sdk.ContextWallClient.lint`** accessor removed — the lint
  engine is gone.

### Migration notes

- **Env vars:** if you set `CRE_*` env vars, keep working — you'll see a
  `DeprecationWarning`. To silence it, rename to `CONTEXTWALL_*`.
- **DB path:** first daemon start on 0.1.5 auto-renames `.ctxfw/cre.db`
  to `.ctxfw/contextwall.db`. If your config pins `storage.db_path`, update it.
- **Grafana:** update panels referencing `cre_proxy_requests_total`,
  `cre_proxy_violations_total`, etc. to the `contextwall_*` prefix.
- **`ContextWallClient.lint`:** the lint API is gone — remove call sites.

## [0.1.4] — earlier 2026

Baseline release before Preflight. Runtime firewall (proxy + policy engine +
compliance export) with `CRE_*` env vars and `cre_*` metrics. Superseded by
0.1.5 with backward-compatible aliases.
