# ContextWall v0.2.0 — SDK consolidation

Small but structurally important release. **The SDK now lives inside the
main `contextwall` package** as `context_firewall.sdk`. The old `contextwall-sdk`
package continues to work as a deprecation shim.

## What changed

- **One package, one release story.** `context_firewall.sdk` is the new home
  for `SafeAnthropic`, `SafeOpenAI`, `ContextWallClient`, and all response
  models. Same class contracts as before.
- **Note on naming:** the PyPI package is named `contextwall` (no separator);
  the Python module has always been `context_firewall` (with underscore).
  So: `pip install contextwall` and `import context_firewall`. The old
  `contextwall-sdk` package continues to install as `contextwall_sdk` (the
  shim).
- **Optional extras** for the provider SDKs:
  - `pip install "contextwall[anthropic]"`
  - `pip install "contextwall[openai]"`
  - `pip install "contextwall[all]"`
- **`contextwall-sdk` 0.2.0** is now a thin shim that installs the main
  package and re-exports from `context_firewall.sdk` with a `DeprecationWarning`.
  It will be removed in v0.4.

## Migration

```diff
- pip install contextwall-sdk[all]
+ pip install "contextwall[all]"

- from contextwall_sdk import SafeAnthropic
+ from context_firewall.sdk import SafeAnthropic
```

Nothing about behavior changed — only the import path and the extras name.
If you don't migrate, the shim keeps working; you'll see a one-time
`DeprecationWarning` and can silence it after the migration.

## Why

The old `contextwall` / `contextwall-sdk` split caused two real problems:

1. **Version drift.** v0.1.5 shipped only for the main package; the SDK
   stayed at 0.1.4. Users didn't know which pair to install.
2. **Doubled release surface.** Every release meant two publishes, two
   changelogs, two READMEs to keep in sync.

Single-package is the pattern most successful OSS security tools follow
(openai, anthropic, snyk agent-scan, semgrep, trivy). The provider-SDK
weight concern that motivated the split originally is now handled cleanly
by optional extras.

## Publish sequence

```bash
# Main package
cd /Users/punakkals/work/context-wall
uv build && uv publish

# Shim package
cd sdk/python
uv build && uv publish
```

## Deferred

- **Removal of `contextwall-sdk`** — v0.4, per the deprecation notice.
- **`contextwall_sdk._anthropic` / `contextwall_sdk._openai` etc.** — those
  private submodules are gone from the shim. If anyone was importing from
  them directly (undocumented), they'll need to update to `context_firewall.sdk`.
