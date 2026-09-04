# MCP community Discord announcement

Short, casual, MCP-specific. Post to the relevant MCP community channel(s).
Not a launch — a "this exists if you're already thinking about the
problem." Wait ~1 week after Show HN so it doesn't look like drive-by
promotion.

## Message

> hey folks 👋 — sharing a tool in case anyone's been thinking about
> "does the MCP server I just installed have poisoned tool descriptions"
>
> `uvx contextwall check --mcp ~/.config/claude-desktop/mcp.json`
>
> spawns each configured MCP server via stdio JSON-RPC, calls `tools/list`
> + `resources/list`, then scans tool descriptions + inputSchema
> descriptions for injection patterns using ContextWall's detector. also
> classifies each tool as write-capable, network-capable, or other via
> name/description heuristics — the "which of my installed tools can rm
> -rf" question, basically.
>
> **critical: it NEVER invokes any tool.** enumeration only. no
> `tools/call`, no `resources/read`. safe against any target (though
> obviously don't scan an MCP server you don't have permission to enumerate).
>
> emits terminal, JSON, or SARIF. SARIF result per finding, level =
> `warning` for capability findings, `error` for injection patterns.
>
> broader tool is a safety preflight for AI agents (`ctxfw check`
> against openai/anthropic endpoints, replay from JSONL, etc.) — the MCP
> adapter is one of four. Apache 2.0. more here:
>
> - github: https://github.com/bytewise-ca/context-wall
> - /vs page (honest comparison against snyk agent-scan and others):
>   https://contextwall.io/vs
> - methodology: https://contextwall.io/methodology
>
> would love to hear from anyone who runs it against their claude desktop
> config — especially interested in "detector found nothing but I know
> this tool is sketchy" reports so we can extend the heuristics.

## Follow-up if someone engages

Be responsive. If they run it and find something on a widely-used server,
ask permission to include the finding as a case study on the site or in a
blog post — with the affected maintainer coordinated first.

If they run it and find NOTHING but the tool clearly *is* sketchy, that's
a bug in the heuristics — file it as a grader-drift or fixture proposal.
