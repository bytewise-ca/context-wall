"""MCP static adapter — component-exposure preflight.

Scans an MCP (Model Context Protocol) config for exposure. For each configured
server:

    1. Spawn the server via stdio JSON-RPC (whatever `command`/`args` say).
    2. Send `initialize`, `tools/list`, `resources/list`.
    3. Classify each tool as write-capable / network-capable / other based on
       name and description heuristics.
    4. Scan tool descriptions + input-schema descriptions + resource metadata
       for injection patterns using the shipped detect_injection().

The adapter NEVER invokes tools (no `tools/call`) and NEVER reads resource
content (no `resources/read`) in v1. Both are opt-in in v0.2 behind explicit
consent flags. This is the safety-first read of the audit — enumeration is
safe against any target; interaction is not.

Config format (matches Claude Desktop / Cursor / mcp-config conventions):

    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        },
        "brave-search": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-brave-search"],
          "env": {"BRAVE_API_KEY": "..."}
        }
      }
    }
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path

from context_firewall.policy.detectors.injection import detect_injection, WARN_THRESHOLD

from ..models import MCPExposure, MCPExposureFinding, MCPServerReport
from ..transport import (
    AgentTransport,
    CapabilityManifest,
    InvalidTargetError,
    SideEffectPosture,
)


# Heuristics for capability classification. Deliberately conservative — false
# positives on write/network capability are safer than false negatives.
_WRITE_HINTS = re.compile(
    r"\b(write|delete|remove|create|update|patch|put|post|exec|execute|run|run_command|spawn|kill|drop|truncate|overwrite)\b",
    re.IGNORECASE,
)
_NETWORK_HINTS = re.compile(
    r"\b(http|https|url|browse|fetch|request|api_call|webhook|dns|socket|smtp|send|download|upload)\b",
    re.IGNORECASE,
)


class MCPStaticAdapter(AgentTransport):
    def __init__(self, config_path: str | Path, timeout: float = 10.0) -> None:
        p = Path(config_path)
        if not p.exists():
            raise InvalidTargetError(f"--mcp config not found: {p}")
        try:
            raw = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise InvalidTargetError(f"cannot parse {p}: {e}") from e

        servers = raw.get("mcpServers") or raw.get("mcp_servers") or {}
        if not isinstance(servers, dict) or not servers:
            raise InvalidTargetError(f"no `mcpServers` block in {p}")
        self._servers = servers
        self._timeout = timeout
        self._config_path = p

        self.capability = CapabilityManifest(
            adapter="mcp-static",
            assessment_mode="component-exposure",
            observes=[
                "tool.names",
                "tool.descriptions",
                "tool.input_schemas",
                "resource.metadata",
            ],
            does_not_observe=[
                "runtime.agent.behavior",
                "model.responses",
                "actual.data.flow",
                "write_capable.tool.execution",
                "network_capable.tool.execution",
                "resource.contents",
            ],
            side_effects=SideEffectPosture(
                invokes_tools=False,
                invokes_dangerous_tools=False,
            ),
        )

    async def enumerate_exposure(self) -> MCPExposure:
        reports: list[MCPServerReport] = []
        for server_name, server_cfg in self._servers.items():
            reports.append(await self._scan_server(server_name, server_cfg))
        return MCPExposure(servers=reports)

    async def close(self) -> None:
        return None

    # ── per-server scan ─────────────────────────────────────────────────────

    async def _scan_server(self, name: str, cfg: dict) -> MCPServerReport:
        command = cfg.get("command")
        args = cfg.get("args") or []
        env_extra = cfg.get("env") or {}
        if not command or not isinstance(command, str):
            return MCPServerReport(server_name=name, error="missing 'command' in server config")

        env = {**os.environ, **{str(k): str(v) for k, v in env_extra.items()}}
        try:
            proc = await asyncio.create_subprocess_exec(
                command,
                *[str(a) for a in args],
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (FileNotFoundError, PermissionError) as e:
            return MCPServerReport(server_name=name, error=f"cannot spawn `{command}`: {e}")

        report = MCPServerReport(server_name=name)
        try:
            responses = await asyncio.wait_for(
                self._exchange(
                    proc,
                    [
                        _rpc("initialize", 1, {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "contextwall-preflight", "version": "0.1"},
                        }),
                        _rpc("notifications/initialized", None, {}, is_notification=True),
                        _rpc("tools/list", 2, {}),
                        _rpc("resources/list", 3, {}),
                    ],
                ),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            report.error = f"mcp server `{name}` timed out after {self._timeout}s"
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return report
        except Exception as e:
            report.error = f"stdio exchange failed with `{name}`: {e}"
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return report

        by_id = {r.get("id"): r for r in responses if isinstance(r, dict) and "id" in r}
        tools = _get_list(by_id.get(2), "tools")
        resources = _get_list(by_id.get(3), "resources")
        _classify_tools(name, tools, report)
        _scan_resources(name, resources, report)
        return report

    async def _exchange(self, proc: asyncio.subprocess.Process, requests: list[dict]) -> list[dict]:
        assert proc.stdin is not None
        assert proc.stdout is not None
        for req in requests:
            proc.stdin.write((json.dumps(req) + "\n").encode())
        try:
            proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass

        raw = await proc.stdout.read()
        try:
            await proc.wait()
        except ProcessLookupError:
            pass

        responses: list[dict] = []
        for line in raw.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                responses.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return responses


# ── helpers ──────────────────────────────────────────────────────────────────


def _rpc(method: str, req_id: int | None, params: dict, is_notification: bool = False) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method, "params": params}
    if not is_notification and req_id is not None:
        msg["id"] = req_id
    return msg


def _get_list(resp: dict | None, key: str) -> list[dict]:
    if not resp or not isinstance(resp, dict):
        return []
    result = resp.get("result") or {}
    items = result.get(key) or []
    return [i for i in items if isinstance(i, dict)]


def _classify_tools(server: str, tools: list[dict], report: MCPServerReport) -> None:
    report.tools_enumerated = len(tools)
    for tool in tools:
        name = tool.get("name", "")
        description = tool.get("description", "") or ""
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        haystack = f"{name} {description}"

        if _WRITE_HINTS.search(haystack):
            report.tools_write_capable.append(name)
            report.findings.append(MCPExposureFinding(
                kind="tool_dangerous_capability",
                target=name,
                server=server,
                excerpt="tool name/description matches write/exec pattern",
            ))
        if _NETWORK_HINTS.search(haystack):
            report.tools_network_capable.append(name)
            report.findings.append(MCPExposureFinding(
                kind="tool_dangerous_capability",
                target=name,
                server=server,
                excerpt="tool name/description matches network pattern",
            ))

        scan_target = _flatten_for_injection_scan(description, schema)
        if not scan_target:
            continue
        result = detect_injection(scan_target)
        if result.detected or result.confidence >= WARN_THRESHOLD:
            report.tools_with_untrusted_instructions.append(name)
            report.findings.append(MCPExposureFinding(
                kind="tool_untrusted_instruction",
                target=name,
                server=server,
                layer=result.layer,
                signal=result.signal,
                excerpt=result.excerpt or (description[:200] if description else ""),
            ))


def _scan_resources(server: str, resources: list[dict], report: MCPServerReport) -> None:
    report.resources_scanned = len(resources)
    for res in resources:
        uri = res.get("uri", "") or res.get("name", "")
        description = res.get("description", "") or ""
        if not description:
            continue
        result = detect_injection(description)
        if result.detected or result.confidence >= WARN_THRESHOLD:
            report.resources_with_injection.append(uri)
            report.findings.append(MCPExposureFinding(
                kind="resource_injection_pattern",
                target=uri,
                server=server,
                layer=result.layer,
                signal=result.signal,
                excerpt=result.excerpt or description[:200],
            ))


def _flatten_for_injection_scan(description: str, schema: dict) -> str:
    """Concatenate everything a poisoned tool might smuggle into the model:
    top-level description + parameter descriptions from the schema."""
    parts: list[str] = []
    if description:
        parts.append(description)
    props = (schema or {}).get("properties") or {}
    if isinstance(props, dict):
        for k, v in props.items():
            if isinstance(v, dict):
                d = v.get("description")
                if isinstance(d, str) and d:
                    parts.append(f"param {k}: {d}")
    return "\n".join(parts)
