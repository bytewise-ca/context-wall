"""Anthropic Messages API adapter.

Speaks the shape at `/v1/messages`:

  - `system` is a top-level string (not a message)
  - `messages` is a list of `{role, content}` where content is either a string
    or a list of typed blocks
  - `tools` is a top-level parameter; tool calls come back as `tool_use`
    blocks inside `content`

This adapter targets the Anthropic-native API and any Anthropic-compatible
proxy (Bedrock proxies, ContextWall's own /proxy/anthropic path, etc.).
"""

from __future__ import annotations

import httpx

from ..models import AgentResponse, ContextItem, ToolCall, ToolDef
from ..transport import (
    AdapterError,
    AgentTransport,
    CapabilityManifest,
    InvalidTargetError,
    SideEffectPosture,
)


_DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicAdapter(AgentTransport):
    def __init__(
        self,
        base_url: str,
        model: str = "claude-3-5-haiku-20241022",
        api_key: str | None = None,
        anthropic_version: str = _DEFAULT_ANTHROPIC_VERSION,
        max_tokens: int = 1024,
        timeout: float = 30.0,
    ) -> None:
        if not base_url:
            raise InvalidTargetError("--anthropic requires a base URL")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._anthropic_version = anthropic_version
        self._max_tokens = max_tokens
        self._client = httpx.AsyncClient(timeout=timeout)

        self.capability = CapabilityManifest(
            adapter="anthropic-compatible",
            assessment_mode="model-boundary",
            observes=[
                "model.requests",
                "model.responses",
                "tool.declarations",
                "tool.arguments",
            ],
            does_not_observe=[
                "provider.retention",
                "agent.nested_model_calls",
                "agent.raw_outbound_http",
            ],
            side_effects=SideEffectPosture(
                invokes_tools=True,
                invokes_dangerous_tools=False,
            ),
        )

    def _build_system(self, system: str, context: list[ContextItem]) -> str:
        parts: list[str] = []
        if system:
            parts.append(system)
        for item in context:
            parts.append(f"[retrieved from {item.source}]\n{item.content}")
        return "\n\n".join(parts)

    def _build_tools(self, tools: list[ToolDef] | None) -> list[dict]:
        if not tools:
            return []
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters or {"type": "object", "properties": {}},
            }
            for t in tools
        ]

    async def send(
        self,
        system: str,
        user_message: str,
        context: list[ContextItem],
        tools: list[ToolDef] | None = None,
    ) -> AgentResponse:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": self._anthropic_version,
        }
        if self._api_key:
            headers["x-api-key"] = self._api_key

        body: dict = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "temperature": 0,
            "messages": [{"role": "user", "content": user_message}],
        }
        combined_system = self._build_system(system, context)
        if combined_system:
            body["system"] = combined_system
        api_tools = self._build_tools(tools)
        if api_tools:
            body["tools"] = api_tools

        try:
            resp = await self._client.post(
                f"{self._base_url}/v1/messages",
                headers=headers,
                json=body,
            )
        except httpx.TransportError as e:
            raise AdapterError(f"cannot reach {self._base_url}: {e}") from e

        if resp.status_code in (401, 403):
            raise AdapterError(f"auth rejected by {self._base_url} ({resp.status_code})")
        if resp.status_code >= 500:
            raise AdapterError(f"upstream 5xx from {self._base_url}: {resp.status_code}")
        if resp.status_code >= 400:
            raise AdapterError(
                f"bad request to {self._base_url}: {resp.status_code} {resp.text[:200]}"
            )

        try:
            payload = resp.json()
        except Exception as e:
            raise AdapterError(f"invalid JSON from {self._base_url}: {e}") from e

        text_chunks: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in payload.get("content", []) or []:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                text_chunks.append(block.get("text", "") or "")
            elif btype == "tool_use":
                tool_calls.append(
                    ToolCall(
                        name=block.get("name", ""),
                        arguments=block.get("input") or {},
                    )
                )

        return AgentResponse(
            text="".join(text_chunks),
            tool_calls=tool_calls,
            raw=payload,
        )

    async def close(self) -> None:
        await self._client.aclose()
