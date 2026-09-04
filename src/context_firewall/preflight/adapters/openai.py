"""OpenAI-compatible adapter.

Works with any endpoint that speaks the `/v1/chat/completions` shape:
vLLM, Ollama, LiteLLM, OpenAI directly, an OpenAI-compat proxy, etc.
"""

from __future__ import annotations

import json

import httpx

from ..models import AgentResponse, ContextItem, ToolCall, ToolDef
from ..transport import (
    AdapterError,
    AgentTransport,
    CapabilityManifest,
    InvalidTargetError,
    SideEffectPosture,
)


class OpenAIAdapter(AgentTransport):
    def __init__(
        self,
        base_url: str,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not base_url:
            raise InvalidTargetError("--openai requires a base URL")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=timeout)

        self.capability = CapabilityManifest(
            adapter="openai-compatible",
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

    def _build_messages(
        self,
        system: str,
        user_message: str,
        context: list[ContextItem],
    ) -> list[dict]:
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        for item in context:
            messages.append(
                {
                    "role": "system",
                    "content": f"[retrieved from {item.source}]\n{item.content}",
                }
            )
        messages.append({"role": "user", "content": user_message})
        return messages

    def _build_tools(self, tools: list[ToolDef] | None) -> list[dict]:
        if not tools:
            return []
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters or {"type": "object", "properties": {}},
                },
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
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        body: dict = {
            "model": self._model,
            "messages": self._build_messages(system, user_message, context),
            "temperature": 0,
        }
        api_tools = self._build_tools(tools)
        if api_tools:
            body["tools"] = api_tools

        try:
            resp = await self._client.post(
                f"{self._base_url}/chat/completions",
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

        choice = (payload.get("choices") or [{}])[0]
        msg = choice.get("message", {}) if isinstance(choice, dict) else {}
        text = msg.get("content") or ""
        tool_calls_raw = msg.get("tool_calls") or []
        tool_calls: list[ToolCall] = []
        for tc in tool_calls_raw:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            args_raw = fn.get("arguments", "{}")
            if isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw)
                except json.JSONDecodeError:
                    args = {"__raw__": args_raw}
            else:
                args = args_raw or {}
            tool_calls.append(ToolCall(name=fn.get("name", ""), arguments=args))

        return AgentResponse(text=text, tool_calls=tool_calls, raw=payload)

    async def close(self) -> None:
        await self._client.aclose()
