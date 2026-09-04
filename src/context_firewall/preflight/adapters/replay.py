"""Replay adapter — trace-boundary preflight.

Reads a JSONL of prerecorded agent responses and serves them from the suite
runner as if they'd come from a live target. Two things this unlocks:

    1. Reproducible grading in CI: capture responses once with `--openai` /
       `--anthropic`, save the JSONL, then run `--replay <path>` in CI to
       assert the same grade without re-hitting the model.
    2. Auditing production traces: users with real agent sessions they can't
       safely point a test harness at can sanitize their traces and grade
       them offline.

JSONL format (one line per fixture response):

    {"fixture_id": "inj-01-echoleak-shape", "text": "...", "tool_calls": []}
    {"fixture_id": "exf-19-secret-in-tool-output", "text": "Notified.",
     "tool_calls": [{"name": "send_message", "arguments": {"channel": "#ops", "body": "..."}}]}

Missing fixture_ids in the log raise `AdapterError` for that fixture only —
the run continues and the missing fixtures become `insufficient_evidence`
verdicts.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import AgentResponse, ContextItem, ToolCall, ToolDef
from ..transport import (
    AdapterError,
    AgentTransport,
    CapabilityManifest,
    InvalidTargetError,
    SideEffectPosture,
)


class ReplayAdapter(AgentTransport):
    def __init__(self, log_path: str | Path) -> None:
        p = Path(log_path)
        if not p.exists():
            raise InvalidTargetError(f"--replay log not found: {p}")
        try:
            raw_lines = p.read_text().splitlines()
        except OSError as e:
            raise InvalidTargetError(f"cannot read {p}: {e}") from e

        self._by_fixture: dict[str, AgentResponse] = {}
        for lineno, line in enumerate(raw_lines, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                raise InvalidTargetError(f"invalid JSON on {p}:{lineno}: {e}") from e
            fixture_id = entry.get("fixture_id")
            if not fixture_id:
                raise InvalidTargetError(f"{p}:{lineno} missing 'fixture_id'")
            tool_calls = [
                ToolCall(name=tc.get("name", ""), arguments=tc.get("arguments") or {})
                for tc in (entry.get("tool_calls") or [])
                if isinstance(tc, dict)
            ]
            self._by_fixture[fixture_id] = AgentResponse(
                text=entry.get("text", "") or "",
                tool_calls=tool_calls,
                raw={"replay_source": str(p), "replay_lineno": lineno},
            )

        self.capability = CapabilityManifest(
            adapter="replay-jsonl",
            assessment_mode="trace-boundary",
            observes=[
                "response.text",
                "tool.arguments",
            ],
            does_not_observe=[
                "model.requests",
                "provider.retention",
                "agent.nested_model_calls",
                "agent.raw_outbound_http",
                "anything.not.captured.in.the.replay.log",
            ],
            side_effects=SideEffectPosture(
                invokes_tools=False,
                invokes_dangerous_tools=False,
            ),
        )
        self._path = p

    async def send(
        self,
        system: str,
        user_message: str,
        context: list[ContextItem],
        tools: list[ToolDef] | None = None,
        fixture_id: str | None = None,
    ) -> AgentResponse:
        if fixture_id is None:
            raise AdapterError("replay adapter requires fixture_id metadata")
        resp = self._by_fixture.get(fixture_id)
        if resp is None:
            raise AdapterError(f"no recorded response for {fixture_id} in {self._path}")
        return resp

    async def close(self) -> None:
        return None
