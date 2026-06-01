"""Pydantic models for control plane push payloads.

These are the only shapes that cross the network boundary. They contain
counts, scores, and names - never content, file paths, or prompt text.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class ViolationEntry(BaseModel):
    type: str        # prompt_injection | secret_leakage | pii:email | ...
    rule: str = ""   # rule_name label from POLICY_ENFORCEMENTS counter
    action: str = "" # block | redact | warn | audit-only
    count: int = 0


class TelemetryMetrics(BaseModel):
    proxy_requests_total: int = 0
    proxy_blocked_total: int = 0
    violations: list[ViolationEntry] = []
    active_sessions: int = 0
    pipeline_requests_total: int = 0
    avg_proxy_latency_ms: float | None = None


class TelemetryBatch(BaseModel):
    daemon_id: str
    period_start: str   # ISO 8601
    period_end: str     # ISO 8601
    metrics: TelemetryMetrics


class HeartbeatPayload(BaseModel):
    daemon_id: str
    status: str         # healthy | degraded | down
    subsystems: dict[str, dict[str, Any]] = {}


class SessionEvent(BaseModel):
    type: str           # session_opened | session_closed
    daemon_id: str
    session_id_hash: str
    started_at: str | None = None
    closed_at: str | None = None
    client_type: str | None = None
    request_count: int = 0
    violation_count: int = 0


class SessionEventsPayload(BaseModel):
    events: list[SessionEvent]


class RegisterPayload(BaseModel):
    daemon_id: str
    daemon_name: str
    version: str = ""
    engines: list[str] = []
    config_hash: str = ""
    capabilities: list[str] = ["telemetry_push", "policy_pull"]


class RegisterResponse(BaseModel):
    daemon_token: str
    policy_version: str = "v0"
    push_url: str = ""
    heartbeat_url: str = ""
    events_url: str = ""
    policies_url: str = ""
