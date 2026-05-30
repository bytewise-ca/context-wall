"""Provenance event data models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class ProvenanceEventHeader(BaseModel):
    event_id: str = Field(default_factory=_uuid)
    event_type: str
    session_id: str
    request_id: str
    occurred_at: datetime = Field(default_factory=_now)


class ContextRequestEvent(ProvenanceEventHeader):
    event_type: str = "context_request"
    task: str
    task_type: str
    keywords: list[str]
    traversal_depth: int
    trust_cutoff: float


class SliceIncludedEvent(ProvenanceEventHeader):
    event_type: str = "slice_included"
    node_id: str
    file_path: str
    trust_score: float
    token_count: int
    include_reason: str


class SliceExcludedEvent(ProvenanceEventHeader):
    event_type: str = "slice_excluded"
    node_id: str
    file_path: str
    trust_score: float
    exclude_reason: str


class OutcomeEvent(ProvenanceEventHeader):
    event_type: str = "outcome"
    outcome_type: str
    success: bool
    score: float
    node_ids: list[str]
    source_id: str = ""


class PolicyEnforcementEvent(BaseModel):
    request_id: str
    session_id: str
    rule_name: str
    action: str
    file_path: str
    node_id: str = ""
    line_numbers: list[int] = Field(default_factory=list)
    reason: str
    pattern_name: str = ""
    source_id: str = ""
    occurred_at: datetime = Field(default_factory=_now)


class Session(BaseModel):
    session_id: str = Field(default_factory=_uuid)
    agent_id: str = ""
    model_version: str = ""
    repository_root: str = ""
    client_type: str = ""
    status: str = "open"
    started_at: datetime = Field(default_factory=_now)
    closed_at: datetime | None = None
    request_count: int = 0
    total_tokens: int = 0
    avg_outcome_score: float | None = None


ProvenanceEvent = ContextRequestEvent | SliceIncludedEvent | SliceExcludedEvent | OutcomeEvent
