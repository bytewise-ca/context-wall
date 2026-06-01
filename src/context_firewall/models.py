"""Shared domain models for ContextWall pipeline."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from context_firewall.source.types import SourceTrustTier


class TaskType(str, Enum):
    BUG_FIX = "BUG_FIX"
    NEW_FEATURE = "NEW_FEATURE"
    REFACTOR = "REFACTOR"
    SECURITY_REVIEW = "SECURITY_REVIEW"
    DEPENDENCY_AUDIT = "DEPENDENCY_AUDIT"


class TraversalStrategy(BaseModel):
    edge_types: list[str] = Field(default_factory=lambda: ["calls", "imports", "inherits"])
    direction: str = "both"
    max_depth: int = 4


class PipelineContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    task: str
    task_type: TaskType
    confidence: float
    keywords: list[str]
    traversal_strategy: TraversalStrategy
    trust_weight_profile: str
    request_id: str
    session_id: str
    received_at: datetime


class ClassificationResult(BaseModel):
    task_type: TaskType
    confidence: float = 1.0
    keywords: list[str] = Field(default_factory=list)
    source: str  # "context-compiler" | "cre-extension" | "fallback"


class RankedSlice(BaseModel):
    node_id: str
    file_path: str
    content: str
    trust_score: float
    token_count: int
    language: str = ""
    symbols: list[str] = Field(default_factory=list)
    signal_breakdown: dict[str, float] = Field(default_factory=dict)
    source_id: str = ""
    source_trust_tier: SourceTrustTier = SourceTrustTier.UNTRUSTED
    compliance_scope: list[str] = Field(default_factory=list)


class TrustRange(BaseModel):
    min: float
    max: float
    p50: float


class ExclusionReason(BaseModel):
    file_path: str
    node_id: str = ""
    reason: str
    score: float
    rule_name: str = ""
    detail: str = ""


class TrustedSlice(BaseModel):
    node_id: str
    file_path: str
    content: str
    trust_score: float
    token_count: int
    language: str = ""
    symbols: list[str] = Field(default_factory=list)


class TrustedContextBundle(BaseModel):
    request_id: str
    session_id: str
    task_type: str
    assembled_at: datetime
    slices: list[TrustedSlice]
    excluded_count: int
    excluded_reasons: list[ExclusionReason]
    summary: str
    total_tokens: int
    token_budget: int
    trust_range: TrustRange
    entropy_score: float
    policy_violations: int


class SubsystemHealth(BaseModel):
    name: str
    healthy: bool
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class SignalBreakdown(BaseModel):
    structural_relevance: float = 0.5
    runtime_evidence: float = 0.5
    freshness: float = 0.5
    stability: float = 0.5
    verification: float = 0.5
    consistency: float = 0.5
    injection_risk: float = 0.0
    entropy_contribution: float = 0.0


class EntropyAnnotation(BaseModel):
    node_id: str
    file_path: str
    entropy_score: float
    signals: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    computed_at: datetime
    stale: bool = False
