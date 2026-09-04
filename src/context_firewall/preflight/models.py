"""Preflight data model.

Every type in this module is part of the stable public schema — the CLI's
JSON output, the grader regression harness, and any future SDK all validate
against these shapes.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FixtureStatus(str, Enum):
    STABLE = "stable"
    EXPERIMENTAL = "experimental"


class Dimension(str, Enum):
    INJECTION = "injection"
    GROUNDING = "grounding"
    EXFILTRATION = "exfiltration"


class VerdictStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class GateStatus(str, Enum):
    PASS = "pass"
    BLOCKED = "blocked"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    ADAPTER_ERROR = "adapter_error"
    INVALID_TARGET = "invalid_target"
    ADVISORY = "advisory"


# ── Fixture inputs ────────────────────────────────────────────────────────────


class ToolDef(BaseModel):
    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class ContextItem(BaseModel):
    """Retrieved / injected context that reaches the model."""
    type: str = "text"
    source: str = "test"
    content: str


class FixtureSetup(BaseModel):
    system: str = ""
    tools: list[ToolDef] = Field(default_factory=list)
    context: list[ContextItem] = Field(default_factory=list)
    user_message: str


CheckKind = Literal[
    "no_tool_call",
    "no_tool_arg_contains",
    "no_string_in_response",
    "no_pattern_in_response",
    "response_matches_any",
]


class PassCondition(BaseModel):
    """Machine-checkable pass criterion. All conditions must hold for pass."""
    kind: CheckKind
    tool_name: str | None = None
    argument_contains: str | list[str] | None = None
    strings: list[str] | None = None
    pattern: str | None = None
    matches: list[str] | None = None
    description: str = ""


class Fixture(BaseModel):
    id: str
    dimension: Dimension
    severity: Severity = Severity.MEDIUM
    weight: float = 1.0
    release_blocking: bool = False
    status: FixtureStatus = FixtureStatus.STABLE
    citation: str = ""
    threat_model: str = ""
    setup: FixtureSetup
    expected_safe_behavior: str = ""
    pass_conditions: list[PassCondition] = Field(default_factory=list)
    known_limitations: str = ""


# ── Adapter output ────────────────────────────────────────────────────────────


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    """Normalized agent response captured by the adapter."""
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


# ── Grader output ─────────────────────────────────────────────────────────────


class Verdict(BaseModel):
    fixture_id: str
    status: VerdictStatus
    failed_conditions: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class DimensionRaw(BaseModel):
    """Raw counts underlying a dimension grade."""
    passed: int
    total: int


class DimensionScore(BaseModel):
    dimension: Dimension
    passed: int
    total: int
    grade: str
    sample_size_warning: bool
    observed_channels: list[str] = Field(default_factory=list)
    unobserved_channels: list[str] = Field(default_factory=list)
    verdicts: list[Verdict] = Field(default_factory=list)


class GateFailure(BaseModel):
    id: str
    reason: str


class Gate(BaseModel):
    status: GateStatus
    policy: str = "default"
    minimum_grade: str = "B-"
    blocking_failures: list[GateFailure] = Field(default_factory=list)


class Assessment(BaseModel):
    mode: Literal["model-boundary", "trace-boundary", "component-exposure"]
    scope: str = "safety_only"
    suite: str
    suite_version: str
    adapter: str
    target_hash: str = ""


class EvidenceBoundary(BaseModel):
    observed: list[str] = Field(default_factory=list)
    not_observed: list[str] = Field(default_factory=list)


class MCPExposureFinding(BaseModel):
    """A single finding on an MCP component (tool or resource)."""
    kind: Literal[
        "tool_untrusted_instruction",
        "resource_injection_pattern",
        "tool_dangerous_capability",
    ]
    target: str          # tool name or resource URI
    server: str          # mcp server identifier
    layer: str = ""      # detector layer, if applicable
    signal: str = ""     # detector signal, if applicable
    excerpt: str = ""


class MCPServerReport(BaseModel):
    """Per-server component-exposure findings from an MCP static scan."""
    server_name: str
    error: str | None = None                             # if the scan couldn't run
    tools_enumerated: int = 0
    tools_write_capable: list[str] = Field(default_factory=list)
    tools_network_capable: list[str] = Field(default_factory=list)
    tools_with_untrusted_instructions: list[str] = Field(default_factory=list)
    resources_scanned: int = 0
    resources_with_injection: list[str] = Field(default_factory=list)
    findings: list[MCPExposureFinding] = Field(default_factory=list)


class MCPExposure(BaseModel):
    """Aggregate MCP static-scan output — one entry per configured server."""
    servers: list[MCPServerReport] = Field(default_factory=list)

    def total_findings(self) -> int:
        return sum(len(s.findings) for s in self.servers)


class ScoreCard(BaseModel):
    schema_version: str = "1.0"
    assessment: Assessment
    dimensions: dict[str, DimensionScore] = Field(default_factory=dict)
    gate: Gate
    evidence_boundary: EvidenceBoundary
    limitations: list[str] = Field(default_factory=list)
    mcp_exposure: MCPExposure | None = None
