"""ContextWall Preflight — agent safety preflight.

Point at your agent. Get a safety scorecard and release decision in 60 seconds.

Public API is stable; imports below drive the CLI, tests, and any future
programmatic use.
"""

from .models import (
    Assessment,
    Dimension,
    DimensionScore,
    EvidenceBoundary,
    Fixture,
    Gate,
    GateStatus,
    MCPExposure,
    MCPExposureFinding,
    MCPServerReport,
    ScoreCard,
    Severity,
    Verdict,
    VerdictStatus,
)
from .transport import AdapterError, AgentTransport, CapabilityManifest, InvalidTargetError

__all__ = [
    "AdapterError",
    "AgentTransport",
    "Assessment",
    "CapabilityManifest",
    "Dimension",
    "DimensionScore",
    "EvidenceBoundary",
    "Fixture",
    "Gate",
    "GateStatus",
    "InvalidTargetError",
    "MCPExposure",
    "MCPExposureFinding",
    "MCPServerReport",
    "ScoreCard",
    "Severity",
    "Verdict",
    "VerdictStatus",
]
