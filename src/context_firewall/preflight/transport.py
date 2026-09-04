"""AgentTransport — the abstraction every adapter implements.

Each adapter declares a capability manifest so the scorecard can render an
explicit assessment boundary. Two scorecards produced by different adapters
must not be compared without their boundaries side by side.

Adapters come in two shapes based on their `assessment_mode`:

    model-boundary / trace-boundary  → implement `send()`
    component-exposure               → implement `enumerate_exposure()`

Both methods have safe defaults that raise; adapters override only what they
support. The suite runner + CLI dispatch on `assessment_mode`, so callers
never mix them up.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal

from pydantic import BaseModel, Field

from .models import AgentResponse, ContextItem, MCPExposure, ToolDef


class SideEffectPosture(BaseModel):
    invokes_tools: bool = False
    invokes_dangerous_tools: bool = False


class CapabilityManifest(BaseModel):
    adapter: str
    assessment_mode: Literal["model-boundary", "trace-boundary", "component-exposure"]
    observes: list[str] = Field(default_factory=list)
    does_not_observe: list[str] = Field(default_factory=list)
    side_effects: SideEffectPosture = Field(default_factory=SideEffectPosture)


class AgentTransport(ABC):
    """Common interface for all Preflight adapters."""

    capability: CapabilityManifest

    async def send(
        self,
        system: str,
        user_message: str,
        context: list[ContextItem],
        tools: list[ToolDef] | None = None,
        fixture_id: str | None = None,
    ) -> AgentResponse:
        """Send messages to the agent target and return a normalized response.

        Behavioral adapters (model-boundary, trace-boundary) override this.
        `fixture_id` is optional metadata that trace-boundary adapters use to
        look up prerecorded responses; other adapters ignore it.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement send(); "
            f"assessment_mode={self.capability.assessment_mode}"
        )

    async def enumerate_exposure(self) -> MCPExposure:
        """Enumerate a component target's exposure surface.

        Component-exposure adapters (MCP static, future config scanners)
        override this. Behavioral adapters do not.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement enumerate_exposure(); "
            f"assessment_mode={self.capability.assessment_mode}"
        )

    @abstractmethod
    async def close(self) -> None:
        """Release adapter resources."""


class InvalidTargetError(Exception):
    """Raised when the target URL or configuration is malformed."""


class AdapterError(Exception):
    """Raised when the adapter cannot inspect the target (network, auth, upstream error).

    Different from a fixture failure: adapter errors mean we could not observe
    behavior at all, so the caller should downgrade the dimension to
    `insufficient_evidence` rather than record a `fail` verdict.
    """
