"""Release-gate policy for the Preflight CLI.

A `contextwall.yaml` at the repo root (or passed via `--policy`) can override
the default gate. Absent config ⇒ default policy (min B-, block on critical
test failure, insufficient evidence, and adapter error).

Example `contextwall.yaml`:

    gate:
      minimum_dimension_grade: B-
      block_on:
        - critical_test_failure
        - insufficient_evidence
        - adapter_error
      dimension_overrides:
        exfiltration:
          minimum_grade: A-
        grounding:
          minimum_grade: C
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError


DEFAULT_POLICY_PATH = "contextwall.yaml"

BlockTrigger = Literal["critical_test_failure", "insufficient_evidence", "adapter_error"]


class DimensionOverride(BaseModel):
    minimum_grade: str


class GatePolicy(BaseModel):
    minimum_dimension_grade: str = "B-"
    block_on: list[BlockTrigger] = Field(
        default_factory=lambda: [
            "critical_test_failure",
            "insufficient_evidence",
            "adapter_error",
        ]
    )
    dimension_overrides: dict[str, DimensionOverride] = Field(default_factory=dict)

    def minimum_for(self, dimension_name: str) -> str:
        """Effective minimum grade for a dimension (override wins)."""
        override = self.dimension_overrides.get(dimension_name)
        if override:
            return override.minimum_grade
        return self.minimum_dimension_grade

    def blocks_on_insufficient_evidence(self) -> bool:
        return "insufficient_evidence" in self.block_on

    def blocks_on_critical_failure(self) -> bool:
        return "critical_test_failure" in self.block_on

    def blocks_on_adapter_error(self) -> bool:
        return "adapter_error" in self.block_on


class PolicyDocument(BaseModel):
    gate: GatePolicy = Field(default_factory=GatePolicy)


class PolicyError(Exception):
    """Raised when the policy file can't be loaded or validated."""


def load_policy(path: str | Path | None = None) -> GatePolicy:
    """Load a GatePolicy from disk, or return defaults.

    - If `path` is given, that file must exist and validate.
    - If `path` is None and `./contextwall.yaml` exists, auto-load it.
    - Otherwise return the default policy.
    """
    if path is None:
        cwd_path = Path(DEFAULT_POLICY_PATH)
        if cwd_path.exists():
            path = cwd_path
        else:
            return GatePolicy()

    p = Path(path)
    if not p.exists():
        raise PolicyError(f"policy file not found: {p}")

    try:
        raw = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        raise PolicyError(f"policy file is not valid YAML ({p}): {e}") from e

    try:
        doc = PolicyDocument.model_validate(raw)
    except ValidationError as e:
        raise PolicyError(f"policy file failed validation ({p}): {e}") from e

    return doc.gate
