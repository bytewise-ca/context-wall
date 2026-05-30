"""Policy DSL — type definitions for expression-tree conditions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SUPPORTED_OPERATORS = frozenset({"eq", "neq", "contains", "matches", "in", "gt", "lt"})

KNOWN_FIELDS = frozenset({
    "source_tier",
    "trust_score",
    "task_scope",
    "user_role",
    "data_classification",
    "file_path",
    "content",
})

MAX_CONDITION_DEPTH = 3


@dataclass
class EvalContext:
    """Runtime evaluation context passed to the expression evaluator."""
    source_tier: str = ""
    trust_score: float = 0.0
    task_scope: str = ""
    user_role: str = ""
    data_classification: str = ""
    file_path: str = ""
    content: str = ""

    def get_field(self, field_name: str) -> Any:
        return getattr(self, field_name, "")


@dataclass
class AppliesWhen:
    """Pre-filter: zero-cost skip when request context does not match."""
    user_roles: list[str] = field(default_factory=list)
    task_scopes: list[str] = field(default_factory=list)
    source_tiers: list[str] = field(default_factory=list)
    data_classifications: list[str] = field(default_factory=list)

    def matches(self, ctx: EvalContext) -> bool:
        """Return True when the context satisfies all non-empty constraints."""
        if self.user_roles and ctx.user_role not in self.user_roles:
            return False
        if self.task_scopes and ctx.task_scope not in self.task_scopes:
            return False
        if self.source_tiers and ctx.source_tier not in self.source_tiers:
            return False
        if self.data_classifications and ctx.data_classification not in self.data_classifications:
            return False
        return True

    @property
    def is_empty(self) -> bool:
        return not any([self.user_roles, self.task_scopes, self.source_tiers, self.data_classifications])


@dataclass
class LeafCondition:
    field: str
    op: str
    value: Any


@dataclass
class AndCondition:
    children: list["PolicyCondition"]


@dataclass
class OrCondition:
    children: list["PolicyCondition"]


@dataclass
class NotCondition:
    child: "PolicyCondition"


# Union type for the expression tree
PolicyCondition = LeafCondition | AndCondition | OrCondition | NotCondition


@dataclass
class ComplianceMapping:
    framework: str = ""
    control_id: str = ""
    description: str = ""


@dataclass
class DSLPolicyRule:
    """Full-featured policy rule with optional expression-tree condition and compliance mapping."""
    name: str
    action: str
    reason: str = ""
    layer: str = "repo"  # fleet | org | team | repo
    applies_when: AppliesWhen = field(default_factory=AppliesWhen)
    condition: PolicyCondition | None = None
    compliance_mapping: ComplianceMapping | None = None
    # Backward-compat fields (flat detector rules)
    scope: str = "content"
    detector: str = ""
    path_prefix: str = ""
    require_tag: str = ""
    custom_patterns: list[str] = field(default_factory=list)
