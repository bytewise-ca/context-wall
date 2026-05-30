"""Policy DSL — YAML parser and expression-tree evaluator.

Evaluator is pure Python with no scripting runtime; deterministic at every call.
"""

from __future__ import annotations

import re
from typing import Any

from context_firewall.policy.dsl.types import (
    AndCondition,
    AppliesWhen,
    ComplianceMapping,
    DSLPolicyRule,
    EvalContext,
    KNOWN_FIELDS,
    LeafCondition,
    MAX_CONDITION_DEPTH,
    NotCondition,
    OrCondition,
    PolicyCondition,
    SUPPORTED_OPERATORS,
)


# ── YAML → AST parser ────────────────────────────────────────────────────────

class PolicyParseError(Exception):
    def __init__(self, message: str, line: int | None = None) -> None:
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


def parse_condition(raw: dict[str, Any], depth: int = 0) -> PolicyCondition:
    """Parse a condition dict into an AST node."""
    if depth >= MAX_CONDITION_DEPTH:
        raise PolicyParseError(
            f"condition-depth-exceeded: depth {depth} > max {MAX_CONDITION_DEPTH}"
        )

    if "and" in raw:
        children = raw["and"]
        if not isinstance(children, list):
            raise PolicyParseError("'and' must be a list")
        return AndCondition(children=[parse_condition(c, depth + 1) for c in children])

    if "or" in raw:
        children = raw["or"]
        if not isinstance(children, list):
            raise PolicyParseError("'or' must be a list")
        return OrCondition(children=[parse_condition(c, depth + 1) for c in children])

    if "not" in raw:
        child = raw["not"]
        if not isinstance(child, dict):
            raise PolicyParseError("'not' must be a dict")
        return NotCondition(child=parse_condition(child, depth + 1))

    # Leaf condition
    field_name = raw.get("field", "")
    op = raw.get("op", "")
    value = raw.get("value")

    if not field_name:
        raise PolicyParseError("leaf condition missing 'field'")
    if field_name not in KNOWN_FIELDS:
        raise PolicyParseError(f"unknown field '{field_name}'; known: {sorted(KNOWN_FIELDS)}")
    if op not in SUPPORTED_OPERATORS:
        raise PolicyParseError(
            f"unsupported operator '{op}'; supported: {sorted(SUPPORTED_OPERATORS)}"
        )
    if value is None:
        raise PolicyParseError(f"leaf condition missing 'value' for field '{field_name}'")

    return LeafCondition(field=field_name, op=op, value=value)


def parse_applies_when(raw: dict[str, Any]) -> AppliesWhen:
    def _as_list(v) -> list[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        return [str(v)]

    return AppliesWhen(
        user_roles=_as_list(raw.get("user_role")),
        task_scopes=_as_list(raw.get("task_scope")),
        source_tiers=_as_list(raw.get("source_tier")),
        data_classifications=_as_list(raw.get("data_classification")),
    )


def parse_compliance_mapping(raw: dict[str, Any]) -> ComplianceMapping:
    return ComplianceMapping(
        framework=str(raw.get("framework", "")),
        control_id=str(raw.get("control_id", "")),
        description=str(raw.get("description", "")),
    )


def parse_rule(raw: dict[str, Any], layer: str = "repo") -> DSLPolicyRule:
    """Parse a single policy rule dict into a DSLPolicyRule."""
    name = raw.get("name", "unnamed")
    action = raw.get("action", "exclude")
    reason = raw.get("reason", "")

    applies_when = AppliesWhen()
    if "applies_when" in raw:
        applies_when = parse_applies_when(raw["applies_when"])

    condition: PolicyCondition | None = None
    if "condition" in raw:
        condition = parse_condition(raw["condition"])

    compliance_mapping: ComplianceMapping | None = None
    if "compliance_mapping" in raw:
        compliance_mapping = parse_compliance_mapping(raw["compliance_mapping"])

    return DSLPolicyRule(
        name=name,
        action=action,
        reason=reason,
        layer=layer,
        applies_when=applies_when,
        condition=condition,
        compliance_mapping=compliance_mapping,
        # Backward-compat flat fields
        scope=raw.get("scope", "content"),
        detector=raw.get("detector", ""),
        path_prefix=raw.get("path_prefix", ""),
        require_tag=raw.get("require_tag", ""),
        custom_patterns=raw.get("custom_patterns", []),
    )


def validate_policy_file(raw: dict[str, Any]) -> list[str]:
    """Validate a parsed YAML policy doc; return list of error strings."""
    errors: list[str] = []
    for i, rule_raw in enumerate(raw.get("rules", [])):
        try:
            parse_rule(rule_raw)
        except PolicyParseError as e:
            errors.append(f"rule[{i}] '{rule_raw.get('name', '?')}': {e}")
    return errors


# ── Expression-tree evaluator ─────────────────────────────────────────────────

_compiled_patterns: dict[str, re.Pattern] = {}


def _get_pattern(pattern_str: str) -> re.Pattern:
    if pattern_str not in _compiled_patterns:
        _compiled_patterns[pattern_str] = re.compile(pattern_str, re.IGNORECASE)
    return _compiled_patterns[pattern_str]


def evaluate(condition: PolicyCondition | None, ctx: EvalContext) -> bool:
    """Evaluate a condition tree against a context. Pure, no I/O."""
    if condition is None:
        return True  # no condition means rule always fires (subject to applies_when)

    if isinstance(condition, LeafCondition):
        return _eval_leaf(condition, ctx)

    if isinstance(condition, AndCondition):
        return all(evaluate(c, ctx) for c in condition.children)

    if isinstance(condition, OrCondition):
        return any(evaluate(c, ctx) for c in condition.children)

    if isinstance(condition, NotCondition):
        return not evaluate(condition.child, ctx)

    return False


def _eval_leaf(leaf: LeafCondition, ctx: EvalContext) -> bool:
    actual = ctx.get_field(leaf.field)
    expected = leaf.value
    op = leaf.op

    if op == "eq":
        return str(actual).lower() == str(expected).lower()
    if op == "neq":
        return str(actual).lower() != str(expected).lower()
    if op == "contains":
        return str(expected).lower() in str(actual).lower()
    if op == "matches":
        return bool(_get_pattern(str(expected)).search(str(actual)))
    if op == "in":
        if not isinstance(expected, list):
            expected = [expected]
        return str(actual).lower() in [str(v).lower() for v in expected]
    if op == "gt":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False
    if op == "lt":
        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False

    return False
