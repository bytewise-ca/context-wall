"""SARIF 2.1.0 reporter.

Emits a SARIF log so CI systems (GitHub Advanced Security, SonarQube,
Codacy, VS Code SARIF viewer) can render Preflight results alongside
other static-analysis findings.

Level mapping:
    critical_test_failure           → error
    dimension_grade_below_minimum   → error
    insufficient_evidence           → note
    adapter_error                   → warning
    (non-release-blocking failures) → warning
"""

from __future__ import annotations

import json
import sys
from typing import IO

from ..models import ScoreCard, Verdict, VerdictStatus

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://schemas.microsoft.com/json-schemas/sarif-2.1.0.json"
_TOOL_URI = "https://github.com/bytewise-ca/context-wall"


def render(scorecard: ScoreCard, stream: IO = sys.stdout) -> None:
    stream.write(json.dumps(build_sarif(scorecard), indent=2))
    stream.write("\n")


def build_sarif(scorecard: ScoreCard) -> dict:
    """Assemble the SARIF document without touching a stream (unit-testable)."""
    rules: list[dict] = []
    results: list[dict] = []
    rule_ids_seen: set[str] = set()

    for dim_name, dim in scorecard.dimensions.items():
        for verdict in dim.verdicts:
            if verdict.fixture_id not in rule_ids_seen:
                rules.append(_rule_for(verdict, dim_name))
                rule_ids_seen.add(verdict.fixture_id)
            result = _result_for(verdict, dim_name)
            if result is not None:
                results.append(result)

    for failure in scorecard.gate.blocking_failures:
        if failure.reason in ("critical_test_failure", "adapter_error"):
            continue  # already emitted per-verdict above
        results.append(
            {
                "ruleId": f"gate::{failure.id}",
                "level": "error",
                "message": {
                    "text": f"gate blocked: {failure.reason.replace('_', ' ')} on {failure.id}"
                },
                "properties": {
                    "gate_status": scorecard.gate.status.value,
                    "gate_policy": scorecard.gate.policy,
                    "minimum_grade": scorecard.gate.minimum_grade,
                },
            }
        )

    # MCP exposure findings — one SARIF result per finding, no rules registered
    # (findings are dynamic per target, not fixture-driven).
    if scorecard.mcp_exposure is not None:
        for server in scorecard.mcp_exposure.servers:
            if server.error:
                results.append(
                    {
                        "ruleId": f"mcp::{server.server_name}::scan-error",
                        "level": "warning",
                        "message": {"text": f"MCP scan error on {server.server_name}: {server.error}"},
                        "properties": {"server": server.server_name, "kind": "scan_error"},
                    }
                )
                continue
            for finding in server.findings:
                level = "warning" if finding.kind == "tool_dangerous_capability" else "error"
                results.append(
                    {
                        "ruleId": f"mcp::{server.server_name}::{finding.kind}",
                        "level": level,
                        "message": {
                            "text": (
                                f"MCP {finding.kind.replace('_', ' ')} on "
                                f"{finding.target} ({server.server_name})"
                                + (f" — {finding.signal}" if finding.signal else "")
                            )
                        },
                        "properties": {
                            "server": server.server_name,
                            "target": finding.target,
                            "kind": finding.kind,
                            "layer": finding.layer,
                            "signal": finding.signal,
                            "excerpt": finding.excerpt,
                        },
                    }
                )

    return {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ContextWall Preflight",
                        "version": scorecard.schema_version,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "assessment_mode": scorecard.assessment.mode,
                    "assessment_scope": scorecard.assessment.scope,
                    "suite": scorecard.assessment.suite,
                    "suite_version": scorecard.assessment.suite_version,
                    "adapter": scorecard.assessment.adapter,
                    "evidence_boundary": scorecard.evidence_boundary.model_dump(),
                    "not_evaluated": [
                        "tool authorization",
                        "correctness",
                        "cost",
                        "latency",
                        "reliability",
                        "tenant isolation",
                        "availability",
                        "data retention",
                    ],
                },
            }
        ],
    }


def _rule_for(verdict: Verdict, dim_name: str) -> dict:
    return {
        "id": verdict.fixture_id,
        "name": verdict.fixture_id,
        "shortDescription": {"text": f"{dim_name}: {verdict.fixture_id}"},
        "fullDescription": {
            "text": f"Preflight fixture {verdict.fixture_id} in dimension {dim_name}."
        },
        "defaultConfiguration": {"level": "warning"},
    }


def _result_for(verdict: Verdict, dim_name: str) -> dict | None:
    if verdict.status == VerdictStatus.PASS:
        return None  # SARIF results are for findings; passing tests don't emit
    if verdict.status == VerdictStatus.INSUFFICIENT_EVIDENCE:
        level = (
            "warning"
            if any(f.startswith("adapter_error:") for f in verdict.failed_conditions)
            else "note"
        )
    else:
        level = "error"

    return {
        "ruleId": verdict.fixture_id,
        "level": level,
        "message": {
            "text": (
                f"{dim_name}: {verdict.status.value}"
                + (f" — {'; '.join(verdict.failed_conditions)}" if verdict.failed_conditions else "")
            )
        },
        "properties": {
            "dimension": dim_name,
            "status": verdict.status.value,
            "failed_conditions": verdict.failed_conditions,
        },
    }
