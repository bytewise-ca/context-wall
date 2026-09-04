"""`ctxfw check` — Preflight CLI command.

Exit codes:
    0   gate passed (or gate advisory)
    2   CLI usage error
    10  gate blocked by safety failure
    11  gate blocked by insufficient evidence
    12  adapter or target error
"""

from __future__ import annotations

import asyncio
import os
import sys

import click

from .adapters.anthropic import AnthropicAdapter
from .adapters.mcp_static import MCPStaticAdapter
from .adapters.openai import OpenAIAdapter
from .adapters.replay import ReplayAdapter
from .grade import compute_dimension_score, compute_gate
from .models import (
    Assessment,
    Dimension,
    DimensionScore,
    EvidenceBoundary,
    Gate,
    GateStatus,
    ScoreCard,
)
from .policy import PolicyError, load_policy
from .redact import redact_scorecard
from .report import json_out as json_report
from .report import sarif as sarif_report
from .report import terminal as term_report
from .suite import SuiteError, load_suite, run_suite
from .transport import AdapterError, AgentTransport, InvalidTargetError


EXIT_OK = 0
EXIT_USAGE = 2
EXIT_GATE_BLOCKED = 10
EXIT_INSUFFICIENT_EVIDENCE = 11
EXIT_ADAPTER_ERROR = 12


@click.command("check", help="Point at your agent. Get a safety preflight in 60 seconds.")
# ── target selection (exactly one) ───────────────────────────────────────────
@click.option("--openai", "openai_url", default=None,
              help="OpenAI-compatible endpoint base URL (e.g. http://localhost:11434/v1)")
@click.option("--openai-model", default="gpt-4o-mini")
@click.option("--openai-key", default=None,
              help="API key for the OpenAI endpoint (or set OPENAI_API_KEY in env)")
@click.option("--anthropic", "anthropic_url", default=None,
              help="Anthropic Messages endpoint base URL (e.g. https://api.anthropic.com)")
@click.option("--anthropic-model", default="claude-3-5-haiku-20241022")
@click.option("--anthropic-key", default=None,
              help="API key for the Anthropic endpoint (or set ANTHROPIC_API_KEY in env)")
@click.option("--replay", "replay_path", type=click.Path(), default=None,
              help="JSONL of prerecorded responses (one per fixture_id); grades offline")
@click.option("--mcp", "mcp_path", type=click.Path(), default=None,
              help="MCP config JSON file (component-exposure scan, never invokes tools)")
# ── suite selection ─────────────────────────────────────────────────────────
@click.option("--suite", default="standard", show_default=True)
@click.option("--suite-version", default="2026.09", show_default=True)
@click.option("--dimensions", default="injection,grounding,exfiltration", show_default=True,
              help="Comma-separated dimensions (ignored for --mcp)")
# ── gate + policy ───────────────────────────────────────────────────────────
@click.option("--policy", "policy_path", type=click.Path(), default=None,
              help="Path to contextwall.yaml gate policy (defaults to ./contextwall.yaml if present)")
@click.option("--gate/--no-gate", default=False,
              help="Enforce release gate (non-zero exit on block)")
@click.option("--fail-below", default=None,
              help="Shorthand minimum-grade floor (e.g. B-); implies --gate")
# ── output ──────────────────────────────────────────────────────────────────
@click.option("--json", "json_out", is_flag=True, help="Emit JSON scorecard")
@click.option("--sarif", "sarif_out", is_flag=True, help="Emit SARIF 2.1.0 log")
@click.option("--no-redact", is_flag=True, default=False,
              help="Do NOT redact secrets/PII from evidence (local debug only)")
def check_cmd(
    openai_url: str | None,
    openai_model: str,
    openai_key: str | None,
    anthropic_url: str | None,
    anthropic_model: str,
    anthropic_key: str | None,
    replay_path: str | None,
    mcp_path: str | None,
    suite: str,
    suite_version: str,
    dimensions: str,
    policy_path: str | None,
    gate: bool,
    fail_below: str | None,
    json_out: bool,
    sarif_out: bool,
    no_redact: bool,
) -> None:
    # ── target validation ───────────────────────────────────────────────────
    targets = [t for t in (openai_url, anthropic_url, replay_path, mcp_path) if t]
    if not targets:
        click.echo(
            "usage: ctxfw check --openai <url>  |  --anthropic <url>\n"
            "                   --replay <log.jsonl>  |  --mcp <config.json>",
            err=True,
        )
        sys.exit(EXIT_USAGE)
    if len(targets) > 1:
        click.echo("error: pass exactly one of --openai / --anthropic / --replay / --mcp per run", err=True)
        sys.exit(EXIT_USAGE)

    if json_out and sarif_out:
        click.echo("error: pass at most one of --json / --sarif", err=True)
        sys.exit(EXIT_USAGE)

    dim_names = [d.strip() for d in dimensions.split(",") if d.strip()]

    # ── policy ──────────────────────────────────────────────────────────────
    try:
        policy = load_policy(policy_path)
    except PolicyError as e:
        click.echo(f"policy error: {e}", err=True)
        sys.exit(EXIT_USAGE)
    policy_name = policy_path if policy_path else ("default" if not _cwd_has_policy() else "contextwall.yaml")
    if fail_below:
        policy = policy.model_copy(update={"minimum_dimension_grade": fail_below})

    # ── adapter ─────────────────────────────────────────────────────────────
    adapter: AgentTransport
    try:
        if openai_url:
            adapter = OpenAIAdapter(
                base_url=openai_url,
                model=openai_model,
                api_key=openai_key or os.environ.get("OPENAI_API_KEY"),
            )
        elif anthropic_url:
            adapter = AnthropicAdapter(
                base_url=anthropic_url,
                model=anthropic_model,
                api_key=anthropic_key or os.environ.get("ANTHROPIC_API_KEY"),
            )
        elif replay_path:
            adapter = ReplayAdapter(log_path=replay_path)
        else:
            assert mcp_path
            adapter = MCPStaticAdapter(config_path=mcp_path)
    except InvalidTargetError as e:
        click.echo(f"invalid target: {e}", err=True)
        sys.exit(EXIT_USAGE)

    # ── dispatch by assessment mode ─────────────────────────────────────────
    if adapter.capability.assessment_mode == "component-exposure":
        scorecard = asyncio.run(_run_exposure(adapter, suite, suite_version))
    else:
        if not dim_names:
            click.echo("error: --dimensions must include at least one entry", err=True)
            sys.exit(EXIT_USAGE)
        try:
            fixtures = load_suite(suite, suite_version, dim_names)
        except SuiteError as e:
            click.echo(f"suite load error: {e}", err=True)
            sys.exit(EXIT_USAGE)
        if not fixtures:
            click.echo(
                f"error: no fixtures matched dimensions={dim_names} in suite {suite}@{suite_version}",
                err=True,
            )
            sys.exit(EXIT_USAGE)
        scorecard = asyncio.run(
            _run_behavioral(adapter, fixtures, dim_names, policy, policy_name, suite, suite_version)
        )

    if not no_redact:
        scorecard = redact_scorecard(scorecard)

    # ── render ──────────────────────────────────────────────────────────────
    if sarif_out:
        sarif_report.render(scorecard, sys.stdout)
    elif json_out:
        json_report.render(scorecard, sys.stdout)
    else:
        term_report.render(scorecard, sys.stdout)

    # ── exit ────────────────────────────────────────────────────────────────
    gating = gate or (fail_below is not None)
    if gating:
        status = scorecard.gate.status
        if status == GateStatus.ADAPTER_ERROR:
            sys.exit(EXIT_ADAPTER_ERROR)
        if status == GateStatus.INSUFFICIENT_EVIDENCE:
            sys.exit(EXIT_INSUFFICIENT_EVIDENCE)
        if status == GateStatus.BLOCKED:
            sys.exit(EXIT_GATE_BLOCKED)
    sys.exit(EXIT_OK)


# ── mode-specific runners ────────────────────────────────────────────────────


async def _run_behavioral(
    adapter: AgentTransport,
    fixtures,
    dim_names: list[str],
    policy,
    policy_name: str,
    suite: str,
    suite_version: str,
) -> ScoreCard:
    try:
        try:
            verdicts = await run_suite(adapter, fixtures)
        except AdapterError as e:
            click.echo(f"adapter error: {e}", err=True)
            sys.exit(EXIT_ADAPTER_ERROR)
    finally:
        await adapter.close()

    fixtures_by_id = {fx.id: fx for fx in fixtures}
    dimension_scores = {}
    for dim in dim_names:
        dim_fixtures = [fx for fx in fixtures if fx.dimension.value == dim]
        dim_ids = {fx.id for fx in dim_fixtures}
        dim_verdicts = [v for v in verdicts if v.fixture_id in dim_ids]
        dimension_scores[dim] = compute_dimension_score(
            dimension_name=dim,
            fixtures=dim_fixtures,
            verdicts=dim_verdicts,
            observed_channels=adapter.capability.observes,
            unobserved_channels=adapter.capability.does_not_observe,
        )

    gate_obj = compute_gate(
        dimensions=dimension_scores,
        fixtures_by_id=fixtures_by_id,
        policy=policy,
        policy_name=policy_name,
    )

    return ScoreCard(
        assessment=Assessment(
            mode=adapter.capability.assessment_mode,
            suite=suite,
            suite_version=suite_version,
            adapter=adapter.capability.adapter,
        ),
        dimensions=dimension_scores,
        gate=gate_obj,
        evidence_boundary=EvidenceBoundary(
            observed=adapter.capability.observes,
            not_observed=adapter.capability.does_not_observe,
        ),
    )


async def _run_exposure(
    adapter: AgentTransport,
    suite: str,
    suite_version: str,
) -> ScoreCard:
    try:
        exposure = await adapter.enumerate_exposure()
    finally:
        await adapter.close()

    dims = {
        name: DimensionScore(
            dimension=Dimension(name),
            passed=0,
            total=0,
            grade="N/A",
            sample_size_warning=True,
            observed_channels=adapter.capability.observes,
            unobserved_channels=adapter.capability.does_not_observe,
            verdicts=[],
        )
        for name in ("injection", "grounding", "exfiltration")
    }

    return ScoreCard(
        assessment=Assessment(
            mode="component-exposure",
            suite=suite,
            suite_version=suite_version,
            adapter=adapter.capability.adapter,
        ),
        dimensions=dims,
        gate=Gate(
            status=GateStatus.ADVISORY,
            policy="component-exposure",
            minimum_grade="N/A",
            blocking_failures=[],
        ),
        evidence_boundary=EvidenceBoundary(
            observed=adapter.capability.observes,
            not_observed=adapter.capability.does_not_observe,
        ),
        mcp_exposure=exposure,
        limitations=[
            "component-exposure mode does not assess runtime agent behavior",
            "for a release decision, run the agent through --openai / --anthropic / --replay",
        ],
    )


def _cwd_has_policy() -> bool:
    from pathlib import Path

    from .policy import DEFAULT_POLICY_PATH

    return Path(DEFAULT_POLICY_PATH).exists()
