"""Suite loader + runner.

Fixture layout on disk:

    src/context_firewall/preflight/fixtures/<suite>/<version>/<dimension>/*.yaml

`load_suite("standard", "2026.09")` returns every stable fixture in the
standard suite pinned at 2026.09. `run_suite(adapter, fixtures)` executes
each fixture against the adapter and returns per-fixture verdicts. Adapter
errors on individual fixtures become `INSUFFICIENT_EVIDENCE` verdicts —
they don't count as failures.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

from .grader.grader import grade_fixture
from .models import Fixture, FixtureStatus, Verdict, VerdictStatus
from .transport import AdapterError, AgentTransport

_SUITES_ROOT = Path(__file__).parent / "fixtures"


class SuiteError(Exception):
    """Raised when a suite cannot be located or parsed."""


def suite_root(name: str, version: str) -> Path:
    return _SUITES_ROOT / name / version


def load_suite(
    name: str,
    version: str,
    dimensions: Iterable[str] | None = None,
    include_experimental: bool = False,
) -> list[Fixture]:
    root = suite_root(name, version)
    if not root.exists():
        raise SuiteError(f"suite {name!r}@{version!r} not found at {root}")

    wanted = set(dimensions) if dimensions else None
    fixtures: list[Fixture] = []
    for path in sorted(root.rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text()) or {}
        try:
            fx = Fixture.model_validate(raw)
        except Exception as e:
            raise SuiteError(f"invalid fixture at {path}: {e}") from e
        if wanted and fx.dimension.value not in wanted:
            continue
        if fx.status == FixtureStatus.EXPERIMENTAL and not include_experimental:
            continue
        fixtures.append(fx)
    return fixtures


async def run_suite(adapter: AgentTransport, fixtures: list[Fixture]) -> list[Verdict]:
    verdicts: list[Verdict] = []
    for fx in fixtures:
        try:
            response = await adapter.send(
                system=fx.setup.system,
                user_message=fx.setup.user_message,
                context=fx.setup.context,
                tools=fx.setup.tools,
                fixture_id=fx.id,
            )
        except AdapterError as e:
            verdicts.append(
                Verdict(
                    fixture_id=fx.id,
                    status=VerdictStatus.INSUFFICIENT_EVIDENCE,
                    failed_conditions=[f"adapter_error: {e}"],
                )
            )
            continue
        verdicts.append(grade_fixture(fx, response))
    return verdicts
