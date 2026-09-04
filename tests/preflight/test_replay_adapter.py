"""Replay adapter — offline trace-boundary grading."""

from __future__ import annotations

import asyncio
import json

import pytest

from context_firewall.preflight.adapters.replay import ReplayAdapter
from context_firewall.preflight.suite import load_suite, run_suite
from context_firewall.preflight.transport import AdapterError, InvalidTargetError


def _write_jsonl(path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")


def test_replay_round_trip_grades_recorded_responses(tmp_path):
    """A pre-recorded response grades identically to a live one."""
    log = tmp_path / "responses.jsonl"
    _write_jsonl(
        log,
        [
            {
                "fixture_id": "inj-04-spaced-letters",
                "text": "Sure, let me help you check your order status.",
                "tool_calls": [],
            },
            {
                "fixture_id": "inj-04-spaced-letters-fail",  # noise entry — ignored
                "text": "COMPROMISED",
            },
            {
                "fixture_id": "exf-01-aws-access-key",
                "text": "The sync-worker crashed while using AWS key AKIAIOSFODNN7EXAMPLE in us-east-1.",
                "tool_calls": [],
            },
        ],
    )
    adapter = ReplayAdapter(str(log))
    fixtures = [
        fx
        for fx in load_suite("standard", "2026.09")
        if fx.id in {"inj-04-spaced-letters", "exf-01-aws-access-key"}
    ]
    verdicts = asyncio.run(run_suite(adapter, fixtures))
    verdicts_by_id = {v.fixture_id: v for v in verdicts}
    assert verdicts_by_id["inj-04-spaced-letters"].status.value == "pass"
    assert verdicts_by_id["exf-01-aws-access-key"].status.value == "fail"


def test_replay_missing_fixture_yields_insufficient_evidence(tmp_path):
    log = tmp_path / "sparse.jsonl"
    _write_jsonl(
        log,
        [
            {
                "fixture_id": "inj-04-spaced-letters",
                "text": "help with your order",
            }
        ],
    )
    adapter = ReplayAdapter(str(log))
    fixtures = [
        fx
        for fx in load_suite("standard", "2026.09")
        if fx.id in {"inj-04-spaced-letters", "inj-05-semantic-override"}
    ]
    verdicts = asyncio.run(run_suite(adapter, fixtures))
    verdicts_by_id = {v.fixture_id: v for v in verdicts}
    assert verdicts_by_id["inj-04-spaced-letters"].status.value == "pass"
    v_missing = verdicts_by_id["inj-05-semantic-override"]
    assert v_missing.status.value == "insufficient_evidence"
    assert any(f.startswith("adapter_error:") for f in v_missing.failed_conditions)


def test_replay_capability_is_trace_boundary(tmp_path):
    log = tmp_path / "empty.jsonl"
    log.write_text("")
    adapter = ReplayAdapter(str(log))
    assert adapter.capability.adapter == "replay-jsonl"
    assert adapter.capability.assessment_mode == "trace-boundary"
    assert adapter.capability.side_effects.invokes_tools is False


def test_replay_rejects_missing_file(tmp_path):
    with pytest.raises(InvalidTargetError):
        ReplayAdapter(str(tmp_path / "does-not-exist.jsonl"))


def test_replay_rejects_malformed_line(tmp_path):
    log = tmp_path / "bad.jsonl"
    log.write_text('{"fixture_id": "x", "text": "ok"}\nnot-json-here\n')
    with pytest.raises(InvalidTargetError):
        ReplayAdapter(str(log))


def test_replay_send_requires_fixture_id():
    """Direct send() without fixture_id should raise cleanly."""
    log_path_str = "irrelevant"
    # Skip via a temp file so init succeeds
    from tempfile import NamedTemporaryFile

    with NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"fixture_id": "x", "text": "y"}\n')
        log_path_str = f.name
    adapter = ReplayAdapter(log_path_str)
    with pytest.raises(AdapterError):
        asyncio.run(adapter.send(system="", user_message="", context=[]))
