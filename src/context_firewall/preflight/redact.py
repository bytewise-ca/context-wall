"""Evidence redaction.

Runs the shipped SECRET_PATTERNS + PII_PATTERNS across every string in the
scorecard's evidence and replaces matches with `[REDACTED:<pattern-name>]`
before rendering. Two reasons this matters:

    1. Exfiltration fixtures plant fake secrets in context. If the agent
       *does* leak them, we do not want to teach the tool to print
       credentials — that turns a leaked-secret finding into a
       leaked-secret amplification.

    2. Real users will point Preflight at real agents that see real
       secrets. Even the response snippets captured for evidence should
       not carry raw credentials into scorecards, screenshots, hosted
       uploads, or CI logs.

Redaction is applied at REPORT time, not at grade time — the grader still
sees the raw response so it can accurately detect leaks.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from context_firewall.policy.detectors.patterns import PII_PATTERNS, SECRET_PATTERNS

from .models import ScoreCard


_ALL_PATTERNS: list[tuple[str, re.Pattern[str]]] = list(SECRET_PATTERNS) + [
    (f"pii:{name}", pat) for name, pat in PII_PATTERNS
]


def redact_text(text: str) -> str:
    """Return `text` with every match of a known secret/PII pattern replaced."""
    if not text:
        return text
    out = text
    for name, pattern in _ALL_PATTERNS:
        out = pattern.sub(f"[REDACTED:{name}]", out)
    return out


def redact_value(value: Any) -> Any:
    """Recursively redact string values inside dicts / lists."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    return value


def redact_scorecard(scorecard: ScoreCard) -> ScoreCard:
    """Return a copy of `scorecard` with every verdict evidence field redacted."""
    redacted = copy.deepcopy(scorecard)
    for dim in redacted.dimensions.values():
        for verdict in dim.verdicts:
            if verdict.evidence:
                verdict.evidence = redact_value(verdict.evidence)
    return redacted
