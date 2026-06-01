"""Individual trust signal computations - all read from pre-indexed data."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import aiosqlite

logger = logging.getLogger(__name__)

# Patterns that indicate injection risk
_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api_key|apikey|api-key)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{20,}[\"']?"),
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"sk-[A-Za-z0-9]{48}"),
]


def compute_injection_risk(content: str) -> float:
    """Return [0.0, 1.0] injection risk score based on pattern matches."""
    if not content:
        return 0.0
    matches = sum(1 for p in _SECRET_PATTERNS if p.search(content))
    return min(1.0, matches * 0.3)


def compute_structural_relevance(base_score: float) -> float:
    """Structural relevance comes directly from context-compiler BFS score."""
    return max(0.0, min(1.0, base_score))


async def compute_runtime_evidence(node_id: str, db: aiosqlite.Connection) -> float:
    """Read runtime signal from pre-indexed SQLite cache."""
    try:
        async with db.execute(
            "SELECT invocation_count, exception_rate, latency_degraded FROM runtime_signals WHERE node_id = ?",
            (node_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return 0.5  # neutral fallback - no OTel data yet
        invocations = row["invocation_count"]
        exception_rate = row["exception_rate"]
        degraded = bool(row["latency_degraded"])
        if invocations == 0:
            return 0.5
        score = min(1.0, invocations / 100)  # saturates at 100+ invocations
        score -= exception_rate * 0.5
        if degraded:
            score -= 0.15
        return max(0.0, score)
    except Exception:
        logger.warning("compute_runtime_evidence failed for node %s", node_id, exc_info=True)
        return 0.5


async def compute_freshness(file_path: str, db: aiosqlite.Connection) -> float:
    """Days-since-last-commit freshness signal."""
    try:
        async with db.execute(
            "SELECT last_commit_at FROM git_metadata WHERE file_path = ?",
            (file_path,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None or row["last_commit_at"] is None:
            return 0.5
        last_commit = datetime.fromisoformat(row["last_commit_at"])
        if last_commit.tzinfo is None:
            last_commit = last_commit.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - last_commit).days
        if age_days <= 7:
            return 1.0
        elif age_days <= 30:
            return 0.8
        elif age_days <= 90:
            return 0.6
        elif age_days <= 365:
            return 0.4
        return 0.2
    except Exception:
        logger.warning("compute_freshness failed for %s", file_path, exc_info=True)
        return 0.5


async def compute_stability(file_path: str, db: aiosqlite.Connection) -> float:
    """Inverse churn rate - fewer commits = more stable."""
    try:
        async with db.execute(
            "SELECT commit_count_30d FROM git_metadata WHERE file_path = ?",
            (file_path,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return 0.5
        churn = row["commit_count_30d"]
        if churn == 0:
            return 1.0
        elif churn <= 2:
            return 0.8
        elif churn <= 5:
            return 0.6
        elif churn <= 10:
            return 0.4
        return 0.2
    except Exception:
        logger.warning("compute_stability failed for %s", file_path, exc_info=True)
        return 0.5


async def compute_entropy_contribution(node_id: str, db: aiosqlite.Connection) -> float:
    """Read pre-computed entropy annotation from SQLite."""
    try:
        async with db.execute(
            "SELECT entropy_score, stale FROM entropy_annotations WHERE node_id = ?",
            (node_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return 0.30  # conservative default for unannotated nodes
        score = float(row["entropy_score"])
        if row["stale"]:
            score = min(1.0, score + 0.15)  # staleness penalty
        return score
    except Exception:
        logger.warning("compute_entropy_contribution failed for node %s", node_id, exc_info=True)
        return 0.30


def compute_verification(content: str, file_path: str) -> float:
    """Proxy: presence of test co-location or assertion patterns."""
    # Simple heuristic - look for test patterns in neighbouring paths
    if "test" in file_path.lower() or "spec" in file_path.lower():
        return 0.8
    if "_test." in file_path or ".test." in file_path:
        return 0.9
    # Content-based proxy: assert statements, pytest markers
    if "assert " in content or "@pytest" in content or "unittest" in content:
        return 0.7
    return 0.5  # neutral


def compute_consistency(content: str) -> float:
    """Proxy: docstring / comment coverage as consistency signal."""
    if not content:
        return 0.5
    lines = content.splitlines()
    if not lines:
        return 0.5
    comment_lines = sum(
        1 for line in lines
        if line.strip().startswith(("#", "//", "/*", "*", '"""', "'''"))
    )
    ratio = comment_lines / len(lines)
    return min(1.0, 0.4 + ratio)


async def compute_enforcement_penalty(source_id: str, db: aiosqlite.Connection) -> float:
    """Return the current [0.0, 1.0] trust penalty for a source.

    Reads from source_enforcement_penalties which is updated by ProvenanceEngine
    each time a deny event is recorded. A penalty of 0.0 means no recent blocks;
    1.0 means the source has been blocked repeatedly without any recovery time.
    Returns 0.0 for unknown sources (no enforcement history = no penalty).
    """
    if not source_id:
        return 0.0
    try:
        async with db.execute(
            "SELECT penalty_score FROM source_enforcement_penalties WHERE source_id = ?",
            (source_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return 0.0
        return max(0.0, min(1.0, float(row["penalty_score"])))
    except Exception:
        logger.warning("compute_enforcement_penalty failed for source %s", source_id, exc_info=True)
        return 0.0
