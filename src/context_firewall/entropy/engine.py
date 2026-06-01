"""Context Entropy Engine - computes entropy annotations offline."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from context_firewall.config import Config
from context_firewall.models import EntropyAnnotation, SubsystemHealth

logger = logging.getLogger(__name__)

# Heuristics: these patterns signal expected divergence, not entropy
_SKIP_PATTERNS = [
    re.compile(r"//\s*cre:skip"),
    re.compile(r"#\s*cre:skip"),
    re.compile(r"(?i)legacy"),
    re.compile(r"(?i)feature.?flag"),
    re.compile(r"(?i)retry"),
]

_NAMING_INCONSISTENCY_PAIRS = [
    (re.compile(r"\bget\w+\b"), re.compile(r"\bfetch\w+\b")),
    (re.compile(r"\bcreate\w+\b"), re.compile(r"\bnew\w+\b")),
    (re.compile(r"\bdelete\w+\b"), re.compile(r"\bremove\w+\b")),
]


def _has_skip_annotation(content: str) -> bool:
    return any(p.search(content) for p in _SKIP_PATTERNS)


def _compute_naming_inconsistency(content: str) -> float:
    """Detect mixed naming conventions (get/fetch, create/new, delete/remove)."""
    score = 0.0
    for pattern_a, pattern_b in _NAMING_INCONSISTENCY_PAIRS:
        has_a = bool(pattern_a.search(content))
        has_b = bool(pattern_b.search(content))
        if has_a and has_b:
            score += 0.33
    return min(1.0, score)


def _compute_dead_code_references(content: str) -> float:
    """Proxy: deprecated/todo/fixme markers as dead code signal."""
    markers = re.findall(r"(?i)(deprecated|todo|fixme|hack|xxx|dead.?code)", content)
    return min(1.0, len(markers) * 0.15)


def _compute_contradictory_documentation(content: str) -> float:
    """Structural contradiction: docstring describes opposite of what code does."""
    doc_lines = re.findall(r'""".*?"""', content, re.DOTALL)
    negations = 0
    for doc in doc_lines:
        negations += len(re.findall(r"\b(not|never|no longer|deprecated|do not|don\'t)\b", doc, re.I))
    return min(1.0, negations * 0.2)


def _compute_semantic_duplication(content_a: str, content_b: str) -> float:
    """Jaccard similarity on significant token sets between two files."""
    tokens_a = set(t for t in re.findall(r"[a-zA-Z_]\w{3,}", content_a.lower()) if len(t) > 4)
    tokens_b = set(t for t in re.findall(r"[a-zA-Z_]\w{3,}", content_b.lower()) if len(t) > 4)
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def _compute_divergent_execution_paths(content: str) -> float:
    """Estimate branching complexity from structural patterns."""
    lines = content.split("\n")
    total = max(1, len(lines))
    # Count branching constructs normalized to file length
    branches = 0
    for line in lines:
        stripped = line.lstrip()
        if re.match(r"(if |elif |else:|except |except:|finally:|case )", stripped):
            branches += 1
        elif re.match(r"(for |while )", stripped):
            branches += 0.5
    # Also penalize high cyclomatic density: > 1 branch per 8 lines is high
    density = branches / (total / 8)
    return min(1.0, density * 0.4)


def _compute_runtime_inconsistency(content: str) -> float:
    """Detect non-deterministic sources: random, time, env vars, network."""
    patterns = [
        r"\brandom\b", r"\brandint\b", r"\brandrange\b", r"\buuid\b",
        r"\bdatetime\.now\b", r"\btime\.time\b", r"\btime\.sleep\b",
        r"\bos\.environ\b", r"\bgetenv\b",
        r"\bsocket\.", r"\brequests\.", r"\bhttpx\.", r"\baiohttp\.",
        r"\bopen\(.*[rwa]", r"\bsubprocess\.",
    ]
    hits = sum(1 for p in patterns if re.search(p, content, re.I))
    return min(1.0, hits * 0.12)


def _aggregate_entropy(signals: dict[str, float]) -> float:
    weights = {
        "semantic_duplication": 0.25,
        "divergent_execution_paths": 0.20,
        "contradictory_documentation": 0.20,
        "dead_code_references": 0.15,
        "naming_inconsistency": 0.10,
        "runtime_inconsistency": 0.10,
    }
    total = sum(weights.get(k, 0.0) * v for k, v in signals.items())
    return max(0.0, min(1.0, total))


class ContextEntropyEngine:
    name = "context_entropy_engine"
    critical = False

    def __init__(self) -> None:
        self._config: Config | None = None
        self._db: aiosqlite.Connection | None = None

    async def init(self, config: Config) -> None:
        self._config = config
        from context_firewall.db.connection import get_db
        self._db = await get_db()
        logger.info("ContextEntropyEngine initialized")

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(name=self.name, healthy=True)

    async def shutdown(self) -> None:
        self._db = None

    async def get_entropy(self, node_id: str) -> float:
        """Hot-path: O(1) lookup from pre-computed annotations."""
        if self._db is None:
            return self._config.entropy.default_score if self._config else 0.30
        try:
            async with self._db.execute(
                "SELECT entropy_score, stale FROM entropy_annotations WHERE node_id = ?",
                (node_id,),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                return self._config.entropy.default_score if self._config else 0.30
            score = float(row["entropy_score"])
            if row["stale"]:
                score = min(1.0, score + 0.15)
            return score
        except Exception:
            logger.warning("entropy score lookup failed for node %s", node_id, exc_info=True)
            return 0.30

    async def run_analysis(self, repository_root: str) -> int:
        """Offline: compute entropy for all files in repository_root."""
        root = Path(repository_root)
        annotated = 0
        exts = ("*.py", "*.ts", "*.go", "*.tsx", "*.js")
        files = []
        for ext in exts:
            files.extend(root.rglob(ext))

        # Load contents once so we can do cross-file duplication comparisons
        contents: list[tuple[str, str]] = []
        for file_path in files:
            try:
                content = file_path.read_text(errors="ignore")
                rel = str(file_path.relative_to(root))
                contents.append((rel, content))
            except Exception as e:
                logger.debug("could not read %s: %s", file_path, e)

        for i, (rel_path, content) in enumerate(contents):
            try:
                # Use adjacent file for duplication comparison (avoids O(N^2) over all files)
                sibling_content = contents[i - 1][1] if i > 0 else ""
                annotation = await self._analyze_file(rel_path, content, sibling_content)
                await self._persist(annotation)
                annotated += 1
            except Exception as e:
                logger.debug("entropy analysis skipped", extra={"file": rel_path, "error": str(e)})
        logger.info("entropy analysis complete", extra={"annotated": annotated})
        return annotated

    async def _analyze_file(
        self, file_path: str, content: str, sibling_content: str = ""
    ) -> EntropyAnnotation:
        if _has_skip_annotation(content):
            signals = {k: 0.0 for k in [
                "semantic_duplication", "divergent_execution_paths",
                "contradictory_documentation", "dead_code_references",
                "naming_inconsistency", "runtime_inconsistency",
            ]}
            return EntropyAnnotation(
                node_id=file_path,
                file_path=file_path,
                entropy_score=0.0,
                signals=signals,
                reasons=["cre:skip annotation present"],
                computed_at=datetime.now(timezone.utc),
            )

        signals: dict[str, float] = {}
        reasons: list[str] = []

        signals["naming_inconsistency"] = _compute_naming_inconsistency(content)
        if signals["naming_inconsistency"] > 0.3:
            reasons.append("mixed naming conventions detected")

        signals["dead_code_references"] = _compute_dead_code_references(content)
        if signals["dead_code_references"] > 0.3:
            reasons.append("deprecated/todo markers found")

        signals["contradictory_documentation"] = _compute_contradictory_documentation(content)
        if signals["contradictory_documentation"] > 0.3:
            reasons.append("potential doc/code contradiction")

        signals["semantic_duplication"] = (
            _compute_semantic_duplication(content, sibling_content) if sibling_content else 0.0
        )
        if signals["semantic_duplication"] > 0.55:
            reasons.append("high token overlap with adjacent file")

        signals["divergent_execution_paths"] = _compute_divergent_execution_paths(content)
        if signals["divergent_execution_paths"] > 0.5:
            reasons.append("high branching complexity")

        signals["runtime_inconsistency"] = _compute_runtime_inconsistency(content)
        if signals["runtime_inconsistency"] > 0.4:
            reasons.append("non-deterministic runtime sources detected")

        entropy_score = _aggregate_entropy(signals)
        return EntropyAnnotation(
            node_id=file_path,
            file_path=file_path,
            entropy_score=entropy_score,
            signals=signals,
            reasons=reasons,
            computed_at=datetime.now(timezone.utc),
        )

    async def _persist(self, annotation: EntropyAnnotation) -> None:
        if self._db is None:
            return
        await self._db.execute(
            """
            INSERT INTO entropy_annotations
                (node_id, file_path, entropy_score, signals, reasons, computed_at, stale)
            VALUES (?, ?, ?, ?, ?, ?, FALSE)
            ON CONFLICT(node_id) DO UPDATE SET
                entropy_score = excluded.entropy_score,
                signals = excluded.signals,
                reasons = excluded.reasons,
                computed_at = excluded.computed_at,
                stale = FALSE
            """,
            (
                annotation.node_id,
                annotation.file_path,
                annotation.entropy_score,
                json.dumps(annotation.signals),
                json.dumps(annotation.reasons),
                annotation.computed_at.isoformat(),
            ),
        )
        await self._db.commit()
