"""Trust Scoring Engine — computes weighted trust scores for candidate nodes."""

from __future__ import annotations

import asyncio
import logging
import time

import aiosqlite

from context_firewall.config import Config
from context_firewall.models import PipelineContext, RankedSlice, SubsystemHealth
from context_firewall.trust.signals import (
    compute_consistency,
    compute_enforcement_penalty,
    compute_entropy_contribution,
    compute_freshness,
    compute_injection_risk,
    compute_runtime_evidence,
    compute_stability,
    compute_structural_relevance,
    compute_verification,
)

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS: dict[str, float] = {
    "structural_relevance": 0.30,
    "runtime_evidence": 0.25,
    "freshness": 0.10,
    "stability": 0.10,
    "verification": 0.10,
    "consistency": 0.05,
    "injection_risk": -0.05,
    "entropy_contribution": -0.15,
    "enforcement_penalty": -0.20,
}


class TrustScoringEngine:
    name = "trust_scoring_engine"
    critical = False

    def __init__(self) -> None:
        self._config: Config | None = None
        self._weights: dict[str, float] = DEFAULT_WEIGHTS.copy()
        self._db: aiosqlite.Connection | None = None

    async def init(self, config: Config) -> None:
        self._config = config
        if config.trust.weights:
            self._weights = {**DEFAULT_WEIGHTS, **config.trust.weights}
        from context_firewall.db.connection import get_db
        self._db = await get_db()
        logger.info("TrustScoringEngine initialized")

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(name=self.name, healthy=self._db is not None)

    async def shutdown(self) -> None:
        self._db = None

    async def score_candidates(
        self,
        candidates: list[RankedSlice],
        ctx: PipelineContext,
    ) -> list[RankedSlice]:
        t0 = time.monotonic()
        if not candidates:
            return []

        # Score all candidates concurrently
        tasks = [self._score_single(c, ctx) for c in candidates]
        scored = await asyncio.gather(*tasks)

        # Apply trust cutoff from config
        cutoff = self._config.graph.trust_cutoff if self._config else 0.30
        result = [s for s in scored if s.trust_score >= cutoff]
        result.sort(key=lambda s: s.trust_score, reverse=True)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug(
            "trust.score_candidates",
            extra={"input": len(candidates), "output": len(result), "latency_ms": elapsed_ms},
        )
        return result

    async def _score_single(self, candidate: RankedSlice, ctx: PipelineContext) -> RankedSlice:
        db = self._db
        node_id = candidate.node_id
        file_path = candidate.file_path
        content = candidate.content

        structural = compute_structural_relevance(candidate.trust_score)
        verification = compute_verification(content, file_path)
        consistency = compute_consistency(content)
        injection = compute_injection_risk(content)

        if db is not None:
            runtime, freshness, stability, entropy, enforcement = await asyncio.gather(
                compute_runtime_evidence(node_id, db),
                compute_freshness(file_path, db),
                compute_stability(file_path, db),
                compute_entropy_contribution(node_id, db),
                compute_enforcement_penalty(candidate.source_id, db),
            )
        else:
            runtime = freshness = stability = 0.5
            entropy = 0.30
            enforcement = 0.0

        w = self._weights
        raw_score = (
            w["structural_relevance"] * structural
            + w["runtime_evidence"] * runtime
            + w["freshness"] * freshness
            + w["stability"] * stability
            + w["verification"] * verification
            + w["consistency"] * consistency
            + w["injection_risk"] * injection  # already negative weight
            + w["entropy_contribution"] * entropy  # already negative weight
            + w["enforcement_penalty"] * enforcement  # already negative weight
        )
        trust_score = max(0.0, min(1.0, raw_score))

        return candidate.model_copy(update={
            "trust_score": trust_score,
            "signal_breakdown": {
                "structural_relevance": structural,
                "runtime_evidence": runtime,
                "freshness": freshness,
                "stability": stability,
                "verification": verification,
                "consistency": consistency,
                "injection_risk": injection,
                "entropy_contribution": entropy,
                "enforcement_penalty": enforcement,
            },
        })
