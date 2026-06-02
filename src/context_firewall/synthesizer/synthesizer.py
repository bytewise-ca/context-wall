"""Context Synthesizer - token budget enforcement and bundle assembly."""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
import uuid
from collections import Counter
from datetime import datetime, timezone

from context_firewall.config import Config
from context_firewall.models import (
    ExclusionReason,
    PipelineContext,
    RankedSlice,
    SubsystemHealth,
    TrustedContextBundle,
    TrustedSlice,
    TrustRange,
)

logger = logging.getLogger(__name__)


class ContextSynthesizer:
    name = "context_synthesizer"
    critical = False

    def __init__(self) -> None:
        self._config: Config | None = None
        self._provenance = None

    async def init(self, config: Config, provenance=None) -> None:
        self._config = config
        self._provenance = provenance
        logger.info("ContextSynthesizer initialized")

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(name=self.name, healthy=True)

    async def shutdown(self) -> None:
        pass

    async def assemble(
        self,
        candidates: list[RankedSlice],
        ctx: PipelineContext,
        policy_violations: int = 0,
    ) -> TrustedContextBundle:
        t0 = time.monotonic()
        budget = self._resolve_budget(ctx.task_type.value)

        candidates = self._dedup_by_diversity(candidates)
        included, excluded = self._enforce_budget(candidates, budget)

        trust_range = self._compute_trust_range(included)
        avg_entropy = statistics.mean(
            c.signal_breakdown.get("entropy_contribution", 0.0) for c in candidates
        ) if candidates else 0.0

        slices = [
            TrustedSlice(
                node_id=c.node_id,
                file_path=c.file_path,
                content=c.content,
                trust_score=c.trust_score,
                token_count=c.token_count,
                language=c.language,
                symbols=c.symbols,
            )
            for c in included
        ]

        below_cutoff = [
            c for c in candidates if c not in included
            and c not in [e[0] for e in excluded]
        ]
        exclusion_reasons = [
            ExclusionReason(
                file_path=c.file_path,
                node_id=c.node_id,
                reason="token_budget",
                score=c.trust_score,
            )
            for c, _ in excluded
        ] + [
            ExclusionReason(
                file_path=c.file_path,
                node_id=c.node_id,
                reason="below_trust_cutoff",
                score=c.trust_score,
            )
            for c in below_cutoff
        ]

        total_tokens = sum(s.token_count for s in slices)
        bundle = TrustedContextBundle(
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            task_type=ctx.task_type.value,
            assembled_at=datetime.now(timezone.utc),
            slices=slices,
            excluded_count=len(excluded) + len(below_cutoff),
            excluded_reasons=exclusion_reasons,
            summary="",
            total_tokens=total_tokens,
            token_budget=budget,
            trust_range=trust_range,
            entropy_score=avg_entropy,
            policy_violations=policy_violations,
        )
        bundle = bundle.model_copy(update={"summary": self._generate_summary(bundle)})

        if self._provenance:
            await self._emit_provenance(bundle, ctx)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug(
            "synthesizer.assemble",
            extra={"included": len(slices), "excluded": bundle.excluded_count, "latency_ms": elapsed_ms},
        )
        return bundle

    def _resolve_budget(self, task_type: str) -> int:
        budgets = {
            "BUG_FIX": 60_000, "NEW_FEATURE": 80_000, "REFACTOR": 100_000,
            "SECURITY_REVIEW": 50_000, "DEPENDENCY_AUDIT": 40_000,
        }
        return budgets.get(task_type, 80_000) - 500

    def _dedup_by_diversity(
        self, candidates: list[RankedSlice], jaccard_threshold: float = 0.72
    ) -> list[RankedSlice]:
        """
        Remove near-duplicate slices before budget packing.

        Two slices are considered duplicates if their symbol sets or content
        word sets share more than jaccard_threshold of their union. The higher-
        trust slice is kept; the duplicate is dropped.

        This prevents the synthesizer from filling the context window with
        six near-identical files (e.g. models/user.py + models/user_v2.py).
        """
        if len(candidates) <= 1:
            return candidates

        ranked = sorted(candidates, key=lambda c: c.trust_score, reverse=True)
        kept: list[RankedSlice] = []
        kept_words: list[frozenset] = []

        for candidate in ranked:
            # Build word set: prefer symbols, fall back to content words
            if candidate.symbols:
                words = frozenset(candidate.symbols)
            else:
                words = frozenset(
                    w.lower() for w in candidate.content.split()
                    if len(w) > 3
                )

            is_duplicate = False
            if len(words) >= 5:  # too few tokens → unreliable Jaccard, keep unconditionally
                for other_words in kept_words:
                    if len(other_words) < 5:
                        continue
                    intersection = len(words & other_words)
                    union = len(words | other_words)
                    if union > 0 and intersection / union >= jaccard_threshold:
                        is_duplicate = True
                        break

            if not is_duplicate:
                kept.append(candidate)
                kept_words.append(words)

        return kept

    def _enforce_budget(
        self, candidates: list[RankedSlice], budget: int
    ) -> tuple[list[RankedSlice], list[tuple[RankedSlice, int]]]:
        included: list[RankedSlice] = []
        excluded: list[tuple[RankedSlice, int]] = []
        remaining = budget
        for candidate in sorted(candidates, key=lambda c: c.trust_score, reverse=True):
            tokens = candidate.token_count or len(candidate.content.encode()) // 4
            if tokens <= remaining:
                included.append(candidate)
                remaining -= tokens
            else:
                excluded.append((candidate, remaining))
        return included, excluded

    def _compute_trust_range(self, included: list[RankedSlice]) -> TrustRange:
        if not included:
            return TrustRange(min=0.0, max=0.0, p50=0.0)
        scores = [c.trust_score for c in included]
        sorted_scores = sorted(scores)
        n = len(sorted_scores)
        p50 = sorted_scores[n // 2]
        return TrustRange(min=min(scores), max=max(scores), p50=p50)

    def _generate_summary(self, bundle: TrustedContextBundle) -> str:
        top_files = bundle.slices[:3]
        top_str = ", ".join(f"{s.file_path} ({s.trust_score:.2f})" for s in top_files)
        if len(bundle.slices) > 3:
            top_str += f" ...and {len(bundle.slices) - 3} more"
        by_reason = Counter(r.reason for r in bundle.excluded_reasons)
        return (
            f"[ContextWall Context Bundle]\n"
            f"Task: {bundle.task_type} | Trust: {bundle.trust_range.min:.2f}–{bundle.trust_range.max:.2f} "
            f"(p50: {bundle.trust_range.p50:.2f}) | Tokens: {bundle.total_tokens}/{bundle.token_budget}\n"
            f"Included: {len(bundle.slices)} files | Excluded: {bundle.excluded_count} "
            f"(below cutoff: {by_reason.get('below_trust_cutoff', 0)}, "
            f"token budget: {by_reason.get('token_budget', 0)}, "
            f"policy: {by_reason.get('policy_exclude', 0)}, "
            f"entropy: {by_reason.get('entropy_penalty', 0)})\n"
            f"Entropy: {bundle.entropy_score:.2f}/1.0 | Policy violations: {bundle.policy_violations}\n"
            f"Top files: {top_str}"
        )

    async def _emit_provenance(self, bundle: TrustedContextBundle, ctx: PipelineContext) -> None:
        from context_firewall.provenance.models import SliceIncludedEvent, SliceExcludedEvent
        for s in bundle.slices:
            await self._provenance.emit(SliceIncludedEvent(
                session_id=ctx.session_id,
                request_id=ctx.request_id,
                node_id=s.node_id,
                file_path=s.file_path,
                trust_score=s.trust_score,
                token_count=s.token_count,
                include_reason="trust_scored",
            ))
        for r in bundle.excluded_reasons:
            await self._provenance.emit(SliceExcludedEvent(
                session_id=ctx.session_id,
                request_id=ctx.request_id,
                node_id=r.node_id,
                file_path=r.file_path,
                trust_score=r.score,
                exclude_reason=r.reason,
            ))

    async def assemble_streaming(self, task: str, session_id: str, candidates: list[RankedSlice]):
        """Yield TrustedSlice events for SSE streaming."""
        import json
        for c in sorted(candidates, key=lambda x: x.trust_score, reverse=True):
            yield {"type": "slice", "file_path": c.file_path, "trust_score": c.trust_score}
        yield {"type": "done"}
