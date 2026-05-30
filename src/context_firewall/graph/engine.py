"""Repository Graph Engine — wraps context-compiler's retrieval pipeline."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from context_firewall.config import Config
from context_firewall.models import PipelineContext, RankedSlice, SubsystemHealth

logger = logging.getLogger(__name__)


class RepositoryGraphEngine:
    name = "repository_graph_engine"
    critical = True

    def __init__(self) -> None:
        self._config: Config | None = None
        self._ready = False

    async def init(self, config: Config) -> None:
        self._config = config
        root = Path(config.repository_root)
        try:
            from context_compiler.indexer.graph import open_database, graph_path
            gp = graph_path(root)
            if gp.exists():
                _ = open_database(root)
                self._ready = True
                logger.info("RepositoryGraphEngine: KuzuDB graph found", extra={"path": str(gp)})
            else:
                logger.warning(
                    "KuzuDB graph not found; run 'context-compiler index' first",
                    extra={"expected": str(gp)},
                )
                self._ready = False
        except Exception as e:
            logger.warning("KuzuDB not reachable at startup", extra={"error": str(e)})
            self._ready = False

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(
            name=self.name,
            healthy=self._ready,
            message="KuzuDB graph ready" if self._ready else "KuzuDB graph missing — run context-compiler index",
        )

    async def shutdown(self) -> None:
        self._ready = False

    async def get_candidates(
        self,
        ctx: PipelineContext,
        repository_root: str | None = None,
    ) -> list[RankedSlice]:
        """Retrieve candidate slices via context-compiler pipeline (runs in thread pool)."""
        t0 = time.monotonic()
        root = repository_root or (self._config.repository_root if self._config else ".")
        max_nodes = self._config.graph.max_nodes if self._config else 50
        trust_cutoff = self._config.graph.trust_cutoff if self._config else 0.30

        try:
            loop = asyncio.get_event_loop()
            slices = await loop.run_in_executor(
                None,
                self._fetch_sync,
                ctx,
                root,
                max_nodes,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000
            logger.debug(
                "graph.get_candidates",
                extra={"count": len(slices), "latency_ms": elapsed_ms},
            )
            return slices
        except Exception as e:
            logger.error("graph.get_candidates failed", extra={"error": str(e)})
            return []

    def _fetch_sync(
        self,
        ctx: PipelineContext,
        repository_root: str,
        max_nodes: int,
    ) -> list[RankedSlice]:
        import kuzu
        from context_compiler.indexer.graph import open_database, graph_path
        from context_compiler.retrieval.classifier import classify
        from context_compiler.retrieval.entry_nodes import find_entry_nodes
        from context_compiler.retrieval.traversal import traverse
        from context_compiler.retrieval.scorer import score_and_compile
        from context_compiler.models import TaskType as CCTaskType

        root = Path(repository_root)
        gp = graph_path(root)
        if not gp.exists():
            logger.warning("graph_path not found", extra={"path": str(gp)})
            return []

        db = open_database(root)
        conn = kuzu.Connection(db)

        # Map CRE task type to context-compiler task type
        cc_type_map = {
            "BUG_FIX": CCTaskType.BUG_FIX,
            "NEW_FEATURE": CCTaskType.NEW_FEATURE,
            "REFACTOR": CCTaskType.REFACTOR,
            # CRE extensions fall back to NEW_FEATURE for traversal
            "SECURITY_REVIEW": CCTaskType.NEW_FEATURE,
            "DEPENDENCY_AUDIT": CCTaskType.NEW_FEATURE,
        }
        cc_task_type = cc_type_map.get(ctx.task_type.value, CCTaskType.NEW_FEATURE)

        match_result = find_entry_nodes(ctx.task, conn, top_k=5)
        if not match_result.candidates:
            return []

        traversal = traverse(match_result.candidates, cc_task_type, conn)

        # Use a generous budget — CRE trust scoring + synthesizer apply their own cutoff
        bundle = score_and_compile(
            traversal.candidates,
            budget=max_nodes * 2000,  # rough token estimate
            conn=conn,
        )

        from context_firewall.source.types import SourceTrustTier
        source_id = str(root)

        slices: list[RankedSlice] = []
        for sn in bundle.included[:max_nodes]:
            c = sn.candidate
            # Read file content for the slice
            content = self._read_slice(root, c.file_path, c.line_start, c.line_end)
            slices.append(RankedSlice(
                node_id=c.node_id,
                file_path=c.file_path,
                content=content,
                trust_score=sn.score,  # context-compiler score; CRE will recompute
                token_count=c.token_count,
                language=c.language.lower() if c.language else "",
                symbols=[c.symbol_name] if c.symbol_name else [],
                source_id=source_id,
                source_trust_tier=SourceTrustTier.INTERNAL,
            ))
        return slices

    def _read_slice(self, root: Path, file_path: str, line_start: int | None, line_end: int | None) -> str:
        try:
            full_path = root / file_path if not Path(file_path).is_absolute() else Path(file_path)
            text = full_path.read_text(errors="ignore")
            if line_start is not None and line_end is not None:
                lines = text.splitlines()
                return "\n".join(lines[max(0, line_start - 1):line_end])
            return text
        except Exception:
            return ""
