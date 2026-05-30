"""Runtime Correlation Engine — async OTLP ingestion pipeline."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import aiosqlite
from rapidfuzz import fuzz

from context_firewall.config import Config
from context_firewall.models import SubsystemHealth

logger = logging.getLogger(__name__)


class SymbolResolver:
    """Resolves span operation names to graph node IDs."""

    def __init__(self) -> None:
        self._by_name: dict[str, list[dict]] = {}
        self._by_service_and_name: dict[str, dict] = {}

    def load(self, nodes: list[dict]) -> None:
        self._by_name.clear()
        self._by_service_and_name.clear()
        for node in nodes:
            name_key = node.get("symbol_name", "").lower()
            service = node.get("service", "")
            self._by_name.setdefault(name_key, []).append(node)
            if service:
                self._by_service_and_name[f"{service}/{name_key}"] = node

    def resolve(self, operation: str, service: str = "", fuzzy_threshold: float = 0.75) -> str | None:
        lower = operation.lower()
        svc_key = f"{service}/{lower}"

        # exact service-scoped match
        if svc_key in self._by_service_and_name:
            return self._by_service_and_name[svc_key].get("id")

        # exact name match (pick first if multiple)
        if lower in self._by_name:
            candidates = self._by_name[lower]
            if len(candidates) == 1:
                return candidates[0].get("id")
            # service disambiguation
            if service:
                for c in candidates:
                    if c.get("service") == service:
                        return c.get("id")
            return candidates[0].get("id")

        # fuzzy fallback
        best_score = 0.0
        best_id = None
        for name_key, nodes in self._by_name.items():
            score = fuzz.ratio(lower, name_key) / 100.0
            if score > best_score and score >= fuzzy_threshold:
                best_score = score
                best_id = nodes[0].get("id")
        return best_id


class RuntimeCorrelationEngine:
    name = "runtime_correlation_engine"
    critical = False

    def __init__(self) -> None:
        self._config: Config | None = None
        self._db: aiosqlite.Connection | None = None
        self._queue: asyncio.Queue | None = None
        self._consumer_tasks: list[asyncio.Task] = []
        self._resolver = SymbolResolver()
        self._pending_traces: dict[str, list[dict]] = {}
        self._signal_buffer: list[dict] = []
        self._flush_task: asyncio.Task | None = None

    async def init(self, config: Config) -> None:
        self._config = config
        from context_firewall.db.connection import get_db
        self._db = await get_db()
        self._queue = asyncio.Queue(maxsize=config.otel.queue_size)
        await self._load_symbol_table()

        if config.otel.enabled:
            for _ in range(config.otel.consumer_workers):
                task = asyncio.create_task(self._consumer_loop())
                self._consumer_tasks.append(task)
            self._flush_task = asyncio.create_task(self._flush_loop())
            logger.info(
                "RuntimeCorrelationEngine initialized",
                extra={"workers": config.otel.consumer_workers},
            )

    async def _load_symbol_table(self) -> None:
        try:
            import kuzu
            from context_compiler.indexer.graph import open_database, graph_path
            from pathlib import Path

            root = Path(self._config.repository_root if self._config else ".")
            gp = graph_path(root)
            if not gp.exists():
                logger.warning("symbol table: graph not found", extra={"path": str(gp)})
                return

            db = open_database(root)
            conn = kuzu.Connection(db)
            # Query all function/method nodes for symbol resolution
            result = conn.execute(
                "MATCH (n:Symbol) RETURN n.id, n.symbol_name, n.file_path"
            )
            nodes = [
                {"id": r[0], "symbol_name": r[1] or "", "file_path": r[2] or "", "service": ""}
                for r in result.fetchall()
            ]
            self._resolver.load(nodes)
            logger.info("symbol table loaded", extra={"nodes": len(nodes)})
        except Exception as e:
            logger.warning("symbol table load failed; all spans will be unresolved", extra={"error": str(e)})

    async def ingest_span(self, span: dict) -> None:
        """Called by OTLP receiver — non-blocking enqueue."""
        if self._queue is None:
            return
        try:
            self._queue.put_nowait(span)
        except asyncio.QueueFull:
            logger.debug("span dropped: queue full")

    async def _consumer_loop(self) -> None:
        cfg = self._config.otel if self._config else None
        fuzzy_threshold = cfg.fuzzy_threshold if cfg else 0.75
        while True:
            try:
                span = await self._queue.get()
                operation = span.get("operation_name", span.get("name", ""))
                service = span.get("service_name", "")
                node_id = self._resolver.resolve(operation, service, fuzzy_threshold)
                if node_id:
                    await asyncio.gather(
                        self._record_signal(span, node_id),
                        self._record_service_edge(span),
                    )
                    self._track_trace(span, node_id)
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("consumer loop error", extra={"error": str(e)})

    def _track_trace(self, span: dict, node_id: str) -> None:
        trace_id = span.get("trace_id", "")
        if not trace_id:
            return
        self._pending_traces.setdefault(trace_id, []).append({**span, "_node_id": node_id})

        cfg = self._config.otel if self._config else None
        timeout = cfg.trace_assembly_timeout_sec if cfg else 30
        asyncio.get_event_loop().call_later(timeout, self._finalize_trace, trace_id)

    def _finalize_trace(self, trace_id: str) -> None:
        spans = self._pending_traces.pop(trace_id, [])
        if not spans:
            return

    async def _record_signal(self, span: dict, node_id: str) -> None:
        duration_ms = span.get("duration_ms", 0.0)
        is_error = span.get("status_code", "") == "ERROR" or bool(span.get("error"))

        self._signal_buffer.append({
            "node_id": node_id,
            "duration_ms": duration_ms,
            "is_error": is_error,
        })

    async def _record_service_edge(self, span: dict) -> None:
        caller = span.get("service_name", "")
        callee = span.get("peer_service", span.get("db_system", ""))
        if not caller or not callee or caller == callee:
            return
        if self._db is None:
            return
        try:
            await self._db.execute(
                """
                INSERT INTO service_map (caller_service, callee_service, observed_count, last_seen_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(caller_service, callee_service) DO UPDATE SET
                    observed_count = observed_count + 1,
                    last_seen_at = excluded.last_seen_at
                """,
                (caller, callee, datetime.now(timezone.utc).isoformat()),
            )
            await self._db.commit()
        except Exception as e:
            logger.error("service edge write failed", extra={"error": str(e)})

    async def _flush_loop(self) -> None:
        cfg = self._config.otel if self._config else None
        interval_s = (cfg.signal_batch_flush_ms if cfg else 500) / 1000.0
        batch_size = cfg.signal_batch_size if cfg else 100

        while True:
            try:
                await asyncio.sleep(interval_s)
                if len(self._signal_buffer) >= batch_size or self._signal_buffer:
                    await self._flush_signals()
            except asyncio.CancelledError:
                await self._flush_signals()
                break
            except Exception as e:
                logger.error("flush loop error", extra={"error": str(e)})

    async def _flush_signals(self) -> None:
        if not self._signal_buffer or self._db is None:
            return

        batch = self._signal_buffer.copy()
        self._signal_buffer.clear()

        # Aggregate by node_id
        aggregated: dict[str, dict] = {}
        for s in batch:
            nid = s["node_id"]
            if nid not in aggregated:
                aggregated[nid] = {"invocations": 0, "errors": 0, "durations": []}
            aggregated[nid]["invocations"] += 1
            if s["is_error"]:
                aggregated[nid]["errors"] += 1
            if s["duration_ms"] > 0:
                aggregated[nid]["durations"].append(s["duration_ms"])

        cfg = self._config.otel if self._config else None
        latency_threshold = cfg.latency_degraded_threshold_ms if cfg else 2000
        exception_threshold = cfg.exception_rate_high_threshold if cfg else 0.10

        for node_id, agg in aggregated.items():
            invocations = agg["invocations"]
            errors = agg["errors"]
            durations = sorted(agg["durations"])
            exception_rate = errors / invocations if invocations else 0.0

            p50 = durations[len(durations) // 2] if durations else None
            p95 = durations[int(len(durations) * 0.95)] if durations else None
            p99 = durations[int(len(durations) * 0.99)] if durations else None
            latency_degraded = p99 is not None and p99 > latency_threshold
            exception_rate_high = exception_rate > exception_threshold

            try:
                await self._db.execute(
                    """
                    INSERT INTO runtime_signals
                        (node_id, invocation_count, exception_count, exception_rate,
                         p50_latency_ms, p95_latency_ms, p99_latency_ms,
                         last_observed_at, latency_degraded, exception_rate_high, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(node_id) DO UPDATE SET
                        invocation_count = invocation_count + excluded.invocation_count,
                        exception_count = exception_count + excluded.exception_count,
                        exception_rate = excluded.exception_rate,
                        p50_latency_ms = excluded.p50_latency_ms,
                        p95_latency_ms = excluded.p95_latency_ms,
                        p99_latency_ms = excluded.p99_latency_ms,
                        last_observed_at = excluded.last_observed_at,
                        latency_degraded = excluded.latency_degraded,
                        exception_rate_high = excluded.exception_rate_high,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        node_id, invocations, errors, exception_rate,
                        p50, p95, p99,
                        datetime.now(timezone.utc).isoformat(),
                        latency_degraded, exception_rate_high,
                    ),
                )
            except Exception as e:
                logger.error("runtime signal write failed", extra={"error": str(e)})
        try:
            await self._db.commit()
        except Exception as e:
            logger.error("runtime signal commit failed", extra={"error": str(e)})

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(
            name=self.name,
            healthy=True,
            details={
                "symbol_table_size": sum(len(v) for v in self._resolver._by_name.values()),
                "queue_size": self._queue.qsize() if self._queue else 0,
            },
        )

    async def shutdown(self) -> None:
        for task in self._consumer_tasks:
            task.cancel()
        if self._flush_task:
            self._flush_task.cancel()
        await self._flush_signals()
