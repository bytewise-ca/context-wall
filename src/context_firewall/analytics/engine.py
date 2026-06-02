"""Analytics Engine - DuckDB in-process queries with snapshot pre-computation."""

from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import aiosqlite
import duckdb

from context_firewall.config import Config
from context_firewall.models import SubsystemHealth

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cre-analytics")


def _get_duckdb_conn(sqlite_path: str) -> duckdb.DuckDBPyConnection:
    conn = duckdb.connect(":memory:", read_only=False)
    conn.execute(f"ATTACH '{sqlite_path}' AS cre (TYPE SQLITE, READ_ONLY TRUE)")
    return conn


def _compute_retrieval_metrics_sync(sqlite_path: str) -> list[dict]:
    with _get_duckdb_conn(sqlite_path) as conn:
        rows = conn.execute("""
            SELECT
                json_extract(payload, '$.file_path') AS file_path,
                COUNT(*) FILTER (WHERE event_type = 'slice_included') AS inclusion_count,
                COUNT(*) FILTER (WHERE event_type = 'slice_excluded') AS exclusion_count,
                AVG(json_extract(payload, '$.trust_score')::FLOAT) AS avg_trust_score
            FROM cre.provenance_events
            WHERE event_type IN ('slice_included', 'slice_excluded')
            GROUP BY file_path
            ORDER BY inclusion_count DESC
            LIMIT 100
        """).fetchall()
    return [
        {
            "file_path": r[0],
            "inclusion_count": r[1],
            "exclusion_count": r[2],
            "avg_trust_score": float(r[3]) if r[3] is not None else None,
        }
        for r in rows
    ]


def _compute_trust_degradation_sync(sqlite_path: str, threshold: float, window_days: int) -> list[dict]:
    with _get_duckdb_conn(sqlite_path) as conn:
        rows = conn.execute(f"""
            WITH ranked AS (
                SELECT
                    node_id,
                    file_path,
                    trust_score,
                    snapshot_at,
                    ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY snapshot_at DESC) AS rn,
                    ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY snapshot_at ASC) AS rn_asc
                FROM cre.trust_score_snapshots
                WHERE snapshot_at > (CURRENT_TIMESTAMP - INTERVAL '{window_days} days')
            ),
            first_last AS (
                SELECT
                    node_id,
                    file_path,
                    MAX(CASE WHEN rn_asc = 1 THEN trust_score END) AS initial_score,
                    MAX(CASE WHEN rn = 1 THEN trust_score END) AS latest_score
                FROM ranked
                GROUP BY node_id, file_path
            )
            SELECT node_id, file_path, initial_score, latest_score,
                   initial_score - latest_score AS degradation
            FROM first_last
            WHERE initial_score - latest_score > {threshold}
            ORDER BY degradation DESC
            LIMIT 50
        """).fetchall()
    return [
        {
            "node_id": r[0],
            "file_path": r[1],
            "initial_score": float(r[2]) if r[2] is not None else None,
            "latest_score": float(r[3]) if r[3] is not None else None,
            "degradation": float(r[4]) if r[4] is not None else None,
        }
        for r in rows
    ]


class AnalyticsEngine:
    name = "analytics_engine"
    critical = False

    def __init__(self) -> None:
        self._config: Config | None = None
        self._db: aiosqlite.Connection | None = None
        self._sqlite_path: str = ".ctxfw/cre.db"

    async def init(self, config: Config) -> None:
        self._config = config
        self._sqlite_path = config.storage.db_path
        from context_firewall.db.connection import get_db
        self._db = await get_db()
        logger.info("AnalyticsEngine initialized")

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(name=self.name, healthy=True)

    async def shutdown(self) -> None:
        pass

    async def get_retrieval_metrics(self) -> dict:
        snapshot = await self._latest_snapshot("retrieval_metrics")
        if snapshot:
            return {"data": snapshot, "source": "snapshot"}
        try:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(
                _executor,
                _compute_retrieval_metrics_sync,
                self._sqlite_path,
            )
            return {"data": data, "source": "live"}
        except Exception as e:
            logger.error("retrieval metrics failed", extra={"error": str(e)})
            return {"data": [], "error": str(e)}

    async def get_trust_degradation(self) -> dict:
        threshold = 0.15
        window_days = 30
        try:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(
                _executor,
                _compute_trust_degradation_sync,
                self._sqlite_path,
                threshold,
                window_days,
            )
            return {"data": data, "threshold": threshold, "window_days": window_days}
        except Exception as e:
            logger.error("trust degradation failed", extra={"error": str(e)})
            return {"data": [], "error": str(e)}

    async def get_entropy_trends(self) -> dict:
        if self._db is None:
            return {"data": []}
        async with self._db.execute(
            """
            SELECT node_id, file_path, entropy_score, snapshot_at
            FROM entropy_snapshots
            ORDER BY snapshot_at DESC
            LIMIT 500
            """
        ) as cursor:
            rows = await cursor.fetchall()
        return {
            "data": [
                {"node_id": r["node_id"], "file_path": r["file_path"],
                 "entropy_score": r["entropy_score"], "snapshot_at": r["snapshot_at"]}
                for r in rows
            ]
        }

    async def get_budget_utilization(self) -> dict:
        snapshot = await self._latest_snapshot("budget_utilization")
        if snapshot:
            return {"data": snapshot, "source": "snapshot"}
        if self._db is None:
            return {"data": []}
        async with self._db.execute(
            """
            SELECT
                json_extract(payload, '$.task_type') AS task_type,
                AVG(CAST(json_extract(payload, '$.total_tokens') AS REAL)
                    / CAST(json_extract(payload, '$.token_budget') AS REAL)) AS avg_utilization,
                COUNT(*) AS bundle_count
            FROM provenance_events
            WHERE event_type = 'context_request'
            GROUP BY task_type
            """
        ) as cursor:
            rows = await cursor.fetchall()
        return {
            "data": [
                {"task_type": r["task_type"], "avg_utilization": r["avg_utilization"], "bundle_count": r["bundle_count"]}
                for r in rows
            ],
            "source": "live",
        }

    async def _latest_snapshot(self, metric_type: str) -> list | None:
        if self._db is None:
            return None
        async with self._db.execute(
            """
            SELECT payload FROM analytics_snapshots
            WHERE metric_type = ?
            ORDER BY computed_at DESC
            LIMIT 1
            """,
            (metric_type,),
        ) as cursor:
            row = await cursor.fetchone()
        if row:
            return json.loads(row["payload"])
        return None

    async def compute_and_store_snapshots(self) -> None:
        """Called by the offline job scheduler."""
        now = datetime.now(timezone.utc)
        try:
            loop = asyncio.get_event_loop()
            retrieval_data = await loop.run_in_executor(
                _executor, _compute_retrieval_metrics_sync, self._sqlite_path
            )
            if self._db:
                await self._db.execute(
                    """
                    INSERT INTO analytics_snapshots
                        (metric_type, granularity, key, payload, computed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("retrieval_metrics", "hourly", "all", json.dumps(retrieval_data), now.isoformat()),
                )
                await self._db.commit()
        except Exception as e:
            logger.error("snapshot computation failed", extra={"error": str(e)})
