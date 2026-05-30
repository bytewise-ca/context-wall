"""Provenance Engine — async write-behind using asyncio.Queue."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

import aiosqlite

from context_firewall.config import Config
from context_firewall.models import SubsystemHealth
from context_firewall.provenance.models import (
    OutcomeEvent,
    PolicyEnforcementEvent,
    ProvenanceEvent,
    Session,
    SliceExcludedEvent,
    SliceIncludedEvent,
)
from context_firewall.compliance.chain import CHAIN_GENESIS_HASH, compute_entry_hash

logger = logging.getLogger(__name__)


class ProvenanceEngine:
    name = "provenance_engine"
    critical = False

    def __init__(self) -> None:
        self._config: Config | None = None
        self._db: aiosqlite.Connection | None = None
        self._queue: asyncio.Queue[ProvenanceEvent | None] = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None
        self._session_queues: dict[str, asyncio.Queue] = {}
        self._flush_events: dict[str, asyncio.Event] = {}
        self._cleanup_task: asyncio.Task | None = None
        self._chain_seq_lock = asyncio.Lock()
        self._hmac_key: str = ""
        # Live event subscribers for WebSocket feed
        self._event_subscribers: list[asyncio.Queue] = []

    async def init(self, config: Config) -> None:
        self._config = config
        self._queue = asyncio.Queue(maxsize=config.provenance.queue_size)
        self._hmac_key = config.compliance_hmac_key or "dev-key"
        from context_firewall.db.connection import get_db
        self._db = await get_db()
        self._writer_task = asyncio.create_task(self._writer_loop())
        self._cleanup_task = asyncio.create_task(self._session_cleanup_loop())
        logger.info("ProvenanceEngine initialized")

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(
            name=self.name,
            healthy=self._writer_task is not None and not self._writer_task.done(),
            details={"queue_size": self._queue.qsize(), "subscribers": len(self._event_subscribers)},
        )

    async def shutdown(self) -> None:
        await self.flush_all()
        if self._writer_task:
            self._queue.put_nowait(None)  # sentinel to stop writer
            await asyncio.wait_for(self._writer_task, timeout=10)
        if self._cleanup_task:
            self._cleanup_task.cancel()

    # ── WebSocket subscriber management ──────────────────────────────────────

    def subscribe_events(self) -> asyncio.Queue:
        """Register a subscriber queue for live event broadcast."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._event_subscribers.append(q)
        return q

    def unsubscribe_events(self, q: asyncio.Queue) -> None:
        try:
            self._event_subscribers.remove(q)
        except ValueError:
            pass

    def _broadcast(self, event_dict: dict) -> None:
        """Non-blocking broadcast to all subscriber queues."""
        dead = []
        for q in self._event_subscribers:
            try:
                q.put_nowait(event_dict)
            except asyncio.QueueFull:
                dead.append(q)  # slow consumer — drop
        for q in dead:
            self.unsubscribe_events(q)

    # ── Event emission ────────────────────────────────────────────────────────

    async def emit(self, event: ProvenanceEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("provenance queue full, event dropped", extra={"event_type": event.event_type})

    async def emit_policy_enforcement(self, event: PolicyEnforcementEvent) -> None:
        if self._db is None:
            return
        try:
            await self._db.execute(
                """
                INSERT INTO policy_enforcement_events
                    (session_id, request_id, rule_name, action, file_path, node_id,
                     reason, pattern_name, source_id, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.session_id,
                    event.request_id,
                    event.rule_name,
                    event.action,
                    event.file_path,
                    event.node_id,
                    event.reason,
                    event.pattern_name,
                    event.source_id,
                    event.occurred_at.isoformat(),
                ),
            )
            await self._db.commit()
            # Broadcast to WebSocket subscribers
            self._broadcast({
                "type": "enforcement",
                "session_id": event.session_id,
                "request_id": event.request_id,
                "rule_name": event.rule_name,
                "action": event.action,
                "file_path": event.file_path,
                "reason": event.reason,
                "pattern_name": event.pattern_name,
                "source_id": event.source_id,
                "occurred_at": event.occurred_at.isoformat(),
            })
            # Compound trust penalty for the source on hard blocks
            if event.action == "deny" and event.source_id:
                await self._compound_source_penalty(event.source_id, event.occurred_at)
        except Exception as e:
            logger.error("Failed to write policy enforcement event", extra={"error": str(e)})

    async def _compound_source_penalty(self, source_id: str, occurred_at: datetime) -> None:
        """Upsert source_enforcement_penalties with exponential compounding.

        Each deny event adds 0.15 to the penalty. Between events the penalty
        decays by 50% per day, so a source that stops triggering violations
        recovers to a clean state in ~4 days without any human intervention.
        """
        _PENALTY_INCREMENT = self._config.enforcement.penalty_increment if self._config else 0.15
        _DECAY_HALF_LIFE_DAYS = self._config.enforcement.decay_half_life_days if self._config else 1.0

        try:
            async with self._db.execute(
                "SELECT penalty_score, last_violation_at FROM source_enforcement_penalties WHERE source_id = ?",
                (source_id,),
            ) as cur:
                row = await cur.fetchone()

            if row is None:
                new_score = _PENALTY_INCREMENT
                new_count = 1
            else:
                prev_score: float = row["penalty_score"]
                last_at = datetime.fromisoformat(row["last_violation_at"])
                if last_at.tzinfo is None:
                    last_at = last_at.replace(tzinfo=timezone.utc)
                elapsed_days = (occurred_at - last_at).total_seconds() / 86400
                # Exponential decay since last violation, then add new increment
                decay_factor = 0.5 ** (elapsed_days / _DECAY_HALF_LIFE_DAYS)
                new_score = min(1.0, prev_score * decay_factor + _PENALTY_INCREMENT)
                new_count = (row["violation_count"] if row else 0) + 1

            await self._db.execute(
                """
                INSERT INTO source_enforcement_penalties
                    (source_id, violation_count, penalty_score, last_violation_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    violation_count   = excluded.violation_count,
                    penalty_score     = excluded.penalty_score,
                    last_violation_at = excluded.last_violation_at,
                    updated_at        = excluded.updated_at
                """,
                (source_id, new_count, new_score, occurred_at.isoformat(), occurred_at.isoformat()),
            )
            await self._db.commit()
            logger.debug(
                "source penalty updated",
                extra={"source_id": source_id, "penalty_score": new_score, "count": new_count},
            )
        except Exception:
            logger.warning("_compound_source_penalty failed for %s", source_id, exc_info=True)

    async def create_session(self, session: Session) -> None:
        if self._db is None:
            return
        await self._db.execute(
            """
            INSERT OR IGNORE INTO sessions
                (session_id, agent_id, model_version, repository_root, client_type, status, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.agent_id,
                session.model_version,
                session.repository_root,
                session.client_type,
                session.status,
                session.started_at.isoformat(),
            ),
        )
        await self._db.commit()

    async def update_session_stats(self, session_id: str, total_tokens: int = 0) -> None:
        """Increment request count and add tokens for a session."""
        if self._db is None:
            return
        try:
            await self._db.execute(
                """
                UPDATE sessions
                SET request_count = request_count + 1,
                    total_tokens = total_tokens + ?
                WHERE session_id = ?
                """,
                (total_tokens, session_id),
            )
            await self._db.commit()
        except Exception as e:
            logger.warning("session stats update failed", extra={"error": str(e)})

    async def flush(self, session_id: str) -> None:
        event = asyncio.Event()
        self._flush_events[session_id] = event
        await event.wait()

    async def flush_all(self) -> None:
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                if item is not None:
                    await self._write_event(item)
            except asyncio.QueueEmpty:
                break

    async def _writer_loop(self) -> None:
        while True:
            try:
                event = await self._queue.get()
                if event is None:
                    break
                await self._write_event(event)
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("provenance writer error", extra={"error": str(e)})

    async def _write_event(self, event: ProvenanceEvent) -> None:
        if self._db is None:
            return
        try:
            payload = event.model_dump_json()
            await self._db.execute(
                """
                INSERT OR IGNORE INTO provenance_events
                    (event_id, event_type, session_id, request_id, occurred_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type,
                    event.session_id,
                    event.request_id,
                    event.occurred_at.isoformat(),
                    payload,
                ),
            )
            await self._append_chain_entry(event.event_id, payload)
            await self._db.commit()

            flush_ev = self._flush_events.pop(event.session_id, None)
            if flush_ev:
                flush_ev.set()

            # Broadcast interesting events to WebSocket subscribers
            if event.event_type in ("slice_included", "slice_excluded"):
                d = json.loads(payload)
                self._broadcast({"type": event.event_type, **d})
        except Exception as e:
            logger.error("Failed to write provenance event", extra={"error": str(e)})

    async def _append_chain_entry(self, event_id: str, payload_json: str) -> None:
        """Append a Merkle chain entry atomically under a per-process lock."""
        if self._db is None:
            return
        async with self._chain_seq_lock:
            try:
                async with self._db.execute(
                    "SELECT COALESCE(MAX(sequence), -1) FROM provenance_chain"
                ) as cur:
                    row = await cur.fetchone()
                    sequence = (row[0] if row else -1) + 1

                if sequence == 0:
                    prev_hash = CHAIN_GENESIS_HASH
                else:
                    async with self._db.execute(
                        "SELECT entry_hash FROM provenance_chain WHERE sequence = ?",
                        (sequence - 1,),
                    ) as cur:
                        ph_row = await cur.fetchone()
                        prev_hash = ph_row[0] if ph_row else CHAIN_GENESIS_HASH

                entry_hash = compute_entry_hash(
                    event_id, payload_json, sequence, prev_hash, self._hmac_key
                )
                now = datetime.now(timezone.utc).isoformat()
                await self._db.execute(
                    """
                    INSERT OR IGNORE INTO provenance_chain
                        (event_id, sequence, prev_hash, entry_hash, chained_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (event_id, sequence, prev_hash, entry_hash, now),
                )
            except Exception as e:
                logger.warning("chain append failed (non-fatal): %s", e)

    async def _session_cleanup_loop(self) -> None:
        """Mark sessions as timed_out if inactive for session_timeout_min minutes."""
        while True:
            try:
                await asyncio.sleep(300)
                if self._db is None:
                    continue
                timeout_min = self._config.provenance.session_timeout_min if self._config else 30
                await self._db.execute(
                    """
                    UPDATE sessions
                    SET status = 'timed_out', closed_at = CURRENT_TIMESTAMP
                    WHERE status = 'open'
                      AND started_at < datetime('now', ?)
                    """,
                    (f"-{timeout_min} minutes",),
                )
                await self._db.commit()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("session cleanup error", extra={"error": str(e)})

    async def get_session(self, session_id: str) -> dict | None:
        if self._db is None:
            return None
        async with self._db.execute(
            """
            SELECT s.*, COUNT(pe.event_id) as event_count
            FROM sessions s
            LEFT JOIN provenance_events pe ON pe.session_id = s.session_id
            WHERE s.session_id = ?
            GROUP BY s.session_id
            """,
            (session_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["id"] = d["session_id"]
        d["status"] = {"open": "active", "timed_out": "closed"}.get(d.get("status", ""), "closed")
        d["started_at"] = d.get("started_at", "")
        return d

    async def list_sessions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        if self._db is None:
            return []
        async with self._db.execute(
            """
            SELECT
                s.session_id,
                s.agent_id,
                s.model_version,
                s.repository_root,
                s.client_type,
                s.status,
                s.started_at,
                s.closed_at,
                s.request_count,
                s.total_tokens,
                COUNT(pe.event_id) as event_count,
                SUM(CASE WHEN enf.action IN ('exclude','block','deny') THEN 1 ELSE 0 END) as violation_count
            FROM sessions s
            LEFT JOIN provenance_events pe ON pe.session_id = s.session_id
            LEFT JOIN policy_enforcement_events enf ON enf.session_id = s.session_id
                AND enf.rule_name != 'context_request'
            WHERE s.session_id NOT LIKE 'sim:%'
            GROUP BY s.session_id
            ORDER BY s.started_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()

        status_map = {"open": "active", "timed_out": "closed", "closed": "closed"}
        result = []
        for r in rows:
            req_count = r["request_count"] or 0
            violations = r["violation_count"] or 0
            # Health: 1.0 = clean, lower = more violations per request
            if req_count > 0:
                health = max(0.0, 1.0 - (violations / max(1, req_count)) * 0.5)
            else:
                health = 1.0
            result.append({
                "id": r["session_id"],
                "session_id": r["session_id"],
                "status": status_map.get(r["status"] or "", "closed"),
                "started_at": r["started_at"],
                "closed_at": r["closed_at"],
                "request_count": req_count,
                "total_tokens": r["total_tokens"] or 0,
                "event_count": r["event_count"] or 0,
                "violation_count": violations,
                "health_score": round(health, 2),
                "repository_root": r["repository_root"] or "",
                "client_type": r["client_type"] or "rest",
            })
        return result

    async def replay(self, session_id: str, request_id: str | None = None) -> list[dict]:
        if self._db is None:
            return []
        query = "SELECT payload, event_type, occurred_at FROM provenance_events WHERE session_id = ?"
        params: list = [session_id]
        if request_id:
            query += " AND request_id = ?"
            params.append(request_id)
        query += " ORDER BY occurred_at ASC"
        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        return [
            {"event_type": r["event_type"], "occurred_at": r["occurred_at"], **json.loads(r["payload"])}
            for r in rows
        ]

    async def get_latest_events(self, limit: int = 50) -> list[dict]:
        """Latest provenance + enforcement events across all sessions, newest first."""
        if self._db is None:
            return []
        # Union provenance events and enforcement events for a unified feed
        async with self._db.execute(
            """
            SELECT 'provenance' as source, event_type, session_id, request_id,
                   occurred_at, payload as detail
            FROM provenance_events
            UNION ALL
            SELECT 'enforcement' as source, action as event_type, session_id, request_id,
                   occurred_at,
                   json_object(
                     'rule_name', rule_name,
                     'action', action,
                     'file_path', file_path,
                     'node_id', COALESCE(node_id, ''),
                     'reason', reason,
                     'pattern_name', COALESCE(pattern_name, '')
                   ) as detail
            FROM policy_enforcement_events
            ORDER BY occurred_at DESC
            LIMIT ?
            """,
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()

        result = []
        for r in rows:
            try:
                detail = json.loads(r["detail"]) if r["detail"] else {}
            except Exception:
                detail = {}
            result.append({
                "source": r["source"],
                "event_type": r["event_type"],
                "session_id": r["session_id"],
                "request_id": r["request_id"],
                "occurred_at": r["occurred_at"],
                "timestamp": r["occurred_at"],
                **detail,
            })
        return result

    async def get_analytics_summary(self, window_hours: int = 24) -> dict:
        """Compute KPI summary from the database."""
        if self._db is None:
            return {"blocked_artifacts": 0, "policy_violations": 0, "total_requests": 0, "active_sessions": 0}
        try:
            # SQLite datetime window — aiosqlite uses sqlite
            window = f"-{window_hours} hours"
            # Violations: enforcement actions that are actual blocks/excludes (not audit markers)
            async with self._db.execute(
                """
                SELECT COUNT(*) FROM policy_enforcement_events
                WHERE action IN ('exclude', 'deny', 'block')
                  AND rule_name != 'context_request'
                  AND session_id NOT LIKE 'sim:%'
                  AND occurred_at > datetime('now', ?)
                """,
                (window,),
            ) as cur:
                blocked = (await cur.fetchone())[0] or 0

            # Policy violations: all enforcement events (excluding audit markers and sim sessions)
            async with self._db.execute(
                """
                SELECT COUNT(*) FROM policy_enforcement_events
                WHERE rule_name != 'context_request'
                  AND session_id NOT LIKE 'sim:%'
                  AND occurred_at > datetime('now', ?)
                """,
                (window,),
            ) as cur:
                violations = (await cur.fetchone())[0] or 0

            # Total requests: count from context_request enforcement events (emitted per pipeline call)
            async with self._db.execute(
                """
                SELECT COUNT(*) FROM policy_enforcement_events
                WHERE rule_name = 'context_request'
                  AND session_id NOT LIKE 'sim:%'
                  AND occurred_at > datetime('now', ?)
                """,
                (window,),
            ) as cur:
                total_requests = (await cur.fetchone())[0] or 0

            # If no context_request events yet, fall back to summing request_count from sessions
            if total_requests == 0:
                async with self._db.execute(
                    "SELECT COALESCE(SUM(request_count), 0) FROM sessions WHERE session_id NOT LIKE 'sim:%'"
                ) as cur:
                    total_requests = (await cur.fetchone())[0] or 0

            async with self._db.execute(
                "SELECT COUNT(*) FROM sessions WHERE status = 'open' AND session_id NOT LIKE 'sim:%'",
            ) as cur:
                active_sessions = (await cur.fetchone())[0] or 0

            return {
                "blocked_artifacts": blocked,
                "policy_violations": violations,
                "total_requests": total_requests,
                "active_sessions": active_sessions,
                "window_hours": window_hours,
            }
        except Exception as e:
            logger.error("analytics summary failed", extra={"error": str(e)})
            return {"blocked_artifacts": 0, "policy_violations": 0, "total_requests": 0, "active_sessions": 0}

    async def record_outcome(self, event: OutcomeEvent) -> None:
        await self.emit(event)
        if self._db is None:
            return
        await self._db.execute(
            """
            INSERT INTO outcome_signals
                (session_id, request_id, outcome_type, success, score, node_ids, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.session_id,
                event.request_id,
                event.outcome_type,
                event.success,
                event.score,
                json.dumps(event.node_ids),
                event.occurred_at.isoformat(),
            ),
        )
        await self._db.commit()
        if event.success and event.source_id:
            await self._reward_source_trust(event.source_id, event.occurred_at)

    async def _reward_source_trust(self, source_id: str, occurred_at: datetime) -> None:
        """Reduce penalty 10% per positive outcome — complements time-based decay."""
        _REWARD_FACTOR = self._config.enforcement.reward_factor if self._config else 0.90
        try:
            async with self._db.execute(
                "SELECT penalty_score FROM source_enforcement_penalties WHERE source_id = ?",
                (source_id,),
            ) as cur:
                row = await cur.fetchone()
            if row is None or row["penalty_score"] == 0.0:
                return
            new_score = max(0.0, row["penalty_score"] * _REWARD_FACTOR)
            await self._db.execute(
                "UPDATE source_enforcement_penalties SET penalty_score = ?, updated_at = ? WHERE source_id = ?",
                (new_score, occurred_at.isoformat(), source_id),
            )
            await self._db.commit()
            logger.debug(
                "source trust rewarded",
                extra={"source_id": source_id, "penalty_score": new_score},
            )
        except Exception:
            logger.warning("_reward_source_trust failed for %s", source_id, exc_info=True)

    async def get_source_penalty(self, source_id: str) -> dict | None:
        """Return current penalty state for a source, or None if no enforcement history."""
        if self._db is None:
            return None
        try:
            async with self._db.execute(
                """
                SELECT violation_count, penalty_score, last_violation_at, updated_at
                FROM source_enforcement_penalties WHERE source_id = ?
                """,
                (source_id,),
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                return None
            return {
                "violation_count": row["violation_count"],
                "penalty_score": round(float(row["penalty_score"]), 4),
                "last_violation_at": row["last_violation_at"],
                "updated_at": row["updated_at"],
            }
        except Exception:
            logger.warning("get_source_penalty failed for %s", source_id, exc_info=True)
            return None

    async def get_all_source_penalties(self) -> dict[str, dict]:
        """Return penalty state for all sources keyed by source_id."""
        if self._db is None:
            return {}
        try:
            async with self._db.execute(
                "SELECT source_id, violation_count, penalty_score, last_violation_at FROM source_enforcement_penalties"
            ) as cur:
                rows = await cur.fetchall()
            return {
                row["source_id"]: {
                    "violation_count": row["violation_count"],
                    "penalty_score": round(float(row["penalty_score"]), 4),
                    "last_violation_at": row["last_violation_at"],
                }
                for row in rows
            }
        except Exception:
            logger.warning("get_all_source_penalties failed", exc_info=True)
            return {}
