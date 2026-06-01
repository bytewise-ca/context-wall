"""Source Trust Registry - full CRUD with trust tier cache and compliance scope."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from context_firewall.source.types import SourceTrustTier

logger = logging.getLogger(__name__)

# Default mapping - overridden by compliance.classification_frameworks in ctxfw.yaml
_DEFAULT_CLASSIFICATION_FRAMEWORKS: dict[str, list[str]] = {
    "phi": ["hipaa"],
    "pii": ["hipaa", "gdpr"],
    "pci": ["pci-dss"],
    "financial": ["sox", "fedramp"],
    "federal": ["fedramp"],
    "classified": ["fedramp"],
    "sensitive": ["soc2"],
    "internal_code": [],
}


@dataclass
class Source:
    id: str
    type: str = "unknown"
    trust_tier: SourceTrustTier = SourceTrustTier.UNTRUSTED
    owner: str = ""
    region: str = ""
    data_classification: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    config: dict[str, Any] = field(default_factory=dict)
    deleted_at: datetime | None = None

    def compliance_scope(self, frameworks: dict[str, list[str]] | None = None) -> list[str]:
        """Return applicable compliance frameworks. Non-empty only for regulated sources."""
        if self.trust_tier != SourceTrustTier.REGULATED:
            return []
        mapping = frameworks if frameworks is not None else _DEFAULT_CLASSIFICATION_FRAMEWORKS
        scope: list[str] = []
        dc = self.data_classification.lower()
        for keyword, fws in mapping.items():
            if keyword in dc:
                for fw in fws:
                    if fw not in scope:
                        scope.append(fw)
        return scope

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "trust_tier": self.trust_tier.value,
            "owner": self.owner,
            "region": self.region,
            "data_classification": self.data_classification,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "config": self.config,
            "compliance_scope": self.compliance_scope(),
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }


class SourceRegistry:
    def __init__(
        self,
        db_path: str,
        classification_frameworks: dict[str, list[str]] | None = None,
    ) -> None:
        self._db_path = db_path
        self._cache: dict[str, Source] = {}
        self._classification_frameworks = (
            classification_frameworks or _DEFAULT_CLASSIFICATION_FRAMEWORKS
        )

    async def init(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sources (
                    id                  TEXT PRIMARY KEY,
                    type                TEXT NOT NULL DEFAULT 'unknown',
                    trust_tier          TEXT NOT NULL DEFAULT 'untrusted',
                    owner               TEXT NOT NULL DEFAULT '',
                    region              TEXT NOT NULL DEFAULT '',
                    data_classification TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL,
                    updated_at          DATETIME NOT NULL,
                    config              TEXT NOT NULL DEFAULT '{}',
                    deleted_at          DATETIME
                )
            """)
            await self._migrate(db)
            # Index for tier lookups by type (complements PK on id)
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_sources_tier ON sources(trust_tier) WHERE deleted_at IS NULL"
            )
            await db.commit()
        await self._warm_cache()

    async def _migrate(self, db: aiosqlite.Connection) -> None:
        """Add any columns introduced after initial schema."""
        existing: set[str] = set()
        async with db.execute("PRAGMA table_info(sources)") as cur:
            async for row in cur:
                existing.add(row[1])

        new_cols = {
            # migration 2 used column name "source_type"; all code uses "type"
            "type": "TEXT NOT NULL DEFAULT 'unknown'",
            "owner": "TEXT NOT NULL DEFAULT ''",
            "region": "TEXT NOT NULL DEFAULT ''",
            "data_classification": "TEXT NOT NULL DEFAULT ''",
            "updated_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
            "config": "TEXT NOT NULL DEFAULT '{}'",
            "deleted_at": "DATETIME",
        }
        for col, definition in new_cols.items():
            if col not in existing:
                await db.execute(f"ALTER TABLE sources ADD COLUMN {col} {definition}")
                logger.info("sources migration: added column %s", col)

    async def _warm_cache(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sources WHERE deleted_at IS NULL"
            ) as cur:
                rows = await cur.fetchall()
        self._cache = {row["id"]: _row_to_source(row) for row in rows}

    def get_trust_tier(self, source_id: str) -> SourceTrustTier:
        """Hot-path O(1) lookup - always served from in-memory cache."""
        source = self._cache.get(source_id)
        if source is None:
            logger.warning("unknown source_id, defaulting to untrusted", extra={"source_id": source_id})
            return SourceTrustTier.UNTRUSTED
        return source.trust_tier

    def get_compliance_scope(self, source_id: str) -> list[str]:
        """Return compliance frameworks for a source. Hot-path, no I/O."""
        source = self._cache.get(source_id)
        return source.compliance_scope(self._classification_frameworks) if source else []

    async def register(
        self,
        source_id: str,
        source_type: str,
        trust_tier: SourceTrustTier,
        *,
        owner: str = "",
        region: str = "",
        data_classification: str = "",
        config: dict[str, Any] | None = None,
    ) -> Source:
        now = datetime.now(timezone.utc)
        config_json = json.dumps(config or {})
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT INTO sources
                    (id, type, trust_tier, owner, region, data_classification,
                     created_at, updated_at, config)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    type                = excluded.type,
                    trust_tier          = excluded.trust_tier,
                    owner               = excluded.owner,
                    region              = excluded.region,
                    data_classification = excluded.data_classification,
                    updated_at          = excluded.updated_at,
                    config              = excluded.config,
                    deleted_at          = NULL
                """,
                (source_id, source_type, trust_tier.value, owner, region, data_classification,
                 now.isoformat(), now.isoformat(), config_json),
            )
            await db.commit()

        source = Source(
            id=source_id, type=source_type, trust_tier=trust_tier,
            owner=owner, region=region, data_classification=data_classification,
            created_at=now, updated_at=now, config=config or {},
        )
        self._cache[source_id] = source
        logger.info("source registered id=%s tier=%s", source_id, trust_tier.value)
        return source

    async def get(self, source_id: str) -> Source | None:
        source = self._cache.get(source_id)
        if source is not None:
            return source
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sources WHERE id = ? AND deleted_at IS NULL", (source_id,)
            ) as cur:
                row = await cur.fetchone()
        return _row_to_source(row) if row else None

    async def list_sources(self) -> list[Source]:
        return list(self._cache.values())

    async def update(
        self,
        source_id: str,
        *,
        source_type: str | None = None,
        trust_tier: SourceTrustTier | None = None,
        owner: str | None = None,
        region: str | None = None,
        data_classification: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> Source | None:
        source = self._cache.get(source_id)
        if source is None:
            return None
        now = datetime.now(timezone.utc)
        updates: dict[str, Any] = {"updated_at": now.isoformat()}
        if source_type is not None:
            updates["type"] = source_type
            source.type = source_type
        if trust_tier is not None:
            updates["trust_tier"] = trust_tier.value
            source.trust_tier = trust_tier
        if owner is not None:
            updates["owner"] = owner
            source.owner = owner
        if region is not None:
            updates["region"] = region
            source.region = region
        if data_classification is not None:
            updates["data_classification"] = data_classification
            source.data_classification = data_classification
        if config is not None:
            updates["config"] = json.dumps(config)
            source.config = config
        source.updated_at = now

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [source_id]
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(f"UPDATE sources SET {set_clause} WHERE id = ?", values)
            await db.commit()

        self._cache[source_id] = source
        return source

    async def remove(self, source_id: str) -> bool:
        """Soft delete: sets deleted_at timestamp, removes from cache."""
        now = datetime.now(timezone.utc)
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute(
                "UPDATE sources SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
                (now.isoformat(), source_id),
            )
            await db.commit()
            affected = cur.rowcount
        if affected:
            self._cache.pop(source_id, None)
            logger.info("source soft-deleted id=%s", source_id)
        return bool(affected)

    async def auto_register_repo_sources(self, repo_roots: list[str]) -> int:
        """Idempotently register code repository paths as internal sources."""
        registered = 0
        for root in repo_roots:
            if root not in self._cache:
                await self.register(
                    root,
                    "code_repository",
                    SourceTrustTier.INTERNAL,
                    data_classification="internal_code",
                )
                registered += 1
        return registered


def _row_to_source(row: aiosqlite.Row) -> Source:
    return Source(
        id=row["id"],
        type=row["type"],
        trust_tier=SourceTrustTier(row["trust_tier"]),
        owner=row["owner"] or "",
        region=row["region"] or "",
        data_classification=row["data_classification"] or "",
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(str(row["updated_at"] or row["created_at"])),
        config=json.loads(row["config"] or "{}"),
        deleted_at=datetime.fromisoformat(row["deleted_at"]) if row["deleted_at"] else None,
    )
