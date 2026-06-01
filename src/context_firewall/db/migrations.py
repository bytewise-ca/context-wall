"""Versioned SQLite migrations.

Each migration is a (version, description, sql_statements) tuple.
The runner applies only migrations whose version is higher than the
current schema_version stored in the DB - safe to run repeatedly.

Adding a migration:
    1. Append a new entry to _MIGRATIONS with the next version number.
    2. Never modify an existing migration entry (already applied on prod DBs).
    3. Use ALTER TABLE ADD COLUMN (not DROP/RECREATE) for additive changes.
"""

from __future__ import annotations

import logging

import aiosqlite

logger = logging.getLogger(__name__)

# ── Migration registry ─────────────────────────────────────────────────────────
# Each entry: (version: int, description: str, statements: list[str])
# Statements are executed inside a transaction; if any fails the migration
# is rolled back and startup aborts.

_MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (
        1,
        "initial schema",
        [
            """
            CREATE TABLE IF NOT EXISTS runtime_signals (
                node_id             TEXT PRIMARY KEY,
                invocation_count    INTEGER NOT NULL DEFAULT 0,
                exception_count     INTEGER NOT NULL DEFAULT 0,
                exception_rate      REAL NOT NULL DEFAULT 0.0,
                p50_latency_ms      REAL,
                p95_latency_ms      REAL,
                p99_latency_ms      REAL,
                last_observed_at    DATETIME,
                latency_degraded    BOOLEAN NOT NULL DEFAULT FALSE,
                exception_rate_high BOOLEAN NOT NULL DEFAULT FALSE,
                updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS service_map (
                caller_service  TEXT NOT NULL,
                callee_service  TEXT NOT NULL,
                observed_count  INTEGER NOT NULL DEFAULT 1,
                last_seen_at    DATETIME NOT NULL,
                PRIMARY KEY (caller_service, callee_service)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id        TEXT PRIMARY KEY,
                agent_id          TEXT,
                model_version     TEXT,
                repository_root   TEXT,
                client_type       TEXT,
                status            TEXT NOT NULL DEFAULT 'open',
                started_at        DATETIME NOT NULL,
                closed_at         DATETIME,
                request_count     INTEGER NOT NULL DEFAULT 0,
                total_tokens      INTEGER NOT NULL DEFAULT 0,
                avg_outcome_score REAL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS provenance_events (
                event_id    TEXT PRIMARY KEY,
                event_type  TEXT NOT NULL,
                session_id  TEXT NOT NULL,
                request_id  TEXT NOT NULL,
                occurred_at DATETIME NOT NULL,
                payload     TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_provenance_session ON provenance_events(session_id, occurred_at)",
            "CREATE INDEX IF NOT EXISTS idx_provenance_request ON provenance_events(request_id, occurred_at)",
            """
            CREATE TABLE IF NOT EXISTS policy_enforcement_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                request_id   TEXT NOT NULL,
                rule_name    TEXT NOT NULL,
                action       TEXT NOT NULL,
                file_path    TEXT NOT NULL,
                node_id      TEXT,
                line_numbers TEXT,
                reason       TEXT NOT NULL,
                pattern_name TEXT,
                occurred_at  DATETIME NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS analytics_snapshots (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type  TEXT NOT NULL,
                granularity  TEXT NOT NULL,
                key          TEXT NOT NULL,
                payload      TEXT NOT NULL,
                computed_at  DATETIME NOT NULL,
                window_start DATETIME,
                window_end   DATETIME
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_analytics_type_key ON analytics_snapshots(metric_type, key, computed_at DESC)",
            """
            CREATE TABLE IF NOT EXISTS entropy_snapshots (
                node_id        TEXT NOT NULL,
                file_path      TEXT NOT NULL,
                entropy_score  REAL NOT NULL,
                active_signals TEXT,
                snapshot_at    DATETIME NOT NULL,
                PRIMARY KEY (node_id, snapshot_at)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS trust_score_snapshots (
                node_id          TEXT NOT NULL,
                file_path        TEXT NOT NULL,
                trust_score      REAL NOT NULL,
                signal_breakdown TEXT,
                snapshot_at      DATETIME NOT NULL,
                trigger_reason   TEXT,
                PRIMARY KEY (node_id, snapshot_at)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS trust_signal_cache (
                node_id          TEXT PRIMARY KEY,
                structural_score REAL,
                runtime_score    REAL,
                freshness_score  REAL,
                stability_score  REAL,
                verification_score REAL,
                consistency_score REAL,
                injection_risk   REAL,
                entropy_score    REAL,
                cached_at        DATETIME NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS outcome_signals (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                request_id      TEXT NOT NULL,
                outcome_type    TEXT NOT NULL,
                success         BOOLEAN NOT NULL,
                score           REAL NOT NULL,
                node_ids        TEXT NOT NULL,
                recorded_at     DATETIME NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS weight_profiles (
                profile_name         TEXT NOT NULL,
                structural_relevance REAL NOT NULL,
                runtime_evidence     REAL NOT NULL,
                freshness            REAL NOT NULL,
                stability            REAL NOT NULL,
                verification         REAL NOT NULL,
                consistency          REAL NOT NULL,
                injection_risk       REAL NOT NULL,
                entropy_contribution REAL NOT NULL,
                updated_at           DATETIME NOT NULL,
                PRIMARY KEY (profile_name)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS entropy_annotations (
                node_id          TEXT PRIMARY KEY,
                file_path        TEXT NOT NULL,
                entropy_score    REAL NOT NULL,
                signals          TEXT NOT NULL,
                reasons          TEXT NOT NULL,
                computed_at      DATETIME NOT NULL,
                stale            BOOLEAN NOT NULL DEFAULT FALSE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS git_metadata (
                file_path        TEXT PRIMARY KEY,
                last_commit_at   DATETIME,
                commit_count_30d INTEGER NOT NULL DEFAULT 0,
                author_count     INTEGER NOT NULL DEFAULT 0,
                indexed_at       DATETIME NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS provenance_chain (
                event_id    TEXT PRIMARY KEY,
                sequence    INTEGER NOT NULL,
                prev_hash   TEXT NOT NULL,
                entry_hash  TEXT NOT NULL,
                chained_at  DATETIME NOT NULL,
                FOREIGN KEY (event_id) REFERENCES provenance_events(event_id)
            )
            """,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_chain_sequence ON provenance_chain(sequence)",
            """
            CREATE TABLE IF NOT EXISTS compliance_bundles (
                bundle_id    TEXT PRIMARY KEY,
                scope_json   TEXT NOT NULL,
                signature    TEXT NOT NULL DEFAULT '',
                generated_at DATETIME NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS key_store (
                key_id       TEXT PRIMARY KEY,
                public_key   TEXT NOT NULL,
                algorithm    TEXT NOT NULL DEFAULT 'Ed25519',
                created_at   DATETIME NOT NULL
            )
            """,
        ],
    ),
    (
        2,
        "source trust registry",
        [
            """
            CREATE TABLE IF NOT EXISTS sources (
                id                  TEXT PRIMARY KEY,
                source_type         TEXT NOT NULL,
                trust_tier          TEXT NOT NULL DEFAULT 'untrusted',
                owner               TEXT NOT NULL DEFAULT '',
                region              TEXT NOT NULL DEFAULT '',
                data_classification TEXT NOT NULL DEFAULT 'internal',
                compliance_scope    TEXT NOT NULL DEFAULT '[]',
                config_json         TEXT NOT NULL DEFAULT '{}',
                created_at          DATETIME NOT NULL,
                deleted_at          DATETIME
            )
            """,
        ],
    ),
    (
        3,
        "transparent proxy tokens",
        [
            """
            CREATE TABLE IF NOT EXISTS proxy_tokens (
                key_id        TEXT PRIMARY KEY,
                key_hash      TEXT NOT NULL UNIQUE,
                project_id    TEXT NOT NULL,
                project_name  TEXT NOT NULL,
                provider      TEXT NOT NULL DEFAULT 'any',
                upstream_key  TEXT NOT NULL,
                scopes        TEXT NOT NULL DEFAULT '["proxy"]',
                created_at    TEXT NOT NULL,
                revoked       INTEGER NOT NULL DEFAULT 0
            )
            """,
        ],
    ),
    (
        4,
        "policy enforcement index for analytics",
        [
            "CREATE INDEX IF NOT EXISTS idx_enforcement_rule ON policy_enforcement_events(rule_name, occurred_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_enforcement_session ON policy_enforcement_events(session_id, occurred_at DESC)",
        ],
    ),
    (
        5,
        "lint findings table",
        [
            """
            CREATE TABLE IF NOT EXISTS lint_findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ran_at      TEXT    NOT NULL,
                window_days INTEGER NOT NULL DEFAULT 30,
                category    TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                subject     TEXT    NOT NULL,
                detail      TEXT    NOT NULL DEFAULT '',
                suggestion  TEXT    NOT NULL DEFAULT '',
                created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_lint_ran_at ON lint_findings(ran_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_lint_severity ON lint_findings(severity, category)",
        ],
    ),
    (
        6,
        "source enforcement penalties",
        [
            # Track cumulative violation history per source for trust score compounding.
            # penalty_score is a [0,1] float: 0 = clean, 1 = maximum distrust.
            # It decays toward 0 over time and compounds on each new deny event.
            """
            CREATE TABLE IF NOT EXISTS source_enforcement_penalties (
                source_id         TEXT PRIMARY KEY,
                violation_count   INTEGER NOT NULL DEFAULT 0,
                penalty_score     REAL NOT NULL DEFAULT 0.0,
                last_violation_at DATETIME NOT NULL,
                updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_sep_updated ON source_enforcement_penalties(updated_at DESC)",
            # Add source_id to enforcement events so blocks can be traced back to sources.
            "ALTER TABLE policy_enforcement_events ADD COLUMN source_id TEXT NOT NULL DEFAULT ''",
        ],
    ),
    (
        7,
        "sources: rename source_type column to type",
        [
            # Migration 2 created the sources table with column 'source_type', but all
            # registry code uses 'type'. SQLite has no RENAME COLUMN before 3.25, so
            # we recreate the table. COALESCE handles DBs where _migrate() already added
            # a 'type' column alongside the original 'source_type'.
            """
            CREATE TABLE IF NOT EXISTS sources_v7 (
                id                  TEXT PRIMARY KEY,
                type                TEXT NOT NULL DEFAULT 'unknown',
                trust_tier          TEXT NOT NULL DEFAULT 'untrusted',
                owner               TEXT NOT NULL DEFAULT '',
                region              TEXT NOT NULL DEFAULT '',
                data_classification TEXT NOT NULL DEFAULT '',
                created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                config              TEXT NOT NULL DEFAULT '{}',
                deleted_at          DATETIME
            )
            """,
            """
            INSERT OR IGNORE INTO sources_v7
                (id, type, trust_tier, owner, region, data_classification,
                 created_at, updated_at, config, deleted_at)
            SELECT
                id,
                COALESCE(source_type, 'unknown'),
                COALESCE(trust_tier, 'untrusted'),
                COALESCE(owner, ''),
                COALESCE(region, ''),
                COALESCE(data_classification, ''),
                COALESCE(created_at, CURRENT_TIMESTAMP),
                CURRENT_TIMESTAMP,
                COALESCE(config_json, '{}'),
                deleted_at
            FROM sources
            """,
            "DROP TABLE sources",
            "ALTER TABLE sources_v7 RENAME TO sources",
            "CREATE INDEX IF NOT EXISTS idx_sources_tier ON sources(trust_tier) WHERE deleted_at IS NULL",
        ],
    ),
]


# ── Runner ─────────────────────────────────────────────────────────────────────

async def run_migrations(db_path: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")

        # Bootstrap the version tracking table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version      INTEGER NOT NULL,
                description  TEXT NOT NULL,
                applied_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()

        async with db.execute("SELECT MAX(version) AS v FROM schema_version") as cur:
            row = await cur.fetchone()
        current = row["v"] if row["v"] is not None else 0

        pending = [(v, desc, stmts) for v, desc, stmts in _MIGRATIONS if v > current]
        if not pending:
            logger.debug("schema up to date at version %d", current)
            return

        for version, description, statements in pending:
            logger.info("applying migration %d: %s", version, description)
            try:
                for stmt in statements:
                    await db.execute(stmt)
                await db.execute(
                    "INSERT INTO schema_version (version, description) VALUES (?, ?)",
                    (version, description),
                )
                await db.commit()
                logger.info("migration %d applied", version)
            except Exception as e:
                await db.rollback()
                logger.error(
                    "migration %d failed - rolling back: %s", version, e
                )
                raise RuntimeError(f"Migration {version} ({description}) failed: {e}") from e

        logger.info(
            "migrations complete: %d → %d (%d applied)",
            current,
            pending[-1][0],
            len(pending),
        )
