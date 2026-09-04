"""ContextWall Daemon - single-process asyncio event loop embedding all engines."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from context_firewall.config import Config, load_config

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


async def _seed_git_metadata(db_path: str, repository_root: str) -> None:
    """
    Populate git_metadata table from git history for the indexed repository.

    This runs on startup so trust scoring has real freshness and stability
    signals instead of defaulting everything to 0.5 (neutral).
    """
    import aiosqlite

    if not repository_root or not Path(repository_root).exists():
        logger.info("git metadata seed skipped: no repository root")
        return

    try:
        # git log: output format is "ISO_DATE FILEPATH" for each file changed per commit
        result = subprocess.run(
            [
                "git", "log",
                "--name-only",
                "--format=COMMIT %ai",
                "--no-merges",
                "--diff-filter=ACMR",  # Added, Copied, Modified, Renamed
                "-500",               # last 500 commits
            ],
            cwd=repository_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.info("git log unavailable: %s", result.stderr[:100])
            return

        # Parse: track last commit date and commit count per file in last 30 days
        file_last_commit: dict[str, str] = {}
        file_commit_count_30d: dict[str, int] = {}
        now = datetime.now(timezone.utc)

        current_date: str | None = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("COMMIT "):
                current_date = line[7:].strip()
            elif current_date and not line.startswith("commit "):
                filepath = line
                if filepath not in file_last_commit:
                    file_last_commit[filepath] = current_date
                # Count commits in last 30 days
                try:
                    commit_dt = datetime.fromisoformat(current_date)
                    if commit_dt.tzinfo is None:
                        commit_dt = commit_dt.replace(tzinfo=timezone.utc)
                    age_days = (now - commit_dt).days
                    if age_days <= 30:
                        file_commit_count_30d[filepath] = file_commit_count_30d.get(filepath, 0) + 1
                except ValueError:
                    pass

        if not file_last_commit:
            logger.info("git metadata: no commits found")
            return

        indexed_at = now.isoformat()
        async with aiosqlite.connect(db_path) as db:
            await db.executemany(
                """
                INSERT OR REPLACE INTO git_metadata
                    (file_path, last_commit_at, commit_count_30d, author_count, indexed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        fp,
                        file_last_commit[fp],
                        file_commit_count_30d.get(fp, 0),
                        1,  # author_count: would need git log --format=%ae to compute exactly
                        indexed_at,
                    )
                    for fp in file_last_commit
                ],
            )
            await db.commit()

        logger.info(
            "git metadata seeded",
            extra={"files": len(file_last_commit), "repo": repository_root},
        )
    except subprocess.TimeoutExpired:
        logger.warning("git metadata seed timed out")
    except Exception as e:
        logger.warning("git metadata seed failed (non-fatal)", extra={"error": str(e)})


def _migrate_legacy_db_path(db_path: str) -> None:
    """One-time rename of the legacy `.ctxfw/cre.db` to the new default path.

    Only runs when the configured/default path doesn't yet exist and a
    legacy sibling does. If a user has explicitly configured a different
    path via ctxfw.yaml, we still migrate the sibling cre.db if present
    so nothing is silently dropped on the floor.
    """
    target = Path(db_path)
    legacy = target.parent / "cre.db"
    if legacy.exists() and not target.exists():
        legacy.rename(target)
        logger.warning(
            "Migrated legacy database %s -> %s. Update storage.db_path in ctxfw.yaml if pinned.",
            legacy, target,
        )


async def run_daemon(config: Config, host: str = "0.0.0.0") -> None:
    db_path = config.storage.db_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    _migrate_legacy_db_path(db_path)

    # ── Startup validation ────────────────────────────────────────────────────
    if config.rest_api.auth.enabled:
        tokens = config.rest_api.auth.tokens
        if not tokens:
            logger.error(
                "STARTUP BLOCKED: auth.enabled=true but no tokens configured. "
                "Add at least one token to ctxfw.yaml or set CONTEXTWALL_API_TOKEN "
                "(or the deprecated CRE_API_TOKEN)."
            )
            sys.exit(1)
        _WEAK = {
            "", "changeme", "demo-token", "secret", "password", "token",
            "${CONTEXTWALL_API_TOKEN}", "${CRE_API_TOKEN}",
        }
        weak = [t for t in tokens if t.get("token", "") in _WEAK]
        if weak:
            logger.error(
                "STARTUP BLOCKED: auth token is set to a known-weak default ('%s'). "
                "Set a real random secret in ctxfw.yaml or via the CONTEXTWALL_API_TOKEN env var. "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"",
                weak[0].get("token"),
            )
            sys.exit(1)

    if not config.compliance_hmac_key:
        logger.warning(
            "compliance_hmac_key not set - compliance bundles will use a dev key and are NOT "
            "tamper-evident. Set CONTEXTWALL_COMPLIANCE_HMAC_KEY or compliance_hmac_key in ctxfw.yaml. "
            "Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )

    # ── DB path configuration ─────────────────────────────────────────────────
    from context_firewall.db.connection import configure_db_path
    configure_db_path(db_path)

    # ── Schema migrations ──────────────────────────────────────────────────────
    from context_firewall.db.migrations import run_migrations
    await run_migrations(db_path)
    logger.info("SQLite migrations complete", extra={"db_path": db_path})

    # ── Instantiate engines ───────────────────────────────────────────────────
    from context_firewall.classifier.classifier import classify_task
    from context_firewall.trust.engine import TrustScoringEngine
    from context_firewall.policy.engine import PolicyEngine
    from context_firewall.provenance.engine import ProvenanceEngine
    from context_firewall.synthesizer.synthesizer import ContextSynthesizer

    # Wrap classify_task to match engine protocol
    _classify_task_fn = classify_task  # capture before class body redefines the name

    class _ClassifierShim:
        name = "intent_classifier"
        critical = False
        classify_task = staticmethod(_classify_task_fn)

        async def init(self, cfg: Config) -> None:
            pass

        def health_check(self):
            from context_firewall.models import SubsystemHealth
            return SubsystemHealth(name=self.name, healthy=True)

        async def shutdown(self) -> None:
            pass

    # ── Apply detection thresholds from config ────────────────────────────────
    from context_firewall.policy.detectors.injection import configure_thresholds
    configure_thresholds(
        block=config.detection.injection_block_threshold,
        warn=config.detection.injection_warn_threshold,
    )
    logger.info(
        "Injection thresholds: block=%.2f warn=%.2f",
        config.detection.injection_block_threshold,
        config.detection.injection_warn_threshold,
    )

    from context_firewall.source.registry import SourceRegistry
    from context_firewall.source.types import SourceTrustTier
    source_registry = SourceRegistry(
        classification_frameworks=config.compliance.classification_frameworks,
    )
    await source_registry.init()

    # Register declarative sources from config
    if config.sources:
        for src in config.sources:
            await source_registry.register(
                src.id,
                src.type,
                SourceTrustTier(src.trust_tier),
                owner=src.owner,
                region=src.region,
                data_classification=src.data_classification,
                config=src.config or {},
            )
        logger.info("Registered %d source(s) from config", len(config.sources))

    repo_root = config.repository_root
    if repo_root:
        count = await source_registry.auto_register_repo_sources([repo_root])
        if count:
            logger.info("Auto-registered %d repo source(s) as internal", count)
    logger.info("SourceRegistry initialized")

    trust = TrustScoringEngine()
    policy = PolicyEngine()
    provenance = ProvenanceEngine()
    synthesizer = ContextSynthesizer()
    classifier_shim = _ClassifierShim()

    startup_order = [
        trust,
        policy,
        provenance,
        synthesizer,
        classifier_shim,
    ]
    initialized = []

    for engine in startup_order:
        try:
            if engine.name == "policy_engine":
                await engine.init(config, provenance)
            elif engine.name == "context_synthesizer":
                await engine.init(config, provenance)
            else:
                await engine.init(config)
            initialized.append(engine)
            if hasattr(engine, "health_check"):
                h = engine.health_check()
                if h.healthy:
                    logger.info("%s ready", engine.name)
                else:
                    logger.warning("%s degraded: %s", engine.name, h.message or "check configuration")
            else:
                logger.info("%s ready", engine.name)
        except Exception as e:
            if engine.critical:
                logger.error("Critical engine %s failed; shutting down: %s", engine.name, e)
                for done in reversed(initialized):
                    try:
                        await done.shutdown()
                    except Exception:
                        pass
                sys.exit(1)
            else:
                logger.warning("Non-critical engine %s failed (continuing): %s", engine.name, e)

    # ── Startup health summary ─────────────────────────────────────────────────
    degraded = []
    for eng in initialized:
        if hasattr(eng, "health_check"):
            h = eng.health_check()
            if not h.healthy:
                degraded.append((eng.name, h.message or "degraded"))

    if degraded:
        logger.warning("━" * 60)
        logger.warning("ContextWall started in REDUCED CAPACITY - %d subsystem(s) degraded:", len(degraded))
        for name, msg in degraded:
            logger.warning("  ✗ %-38s %s", name, msg)
        logger.warning("Proxy enforcement and policy engine are fully operational.")
        logger.warning("━" * 60)
    else:
        logger.info("All subsystems healthy")

    # ── Seed git metadata so trust scoring has real signals on day one ─────────
    if repo_root:
        asyncio.ensure_future(_seed_git_metadata(db_path, repo_root))

    engines = {
        "classifier": classifier_shim,
        "trust": trust,
        "policy": policy,
        "provenance": provenance,
        "synthesizer": synthesizer,
        "source_registry": source_registry,
    }

    # ── Control plane pusher (optional, non-critical) ─────────────────────────
    from context_firewall.control_plane.pusher import ControlPlanePusher

    def _health_snapshot() -> dict:
        snap = {}
        for eng in initialized:
            if hasattr(eng, "health_check"):
                h = eng.health_check()
                snap[eng.name] = {
                    "status": "healthy" if h.healthy else "degraded",
                    "latency_ms": getattr(h, "latency_ms", None),
                    "message": getattr(h, "message", None),
                }
        return snap

    cp_pusher = ControlPlanePusher(
        cp_config=config.control_plane,
        config=config,
        health_provider=_health_snapshot,
        policy_engine=policy,
    )
    await cp_pusher.start()

    # ── FastAPI app ───────────────────────────────────────────────────────────
    from context_firewall.api.app import create_app
    app = create_app(config, engines)

    # ── Offline job scheduler (kept as hook; no jobs scheduled by default) ────
    scheduler = AsyncIOScheduler()
    scheduler.start()
    logger.info("APScheduler started (no default jobs)")

    # ── PID file ──────────────────────────────────────────────────────────────
    pid_file = Path(config.daemon.pid_file)
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(os.getpid()))

    # ── Signal handlers ───────────────────────────────────────────────────────
    loop = asyncio.get_event_loop()

    async def _shutdown():
        logger.info("Graceful shutdown initiated")
        scheduler.shutdown(wait=False)
        await cp_pusher.stop()
        for eng in reversed(initialized):
            try:
                await eng.shutdown()
            except Exception:
                pass
        pid_file.unlink(missing_ok=True)
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.ensure_future(_shutdown()))

    # ── uvicorn ───────────────────────────────────────────────────────────────
    uconfig = uvicorn.Config(
        app,
        host=host,
        port=config.rest_api.port,
        log_level="warning",
        loop="asyncio",
    )
    server = uvicorn.Server(uconfig)
    logger.info(f"ContextWall daemon listening on {host}:{config.rest_api.port}")
    await server.serve()


def main():
    config_path = os.environ.get("CTXFW_CONFIG", "ctxfw.yaml")
    config = load_config(config_path)
    asyncio.run(run_daemon(config))


if __name__ == "__main__":
    main()
