"""FastMCP server with ContextWall tools."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from fastmcp import FastMCP

logger = logging.getLogger(__name__)


def create_mcp_server(engines: dict[str, Any] | None = None, config=None) -> FastMCP:
    mcp = FastMCP("context-firewall")
    _engines = engines or {}

    @mcp.tool()
    async def retrieve_bundle(
        task: str,
        session_id: str | None = None,
        repository_root: str | None = None,
        token_budget: int | None = None,
    ) -> str:
        """
        Retrieve a trusted context bundle for the given task.
        Returns JSON with included file slices, trust scores, and summary.
        """
        sid = session_id or str(uuid.uuid4())
        classifier = _engines.get("classifier")
        graph = _engines.get("graph")
        trust = _engines.get("trust")
        policy = _engines.get("policy")
        synthesizer = _engines.get("synthesizer")

        if not (classifier and graph and synthesizer):
            return json.dumps({"error": "engines not ready"})

        from context_firewall.classifier.classifier import build_pipeline_context
        cfg = config or (lambda: None)()
        from context_firewall.config import Config
        cfg = cfg if cfg else Config()

        classification = classifier.classify_task(task)
        ctx = build_pipeline_context(task, classification, sid, cfg)

        candidates = await graph.get_candidates(ctx, repository_root)
        if trust:
            candidates = await trust.score_candidates(candidates, ctx)

        violations = 0
        if policy:
            candidates, violations = await policy.evaluate(candidates, ctx.request_id, sid)

        bundle = await synthesizer.assemble(candidates, ctx, violations)
        return json.dumps({
            "session_id": sid,
            "request_id": bundle.request_id,
            "task_type": bundle.task_type,
            "summary": bundle.summary,
            "total_tokens": bundle.total_tokens,
            "token_budget": bundle.token_budget,
            "slices": [
                {
                    "file_path": s.file_path,
                    "trust_score": s.trust_score,
                    "token_count": s.token_count,
                    "content": s.content,
                }
                for s in bundle.slices
            ],
            "excluded_count": bundle.excluded_count,
            "trust_range": bundle.trust_range.model_dump(),
            "entropy_score": bundle.entropy_score,
            "policy_violations": bundle.policy_violations,
        })

    @mcp.tool()
    async def replay_provenance(
        session_id: str,
        request_id: str | None = None,
    ) -> str:
        """
        Replay provenance events for a session or specific request.
        Returns JSON array of recorded events.
        """
        provenance = _engines.get("provenance")
        if not provenance:
            return json.dumps({"error": "provenance engine unavailable"})
        events = await provenance.replay(session_id, request_id)
        return json.dumps({"events": events, "count": len(events)})

    @mcp.tool()
    async def query_graph(
        query_type: str,
        symbol: str,
        service: str | None = None,
        max_depth: int = 2,
    ) -> str:
        """
        Query the repository graph for a symbol's relationships.
        query_type: 'callers', 'callees', 'imports', 'file_info'
        """
        try:
            import kuzu
            from pathlib import Path
            from context_compiler.indexer.graph import open_database, graph_path

            repo_root = Path(config.repository_root if config else ".")
            gp = graph_path(repo_root)
            if not gp.exists():
                return json.dumps({"error": "graph not found - run context-compiler index"})

            db = open_database(repo_root)
            conn = kuzu.Connection(db)

            if query_type == "callers":
                result = conn.execute(
                    "MATCH (caller:Symbol)-[:CALLS]->(n:Symbol) WHERE n.symbol_name = $sym "
                    "RETURN caller.id, caller.symbol_name, caller.file_path LIMIT 20",
                    {"sym": symbol},
                )
            elif query_type == "callees":
                result = conn.execute(
                    "MATCH (n:Symbol)-[:CALLS]->(callee:Symbol) WHERE n.symbol_name = $sym "
                    "RETURN callee.id, callee.symbol_name, callee.file_path LIMIT 20",
                    {"sym": symbol},
                )
            elif query_type == "imports":
                result = conn.execute(
                    "MATCH (n:Symbol)-[:IMPORTS]->(dep:Symbol) WHERE n.symbol_name = $sym "
                    "RETURN dep.id, dep.symbol_name, dep.file_path LIMIT 20",
                    {"sym": symbol},
                )
            elif query_type == "file_info":
                result = conn.execute(
                    "MATCH (n:Symbol) WHERE n.file_path CONTAINS $sym "
                    "RETURN n.id, n.symbol_name, n.file_path LIMIT 20",
                    {"sym": symbol},
                )
            else:
                return json.dumps({"error": f"unknown query_type: {query_type}"})

            rows = result.fetchall()
            return json.dumps({
                "query_type": query_type,
                "symbol": symbol,
                "results": [{"id": r[0], "name": r[1], "file_path": r[2]} for r in rows],
                "count": len(rows),
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    async def get_source_trust(source_id: str) -> str:
        """
        Look up the trust tier and compliance scope for a registered source.
        Returns JSON with trust_tier, compliance_scope, and full source metadata.
        """
        registry = _engines.get("source_registry")
        if not registry:
            return json.dumps({"error": "source registry unavailable"})
        source = await registry.get(source_id)
        if source is None:
            tier = registry.get_trust_tier(source_id)
            return json.dumps({
                "source_id": source_id,
                "trust_tier": tier.value,
                "compliance_scope": [],
                "registered": False,
            })
        return json.dumps({
            "source_id": source_id,
            "trust_tier": source.trust_tier.value,
            "compliance_scope": source.compliance_scope(),
            "registered": True,
            "owner": source.owner,
            "region": source.region,
            "data_classification": source.data_classification,
        })

    @mcp.tool()
    async def export_compliance_bundle(
        session_id: str | None = None,
        framework: str | None = None,
    ) -> str:
        """
        Export a signed compliance audit bundle for a session or framework.
        Returns JSON ComplianceExportBundle with Merkle chain proof and control mappings.
        """
        if config is None:
            return json.dumps({"error": "config not available"})
        try:
            from context_firewall.compliance.export import ComplianceExporter, ExportScope
            hmac_key = config.compliance_hmac_key or "dev-key"
            baa_mode = getattr(config, "compliance_baa_mode", False)
            exporter = ComplianceExporter(
                db_path=config.storage.db_path,
                hmac_key=hmac_key,
                baa_mode=baa_mode,
            )
            scope = ExportScope(session_id=session_id, framework=framework)
            bundle = await exporter.export(scope)
            return json.dumps(bundle.to_dict(), default=str)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    async def refresh(changed_files: list[str]) -> str:
        """
        Trigger incremental graph refresh for the given changed files.
        Returns JSON with refresh status and count of files processed.
        """
        try:
            from pathlib import Path
            from context_compiler.indexer.indexer import refresh_repository

            repo_root = Path(config.repository_root if config else ".")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                refresh_repository,
                repo_root,
                changed_files,
            )
            return json.dumps({
                "status": "refreshed",
                "files_processed": len(changed_files),
                "changed_files": changed_files,
            })
        except Exception as e:
            logger.error("refresh failed", extra={"error": str(e)})
            return json.dumps({"status": "error", "error": str(e)})

    return mcp
