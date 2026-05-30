"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse

from context_firewall.api.models import (
    AnalyzeRequest,
    APIToken,
    BundleRequest,
    ErrorResponse,
    OutcomeRequest,
)
from context_firewall.config import Config

logger = logging.getLogger(__name__)


def _build_token_store(config: Config) -> dict[str, APIToken]:
    store: dict[str, APIToken] = {}
    for entry in config.rest_api.auth.tokens:
        token_val = entry.get("token", "")
        if token_val:
            store[token_val] = APIToken(
                token=token_val,
                name=entry.get("name", "unnamed"),
                scopes=entry.get("scopes", ["analyze", "bundle"]),
            )
    return store


def create_app(
    config: Config,
    engines: dict[str, Any] | None = None,
) -> FastAPI:
    app = FastAPI(title="CRE API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    _engines = engines or {}
    token_store = _build_token_store(config)
    auth_enabled = config.rest_api.auth.enabled

    # ── Auth ──────────────────────────────────────────────────────────────────

    async def require_auth(authorization: str = Header(alias="Authorization", default="")) -> APIToken:
        if not auth_enabled:
            return APIToken(token="", name="anonymous", scopes=["analyze", "bundle"])
        bearer = authorization.removeprefix("Bearer ").strip()
        api_token = token_store.get(bearer)
        if not api_token:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid token", "code": "UNAUTHORIZED"},
            )
        return api_token

    def require_scope(scope: str):
        async def check(token: APIToken = Depends(require_auth)) -> APIToken:
            if scope not in token.scopes:
                raise HTTPException(
                    status_code=403,
                    detail={"error": "insufficient scope", "code": "FORBIDDEN"},
                )
            return token
        return check

    # ── Middleware ────────────────────────────────────────────────────────────

    @app.middleware("http")
    async def logging_middleware(request: Request, call_next):
        req_id = str(uuid.uuid4())[:8]
        request.state.request_id = req_id
        response = await call_next(request)
        logger.info(
            "http",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "request_id": req_id,
            },
        )
        return response

    # ── Pipeline helper ───────────────────────────────────────────────────────

    async def _run_pipeline(task: str, session_id: str, repository_root: str | None, request: Request):
        from context_firewall import metrics as m

        classifier = _engines.get("classifier")
        graph = _engines.get("graph")
        trust = _engines.get("trust")
        policy = _engines.get("policy")
        synthesizer = _engines.get("synthesizer")
        provenance = _engines.get("provenance")

        req_id = getattr(request.state, "request_id", str(uuid.uuid4())[:8])

        if not classifier or not graph or not synthesizer:
            m.ERRORS.labels(component="pipeline").inc()
            raise HTTPException(status_code=503, detail={"error": "engines not ready", "code": "SERVICE_UNAVAILABLE"})

        # Auto-create session on first use (INSERT OR IGNORE is safe for repeat calls)
        if provenance:
            from context_firewall.provenance.models import Session
            await provenance.create_session(Session(
                session_id=session_id,
                agent_id="api",
                model_version="",
                repository_root=repository_root or config.repository_root or "",
                client_type="rest",
                status="open",
                started_at=datetime.now(timezone.utc),
            ))

        from context_firewall.classifier.classifier import build_pipeline_context
        classification = classifier.classify_task(task)
        ctx = build_pipeline_context(task, classification, session_id, config)
        task_type = classification.task_type.value

        # Emit context_request event so live feed shows incoming pipeline requests
        if provenance:
            from context_firewall.provenance.models import PolicyEnforcementEvent
            await provenance.emit_policy_enforcement(PolicyEnforcementEvent(
                request_id=ctx.request_id,
                session_id=session_id,
                rule_name="context_request",
                action="audit-only",
                file_path="",
                reason=f"task={task_type} session={session_id}",
                occurred_at=datetime.now(timezone.utc),
            ))

        t0 = time.perf_counter()
        try:
            candidates = await graph.get_candidates(ctx, repository_root)

            if trust:
                candidates = await trust.score_candidates(candidates, ctx)

            violations = 0
            if policy:
                candidates, violations = await policy.evaluate(candidates, ctx.request_id, session_id)
                if violations:
                    m.POLICY_ENFORCEMENTS.labels(action="deny", rule_name="pipeline").inc(violations)

            bundle = await synthesizer.assemble(candidates, ctx, violations)

            elapsed = time.perf_counter() - t0
            m.PIPELINE_REQUESTS.labels(task_type=task_type, status="ok").inc()
            m.PIPELINE_DURATION.labels(task_type=task_type).observe(elapsed)
            m.PIPELINE_SLICES.labels(task_type=task_type).observe(len(bundle.slices))
            m.PIPELINE_TOKENS.labels(task_type=task_type).observe(bundle.total_tokens)
        except asyncio.TimeoutError:
            m.PIPELINE_REQUESTS.labels(task_type=task_type, status="timeout").inc()
            m.ERRORS.labels(component="pipeline").inc()
            raise
        except Exception:
            m.PIPELINE_REQUESTS.labels(task_type=task_type, status="error").inc()
            m.ERRORS.labels(component="pipeline").inc()
            raise

        # Update session stats after each successful request
        if provenance:
            await provenance.update_session_stats(session_id, total_tokens=bundle.total_tokens)

        return bundle

    # ── Core pipeline endpoints ───────────────────────────────────────────────

    @app.post("/analyze")
    async def analyze(
        body: AnalyzeRequest,
        request: Request,
        _token: APIToken = Depends(require_scope("analyze")),
    ):
        sid = body.session_id or str(uuid.uuid4())
        bundle = await asyncio.wait_for(
            _run_pipeline(body.task, sid, body.repository_root, request),
            timeout=30,
        )
        graph = _engines.get("graph")
        graph_ready = graph.health_check().healthy if graph else False
        response: dict = {
            "session_id": sid,
            "request_id": bundle.request_id,
            "task_type": bundle.task_type,
            "slices": [s.model_dump() for s in bundle.slices],
            "total_tokens": bundle.total_tokens,
            "excluded_count": bundle.excluded_count,
            "trust_range": bundle.trust_range.model_dump(),
            "entropy_score": bundle.entropy_score,
        }
        if not graph_ready:
            response["graph_status"] = "unavailable"
            response["graph_message"] = "KuzuDB graph not indexed — run 'context-compiler index' on the repository first"
        elif not bundle.slices:
            response["graph_status"] = "no_candidates"
            response["graph_message"] = "Graph is ready but no candidates matched this task — check repository_root or task description"
        else:
            response["graph_status"] = "ok"
        return response

    @app.post("/bundle")
    async def bundle(
        body: BundleRequest,
        request: Request,
        _token: APIToken = Depends(require_scope("bundle")),
    ):
        accept = request.headers.get("accept", "")
        sid = body.session_id or str(uuid.uuid4())

        if accept == "text/event-stream":
            async def stream():
                synthesizer = _engines.get("synthesizer")
                if synthesizer:
                    async for event in synthesizer.assemble_streaming(body.task, sid, []):
                        yield f"data: {json.dumps(event)}\n\n"
            return StreamingResponse(stream(), media_type="text/event-stream")

        bundle_result = await asyncio.wait_for(
            _run_pipeline(body.task, sid, body.repository_root, request),
            timeout=60,
        )
        return bundle_result.model_dump()

    # ── Provenance endpoints ──────────────────────────────────────────────────

    @app.get("/provenance/sessions")
    async def list_sessions(
        limit: int = 50,
        offset: int = 0,
        _token: APIToken = Depends(require_auth),
    ):
        provenance = _engines.get("provenance")
        if not provenance:
            return {"sessions": [], "limit": limit, "offset": offset}
        sessions = await asyncio.wait_for(
            provenance.list_sessions(limit=limit, offset=offset),
            timeout=10,
        )
        return {"sessions": sessions, "limit": limit, "offset": offset}

    @app.get("/provenance/sessions/{session_id}")
    async def get_session(
        session_id: str,
        _token: APIToken = Depends(require_auth),
    ):
        provenance = _engines.get("provenance")
        if not provenance:
            raise HTTPException(status_code=503, detail={"error": "provenance unavailable", "code": "SERVICE_UNAVAILABLE"})
        session = await asyncio.wait_for(provenance.get_session(session_id), timeout=10)
        if not session:
            raise HTTPException(status_code=404, detail={"error": "session not found", "code": "NOT_FOUND"})
        return session

    @app.get("/provenance/replay")
    async def replay(
        session_id: str,
        request_id: str | None = None,
        _token: APIToken = Depends(require_auth),
    ):
        provenance = _engines.get("provenance")
        if not provenance:
            raise HTTPException(status_code=503, detail={"error": "provenance unavailable", "code": "SERVICE_UNAVAILABLE"})
        events = await asyncio.wait_for(
            provenance.replay(session_id, request_id),
            timeout=10,
        )
        return {"events": events, "count": len(events)}

    @app.post("/provenance/outcome")
    async def record_outcome(
        body: OutcomeRequest,
        _token: APIToken = Depends(require_auth),
    ):
        provenance = _engines.get("provenance")
        if provenance:
            from context_firewall.provenance.models import OutcomeEvent
            event = OutcomeEvent(
                session_id=body.session_id,
                request_id=body.request_id,
                outcome_type=body.outcome_type,
                success=body.success,
                score=body.score,
                node_ids=body.node_ids,
                source_id=body.source_id,
            )
            await asyncio.wait_for(provenance.record_outcome(event), timeout=5)
        return {"status": "recorded"}

    @app.get("/provenance/latest")
    async def get_latest_provenance(
        limit: int = 50,
        _token: APIToken = Depends(require_auth),
    ):
        """Latest events across all sessions — used by the live feed."""
        provenance = _engines.get("provenance")
        if not provenance:
            return {"events": []}
        events = await asyncio.wait_for(
            provenance.get_latest_events(limit=limit),
            timeout=10,
        )
        return {"events": events}

    # ── WebSocket live feed ───────────────────────────────────────────────────

    @app.websocket("/ws/events")
    async def ws_events(websocket: WebSocket):
        """Real-time enforcement and provenance event feed."""
        await websocket.accept()
        provenance = _engines.get("provenance")
        if not provenance:
            await websocket.send_json({"type": "error", "message": "provenance engine unavailable"})
            await websocket.close()
            return

        q = provenance.subscribe_events()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30)
                    await websocket.send_json(event)
                except asyncio.TimeoutError:
                    # Send heartbeat to keep connection alive
                    await websocket.send_json({"type": "heartbeat", "ts": datetime.now(timezone.utc).isoformat()})
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.warning("WebSocket error", extra={"error": str(e)})
        finally:
            provenance.unsubscribe_events(q)

    # ── Policy simulation endpoint ────────────────────────────────────────────

    @app.post("/v1/policy/simulate")
    async def simulate_policy(
        body: dict,
        _token: APIToken = Depends(require_auth),
    ):
        """
        Simulate policy evaluation against provided content without blocking anything.
        Returns what would be blocked/allowed and by which rule.
        """
        from context_firewall.models import RankedSlice
        from context_firewall.source.types import SourceTrustTier
        from context_firewall.policy.detectors.injection import detect_injection

        policy = _engines.get("policy")
        content = body.get("content", "")
        file_path = body.get("file_path", "simulated")
        tier_raw = body.get("source_tier", "untrusted")

        try:
            tier = SourceTrustTier(tier_raw)
        except ValueError:
            tier = SourceTrustTier.UNTRUSTED

        candidate = RankedSlice(
            node_id=f"sim:{uuid.uuid4().hex[:8]}",
            file_path=file_path,
            content=content,
            trust_score=0.5,
            token_count=len(content.split()),
            source_trust_tier=tier,
        )

        # Run injection detection on the content regardless of policy
        injection_result = detect_injection(content)

        # Run through policy engine — events are tagged with sim: prefix so they
        # can be filtered from the main feed; no provenance manipulation needed.
        verdict = "allow"
        if policy:
            sim_session = f"sim:{uuid.uuid4().hex[:8]}"
            sim_request = f"sim:{uuid.uuid4().hex[:8]}"
            filtered, violations = await policy.evaluate([candidate], sim_request, sim_session)
            if not filtered:
                verdict = "block"
            elif violations > 0:
                verdict = "redact"

        return {
            "verdict": verdict,
            "content_length": len(content),
            "source_tier": tier.value,
            "injection_detection": {
                "detected": injection_result.detected,
                "confidence": round(injection_result.confidence, 3),
                "layer": injection_result.layer,
                "signal": injection_result.signal,
                "excerpt": injection_result.excerpt,
            },
            "would_block": verdict == "block",
            "would_redact": verdict == "redact",
        }

    # ── Active policy rules ───────────────────────────────────────────────────

    @app.get("/v1/policy/rules")
    async def list_policy_rules(_token: APIToken = Depends(require_auth)):
        """Return all currently active policy rules (builtin + DSL layers)."""
        policy = _engines.get("policy")
        if not policy:
            return {"rules": [], "total": 0}
        rules = policy.get_active_rules()
        return {"rules": rules, "total": len(rules)}

    # ── Trust score explanation endpoint ─────────────────────────────────────

    @app.get("/v1/explain/{request_id}")
    async def explain_request(
        request_id: str,
        _token: APIToken = Depends(require_auth),
    ):
        """
        Return signal-level explanation for every slice included/excluded in a request.
        Pulls from provenance events for that request_id.
        """
        provenance = _engines.get("provenance")
        if not provenance:
            raise HTTPException(status_code=503, detail={"error": "provenance unavailable"})

        events = await asyncio.wait_for(
            provenance.replay(session_id="", request_id=request_id),
            timeout=10,
        )

        # If replay by session+request fails, try querying by request_id only
        if not events:
            db = provenance._db
            if db:
                async with db.execute(
                    "SELECT payload, event_type, occurred_at FROM provenance_events WHERE request_id = ? ORDER BY occurred_at ASC",
                    (request_id,),
                ) as cur:
                    rows = await cur.fetchall()
                events = [
                    {"event_type": r["event_type"], "occurred_at": r["occurred_at"], **json.loads(r["payload"])}
                    for r in rows
                ]

        included = [e for e in events if e.get("event_type") == "slice_included"]
        excluded = [e for e in events if e.get("event_type") == "slice_excluded"]

        # Also fetch enforcement events for this request
        enforcements = []
        db = provenance._db
        if db:
            async with db.execute(
                """
                SELECT rule_name, action, file_path, reason, pattern_name, occurred_at
                FROM policy_enforcement_events WHERE request_id = ?
                ORDER BY occurred_at ASC
                """,
                (request_id,),
            ) as cur:
                rows = await cur.fetchall()
            enforcements = [dict(r) for r in rows]

        return {
            "request_id": request_id,
            "included_count": len(included),
            "excluded_count": len(excluded),
            "enforcement_count": len(enforcements),
            "included_slices": [
                {
                    "file_path": e.get("file_path", ""),
                    "node_id": e.get("node_id", ""),
                    "trust_score": e.get("trust_score", 0),
                    "token_count": e.get("token_count", 0),
                    "include_reason": e.get("include_reason", ""),
                }
                for e in included
            ],
            "excluded_slices": [
                {
                    "file_path": e.get("file_path", ""),
                    "node_id": e.get("node_id", ""),
                    "trust_score": e.get("trust_score", 0),
                    "exclude_reason": e.get("exclude_reason", ""),
                }
                for e in excluded
            ],
            "enforcements": enforcements,
        }

    # ── Analytics summary KPI ─────────────────────────────────────────────────

    @app.get("/analytics/summary")
    async def analytics_summary(
        window_hours: int = 24,
        _token: APIToken = Depends(require_auth),
    ):
        """Aggregate KPI metrics for dashboard cards."""
        provenance = _engines.get("provenance")
        if not provenance:
            return {"blocked_artifacts": 0, "policy_violations": 0, "total_requests": 0, "active_sessions": 0}
        return await asyncio.wait_for(
            provenance.get_analytics_summary(window_hours=window_hours),
            timeout=10,
        )

    # ── Other endpoints ───────────────────────────────────────────────────────

    @app.post("/webhook/ci")
    async def ci_webhook(
        request: Request,
        _token: APIToken = Depends(require_auth),
    ):
        payload = await request.json()
        logger.info("ci_webhook received", extra={"payload_keys": list(payload.keys())})
        return {"status": "received"}

    @app.get("/health")
    async def health():
        subsystems = {}
        for name, engine in _engines.items():
            if hasattr(engine, "health_check"):
                h = engine.health_check()
                subsystems[name] = {
                    "healthy": h.healthy,
                    "status": "healthy" if h.healthy else "degraded",
                    "message": h.message,
                }
        all_healthy = all(v["healthy"] for v in subsystems.values()) if subsystems else True
        return {
            "status": "healthy" if all_healthy else "degraded",
            "subsystems": subsystems,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "0.1.0",
        }

    # ── Source Trust Registry ─────────────────────────────────────────────────

    @app.post("/v1/sources")
    async def register_source(
        body: dict,
        _token: APIToken = Depends(require_auth),
    ):
        registry = _engines.get("source_registry")
        if not registry:
            raise HTTPException(status_code=503, detail={"error": "source registry unavailable", "code": "SERVICE_UNAVAILABLE"})

        from context_firewall.source.types import SourceTrustTier
        source_id = body.get("id", "").strip()
        source_type = body.get("type", "unknown").strip()
        tier_raw = body.get("trust_tier", "untrusted")

        if not source_id:
            raise HTTPException(status_code=422, detail={"error": "id is required"})

        valid_tiers = {t.value for t in SourceTrustTier}
        if tier_raw not in valid_tiers:
            raise HTTPException(
                status_code=422,
                detail={"error": f"invalid trust_tier '{tier_raw}'", "valid": sorted(valid_tiers)},
            )

        tier = SourceTrustTier(tier_raw)
        source = await registry.register(
            source_id,
            source_type,
            tier,
            owner=body.get("owner", ""),
            region=body.get("region", ""),
            data_classification=body.get("data_classification", ""),
            config=body.get("config") or {},
        )
        return {"status": "ok", "source": source.to_dict()}

    @app.get("/v1/sources")
    async def list_sources(_token: APIToken = Depends(require_auth)):
        registry = _engines.get("source_registry")
        if not registry:
            return {"sources": []}
        sources = await registry.list_sources()
        provenance = _engines.get("provenance")
        penalties = await provenance.get_all_source_penalties() if provenance else {}
        result = []
        for s in sources:
            d = s.to_dict()
            d["enforcement_penalty"] = penalties.get(s.id)
            result.append(d)
        return {"sources": result}

    @app.get("/v1/sources/{source_id}/trust")
    async def get_source_trust(source_id: str, _token: APIToken = Depends(require_auth)):
        """Full trust health for a source: tier + live penalty score + enforcement history."""
        registry = _engines.get("source_registry")
        if not registry:
            raise HTTPException(status_code=503, detail={"error": "source registry unavailable", "code": "SERVICE_UNAVAILABLE"})
        source = await registry.get(source_id)
        if not source:
            raise HTTPException(status_code=404, detail={"error": "source not found", "code": "NOT_FOUND"})
        provenance = _engines.get("provenance")
        penalty = await provenance.get_source_penalty(source_id) if provenance else None
        return {
            "source_id": source_id,
            "trust_tier": source.trust_tier.value,
            "compliance_scope": source.compliance_scope(),
            "enforcement_penalty": penalty,
            "trust_health": "clean" if penalty is None else (
                "degraded" if penalty["penalty_score"] >= 0.5 else
                "warned" if penalty["penalty_score"] >= 0.15 else "recovering"
            ),
        }

    @app.get("/v1/sources/{source_id}")
    async def get_source(source_id: str, _token: APIToken = Depends(require_auth)):
        registry = _engines.get("source_registry")
        if not registry:
            raise HTTPException(status_code=503, detail={"error": "source registry unavailable", "code": "SERVICE_UNAVAILABLE"})
        source = await registry.get(source_id)
        if not source:
            raise HTTPException(status_code=404, detail={"error": "source not found", "code": "NOT_FOUND"})
        provenance = _engines.get("provenance")
        penalty = await provenance.get_source_penalty(source_id) if provenance else None
        d = source.to_dict()
        d["enforcement_penalty"] = penalty
        return d

    @app.patch("/v1/sources/{source_id}")
    async def update_source(
        source_id: str,
        body: dict,
        _token: APIToken = Depends(require_auth),
    ):
        registry = _engines.get("source_registry")
        if not registry:
            raise HTTPException(status_code=503, detail={"error": "source registry unavailable", "code": "SERVICE_UNAVAILABLE"})
        from context_firewall.source.types import SourceTrustTier
        tier = None
        if "trust_tier" in body:
            try:
                tier = SourceTrustTier(body["trust_tier"])
            except ValueError:
                raise HTTPException(status_code=422, detail={"error": f"invalid trust_tier '{body['trust_tier']}'"})
        updated = await registry.update(
            source_id,
            source_type=body.get("type"),
            trust_tier=tier,
            owner=body.get("owner"),
            region=body.get("region"),
            data_classification=body.get("data_classification"),
            config=body.get("config"),
        )
        if not updated:
            raise HTTPException(status_code=404, detail={"error": "source not found", "code": "NOT_FOUND"})
        return {"status": "ok", "source": updated.to_dict()}

    @app.delete("/v1/sources/{source_id}")
    async def delete_source(
        source_id: str,
        _token: APIToken = Depends(require_auth),
    ):
        registry = _engines.get("source_registry")
        if not registry:
            raise HTTPException(status_code=503, detail={"error": "source registry unavailable", "code": "SERVICE_UNAVAILABLE"})
        removed = await registry.remove(source_id)
        if not removed:
            raise HTTPException(status_code=404, detail={"error": "source not found", "code": "NOT_FOUND"})
        provenance = _engines.get("provenance")
        if provenance:
            from context_firewall.provenance.models import PolicyEnforcementEvent
            import uuid as _uuid
            await provenance.emit_policy_enforcement(PolicyEnforcementEvent(
                request_id=str(_uuid.uuid4())[:8],
                session_id="system",
                rule_name="source-removed",
                action="audit-only",
                file_path="",
                reason=f"source {source_id} soft-deleted via API",
            ))
        return {"status": "removed", "source_id": source_id}

    @app.post("/v1/filter")
    async def filter_documents(
        body: dict,
        request: Request,
        _token: APIToken = Depends(require_auth),
    ):
        """Filter raw documents through the trust + policy pipeline. Used by demo agent for web content."""
        from context_firewall.models import RankedSlice
        from context_firewall.source.types import SourceTrustTier

        registry = _engines.get("source_registry")
        policy = _engines.get("policy")
        provenance = _engines.get("provenance")

        source_id = body.get("source_id", "")
        documents = body.get("documents", [])
        session_id = body.get("session_id") or str(uuid.uuid4())
        req_id = getattr(request.state, "request_id", str(uuid.uuid4())[:8])

        tier = SourceTrustTier.UNTRUSTED
        if registry and source_id:
            tier = registry.get_trust_tier(source_id)

        candidates = []
        for i, doc in enumerate(documents):
            content = doc.get("content", "") if isinstance(doc, dict) else str(doc)
            url = doc.get("url", f"doc-{i}") if isinstance(doc, dict) else f"doc-{i}"
            candidates.append(RankedSlice(
                node_id=f"{source_id}:{i}",
                file_path=url,
                content=content,
                trust_score=0.5,
                token_count=len(content.split()),
                source_id=source_id,
                source_trust_tier=tier,
            ))

        violations = 0
        allowed = candidates
        if policy:
            allowed, violations = await policy.evaluate(candidates, req_id, session_id)

        return {
            "session_id": session_id,
            "source_id": source_id,
            "source_trust_tier": tier.value,
            "total": len(candidates),
            "allowed": len(allowed),
            "blocked": len(candidates) - len(allowed),
            "violations": violations,
            "documents": [
                {
                    "url": d.file_path,
                    "content": d.content,
                    "source_trust_tier": d.source_trust_tier.value,
                    "allowed": True,
                }
                for d in allowed
            ],
            "blocked_documents": [
                {
                    "url": c.file_path,
                    "source_trust_tier": c.source_trust_tier.value,
                    "allowed": False,
                }
                for c in candidates
                if not any(a.file_path == c.file_path for a in allowed)
            ],
        }

    # ── Compliance Export ─────────────────────────────────────────────────────

    def _make_exporter():
        from context_firewall.compliance.export import ComplianceExporter
        hmac_key = config.compliance_hmac_key or "dev-key"
        baa_mode = getattr(config, "compliance_baa_mode", False)
        return ComplianceExporter(
            db_path=config.storage.db_path,
            hmac_key=hmac_key,
            baa_mode=baa_mode,
        )

    @app.get("/v1/compliance/export/{session_id}")
    async def export_compliance_by_session(
        session_id: str,
        framework: str | None = None,
        _token: APIToken = Depends(require_auth),
    ):
        from context_firewall.compliance.export import ExportScope
        exporter = _make_exporter()
        scope = ExportScope(session_id=session_id, framework=framework)
        bundle = await asyncio.wait_for(exporter.export(scope), timeout=30)
        return bundle.to_dict()

    @app.post("/v1/compliance/export")
    async def export_compliance(
        body: dict,
        _token: APIToken = Depends(require_auth),
    ):
        from context_firewall.compliance.export import ExportScope
        exporter = _make_exporter()
        scope = ExportScope(
            session_id=body.get("session_id"),
            from_ts=body.get("from_ts"),
            to_ts=body.get("to_ts"),
            framework=body.get("framework"),
        )
        bundle = await asyncio.wait_for(exporter.export(scope), timeout=30)
        return bundle.to_dict()

    @app.get("/v1/compliance/verify/{bundle_id}")
    async def verify_compliance_bundle(
        bundle_id: str,
        _token: APIToken = Depends(require_auth),
    ):
        return {
            "bundle_id": bundle_id,
            "status": "use POST /v1/compliance/verify with full bundle body",
        }

    @app.post("/v1/compliance/verify")
    async def verify_compliance_bundle_body(
        body: dict,
        _token: APIToken = Depends(require_auth),
    ):
        from context_firewall.compliance.export import (
            ChainProof, ComplianceExportBundle, ExportScope, RetentionPolicy, TenantMetadata
        )
        exporter = _make_exporter()
        try:
            chain_proof_data = body.get("chain_proof", {})
            cp = ChainProof(**chain_proof_data)
            bundle = ComplianceExportBundle(
                bundle_id=body.get("bundle_id", ""),
                export_scope=body.get("export_scope", {}),
                provenance_entries=body.get("provenance_entries", []),
                chain_proof=cp,
                control_mappings=body.get("control_mappings", []),
                tenant_metadata=TenantMetadata(**body.get("tenant_metadata", {})),
                retention_policy=RetentionPolicy(**body.get("retention_policy", {})),
                public_key_pem=body.get("public_key_pem", ""),
                signature=body.get("signature", ""),
            )
        except Exception as e:
            raise HTTPException(status_code=422, detail={"error": f"invalid bundle: {e}"})
        ok, message = await asyncio.wait_for(exporter.verify(bundle), timeout=10)
        return {"valid": ok, "message": message, "bundle_id": bundle.bundle_id}

    @app.get("/status")
    async def status():
        return {
            "version": "0.1.0",
            "repository_root": config.repository_root,
            "engines": list(_engines.keys()),
        }

    @app.get("/analytics/retrieval")
    async def analytics_retrieval(_token: APIToken = Depends(require_auth)):
        analytics = _engines.get("analytics")
        if not analytics:
            return {"data": [], "error": "analytics engine unavailable"}
        return await asyncio.wait_for(analytics.get_retrieval_metrics(), timeout=10)

    @app.get("/analytics/entropy")
    async def analytics_entropy(_token: APIToken = Depends(require_auth)):
        analytics = _engines.get("analytics")
        if not analytics:
            return {"data": [], "error": "analytics engine unavailable"}
        return await asyncio.wait_for(analytics.get_entropy_trends(), timeout=10)

    @app.get("/analytics/trust-degradation")
    async def analytics_trust_degradation(_token: APIToken = Depends(require_auth)):
        analytics = _engines.get("analytics")
        if not analytics:
            return {"data": [], "error": "analytics engine unavailable"}
        return await asyncio.wait_for(analytics.get_trust_degradation(), timeout=10)

    @app.get("/analytics/budget-utilization")
    async def analytics_budget(_token: APIToken = Depends(require_auth)):
        analytics = _engines.get("analytics")
        if not analytics:
            return {"data": [], "error": "analytics engine unavailable"}
        return await asyncio.wait_for(analytics.get_budget_utilization(), timeout=10)

    @app.get("/analytics/injection-layers")
    async def injection_layer_breakdown(
        window_hours: int = 24,
        _token: APIToken = Depends(require_auth),
    ):
        """Breakdown of proxy injection blocks by detection layer.

        Returns counts for:
          - layer1_structural  (bidi chars, zero-width, template markers)
          - layer2_regex       (normalized pattern matching)
          - layer3_heuristic   (semantic feature scoring — catches paraphrases)
          - base_scanner       (original regex scanner: prompt_injection, PII, secrets)

        High demo value: shows what Layer 3 caught that L1+L2 missed.
        """
        provenance = _engines.get("provenance")
        if not provenance or not provenance._db:
            return {
                "window_hours": window_hours,
                "layer1_structural": 0,
                "layer2_regex": 0,
                "layer3_heuristic": 0,
                "base_scanner": 0,
                "total_injection_blocks": 0,
            }

        import re as _re
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()

        async with provenance._db.execute(
            """
            SELECT reason FROM policy_enforcement_events
            WHERE action = 'deny' AND occurred_at >= ?
            """,
            (cutoff,),
        ) as cur:
            rows = await cur.fetchall()

        _VIOLATIONS_RE = _re.compile(r"violations=\[([^\]]*)\]")
        counts: dict[str, int] = {
            "layer1_structural": 0,
            "layer2_regex": 0,
            "layer3_heuristic": 0,
            "base_scanner": 0,
        }
        _LAYER_MAP = {"structural": "layer1_structural", "regex": "layer2_regex", "heuristic": "layer3_heuristic"}
        _SCANNER_PREFIXES = ("prompt_injection", "secret_leakage:", "pii:")

        for row in rows:
            reason: str = row["reason"] or ""
            m = _VIOLATIONS_RE.search(reason)
            if not m:
                continue
            for viol in m.group(1).split(","):
                viol = viol.strip()
                if not viol or viol == "none":
                    continue
                if viol.startswith("injection_heuristic:"):
                    # format: injection_heuristic:{layer}:{signal}
                    parts = viol.split(":", 2)
                    layer_key = _LAYER_MAP.get(parts[1] if len(parts) > 1 else "", "")
                    if layer_key:
                        counts[layer_key] += 1
                elif any(viol.startswith(p) for p in _SCANNER_PREFIXES):
                    counts["base_scanner"] += 1

        total = sum(counts.values())
        return {
            "window_hours": window_hours,
            **counts,
            "total_injection_blocks": total,
        }

    # ── Lint ──────────────────────────────────────────────────────────────────

    @app.get("/v1/lint/latest")
    async def lint_latest(_token: APIToken = Depends(require_auth)):
        lint = _engines.get("lint")
        if lint is None:
            raise HTTPException(status_code=503, detail="lint engine unavailable")
        result = await lint.get_latest()
        if result is None:
            return {"ran_at": None, "findings": [], "summary": {}, "window_days": 30}
        return result

    @app.post("/v1/lint/run")
    async def lint_run(
        window_days: int = 30,
        _token: APIToken = Depends(require_scope("admin")),
    ):
        lint = _engines.get("lint")
        if lint is None:
            raise HTTPException(status_code=503, detail="lint engine unavailable")
        report = await lint.run(window_days=window_days)
        return report.as_dict()

    # ── Transparent proxy ─────────────────────────────────────────────────────

    from context_firewall.proxy.tokens import TokenStore
    from context_firewall.proxy.router import create_proxy_router

    _token_store = TokenStore(db=None)  # DB injected at startup
    proxy_router = create_proxy_router(_token_store, _engines)
    app.include_router(proxy_router)

    # ── Prometheus metrics ────────────────────────────────────────────────────

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics():
        """Prometheus text-format scrape endpoint. No auth required (ops standard)."""
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        from context_firewall import metrics as m

        # Refresh gauges from live DB state before each scrape
        provenance = _engines.get("provenance")
        if provenance:
            try:
                sessions = await provenance.list_sessions(limit=1000)
                active = sum(1 for s in sessions if s.get("status") == "active")
                m.ACTIVE_SESSIONS.set(active)
            except Exception:
                pass

        if _token_store._db is not None:
            try:
                keys = await _token_store.list_tokens()
                m.PROXY_KEYS_ACTIVE.set(len(keys))
            except Exception:
                pass

        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    @app.on_event("startup")
    async def _init_proxy_db():
        from context_firewall.db.connection import get_db
        db = await get_db()
        _token_store.set_db(db)
        logger.info("proxy token store ready")

    return app
