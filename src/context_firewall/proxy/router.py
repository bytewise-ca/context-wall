"""Transparent LLM proxy router.

Endpoints:
  POST /proxy/anthropic/v1/messages          - Anthropic Messages API
  POST /proxy/openai/v1/chat/completions     - OpenAI Chat Completions API
  POST /v1/keys                              - provision a new ContextWall proxy key
  GET  /v1/keys                              - list proxy keys (masked)
  DELETE /v1/keys/{key_prefix}              - revoke a proxy key

Usage (developer side):
  export ANTHROPIC_BASE_URL=http://localhost:8080/proxy/anthropic
  export ANTHROPIC_API_KEY=sk-cre-<your-cre-key>
  # That's it - every anthropic SDK call now flows through ContextWall.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import StreamingResponse

from context_firewall.proxy.scanner import ScanResult, ScanViolation, extract_messages, scan_messages
from context_firewall.proxy.tokens import TokenStore

logger = logging.getLogger(__name__)

ANTHROPIC_BASE = "https://api.anthropic.com"
OPENAI_BASE = "https://api.openai.com"
ANTHROPIC_VERSION = "2023-06-01"

# Hop-by-hop headers we must strip before forwarding
_HOP_BY_HOP = frozenset([
    "host", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding",
    "upgrade", "content-length",
])


def _forward_headers(request: Request, upstream_key: str, provider: str) -> dict[str, str]:
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    # Replace auth with real upstream key
    if provider == "anthropic":
        headers["x-api-key"] = upstream_key
        headers.pop("authorization", None)
        # Ensure required Anthropic headers
        if "anthropic-version" not in headers:
            headers["anthropic-version"] = ANTHROPIC_VERSION
    else:
        headers["authorization"] = f"Bearer {upstream_key}"
    return headers


async def _emit_proxy_event(
    provenance: Any,
    session_id: str,
    request_id: str,
    scan: ScanResult,
    provider: str,
    project_name: str,
    source_trust_tier: str = "unknown",
    source_id: str = "",
) -> None:
    from context_firewall import metrics as m

    result = "allowed" if scan.allowed else "blocked"
    m.PROXY_REQUESTS.labels(provider=provider, result=result).inc()
    for v in scan.violations:
        m.PROXY_VIOLATIONS.labels(violation_type=v.category).inc()
    if not scan.allowed:
        m.POLICY_ENFORCEMENTS.labels(action="deny", rule_name="proxy_scanner").inc()

    if not provenance:
        return
    try:
        from context_firewall.provenance.models import PolicyEnforcementEvent
        action = "audit-only" if scan.allowed else "deny"
        violations_str = ", ".join(scan.violation_names) if scan.violations else "none"
        await provenance.emit_policy_enforcement(PolicyEnforcementEvent(
            request_id=request_id,
            session_id=session_id,
            rule_name="proxy_request",
            action=action,
            file_path="",
            source_id=source_id,
            reason=f"provider={provider} project={project_name} tier={source_trust_tier} violations=[{violations_str}]",
            occurred_at=datetime.now(timezone.utc),
        ))
    except Exception:
        logger.debug("failed to emit proxy provenance event", exc_info=True)


def _lookup_source_tier(engines: dict[str, Any], project_id: str) -> Any:
    """O(1) trust tier lookup from the source registry in-memory cache.

    Uses project_id as the source ID (the simulator and SDK both register
    sources with the same ID they pass as project_id). Falls back to UNTRUSTED
    for unregistered projects so enforcement is conservative by default.
    """
    from context_firewall.source.types import SourceTrustTier
    registry = engines.get("source_registry")
    if registry is None:
        return SourceTrustTier.UNTRUSTED
    return registry.get_trust_tier(project_id)


def _apply_heuristic_scan(
    scan: ScanResult,
    messages: list[dict],
    trust_tier: Any,
) -> ScanResult:
    """Run the multi-layer injection detector on top of the base regex scan.

    Only fires for non-internal tiers and only when the base scan allowed
    the request - if regex already blocked, skip to avoid redundant work.

    The policy detector adds three layers the regex scanner misses:
      Layer 1 - structural: bidi chars, zero-width, spaced-letter obfuscation
      Layer 2 - normalized regex: patterns applied to de-obfuscated text
      Layer 3 - heuristic: semantic paraphrase scoring without LLM inference

    New violations are merged into the result. Any heuristic blocking violation
    flips allowed=False.
    """
    from context_firewall.source.types import SourceTrustTier

    if trust_tier == SourceTrustTier.INTERNAL:
        return scan  # internal sources are trusted; skip extra scan
    if not scan.allowed:
        return scan  # already blocked by regex; no need to continue

    try:
        from context_firewall.policy.detectors.injection import (
            detect_injection, BLOCK_THRESHOLD, WARN_THRESHOLD,
        )
    except ImportError:
        return scan

    extra: list[ScanViolation] = []
    for msg in messages:
        content = msg.get("content", "")
        texts: list[str] = []
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))

        for text in texts:
            if not text:
                continue
            result = detect_injection(text)
            if result.confidence >= WARN_THRESHOLD:
                # Only emit heuristic violations the regex layer didn't already catch.
                # Category naming makes them distinguishable in the dashboard.
                severity = "block" if result.confidence >= BLOCK_THRESHOLD else "warn"
                extra.append(ScanViolation(
                    category=f"injection_heuristic:{result.layer}:{result.signal}",
                    pattern=result.layer,
                    severity=severity,
                    excerpt=result.excerpt,
                ))

    if not extra:
        return scan

    merged = scan.violations + extra
    new_blocking = [v for v in extra if v.severity == "block"]
    if new_blocking:
        reason = "; ".join(f"{v.category} detected" for v in new_blocking[:3])
        return ScanResult(
            allowed=False,
            violations=merged,
            blocked_reason=reason,
            source_trust_tier=scan.source_trust_tier,
        )
    return ScanResult(
        allowed=True,
        violations=merged,
        blocked_reason=None,
        source_trust_tier=scan.source_trust_tier,
    )


def create_proxy_router(token_store: TokenStore, engines: dict[str, Any]) -> APIRouter:
    router = APIRouter()

    # ── Key management ─────────────────────────────────────────────────────────

    @router.post("/v1/keys", status_code=201)
    async def create_key(
        body: dict,
        authorization: str = Header(alias="Authorization", default=""),
    ):
        """Provision a new ContextWall proxy key for a project.

        Body:
          project_id    (str, required)
          project_name  (str, optional)
          upstream_key  (str, required) - real Anthropic/OpenAI key
          provider      (str, optional) - "anthropic" | "openai" | "any"
          scopes        (list[str], optional)

        Returns the raw key ONCE. Store it - it cannot be retrieved again.
        """
        project_id = (body.get("project_id") or "").strip()
        upstream_key = (body.get("upstream_key") or "").strip()
        if not project_id:
            raise HTTPException(status_code=422, detail={"error": "project_id is required"})
        if not upstream_key:
            raise HTTPException(status_code=422, detail={"error": "upstream_key is required"})

        raw, token = await token_store.create(
            project_id=project_id,
            project_name=body.get("project_name", project_id),
            upstream_key=upstream_key,
            provider=body.get("provider", "any"),
            scopes=body.get("scopes"),
        )
        return {
            "key": raw,
            "key_preview": raw[:12] + "..." + raw[-4:],
            "project_id": token.project_id,
            "project_name": token.project_name,
            "provider": token.provider,
            "created_at": token.created_at.isoformat(),
            "warning": "Store this key now - it will not be shown again.",
        }

    @router.get("/v1/keys")
    async def list_keys(project_id: str | None = None):
        return {"keys": await token_store.list_tokens(project_id=project_id)}

    @router.delete("/v1/keys/{key_prefix}", status_code=200)
    async def revoke_key(key_prefix: str):
        revoked = await token_store.revoke(key_prefix)
        if not revoked:
            raise HTTPException(status_code=404, detail={"error": "key not found or already revoked"})
        return {"status": "revoked", "key_prefix": key_prefix}

    # ── Proxy helpers ──────────────────────────────────────────────────────────

    async def _resolve_token(authorization: str) -> Any:
        """Look up and return the ProxyToken, or raise 401."""
        bearer = authorization.removeprefix("Bearer ").strip()
        if not bearer:
            # Also check x-api-key header pattern used by Anthropic SDK
            raise HTTPException(
                status_code=401,
                detail={"error": "missing Authorization header", "code": "UNAUTHORIZED"},
            )
        token = await token_store.lookup(bearer)
        if not token:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid or revoked ContextWall key", "code": "UNAUTHORIZED"},
            )
        return token

    async def _resolve_token_from_request(request: Request) -> Any:
        """Try Authorization header, then x-api-key (Anthropic SDK pattern)."""
        auth = request.headers.get("authorization", "")
        if not auth:
            xkey = request.headers.get("x-api-key", "")
            if xkey:
                auth = f"Bearer {xkey}"
        if not auth:
            raise HTTPException(
                status_code=401,
                detail={"error": "missing Authorization or x-api-key header", "code": "UNAUTHORIZED"},
            )
        bearer = auth.removeprefix("Bearer ").strip()
        token = await token_store.lookup(bearer)
        if not token:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid or revoked ContextWall key", "code": "UNAUTHORIZED"},
            )
        return token

    def _block_response(scan: ScanResult, provider: str) -> dict:
        """Build a provider-shaped block response so the SDK gets something parseable."""
        if provider == "anthropic":
            return {
                "type": "error",
                "error": {
                    "type": "cre_policy_violation",
                    "message": f"ContextWall blocked: {scan.blocked_reason}",
                    "violations": scan.violation_names,
                },
            }
        # openai shape
        return {
            "error": {
                "message": f"ContextWall blocked: {scan.blocked_reason}",
                "type": "cre_policy_violation",
                "code": "content_policy_violation",
                "violations": scan.violation_names,
            }
        }

    async def _stream_proxy(
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict,
        body: bytes,
    ):
        """Async generator that streams response bytes from upstream."""
        async with client.stream(method, url, content=body, headers=headers) as resp:
            yield resp.status_code, dict(resp.headers)
            async for chunk in resp.aiter_bytes():
                yield chunk

    # ── Anthropic proxy ────────────────────────────────────────────────────────

    @router.post("/proxy/anthropic/v1/messages")
    @router.post("/proxy/anthropic/v1/messages/")
    async def proxy_anthropic(request: Request):
        token = await _resolve_token_from_request(request)
        raw_body = await request.body()

        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail={"error": "invalid JSON body"})

        # Trust-tier-aware scan: look up source tier from registry, then scan
        tier = _lookup_source_tier(engines, token.project_id)
        messages = extract_messages(body, "anthropic")
        scan = scan_messages(messages, trust_tier=tier)
        # Multi-layer heuristic detector for non-internal, non-blocked requests
        scan = _apply_heuristic_scan(scan, messages, tier)

        request_id = str(uuid.uuid4())
        session_id = body.get("metadata", {}).get("user_id", f"proxy-{request_id[:8]}")
        provenance = engines.get("provenance")
        await _emit_proxy_event(
            provenance, session_id, request_id, scan,
            "anthropic", token.project_name, scan.source_trust_tier,
            source_id=token.project_id,
        )

        if not scan.allowed:
            logger.warning(
                "proxy:anthropic blocked",
                extra={"project": token.project_name, "reason": scan.blocked_reason},
            )
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=400,
                content=_block_response(scan, "anthropic"),
                headers={"x-cre-blocked": "true", "x-cre-reason": scan.blocked_reason or "policy"},
            )

        upstream_url = f"{ANTHROPIC_BASE}/v1/messages"
        fwd_headers = _forward_headers(request, token.upstream_key, "anthropic")
        is_streaming = body.get("stream", False)

        logger.info(
            "proxy:anthropic forward",
            extra={"project": token.project_name, "stream": is_streaming},
        )

        from context_firewall import metrics as m
        t0 = time.perf_counter()

        if is_streaming:
            async def stream_gen():
                async with httpx.AsyncClient(timeout=120) as client:
                    async with client.stream(
                        "POST", upstream_url,
                        content=raw_body,
                        headers=fwd_headers,
                    ) as resp:
                        async for chunk in resp.aiter_bytes():
                            yield chunk
                m.PROXY_DURATION.labels(provider="anthropic").observe(time.perf_counter() - t0)

            return StreamingResponse(
                stream_gen(),
                media_type="text/event-stream",
                headers={
                    "x-cre-proxied": "true",
                    "x-cre-project": token.project_name,
                    "cache-control": "no-cache",
                },
            )
        else:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(upstream_url, content=raw_body, headers=fwd_headers)
            m.PROXY_DURATION.labels(provider="anthropic").observe(time.perf_counter() - t0)
            from fastapi.responses import Response
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                media_type=resp.headers.get("content-type", "application/json"),
                headers={
                    "x-cre-proxied": "true",
                    "x-cre-project": token.project_name,
                },
            )

    # ── OpenAI proxy ───────────────────────────────────────────────────────────

    @router.post("/proxy/openai/v1/chat/completions")
    @router.post("/proxy/openai/v1/chat/completions/")
    async def proxy_openai(request: Request):
        token = await _resolve_token_from_request(request)
        raw_body = await request.body()

        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail={"error": "invalid JSON body"})

        tier = _lookup_source_tier(engines, token.project_id)
        messages = extract_messages(body, "openai")
        scan = scan_messages(messages, trust_tier=tier)
        scan = _apply_heuristic_scan(scan, messages, tier)

        request_id = str(uuid.uuid4())
        session_id = body.get("user", f"proxy-{request_id[:8]}")
        provenance = engines.get("provenance")
        await _emit_proxy_event(
            provenance, session_id, request_id, scan,
            "openai", token.project_name, scan.source_trust_tier,
            source_id=token.project_id,
        )

        if not scan.allowed:
            logger.warning(
                "proxy:openai blocked",
                extra={"project": token.project_name, "reason": scan.blocked_reason},
            )
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=400,
                content=_block_response(scan, "openai"),
                headers={"x-cre-blocked": "true", "x-cre-reason": scan.blocked_reason or "policy"},
            )

        upstream_url = f"{OPENAI_BASE}/v1/chat/completions"
        fwd_headers = _forward_headers(request, token.upstream_key, "openai")
        is_streaming = body.get("stream", False)

        logger.info(
            "proxy:openai forward",
            extra={"project": token.project_name, "stream": is_streaming},
        )

        from context_firewall import metrics as m
        t0 = time.perf_counter()

        if is_streaming:
            async def stream_gen():
                async with httpx.AsyncClient(timeout=120) as client:
                    async with client.stream(
                        "POST", upstream_url,
                        content=raw_body,
                        headers=fwd_headers,
                    ) as resp:
                        async for chunk in resp.aiter_bytes():
                            yield chunk
                m.PROXY_DURATION.labels(provider="openai").observe(time.perf_counter() - t0)

            return StreamingResponse(
                stream_gen(),
                media_type="text/event-stream",
                headers={
                    "x-cre-proxied": "true",
                    "x-cre-project": token.project_name,
                    "cache-control": "no-cache",
                },
            )
        else:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(upstream_url, content=raw_body, headers=fwd_headers)
            m.PROXY_DURATION.labels(provider="openai").observe(time.perf_counter() - t0)
            from fastapi.responses import Response
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                media_type=resp.headers.get("content-type", "application/json"),
                headers={
                    "x-cre-proxied": "true",
                    "x-cre-project": token.project_name,
                },
            )

    # ── Proxy health ───────────────────────────────────────────────────────────

    @router.get("/proxy/health")
    async def proxy_health():
        return {
            "proxy": "ok",
            "providers": ["anthropic", "openai"],
            "endpoints": [
                "POST /proxy/anthropic/v1/messages",
                "POST /proxy/openai/v1/chat/completions",
            ],
            "setup": {
                "anthropic": "export ANTHROPIC_BASE_URL=http://<cre-host>/proxy/anthropic",
                "openai": "export OPENAI_BASE_URL=http://<cre-host>/proxy/openai",
                "key": "Use your sk-cre-xxx key as ANTHROPIC_API_KEY / OPENAI_API_KEY",
            },
        }

    return router
