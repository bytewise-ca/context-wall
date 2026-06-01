"""ContextWallClient - admin HTTP client for the ContextWall daemon.

Used for provisioning proxy keys, registering sources, checking health,
and querying analytics/lint results.

Example::

    from contextwall_sdk import ContextWallClient

    cre = ContextWallClient(api_key="...", base_url="http://localhost:8080")

    # Provision a key for an agent
    result = cre.keys.create(
        project_id="my-agent",
        project_name="Production Agent",
        upstream_key="sk-ant-...",
        provider="anthropic",
    )
    print(result.key)  # sk-cre-xxx - save this

    # Register a web search source as untrusted
    cre.sources.register(
        id="brave-search",
        type="web_search",
        trust_tier="untrusted",
        owner="research-team",
    )

    # Trigger a lint audit
    report = cre.lint.run(window_days=30)
    print(report["summary"])
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

import httpx


# ── Response models ────────────────────────────────────────────────────────────

@dataclass
class ProxyKeyResult:
    key: str
    key_preview: str
    project_id: str
    project_name: str
    provider: str
    created_at: str
    warning: str


@dataclass
class ProxyKey:
    key_id: str
    project_id: str
    project_name: str
    provider: str
    scopes: list[str]
    created_at: str


@dataclass
class HealthStatus:
    status: Literal["healthy", "degraded", "down"]
    subsystems: dict[str, Any]
    timestamp: str
    version: str | None = None


@dataclass
class AnalyticsSummary:
    total_requests: int
    blocked_artifacts: int
    policy_violations: int
    active_sessions: int
    window_hours: int


@dataclass
class Source:
    id: str
    type: str
    trust_tier: str
    owner: str
    region: str
    data_classification: str
    registered_at: str


# ── Keys sub-client ────────────────────────────────────────────────────────────

class _KeysClient:
    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def create(
        self,
        project_id: str,
        upstream_key: str,
        project_name: str | None = None,
        provider: Literal["anthropic", "openai", "any"] = "anthropic",
        scopes: list[str] | None = None,
    ) -> ProxyKeyResult:
        resp = self._http.post(
            "/v1/keys",
            json={
                "project_id": project_id,
                "project_name": project_name or project_id,
                "upstream_key": upstream_key,
                "provider": provider,
                "scopes": scopes,
            },
        )
        resp.raise_for_status()
        d = resp.json()
        return ProxyKeyResult(**{k: v for k, v in d.items()})

    def list(self, project_id: str | None = None) -> list[ProxyKey]:
        params = {"project_id": project_id} if project_id else {}
        resp = self._http.get("/v1/keys", params=params)
        resp.raise_for_status()
        return [ProxyKey(**k) for k in resp.json().get("keys", [])]

    def revoke(self, key_prefix: str) -> bool:
        resp = self._http.delete(f"/v1/keys/{key_prefix}")
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True


class _AsyncKeysClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def create(
        self,
        project_id: str,
        upstream_key: str,
        project_name: str | None = None,
        provider: Literal["anthropic", "openai", "any"] = "anthropic",
        scopes: list[str] | None = None,
    ) -> ProxyKeyResult:
        resp = await self._http.post(
            "/v1/keys",
            json={
                "project_id": project_id,
                "project_name": project_name or project_id,
                "upstream_key": upstream_key,
                "provider": provider,
                "scopes": scopes,
            },
        )
        resp.raise_for_status()
        d = resp.json()
        return ProxyKeyResult(**{k: v for k, v in d.items()})

    async def list(self, project_id: str | None = None) -> list[ProxyKey]:
        params = {"project_id": project_id} if project_id else {}
        resp = await self._http.get("/v1/keys", params=params)
        resp.raise_for_status()
        return [ProxyKey(**k) for k in resp.json().get("keys", [])]

    async def revoke(self, key_prefix: str) -> bool:
        resp = await self._http.delete(f"/v1/keys/{key_prefix}")
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True


# ── Sources sub-client ────────────────────────────────────────────────────────

class _SourcesClient:
    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def register(
        self,
        id: str,
        type: str,
        trust_tier: Literal["internal", "external", "untrusted", "regulated"],
        owner: str = "",
        region: str = "",
        data_classification: str = "internal",
    ) -> Source:
        resp = self._http.post(
            "/v1/sources",
            json={
                "id": id,
                "type": type,
                "trust_tier": trust_tier,
                "owner": owner,
                "region": region,
                "data_classification": data_classification,
            },
        )
        resp.raise_for_status()
        return _parse_source(resp.json())

    def list(self) -> list[Source]:
        resp = self._http.get("/v1/sources")
        resp.raise_for_status()
        return [_parse_source(s) for s in resp.json().get("sources", [])]

    def get(self, source_id: str) -> Source:
        resp = self._http.get(f"/v1/sources/{source_id}")
        resp.raise_for_status()
        return _parse_source(resp.json())

    def update_tier(
        self,
        source_id: str,
        trust_tier: Literal["internal", "external", "untrusted", "regulated"],
    ) -> Source:
        resp = self._http.patch(
            f"/v1/sources/{source_id}",
            json={"trust_tier": trust_tier},
        )
        resp.raise_for_status()
        return _parse_source(resp.json())

    def delete(self, source_id: str) -> bool:
        resp = self._http.delete(f"/v1/sources/{source_id}")
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True


class _AsyncSourcesClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def register(
        self,
        id: str,
        type: str,
        trust_tier: Literal["internal", "external", "untrusted", "regulated"],
        owner: str = "",
        region: str = "",
        data_classification: str = "internal",
    ) -> Source:
        resp = await self._http.post(
            "/v1/sources",
            json={
                "id": id,
                "type": type,
                "trust_tier": trust_tier,
                "owner": owner,
                "region": region,
                "data_classification": data_classification,
            },
        )
        resp.raise_for_status()
        return _parse_source(resp.json())

    async def list(self) -> list[Source]:
        resp = await self._http.get("/v1/sources")
        resp.raise_for_status()
        return [_parse_source(s) for s in resp.json().get("sources", [])]

    async def get(self, source_id: str) -> Source:
        resp = await self._http.get(f"/v1/sources/{source_id}")
        resp.raise_for_status()
        return _parse_source(resp.json())

    async def update_tier(
        self,
        source_id: str,
        trust_tier: Literal["internal", "external", "untrusted", "regulated"],
    ) -> Source:
        resp = await self._http.patch(
            f"/v1/sources/{source_id}",
            json={"trust_tier": trust_tier},
        )
        resp.raise_for_status()
        return _parse_source(resp.json())

    async def delete(self, source_id: str) -> bool:
        resp = await self._http.delete(f"/v1/sources/{source_id}")
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True


def _parse_source(d: dict) -> Source:
    return Source(
        id=d.get("id", ""),
        type=d.get("type", ""),
        trust_tier=d.get("trust_tier", ""),
        owner=d.get("owner", ""),
        region=d.get("region", ""),
        data_classification=d.get("data_classification", ""),
        registered_at=d.get("registered_at", ""),
    )


# ── Lint sub-client ────────────────────────────────────────────────────────────

class _LintClient:
    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def latest(self) -> dict[str, Any]:
        resp = self._http.get("/v1/lint/latest")
        resp.raise_for_status()
        return resp.json()

    def run(self, window_days: int = 30) -> dict[str, Any]:
        resp = self._http.post("/v1/lint/run", params={"window_days": window_days})
        resp.raise_for_status()
        return resp.json()


class _AsyncLintClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def latest(self) -> dict[str, Any]:
        resp = await self._http.get("/v1/lint/latest")
        resp.raise_for_status()
        return resp.json()

    async def run(self, window_days: int = 30) -> dict[str, Any]:
        resp = await self._http.post("/v1/lint/run", params={"window_days": window_days})
        resp.raise_for_status()
        return resp.json()


# ── Main clients ───────────────────────────────────────────────────────────────

class ContextWallClient:
    """Synchronous admin client for the ContextWall daemon.

    Args:
        api_key:  ContextWall admin API key (set in ctxfw.yaml). Falls back to
                  ``CRE_API_KEY`` env var, then ``CRE_API_TOKEN``.
        base_url: ContextWall daemon URL. Falls back to ``CTXFW_URL`` env var,
                  then ``http://localhost:8080``.
        timeout:  Request timeout in seconds (default 30).
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        key = (
            api_key
            or os.environ.get("CRE_API_KEY")
            or os.environ.get("CRE_API_TOKEN")
            or ""
        )
        url = (
            base_url
            or os.environ.get("CRE_URL")
            or "http://localhost:8080"
        ).rstrip("/")

        self._http = httpx.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            timeout=timeout,
        )
        self.keys = _KeysClient(self._http)
        self.sources = _SourcesClient(self._http)
        self.lint = _LintClient(self._http)

    def health(self) -> HealthStatus:
        resp = self._http.get("/health")
        resp.raise_for_status()
        d = resp.json()
        return HealthStatus(
            status=d["status"],
            subsystems=d.get("subsystems", {}),
            timestamp=d.get("timestamp", ""),
            version=d.get("version"),
        )

    def analytics(self, window_hours: int = 24) -> AnalyticsSummary:
        resp = self._http.get("/analytics/summary", params={"window_hours": window_hours})
        resp.raise_for_status()
        d = resp.json()
        return AnalyticsSummary(
            total_requests=d.get("total_requests", 0),
            blocked_artifacts=d.get("blocked_artifacts", 0),
            policy_violations=d.get("policy_violations", 0),
            active_sessions=d.get("active_sessions", 0),
            window_hours=window_hours,
        )

    def proxy_health(self) -> dict:
        resp = self._http.get("/proxy/health")
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ContextWallClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncContextWallClient:
    """Async admin client for the ContextWall daemon. Same API as ContextWallClient but awaitable."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        key = (
            api_key
            or os.environ.get("CRE_API_KEY")
            or os.environ.get("CRE_API_TOKEN")
            or ""
        )
        url = (
            base_url
            or os.environ.get("CRE_URL")
            or "http://localhost:8080"
        ).rstrip("/")

        self._http = httpx.AsyncClient(
            base_url=url,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            timeout=timeout,
        )
        self.keys = _AsyncKeysClient(self._http)
        self.sources = _AsyncSourcesClient(self._http)
        self.lint = _AsyncLintClient(self._http)

    async def health(self) -> HealthStatus:
        resp = await self._http.get("/health")
        resp.raise_for_status()
        d = resp.json()
        return HealthStatus(
            status=d["status"],
            subsystems=d.get("subsystems", {}),
            timestamp=d.get("timestamp", ""),
            version=d.get("version"),
        )

    async def analytics(self, window_hours: int = 24) -> AnalyticsSummary:
        resp = await self._http.get("/analytics/summary", params={"window_hours": window_hours})
        resp.raise_for_status()
        d = resp.json()
        return AnalyticsSummary(
            total_requests=d.get("total_requests", 0),
            blocked_artifacts=d.get("blocked_artifacts", 0),
            policy_violations=d.get("policy_violations", 0),
            active_sessions=d.get("active_sessions", 0),
            window_hours=window_hours,
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncContextWallClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
