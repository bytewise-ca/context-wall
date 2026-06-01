"""ContextWall API client for the demo agent."""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)

CRE_API_URL = os.environ.get("CRE_API_URL", "http://localhost:8080")
CRE_API_TOKEN = os.environ.get("CRE_API_TOKEN", "demo-token")

_HEADERS = {"Authorization": f"Bearer {CRE_API_TOKEN}", "Content-Type": "application/json"}


async def wait_for_cre(timeout: int = 60) -> bool:
    import asyncio
    async with httpx.AsyncClient() as client:
        for _ in range(timeout // 2):
            try:
                r = await client.get(f"{CRE_API_URL}/health", timeout=2)
                if r.status_code == 200:
                    return True
            except Exception:
                pass
            await asyncio.sleep(2)
    return False


async def register_source(source_id: str, source_type: str, trust_tier: str) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{CRE_API_URL}/v1/sources",
            json={"id": source_id, "type": source_type, "trust_tier": trust_tier},
            headers=_HEADERS,
            timeout=10,
        )
        r.raise_for_status()
        return r.json()


async def filter_documents(
    source_id: str,
    documents: list[dict],
    session_id: str,
) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{CRE_API_URL}/v1/filter",
            json={"source_id": source_id, "documents": documents, "session_id": session_id},
            headers=_HEADERS,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()


async def get_latest_provenance(limit: int = 20) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{CRE_API_URL}/provenance/latest",
            params={"limit": limit},
            headers=_HEADERS,
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
        return {"events": []}
