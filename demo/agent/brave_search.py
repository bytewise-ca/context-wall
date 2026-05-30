"""Brave Search API integration."""

from __future__ import annotations

import os

import httpx

BRAVE_API_KEY = os.environ.get("BRAVE_API_KEY", "")
BRAVE_API_URL = "https://api.search.brave.com/res/v1/web/search"


async def search(query: str, count: int = 5) -> list[dict]:
    if not BRAVE_API_KEY:
        return []
    headers = {"Accept": "application/json", "X-Subscription-Token": BRAVE_API_KEY}
    async with httpx.AsyncClient() as client:
        r = await client.get(
            BRAVE_API_URL,
            params={"q": query, "count": count},
            headers=headers,
            timeout=10,
        )
        r.raise_for_status()
    results = r.json().get("web", {}).get("results", [])
    return [
        {"url": item.get("url", ""), "content": item.get("description", item.get("title", ""))}
        for item in results
    ]
