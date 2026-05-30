"""CRE Demo Agent — web-browsing Claude agent with context firewall."""

from __future__ import annotations

# Load .env before any module reads os.environ at import time
from dotenv import load_dotenv
load_dotenv()

import asyncio
import logging
import os
import sys
import uuid
from typing import Any

import anthropic
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from brave_search import search
from cre_client import filter_documents, get_latest_provenance, register_source, wait_for_cre
from scenarios import SCENARIOS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
BRAVE_API_KEY = os.environ.get("BRAVE_API_KEY", "")
WITH_CRE = os.environ.get("WITH_CRE", "true").lower() == "true"
SEARCH_RESULTS = int(os.environ.get("SEARCH_RESULTS", "5"))
BRAVE_SOURCE_ID = "brave-web-search"

app = FastAPI(title="CRE Demo Agent")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_claude = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)


def _check_required_env() -> None:
    if not ANTHROPIC_API_KEY:
        print("\n❌ Missing required environment variable: ANTHROPIC_API_KEY")
        print("   Copy .env.example to .env and add your Anthropic API key.\n")
        sys.exit(1)
    if not BRAVE_API_KEY:
        logger.warning(
            "BRAVE_API_KEY not set — /demo/search will return empty results. "
            "Pre-built scenarios (1/2/3) work without it."
        )


async def _ask_claude(task: str, context_docs: list[dict]) -> str:
    context_text = "\n\n---\n\n".join(
        f"Source: {d.get('url', 'unknown')}\n{d.get('content', '')}"
        for d in context_docs
    )
    message = await _claude.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Task: {task}\n\n"
                    f"Use the following retrieved documents to complete the task:\n\n"
                    f"{context_text}"
                ),
            }
        ],
    )
    return message.content[0].text


async def _run_with_cre(task: str, raw_docs: list[dict], session_id: str) -> dict:
    """Filter documents through CRE before passing to Claude."""
    filter_result = await filter_documents(BRAVE_SOURCE_ID, raw_docs, session_id)
    allowed_docs = filter_result.get("documents", [])
    blocked_count = filter_result.get("blocked", 0)

    if not allowed_docs:
        return {
            "mode": "PROTECTED",
            "session_id": session_id,
            "response": "[All retrieved documents were blocked by CRE policy. No content reached Claude.]",
            "total_docs": len(raw_docs),
            "allowed_docs": 0,
            "blocked_docs": blocked_count,
            "filter_result": filter_result,
        }

    response = await _ask_claude(task, allowed_docs)
    return {
        "mode": "PROTECTED",
        "session_id": session_id,
        "response": response,
        "total_docs": len(raw_docs),
        "allowed_docs": len(allowed_docs),
        "blocked_docs": blocked_count,
        "filter_result": filter_result,
    }


async def _run_without_cre(task: str, raw_docs: list[dict], session_id: str) -> dict:
    """Pass documents directly to Claude — unprotected."""
    response = await _ask_claude(task, raw_docs)
    return {
        "mode": "UNPROTECTED",
        "session_id": session_id,
        "response": response,
        "total_docs": len(raw_docs),
        "allowed_docs": len(raw_docs),
        "blocked_docs": 0,
        # Synthetic filter_result so the dashboard artifact feed shows documents
        # as "passed through unfiltered" rather than blank.
        "filter_result": {
            "documents": [
                {**d, "source_trust_tier": "unfiltered", "allowed": True}
                for d in raw_docs
            ],
            "blocked_documents": [],
            "allowed": len(raw_docs),
            "blocked": 0,
            "source_trust_tier": "unfiltered",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "mode": "PROTECTED" if WITH_CRE else "UNPROTECTED"}


@app.post("/demo/run-scenario/{scenario_id}")
async def run_scenario(scenario_id: int):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_id} not found. Valid: 1, 2, 3")

    scenario = SCENARIOS[scenario_id]
    session_id = str(uuid.uuid4())[:8]

    # Mix injected document in with clean documents
    all_docs = [scenario["injected_document"]] + scenario["clean_documents"]

    if WITH_CRE:
        result = await _run_with_cre(scenario["task"], all_docs, session_id)
    else:
        result = await _run_without_cre(scenario["task"], all_docs, session_id)

    return {
        "scenario": scenario_id,
        "name": scenario["name"],
        "description": scenario["description"],
        "reference": scenario["reference"],
        "task": scenario["task"],
        "injected_url": scenario["injected_document"]["url"],
        **result,
    }


@app.post("/demo/search")
async def demo_search(body: dict):
    query = body.get("query", "").strip()
    if not query:
        raise HTTPException(status_code=422, detail="query is required")

    session_id = str(uuid.uuid4())[:8]
    raw_docs = await search(query, count=SEARCH_RESULTS)

    if WITH_CRE:
        return await _run_with_cre(query, raw_docs, session_id)
    else:
        return await _run_without_cre(query, raw_docs, session_id)


@app.get("/demo/provenance")
async def demo_provenance():
    return await get_latest_provenance()


@app.get("/demo/mode")
async def demo_mode():
    return {"mode": "PROTECTED" if WITH_CRE else "UNPROTECTED", "with_cre": WITH_CRE}


@app.on_event("startup")
async def startup():
    _check_required_env()

    if WITH_CRE:
        logger.info("Waiting for CRE to be ready...")
        ready = await wait_for_cre(timeout=60)
        if not ready:
            logger.error("CRE did not become ready in time — exiting")
            sys.exit(1)

        logger.info("Registering Brave Search as untrusted source in CRE")
        await register_source(BRAVE_SOURCE_ID, "web", "untrusted")
        logger.info("CRE ready. Demo agent running in PROTECTED mode.")
    else:
        logger.info("Demo agent running in UNPROTECTED mode (WITH_CRE=false)")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
