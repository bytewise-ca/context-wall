"""REST API request/response Pydantic models."""

from __future__ import annotations

from pydantic import BaseModel

DEFAULT_TRUST_CUTOFF: float = 0.30


class AnalyzeOptions(BaseModel):
    max_candidates: int = 20
    trust_cutoff: float = DEFAULT_TRUST_CUTOFF


class AnalyzeRequest(BaseModel):
    task: str
    session_id: str | None = None
    repository_root: str | None = None
    options: AnalyzeOptions = AnalyzeOptions()


class BundleOptions(BaseModel):
    token_budget: int | None = None
    trust_cutoff: float = DEFAULT_TRUST_CUTOFF
    include_summary: bool = True


class BundleRequest(BaseModel):
    task: str
    session_id: str | None = None
    repository_root: str | None = None
    options: BundleOptions = BundleOptions()


class OutcomeRequest(BaseModel):
    session_id: str
    request_id: str
    outcome_type: str
    success: bool
    score: float
    node_ids: list[str] = []
    source_id: str = ""


class APIToken(BaseModel):
    token: str
    name: str
    scopes: list[str]


class ErrorResponse(BaseModel):
    error: str
    code: str
    request_id: str = ""
