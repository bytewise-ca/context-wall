"""Prometheus metrics registry for the ContextWall daemon.

All metrics are module-level singletons so they accumulate across requests.
Import and call from API handlers - no threading concerns, prometheus_client
uses thread-safe internals.

Scraped at GET /metrics in Prometheus text format.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info, CollectorRegistry, REGISTRY

# ── Build info ─────────────────────────────────────────────────────────────────

BUILD_INFO = Info(
    "cre_build",
    "ContextWall daemon build information",
)
BUILD_INFO.info({"version": "0.1.0", "component": "cre-daemon"})

# ── Proxy metrics ──────────────────────────────────────────────────────────────

PROXY_REQUESTS = Counter(
    "cre_proxy_requests_total",
    "Total requests processed by the transparent LLM proxy",
    ["provider", "result"],  # result: allowed | blocked
)

PROXY_VIOLATIONS = Counter(
    "cre_proxy_violations_total",
    "Policy violations detected by the proxy scanner",
    ["violation_type"],  # prompt_injection | secret_leakage:xxx | pii:xxx
)

PROXY_DURATION = Histogram(
    "cre_proxy_request_duration_seconds",
    "End-to-end proxy request duration (including upstream LLM latency for allowed requests)",
    ["provider"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
)

# ── Pipeline metrics (analyze / bundle endpoints) ─────────────────────────────

PIPELINE_REQUESTS = Counter(
    "cre_pipeline_requests_total",
    "Requests through the context retrieval pipeline",
    ["task_type", "status"],  # status: ok | error | timeout
)

PIPELINE_DURATION = Histogram(
    "cre_pipeline_duration_seconds",
    "Context retrieval pipeline duration",
    ["task_type"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 15.0, 30.0),
)

PIPELINE_SLICES = Histogram(
    "cre_pipeline_slices_returned",
    "Number of context slices returned per pipeline request",
    ["task_type"],
    buckets=(0, 1, 2, 5, 10, 20, 50),
)

PIPELINE_TOKENS = Histogram(
    "cre_pipeline_tokens_returned",
    "Total tokens in assembled context bundle",
    ["task_type"],
    buckets=(1000, 5000, 10000, 20000, 40000, 80000, 120000),
)

# ── Policy enforcement metrics ────────────────────────────────────────────────

POLICY_ENFORCEMENTS = Counter(
    "cre_policy_enforcements_total",
    "Policy enforcement decisions",
    ["action", "rule_name"],  # action: deny | redact | warn | audit-only
)

# ── Session metrics (gauge: current state) ────────────────────────────────────

ACTIVE_SESSIONS = Gauge(
    "cre_active_sessions",
    "Number of currently open agent sessions",
)

# ── Error metrics ─────────────────────────────────────────────────────────────

ERRORS = Counter(
    "cre_errors_total",
    "Internal errors by component",
    ["component"],  # proxy | pipeline | policy | analytics
)

# ── Key management ─────────────────────────────────────────────────────────────

PROXY_KEYS_ACTIVE = Gauge(
    "cre_proxy_keys_active",
    "Number of active (non-revoked) ContextWall proxy keys",
)
