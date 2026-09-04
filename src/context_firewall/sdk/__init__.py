"""ContextWall client SDK — drop-in wrappers and admin client.

Available since v0.2.0. Ships inside the main ``contextwall`` PyPI package
(which imports as ``context_firewall`` in Python).

Install extras for the provider SDK(s) you use::

    pip install "contextwall[anthropic]"    # anthropic>=0.25
    pip install "contextwall[openai]"       # openai>=1.0
    pip install "contextwall[all]"          # both

Anthropic quickstart::

    from context_firewall.sdk import SafeAnthropic, ContextWallBlockedError

    client = SafeAnthropic(cre_key="sk-cw-...", cre_url="http://localhost:8080")

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    except ContextWallBlockedError as e:
        print(f"Blocked: {e.violations}")

OpenAI-compatible (works with OpenAI, vLLM, Ollama, LiteLLM, Mistral,
Groq, Together, etc.)::

    from context_firewall.sdk import SafeOpenAI

    client = SafeOpenAI(cre_url="http://localhost:8080",
                        base_url="https://api.mistral.ai/v1")

Zero-code proxy mode (any provider, no SDK changes)::

    export ANTHROPIC_BASE_URL=http://localhost:8080/proxy/anthropic
    export OPENAI_BASE_URL=http://localhost:8080/proxy/openai
    # your existing code runs unchanged

The legacy top-level package ``contextwall_sdk`` still works as a
deprecation shim and re-exports everything below. It will be removed in v0.4.
"""

from ._anthropic import AsyncSafeAnthropic, SafeAnthropic
from ._openai import AsyncSafeOpenAI, SafeOpenAI
from .client import (
    AnalyticsSummary,
    AsyncContextWallClient,
    ContextWallClient,
    HealthStatus,
    ProxyKey,
    ProxyKeyResult,
    Source,
)
from .exceptions import (
    ContextWallAuthError,
    ContextWallBlockedError,
    ContextWallError,
    ContextWallUnavailableError,
)

__all__ = [
    # Exceptions
    "ContextWallAuthError",
    "ContextWallBlockedError",
    "ContextWallError",
    "ContextWallUnavailableError",
    # Anthropic wrappers
    "AsyncSafeAnthropic",
    "SafeAnthropic",
    # OpenAI wrappers
    "AsyncSafeOpenAI",
    "SafeOpenAI",
    # Admin client
    "AsyncContextWallClient",
    "ContextWallClient",
    # Response models
    "AnalyticsSummary",
    "HealthStatus",
    "ProxyKey",
    "ProxyKeyResult",
    "Source",
]
