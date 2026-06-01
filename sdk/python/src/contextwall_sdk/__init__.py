"""ContextWall SDK - drop-in context firewall enforcement for any LLM.

Built-in wrappers for Anthropic and OpenAI. Any OpenAI-compatible API
(Mistral, Groq, Together, Ollama, etc.) works via SafeOpenAI. For other
providers, point the SDK at the ContextWall proxy and use your provider's
client unchanged.

Quick start (Anthropic)::

    pip install 'contextwall-sdk[anthropic]'

    from contextwall_sdk import SafeAnthropic, ContextWallBlockedError

    client = SafeAnthropic(ctxfw_url="http://localhost:8080")

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    except ContextWallBlockedError as e:
        print(f"Blocked: {e.violations}")

Quick start (any OpenAI-compatible API)::

    pip install 'contextwall-sdk[openai]'

    from contextwall_sdk import SafeOpenAI

    # Works with OpenAI, Mistral, Groq, Together, Ollama, etc.
    client = SafeOpenAI(ctxfw_url="http://localhost:8080", base_url="https://api.mistral.ai/v1")

Zero-code proxy mode (any provider, no SDK changes)::

    export ANTHROPIC_BASE_URL=http://localhost:8080/proxy/anthropic
    export OPENAI_BASE_URL=http://localhost:8080/proxy/openai
    # your existing code runs unchanged
"""

from .exceptions import ContextWallError, ContextWallBlockedError, ContextWallUnavailableError, ContextWallAuthError
from ._anthropic import SafeAnthropic, AsyncSafeAnthropic
from ._openai import SafeOpenAI, AsyncSafeOpenAI
from .client import ContextWallClient, AsyncContextWallClient, Source, ProxyKeyResult, HealthStatus, AnalyticsSummary

__version__ = "0.1.0"

__all__ = [
    # Exceptions
    "ContextWallError",
    "ContextWallBlockedError",
    "ContextWallUnavailableError",
    "ContextWallAuthError",
    # Anthropic wrappers
    "SafeAnthropic",
    "AsyncSafeAnthropic",
    # OpenAI wrappers
    "SafeOpenAI",
    "AsyncSafeOpenAI",
    # Admin client
    "ContextWallClient",
    "AsyncContextWallClient",
    # Response models
    "Source",
    "ProxyKeyResult",
    "HealthStatus",
    "AnalyticsSummary",
]
