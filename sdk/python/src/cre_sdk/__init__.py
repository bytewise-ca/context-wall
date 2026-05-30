"""CRE SDK — drop-in context firewall for Anthropic and OpenAI agents.

Quick start::

    pip install 'cre-sdk[anthropic]'

    from cre_sdk import SafeAnthropic, CREBlockedError

    client = SafeAnthropic()   # reads CRE_KEY and CRE_URL from env

    try:
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    except CREBlockedError as e:
        print(f"Blocked: {e.violations}")

Provisioning a key (admin)::

    from cre_sdk import CREClient

    cre = CREClient(api_key="...", base_url="http://localhost:8080")
    result = cre.keys.create(
        project_id="my-agent",
        upstream_key="sk-ant-...",
    )
    print(result.key)   # sk-cre-xxx  — store this securely
"""

from .exceptions import CREError, CREBlockedError, CREUnavailableError, CREAuthError
from ._anthropic import SafeAnthropic, AsyncSafeAnthropic
from ._openai import SafeOpenAI, AsyncSafeOpenAI
from .client import CREClient, AsyncCREClient, Source, ProxyKeyResult, HealthStatus, AnalyticsSummary

__version__ = "0.1.0"

__all__ = [
    # Exceptions
    "CREError",
    "CREBlockedError",
    "CREUnavailableError",
    "CREAuthError",
    # Anthropic wrappers
    "SafeAnthropic",
    "AsyncSafeAnthropic",
    # OpenAI wrappers
    "SafeOpenAI",
    "AsyncSafeOpenAI",
    # Admin client
    "CREClient",
    "AsyncCREClient",
    # Response models
    "Source",
    "ProxyKeyResult",
    "HealthStatus",
    "AnalyticsSummary",
]
