"""DEPRECATED — ``contextwall_sdk`` is now ``context_firewall.sdk``.

As of ContextWall 0.2.0 the SDK ships inside the main ``contextwall`` package.
This top-level ``contextwall_sdk`` module is a thin deprecation shim that
re-exports everything from ``context_firewall.sdk``. It will be removed in v0.4.

Migration::

    - pip install contextwall-sdk
    + pip install "contextwall[all]"        # or [anthropic] / [openai]

    - from contextwall_sdk import SafeAnthropic
    + from context_firewall.sdk import SafeAnthropic

Nothing about the class or method contracts changed — only the import path.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "contextwall_sdk is deprecated and has moved to `context_firewall.sdk`. "
    "Install with `pip install \"contextwall[all]\"` and import from "
    "`context_firewall.sdk` instead. This shim will be removed in v0.4.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export the full public API from the new location.
from context_firewall.sdk import (  # noqa: E402
    AnalyticsSummary,
    AsyncContextWallClient,
    AsyncSafeAnthropic,
    AsyncSafeOpenAI,
    ContextWallAuthError,
    ContextWallBlockedError,
    ContextWallClient,
    ContextWallError,
    ContextWallUnavailableError,
    HealthStatus,
    ProxyKey,
    ProxyKeyResult,
    SafeAnthropic,
    SafeOpenAI,
    Source,
    __all__ as _CTXFW_SDK_ALL,
)

__all__ = list(_CTXFW_SDK_ALL)
