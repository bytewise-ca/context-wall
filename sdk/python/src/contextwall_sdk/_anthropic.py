"""SafeAnthropic - drop-in Anthropic client with CRE enforcement.

Usage::

    # Before
    import anthropic
    client = anthropic.Anthropic(api_key="sk-ant-...")

    # After (one line change, everything else identical)
    from contextwall_sdk import SafeAnthropic
    client = SafeAnthropic(cre_key="sk-cre-...", cre_url="http://localhost:8080")

    # Same API
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}],
    )

Environment variables (no code changes needed)::

    CRE_KEY=sk-cre-...
    CRE_URL=http://localhost:8080

    from contextwall_sdk import SafeAnthropic
    client = SafeAnthropic()  # reads from env
"""

from __future__ import annotations

import os
from typing import Any, Iterator, AsyncIterator

from .exceptions import ContextWallBlockedError, ContextWallUnavailableError, ContextWallAuthError


def _check_cre_block(body: Any) -> None:
    """Raise ContextWallBlockedError if the response body is a CRE policy violation."""
    if not isinstance(body, dict):
        return
    err = body.get("error", {})
    if isinstance(err, dict) and err.get("type") == "cre_policy_violation":
        raise ContextWallBlockedError(
            blocked_reason=err.get("message", "policy violation"),
            violations=err.get("violations", []),
            raw_body=body,
        )


def _wrap_exception(exc: Exception, cre_url: str) -> None:
    """Convert underlying SDK exceptions into CRE-specific ones where applicable."""
    try:
        import httpx
        if isinstance(exc, httpx.ConnectError):
            raise ContextWallUnavailableError(cre_url, cause=exc) from exc
    except ImportError:
        pass

    # Anthropic SDK exception inspection
    exc_type = type(exc).__name__
    if exc_type in ("AuthenticationError",):
        raise ContextWallAuthError() from exc

    if exc_type in ("BadRequestError", "APIStatusError"):
        body = getattr(exc, "body", None)
        _check_cre_block(body)


class _StreamContextWrapper:
    """Wraps an Anthropic stream context manager to catch CRE blocks on entry."""

    def __init__(self, stream_cm: Any, cre_url: str) -> None:
        self._cm = stream_cm
        self._cre_url = cre_url

    def __enter__(self) -> Any:
        try:
            return self._cm.__enter__()
        except Exception as exc:
            _wrap_exception(exc, self._cre_url)
            raise

    def __exit__(self, *args: Any) -> Any:
        return self._cm.__exit__(*args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cm, name)


class _AsyncStreamContextWrapper:
    def __init__(self, stream_cm: Any, cre_url: str) -> None:
        self._cm = stream_cm
        self._cre_url = cre_url

    async def __aenter__(self) -> Any:
        try:
            return await self._cm.__aenter__()
        except Exception as exc:
            _wrap_exception(exc, self._cre_url)
            raise

    async def __aexit__(self, *args: Any) -> Any:
        return await self._cm.__aexit__(*args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cm, name)


class _MessagesWrapper:
    """Wraps anthropic.resources.Messages to surface CRE-specific errors."""

    def __init__(self, messages: Any, cre_url: str, fallback: bool) -> None:
        self._messages = messages
        self._cre_url = cre_url
        self._fallback = fallback

    def create(self, **kwargs: Any) -> Any:
        try:
            return self._messages.create(**kwargs)
        except Exception as exc:
            _wrap_exception(exc, self._cre_url)
            raise

    def stream(self, **kwargs: Any) -> _StreamContextWrapper:
        # stream() returns a context manager; errors from CRE surface on __enter__
        return _StreamContextWrapper(self._messages.stream(**kwargs), self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)


class _AsyncMessagesWrapper:
    def __init__(self, messages: Any, cre_url: str, fallback: bool) -> None:
        self._messages = messages
        self._cre_url = cre_url
        self._fallback = fallback

    async def create(self, **kwargs: Any) -> Any:
        try:
            return await self._messages.create(**kwargs)
        except Exception as exc:
            _wrap_exception(exc, self._cre_url)
            raise

    def stream(self, **kwargs: Any) -> _AsyncStreamContextWrapper:
        return _AsyncStreamContextWrapper(self._messages.stream(**kwargs), self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)


class SafeAnthropic:
    """Drop-in replacement for ``anthropic.Anthropic`` with CRE enforcement.

    Args:
        cre_key:               Your ``sk-cre-xxx`` key. Falls back to
                               ``CRE_KEY`` then ``ANTHROPIC_API_KEY`` env vars.
        cre_url:               CRE daemon URL. Falls back to ``CRE_URL`` env var,
                               then ``http://localhost:8080``.
        fallback_on_unavailable: If True and CRE is unreachable, raises
                               ``ContextWallUnavailableError`` (default False = fail fast).
        **kwargs:              Passed through to ``anthropic.Anthropic()``.

    Raises:
        ContextWallBlockedError:       When ContextWall blocks the request (policy violation).
        ContextWallUnavailableError:   When ContextWall cannot be reached (and fallback is off).
        ContextWallAuthError:          When the ContextWall key is rejected.
        ImportError:           If ``anthropic`` package is not installed.
    """

    def __init__(
        self,
        cre_key: str | None = None,
        cre_url: str | None = None,
        fallback_on_unavailable: bool = False,
        **kwargs: Any,
    ) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise ImportError(
                "anthropic package is required: pip install 'contextwall-sdk[anthropic]'"
            ) from e

        self._cre_url = (
            cre_url or os.environ.get("CRE_URL") or "http://localhost:8080"
        ).rstrip("/")
        self._fallback = fallback_on_unavailable

        key = (
            cre_key
            or os.environ.get("CRE_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or ""
        )

        self._client = anthropic.Anthropic(
            api_key=key,
            base_url=f"{self._cre_url}/proxy/anthropic",
            **kwargs,
        )

    @property
    def messages(self) -> _MessagesWrapper:
        return _MessagesWrapper(self._client.messages, self._cre_url, self._fallback)

    @property
    def beta(self) -> Any:
        return self._client.beta

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class AsyncSafeAnthropic:
    """Async version of SafeAnthropic. Drop-in for ``anthropic.AsyncAnthropic``.

    Example::

        client = AsyncSafeAnthropic()
        response = await client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(
        self,
        cre_key: str | None = None,
        cre_url: str | None = None,
        fallback_on_unavailable: bool = False,
        **kwargs: Any,
    ) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise ImportError(
                "anthropic package is required: pip install 'contextwall-sdk[anthropic]'"
            ) from e

        self._cre_url = (
            cre_url or os.environ.get("CRE_URL") or "http://localhost:8080"
        ).rstrip("/")
        self._fallback = fallback_on_unavailable

        key = (
            cre_key
            or os.environ.get("CRE_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or ""
        )

        self._client = anthropic.AsyncAnthropic(
            api_key=key,
            base_url=f"{self._cre_url}/proxy/anthropic",
            **kwargs,
        )

    @property
    def messages(self) -> _AsyncMessagesWrapper:
        return _AsyncMessagesWrapper(self._client.messages, self._cre_url, self._fallback)

    @property
    def beta(self) -> Any:
        return self._client.beta

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
