"""SafeOpenAI - drop-in OpenAI client with CRE enforcement.

Usage::

    # Before
    import openai
    client = openai.OpenAI(api_key="sk-...")

    # After (one line change)
    from cre_sdk import SafeOpenAI
    client = SafeOpenAI(cre_key="sk-cre-...", cre_url="http://localhost:8080")

    # Same API
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )

Environment variables::

    CRE_KEY=sk-cre-...
    CRE_URL=http://localhost:8080

    from cre_sdk import SafeOpenAI
    client = SafeOpenAI()
"""

from __future__ import annotations

import os
from typing import Any

from .exceptions import CREBlockedError, CREUnavailableError, CREAuthError


def _check_cre_block(body: Any) -> None:
    if not isinstance(body, dict):
        return
    err = body.get("error", {})
    if isinstance(err, dict) and err.get("type") == "cre_policy_violation":
        raise CREBlockedError(
            blocked_reason=err.get("message", "policy violation"),
            violations=err.get("violations", []),
            raw_body=body,
        )


def _wrap_exception(exc: Exception, cre_url: str) -> None:
    try:
        import httpx
        if isinstance(exc, httpx.ConnectError):
            raise CREUnavailableError(cre_url, cause=exc) from exc
    except ImportError:
        pass

    exc_type = type(exc).__name__
    if exc_type == "AuthenticationError":
        raise CREAuthError() from exc

    if exc_type in ("BadRequestError", "APIStatusError", "APIError"):
        # OpenAI SDK stores the body differently
        body = getattr(exc, "body", None) or getattr(exc, "response", {})
        if hasattr(body, "json"):
            try:
                body = body.json()
            except Exception:
                pass
        _check_cre_block(body)


class _StreamContextWrapper:
    """Wraps an OpenAI stream context manager to catch CRE blocks on entry."""

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


class _CompletionsWrapper:
    def __init__(self, completions: Any, cre_url: str) -> None:
        self._completions = completions
        self._cre_url = cre_url

    def create(self, **kwargs: Any) -> Any:
        try:
            return self._completions.create(**kwargs)
        except Exception as exc:
            _wrap_exception(exc, self._cre_url)
            raise

    def stream(self, **kwargs: Any) -> _StreamContextWrapper:
        return _StreamContextWrapper(self._completions.stream(**kwargs), self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _AsyncCompletionsWrapper:
    def __init__(self, completions: Any, cre_url: str) -> None:
        self._completions = completions
        self._cre_url = cre_url

    async def create(self, **kwargs: Any) -> Any:
        try:
            return await self._completions.create(**kwargs)
        except Exception as exc:
            _wrap_exception(exc, self._cre_url)
            raise

    def stream(self, **kwargs: Any) -> _AsyncStreamContextWrapper:
        return _AsyncStreamContextWrapper(self._completions.stream(**kwargs), self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _ChatWrapper:
    def __init__(self, chat: Any, cre_url: str) -> None:
        self._chat = chat
        self._cre_url = cre_url

    @property
    def completions(self) -> _CompletionsWrapper:
        return _CompletionsWrapper(self._chat.completions, self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class _AsyncChatWrapper:
    def __init__(self, chat: Any, cre_url: str) -> None:
        self._chat = chat
        self._cre_url = cre_url

    @property
    def completions(self) -> _AsyncCompletionsWrapper:
        return _AsyncCompletionsWrapper(self._chat.completions, self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class SafeOpenAI:
    """Drop-in replacement for ``openai.OpenAI`` with CRE enforcement.

    Args:
        cre_key:               Your ``sk-cre-xxx`` key. Falls back to
                               ``CRE_KEY`` then ``OPENAI_API_KEY`` env vars.
        cre_url:               CRE daemon URL. Falls back to ``CRE_URL`` env var,
                               then ``http://localhost:8080``.
        **kwargs:              Passed through to ``openai.OpenAI()``.

    Raises:
        CREBlockedError:       When CRE blocks the request.
        CREUnavailableError:   When CRE cannot be reached.
        CREAuthError:          When the CRE key is rejected.
        ImportError:           If ``openai`` package is not installed.
    """

    def __init__(
        self,
        cre_key: str | None = None,
        cre_url: str | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            import openai
        except ImportError as e:
            raise ImportError(
                "openai package is required: pip install 'cre-sdk[openai]'"
            ) from e

        self._cre_url = (
            cre_url or os.environ.get("CRE_URL") or "http://localhost:8080"
        ).rstrip("/")

        key = (
            cre_key
            or os.environ.get("CRE_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        )

        self._client = openai.OpenAI(
            api_key=key,
            base_url=f"{self._cre_url}/proxy/openai/v1",
            **kwargs,
        )

    @property
    def chat(self) -> _ChatWrapper:
        return _ChatWrapper(self._client.chat, self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class AsyncSafeOpenAI:
    """Async version of SafeOpenAI. Drop-in for ``openai.AsyncOpenAI``."""

    def __init__(
        self,
        cre_key: str | None = None,
        cre_url: str | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            import openai
        except ImportError as e:
            raise ImportError(
                "openai package is required: pip install 'cre-sdk[openai]'"
            ) from e

        self._cre_url = (
            cre_url or os.environ.get("CRE_URL") or "http://localhost:8080"
        ).rstrip("/")

        key = (
            cre_key
            or os.environ.get("CRE_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        )

        self._client = openai.AsyncOpenAI(
            api_key=key,
            base_url=f"{self._cre_url}/proxy/openai/v1",
            **kwargs,
        )

    @property
    def chat(self) -> _AsyncChatWrapper:
        return _AsyncChatWrapper(self._client.chat, self._cre_url)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
