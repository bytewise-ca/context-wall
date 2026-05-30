"""CRE SDK exceptions."""

from __future__ import annotations


class CREError(Exception):
    """Base class for all CRE SDK errors."""


class CREBlockedError(CREError):
    """Raised when CRE blocks a request due to a policy violation.

    This replaces the generic ``BadRequestError`` the underlying SDK would raise,
    giving you structured access to what was detected and why.

    Example::

        try:
            client.messages.create(...)
        except CREBlockedError as e:
            print(e.violations)      # ["prompt_injection"]
            print(e.blocked_reason)  # "prompt_injection detected in message content"
    """

    def __init__(
        self,
        blocked_reason: str,
        violations: list[str],
        raw_body: dict | None = None,
    ) -> None:
        self.blocked_reason = blocked_reason
        self.violations = violations
        self.raw_body = raw_body or {}
        super().__init__(f"CRE blocked request: {blocked_reason}")


class CREUnavailableError(CREError):
    """Raised when the CRE daemon cannot be reached and fallback is disabled."""

    def __init__(self, url: str, cause: Exception | None = None) -> None:
        self.url = url
        self.cause = cause
        super().__init__(
            f"CRE daemon unreachable at {url}. "
            "Set fallback_on_unavailable=True to fall through to the real API."
        )


class CREAuthError(CREError):
    """Raised when the CRE key is invalid or revoked."""

    def __init__(self, message: str = "Invalid or revoked CRE key") -> None:
        super().__init__(message)
