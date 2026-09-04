"""Backward-compatibility helpers for the CRE→ContextWall SDK rename.

Reads new CONTEXTWALL_* env vars, falling back to the deprecated CRE_* names.
Emits a DeprecationWarning on the fallback path. Remove in v0.3.
"""

from __future__ import annotations

import os
import warnings

_LEGACY_ENV: dict[str, str] = {
    "CONTEXTWALL_URL": "CRE_URL",
    "CONTEXTWALL_API_KEY": "CRE_API_KEY",
    "CONTEXTWALL_API_TOKEN": "CRE_API_TOKEN",
    "CONTEXTWALL_KEY": "CRE_KEY",
}

_POLICY_VIOLATION_TYPES = frozenset({"contextwall_policy_violation", "cre_policy_violation"})


def getenv_with_legacy(name: str, default: str | None = None) -> str | None:
    """Read `name` from env; fall back to the deprecated CRE_* alias with a warning."""
    val = os.environ.get(name)
    if val is not None:
        return val
    legacy = _LEGACY_ENV.get(name)
    if legacy:
        legacy_val = os.environ.get(legacy)
        if legacy_val is not None:
            warnings.warn(
                f"{legacy} is deprecated; use {name} instead. "
                "Support for the legacy name will be removed in v0.3.",
                DeprecationWarning,
                stacklevel=2,
            )
            return legacy_val
    return default


def is_policy_violation_type(t: str | None) -> bool:
    """Return True if an error `type` value indicates a ContextWall block.

    Accepts both the current `contextwall_policy_violation` and the legacy
    `cre_policy_violation` so a new SDK works against an old daemon and vice-versa.
    """
    return t in _POLICY_VIOLATION_TYPES
