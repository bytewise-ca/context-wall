"""Backward-compatibility helpers for the CRE→ContextWall naming migration.

Reads the new CONTEXTWALL_* env vars, falling back to the deprecated CRE_*
names with a DeprecationWarning. Introduced 2026-08 as part of the OSS rename.
Remove the fallback path in v0.3.
"""

from __future__ import annotations

import os
import warnings

# New name -> deprecated legacy name
_LEGACY_ENV: dict[str, str] = {
    "CONTEXTWALL_API_TOKEN": "CRE_API_TOKEN",
    "CONTEXTWALL_COMPLIANCE_HMAC_KEY": "CRE_COMPLIANCE_HMAC_KEY",
    "CONTEXTWALL_CONTROL_PLANE_TOKEN": "CRE_CONTROL_PLANE_TOKEN",
    "CONTEXTWALL_URL": "CRE_URL",
    "CONTEXTWALL_API_KEY": "CRE_API_KEY",
}


def getenv_with_legacy(name: str, default: str | None = None) -> str | None:
    """Read `name` from env; on miss, fall back to the deprecated CRE_* alias.

    Emits a DeprecationWarning when the legacy alias supplies the value.
    """
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
