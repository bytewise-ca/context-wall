"""Source trust tier types."""

from __future__ import annotations

from enum import Enum


class SourceTrustTier(str, Enum):
    INTERNAL = "internal"      # org-owned, high trust (code repos, internal wikis)
    EXTERNAL = "external"      # third-party, medium trust (vendor docs, partner APIs)
    UNTRUSTED = "untrusted"   # public web, user input — instruction patterns blocked
    REGULATED = "regulated"   # PHI/PII in scope — HIPAA/SOC2 enforcement required
