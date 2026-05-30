"""BAA (Business Associate Agreement) mode — PHI/PII redaction and retention enforcement.

Tasks 8.10–8.11.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# BAA minimum retention: 6 years = 2190 days (45 CFR 164.530(j))
BAA_MIN_RETENTION_DAYS = 2190

_REDACTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED-EMAIL]"),
    # MRN: varies by system; common patterns
    ("mrn", re.compile(r"\bMRN[:\s#]*\d{5,10}\b", re.IGNORECASE), "[REDACTED-MRN]"),
    # Date of birth
    ("dob", re.compile(r"\bDOB[:\s]*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b", re.IGNORECASE), "[REDACTED-DOB]"),
    # Phone numbers (US format)
    ("phone", re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b"), "[REDACTED-PHONE]"),
]


def redact_phi(text: str) -> tuple[str, list[str]]:
    """Redact PHI/PII patterns from text before provenance write.

    Returns (redacted_text, list_of_pattern_names_that_fired).
    """
    fired: list[str] = []
    result = text
    for name, pattern, replacement in _REDACTION_PATTERNS:
        new_result, count = pattern.subn(replacement, result)
        if count > 0:
            fired.append(name)
            result = new_result
    return result, fired


def enforce_baa_retention(configured_days: int) -> tuple[int, bool]:
    """Override retention below the 6-year BAA minimum.

    Returns (effective_days, was_overridden). Emits warning if overridden.
    """
    if configured_days < BAA_MIN_RETENTION_DAYS:
        logger.warning(
            "baa-retention-override: configured retention %d days is below BAA minimum %d days; "
            "overriding to %d days",
            configured_days,
            BAA_MIN_RETENTION_DAYS,
            BAA_MIN_RETENTION_DAYS,
        )
        return BAA_MIN_RETENTION_DAYS, True
    return configured_days, False
