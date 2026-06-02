"""Canonical secret and PII detection patterns.

Single source of truth used by both the policy engine (file-content scanning)
and the proxy scanner (inbound message scanning). Format: (name, compiled_pattern).
"""

import re

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key",       re.compile(r"AKIA[0-9A-Z]{16}")),
    ("anthropic_api_key",    re.compile(r"sk-ant-[a-zA-Z0-9\-]{20,}")),
    ("openai_api_key",       re.compile(r"sk-(?:proj-|org-)?[a-zA-Z0-9\-]{20,}")),
    ("github_pat",           re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("github_actions_token", re.compile(r"ghs_[a-zA-Z0-9]{36}")),
    ("google_api_key",       re.compile(r"AIza[a-zA-Z0-9\-_]{35}")),
    ("private_key",          re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt_bearer",           re.compile(r"Bearer\s+eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+")),
    ("generic_secret",       re.compile(r"(?i)(?:api_key|apikey|api-key|secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9+/\-_]{20,}['\"]?")),
    ("hardcoded_password",   re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*\S{8,}")),
]

PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email",       re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("ssn",         re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    ("phone_us",    re.compile(r"\b\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")),
]
