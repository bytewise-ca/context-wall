"""Inbound message scanner for the transparent proxy.

Runs on every message before it is forwarded to the upstream LLM.
Detects prompt injection, credential leakage, and PII patterns.
Operates entirely in-process - no external calls, no LLM inference.

Trust-tier-aware scanning:
  internal   - lightest touch; PII warn-only, disabled by default
  external   - PII enabled (warn), same injection threshold
  untrusted  - PII enabled and blocks; untrusted source exfiltration risk
  regulated  - same as untrusted; PHI/PII in requests triggers compliance block
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from context_firewall.source.types import SourceTrustTier

# ── Compiled patterns ─────────────────────────────────────────────────────────

_INJECTION_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"new\s+instructions?\s*[:：]",
        r"system\s+(prompt|override|instruction)\s*[:：]",
        r"\bact\s+as\s+(?:if\s+you\s+are|an?)\s+(?:unrestricted|jailbroken|dan\b)",
        r"\bjailbreak\b",
        r"\bdan\s+mode\b",
        r"you\s+are\s+now\s+(?:a\s+)?(?:evil|malicious|unrestricted)",
        r"pretend\s+(?:you\s+have\s+no\s+)?(?:restrictions?|guidelines?|rules?)",
        r"developer\s+mode\s*(?:enabled|on|activated)",
        r"sudo\s+(?:mode|override)",
        r"bypass\s+(?:your\s+)?(?:safety|filter|restriction|guideline)",
        r"<\s*script\s*>",
        r"\bprompt\s+injection\b",
        # Indirect injection via data payloads
        r"---\s*SYSTEM\s*---",
        r"\[\s*INST\s*\]",
        r"<\|im_start\|>system",
    ]
]

_SECRET_PATTERNS = [
    (re.compile(r"sk-(?:proj-|org-)?[a-zA-Z0-9\-]{20,}"), "OpenAI API key"),
    (re.compile(r"sk-ant-[a-zA-Z0-9\-]{20,}"), "Anthropic API key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal token"),
    (re.compile(r"ghs_[a-zA-Z0-9]{36}"), "GitHub Actions token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S{8,}", re.I), "Hardcoded password"),
    (re.compile(r"(?:secret|token|api_key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9+/\-_]{16,}['\"]", re.I), "Hardcoded secret"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key material"),
    (re.compile(r"Bearer\s+eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"), "JWT Bearer token"),
]

_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "US SSN"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), "Credit card number"),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"), "Email address"),
]


@dataclass
class ScanViolation:
    category: str
    pattern: str
    severity: str  # "block" | "warn"
    excerpt: str = ""


@dataclass
class ScanResult:
    allowed: bool
    violations: list[ScanViolation] = field(default_factory=list)
    blocked_reason: str | None = None
    source_trust_tier: str = "unknown"

    @property
    def violation_names(self) -> list[str]:
        return [v.category for v in self.violations]


def _excerpt(text: str, match: re.Match, context: int = 40) -> str:
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    snippet = text[start:end].replace("\n", " ")
    return f"...{snippet}..."


def scan_messages(
    messages: list[dict],
    *,
    scan_pii: bool = False,
    trust_tier: "SourceTrustTier | None" = None,
) -> ScanResult:
    """Scan a list of {role, content} dicts for threats.

    Returns ScanResult with allowed=False and blocked_reason set if a
    blocking violation is found.

    trust_tier drives PII enforcement:
      untrusted / regulated - PII enabled, severity=block (exfiltration / compliance risk)
      external              - PII enabled, severity=warn
      internal              - PII disabled by default (unchanged by this parameter)
      None                  - falls back to scan_pii kwarg
    """
    # Resolve tier value once
    tier_val = trust_tier.value if trust_tier is not None and hasattr(trust_tier, "value") else (
        str(trust_tier) if trust_tier is not None else "unknown"
    )

    # Tier-aware PII defaults
    pii_enabled = scan_pii
    pii_severity = "warn"
    if tier_val in ("untrusted", "regulated"):
        pii_enabled = True
        pii_severity = "block"
    elif tier_val == "external":
        pii_enabled = True
        pii_severity = "warn"

    violations: list[ScanViolation] = []

    for msg in messages:
        content = msg.get("content", "")

        # content can be a string or a list of content blocks (Anthropic format)
        texts: list[str] = []
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))
                elif isinstance(block, str):
                    texts.append(block)

        for text in texts:
            if not text:
                continue

            # Prompt injection - always block regardless of tier
            for pat in _INJECTION_PATTERNS:
                m = pat.search(text)
                if m:
                    violations.append(ScanViolation(
                        category="prompt_injection",
                        pattern=pat.pattern,
                        severity="block",
                        excerpt=_excerpt(text, m),
                    ))

            # Secret leakage - always block regardless of tier
            for pat, label in _SECRET_PATTERNS:
                m = pat.search(text)
                if m:
                    # Skip if it looks like a ContextWall key (we issue those)
                    matched = m.group(0)
                    if matched.startswith("sk-cre-"):
                        continue
                    violations.append(ScanViolation(
                        category=f"secret_leakage:{label.lower().replace(' ', '_')}",
                        pattern=label,
                        severity="block",
                        excerpt=_excerpt(text, m),
                    ))

            # PII - severity and enablement depend on source trust tier
            if pii_enabled:
                for pat, label in _PII_PATTERNS:
                    m = pat.search(text)
                    if m:
                        violations.append(ScanViolation(
                            category=f"pii:{label.lower().replace(' ', '_')}",
                            pattern=label,
                            severity=pii_severity,
                            excerpt="[redacted]",
                        ))

    blocking = [v for v in violations if v.severity == "block"]
    if blocking:
        reason = "; ".join(
            f"{v.category} detected in message content" for v in blocking[:3]
        )
        return ScanResult(
            allowed=False,
            violations=violations,
            blocked_reason=reason,
            source_trust_tier=tier_val,
        )

    return ScanResult(allowed=True, violations=violations, source_trust_tier=tier_val)


def extract_messages(body: dict, provider: str) -> list[dict]:
    """Pull message list from provider-specific request body."""
    if provider == "anthropic":
        msgs: list[dict] = []
        system = body.get("system")
        if system:
            if isinstance(system, str):
                msgs.append({"role": "system", "content": system})
            elif isinstance(system, list):
                msgs.append({"role": "system", "content": system})
        msgs.extend(body.get("messages", []))
        return msgs
    # openai
    return body.get("messages", [])
