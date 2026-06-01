"""Policy Engine - evaluates compiled policy rules against FileSlice candidates."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from context_firewall.config import Config
from context_firewall.models import RankedSlice, SubsystemHealth
from context_firewall.policy.detectors.injection import detect_injection, BLOCK_THRESHOLD, WARN_THRESHOLD
from context_firewall.source.types import SourceTrustTier

if TYPE_CHECKING:
    from context_firewall.provenance.engine import ProvenanceEngine

logger = logging.getLogger(__name__)

_BUILTIN_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic_api_key", re.compile(r"(?i)(api_key|apikey|api-key)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{20,}[\"']?")),
    ("generic_password", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{48}")),
]

_BUILTIN_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("phone_us", re.compile(r"\b\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")),
]

# _INJECTION_PATTERNS removed - injection detection now handled by
# context_firewall.policy.detectors.injection (multi-layer: structural + regex + heuristic)


class PolicyRule:
    def __init__(
        self,
        name: str,
        scope: str,
        detector: str,
        action: str,
        path_prefix: str = "",
        require_tag: str = "",
        reason: str = "",
        custom_patterns: list[str] | None = None,
    ) -> None:
        self.name = name
        self.scope = scope
        self.detector = detector
        self.action = action
        self.path_prefix = path_prefix
        self.require_tag = require_tag
        self.reason = reason or f"{detector} match"
        self._compiled_custom: list[re.Pattern] = [
            re.compile(p) for p in (custom_patterns or [])
        ]

    def matches(self, candidate: RankedSlice) -> tuple[bool, str, str]:
        """Return (matched, pattern_name, matched_text)."""
        if self.path_prefix and not candidate.file_path.startswith(self.path_prefix):
            return False, "", ""

        text = self._get_scope_text(candidate)
        if not text:
            return False, "", ""

        if self.detector == "secret":
            for name, pattern in _BUILTIN_SECRET_PATTERNS:
                if pattern.search(text):
                    return True, name, ""
            for pattern in self._compiled_custom:
                if pattern.search(text):
                    return True, "custom_secret", ""

        elif self.detector == "pii":
            for name, pattern in _BUILTIN_PII_PATTERNS:
                if pattern.search(text):
                    return True, name, ""

        elif self.detector == "injection":
            result = detect_injection(text)
            if result.detected:
                return True, result.signal, result.excerpt

        elif self.detector == "path_prefix":
            return bool(self.path_prefix and candidate.file_path.startswith(self.path_prefix)), "", ""

        elif self.detector == "tag" and self.require_tag:
            return self.require_tag in candidate.symbols, "", ""

        return False, "", ""

    def _get_scope_text(self, candidate: RankedSlice) -> str:
        if self.scope == "content":
            return candidate.content
        elif self.scope == "file_path":
            return candidate.file_path
        return candidate.content  # "all" scope


class CompiledPolicy:
    def __init__(self, rules: list[PolicyRule], denied_paths: list[str]) -> None:
        self.rules = rules
        self.denied_paths = denied_paths


_policy_lock = asyncio.Lock()
_compiled_policy: CompiledPolicy | None = None




def _load_default_policy() -> CompiledPolicy:
    return CompiledPolicy(
        rules=[
            PolicyRule(
                name="builtin_secrets",
                scope="content",
                detector="secret",
                action="exclude",
                reason="secret pattern detected",
            ),
            PolicyRule(
                name="builtin_pii",
                scope="content",
                detector="pii",
                action="redact",
                reason="PII pattern detected",
            ),
        ],
        denied_paths=[],
    )


def _parse_policy_dir(policy_dir: Path) -> CompiledPolicy:
    rules: list[PolicyRule] = []
    denied_paths: list[str] = []

    yaml_files = sorted(policy_dir.glob("*.yaml")) + sorted(policy_dir.glob("*.yml"))
    for yaml_file in yaml_files:
        try:
            raw = yaml.safe_load(yaml_file.read_text()) or {}
            for rule_data in raw.get("rules", []):
                rules.append(PolicyRule(
                    name=rule_data.get("name", "unnamed"),
                    scope=rule_data.get("scope", "content"),
                    detector=rule_data.get("detector", "secret"),
                    action=rule_data.get("action", "exclude"),
                    path_prefix=rule_data.get("path_prefix", ""),
                    require_tag=rule_data.get("require_tag", ""),
                    reason=rule_data.get("reason", ""),
                    custom_patterns=rule_data.get("custom_patterns", []),
                ))
            denied_paths.extend(raw.get("denied_paths", []))
        except Exception as e:
            logger.warning("Failed to load policy file", extra={"file": str(yaml_file), "error": str(e)})

    # always include builtins
    default = _load_default_policy()
    return CompiledPolicy(rules=default.rules + rules, denied_paths=denied_paths)


class PolicyEngine:
    name = "policy_engine"
    critical = False

    def __init__(self) -> None:
        self._config: Config | None = None
        self._watcher = None
        self._provenance: ProvenanceEngine | None = None
        self._dsl_cache = None  # PolicyStackCache, loaded lazily

    async def init(self, config: Config, provenance: ProvenanceEngine | None = None) -> None:
        global _compiled_policy
        self._config = config
        self._provenance = provenance

        policy_dir = Path(config.policy.policy_dir)
        async with _policy_lock:
            if policy_dir.exists():
                _compiled_policy = _parse_policy_dir(policy_dir)
            else:
                _compiled_policy = _load_default_policy()

        # Boot four-layer DSL stack cache if directory structure exists
        dsl_base = policy_dir
        if dsl_base.exists():
            from context_firewall.policy.dsl.loader import PolicyStackCache
            self._dsl_cache = PolicyStackCache(dsl_base)
            await self._dsl_cache.init()

        self._start_watcher(policy_dir)
        logger.info("PolicyEngine initialized", extra={"rules": len(_compiled_policy.rules)})

    def _start_watcher(self, policy_dir: Path) -> None:
        # DSL cache has its own watcher; only start the flat-file watcher here
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            engine = self

            class _PolicyHandler(FileSystemEventHandler):
                def on_modified(self, event):
                    if event.src_path.endswith((".yaml", ".yml")):
                        asyncio.get_event_loop().call_soon_threadsafe(
                            lambda: asyncio.ensure_future(engine._reload())
                        )

                def on_created(self, event):
                    self.on_modified(event)

            if policy_dir.exists():
                observer = Observer()
                observer.schedule(_PolicyHandler(), str(policy_dir), recursive=False)
                observer.daemon = True
                observer.start()
                self._watcher = observer
        except Exception as e:
            logger.warning("Policy file watcher failed to start", extra={"error": str(e)})

    async def _reload(self) -> None:
        global _compiled_policy
        policy_dir = Path(self._config.policy.policy_dir)
        async with _policy_lock:
            _compiled_policy = _parse_policy_dir(policy_dir)
        logger.info("Policy reloaded", extra={"rules": len(_compiled_policy.rules)})

    async def load_control_plane_rules(self, rules: list[dict]) -> None:
        """Merge control-plane rules into the active policy, replacing any previous CP rules."""
        global _compiled_policy
        async with _policy_lock:
            base = _compiled_policy or _load_default_policy()
            local_rules = [r for r in base.rules if not getattr(r, "_from_control_plane", False)]
            cp_rules: list[PolicyRule] = []
            for rule_data in rules:
                pr = PolicyRule(
                    name=rule_data.get("name", "unnamed"),
                    scope=rule_data.get("scope", "content"),
                    detector=rule_data.get("detector", "secret"),
                    action=rule_data.get("action", "block"),
                    path_prefix=rule_data.get("path_prefix", ""),
                    reason=rule_data.get("reason", ""),
                )
                pr._from_control_plane = True  # type: ignore[attr-defined]
                cp_rules.append(pr)
            _compiled_policy = CompiledPolicy(
                rules=local_rules + cp_rules,
                denied_paths=base.denied_paths,
            )
        logger.info("Control-plane rules applied: %d rules", len(cp_rules))

    def health_check(self) -> SubsystemHealth:
        return SubsystemHealth(name=self.name, healthy=_compiled_policy is not None)

    def get_active_rules(self) -> list[dict]:
        """Return serializable snapshot of currently active policy rules."""
        policy = _compiled_policy or _load_default_policy()
        rules = []
        for r in policy.rules:
            rules.append({
                "name": r.name,
                "scope": r.scope,
                "detector": r.detector,
                "action": r.action,
                "layer": "fleet",
                "reason": r.reason,
                "path_prefix": r.path_prefix or None,
                "source": "builtin" if r.name.startswith("builtin_") else "config",
                "compliance_mapping": None,
            })
        if self._dsl_cache:
            stack = self._dsl_cache.get()
            if stack:
                for r in stack.rules:
                    cm = None
                    if r.compliance_mapping:
                        cm = f"{r.compliance_mapping.framework}: {r.compliance_mapping.control_id}"
                    rules.append({
                        "name": r.name,
                        "scope": r.scope if r.scope else "content",
                        "detector": r.detector if r.detector else "dsl",
                        "action": r.action,
                        "layer": r.layer,
                        "reason": r.reason,
                        "path_prefix": r.path_prefix or None,
                        "source": "dsl",
                        "compliance_mapping": cm,
                    })
        return rules

    async def shutdown(self) -> None:
        if self._watcher:
            self._watcher.stop()
        if self._dsl_cache:
            await self._dsl_cache.shutdown()

    async def evaluate(
        self,
        candidates: list[RankedSlice],
        request_id: str,
        session_id: str,
    ) -> tuple[list[RankedSlice], int]:
        """Evaluate policy rules against candidates. Returns (filtered_list, violation_count)."""
        policy = _compiled_policy or _load_default_policy()
        block_event = asyncio.Event()
        violations = 0

        tasks = [
            self._evaluate_one(c, policy, request_id, session_id, block_event)
            for c in candidates
        ]
        results = await asyncio.gather(*tasks)

        filtered: list[RankedSlice] = []
        for include, candidate, violation in results:
            if violation:
                violations += 1
            if include and candidate is not None:
                filtered.append(candidate)

        return filtered, violations

    async def _evaluate_one(
        self,
        candidate: RankedSlice,
        policy: CompiledPolicy,
        request_id: str,
        session_id: str,
        block_event: asyncio.Event,
    ) -> tuple[bool, RankedSlice | None, bool]:
        if block_event.is_set():
            return False, None, False

        # Access control: denied path prefixes
        for denied in policy.denied_paths:
            if candidate.file_path.startswith(denied):
                return False, None, True

        # Built-in: multi-layer injection detection on untrusted/external sources
        if candidate.source_trust_tier in (SourceTrustTier.UNTRUSTED, SourceTrustTier.EXTERNAL):
            result = detect_injection(candidate.content)
            if result.confidence >= WARN_THRESHOLD:
                action = "exclude" if result.detected else "warn"
                await self._emit_injection_detection(
                    request_id, session_id, candidate, result, action,
                )
                if result.detected:
                    return False, None, True

        # DSL four-layer rules - fleet deny wins, then other layers
        if self._dsl_cache:
            stack = self._dsl_cache.get()
            if stack:
                result = await self._evaluate_dsl_stack(
                    candidate, stack, request_id, session_id, block_event
                )
                if result is not None:
                    return result

        # Flat legacy rules (backward compat)
        for rule in policy.rules:
            matched, pattern_name, _ = rule.matches(candidate)
            if not matched:
                continue

            if rule.action == "block":
                block_event.set()
                await self._emit_enforcement(request_id, session_id, rule, candidate, pattern_name)
                return False, None, True
            elif rule.action == "exclude":
                await self._emit_enforcement(request_id, session_id, rule, candidate, pattern_name)
                return False, None, True
            elif rule.action == "redact":
                await self._emit_enforcement(request_id, session_id, rule, candidate, pattern_name)
                redacted = candidate.model_copy(update={"content": "[REDACTED]"})
                return True, redacted, True

        return True, candidate, False

    async def _evaluate_dsl_stack(
        self,
        candidate: RankedSlice,
        stack,
        request_id: str,
        session_id: str,
        block_event: asyncio.Event,
    ):
        """Evaluate DSL rules in layer order with deny-wins semantics.

        Fleet deny actions are checked first and cannot be overridden by lower layers.
        Returns a result tuple or None to fall through to flat rules.
        """
        from context_firewall.policy.dsl.evaluator import evaluate
        from context_firewall.policy.dsl.types import EvalContext

        ctx = EvalContext(
            source_tier=candidate.source_trust_tier.value,
            trust_score=candidate.trust_score,
            task_scope="",
            user_role="",
            data_classification="",
            file_path=candidate.file_path,
            content=candidate.content,
        )

        # Fleet deny-wins pass: check fleet deny/exclude rules first
        for rule in stack.fleet_rules:
            if rule.action not in ("deny", "exclude", "block"):
                continue
            if not rule.applies_when.is_empty and not rule.applies_when.matches(ctx):
                continue  # AppliesWhen pre-filter
            if not evaluate(rule.condition, ctx):
                continue
            await self._emit_dsl_enforcement(request_id, session_id, rule, candidate)
            if rule.action == "block":
                block_event.set()
            return False, None, True

        # Full stack: all layers in order
        for rule in stack.rules:
            if rule.action in ("deny", "exclude", "block") and rule.layer == "fleet":
                continue  # already handled above
            if not rule.applies_when.is_empty and not rule.applies_when.matches(ctx):
                continue  # AppliesWhen pre-filter
            if not evaluate(rule.condition, ctx):
                continue

            action = rule.action
            await self._emit_dsl_enforcement(request_id, session_id, rule, candidate)

            if action in ("deny", "exclude"):
                return False, None, True
            if action == "block":
                block_event.set()
                return False, None, True
            if action == "redact":
                redacted = candidate.model_copy(update={"content": "[REDACTED]"})
                return True, redacted, True
            if action in ("warn", "audit-only"):
                continue  # log the event but allow the candidate through

        return None  # no DSL rule matched; fall through to flat rules

    async def _emit_injection_detection(
        self,
        request_id: str,
        session_id: str,
        candidate: RankedSlice,
        result,
        action: str,
    ) -> None:
        if self._provenance is None:
            return
        from context_firewall.provenance.models import PolicyEnforcementEvent
        event = PolicyEnforcementEvent(
            request_id=request_id,
            session_id=session_id,
            rule_name="injection-detector",
            action=action,
            file_path=candidate.file_path,
            node_id=candidate.node_id,
            reason=(
                f"[{result.layer}] {result.signal} "
                f"(confidence={result.confidence:.2f}, tier={candidate.source_trust_tier.value})"
            ),
            pattern_name=result.signal,
            occurred_at=datetime.now(timezone.utc),
        )
        await self._provenance.emit_policy_enforcement(event)

    async def _emit_enforcement(
        self,
        request_id: str,
        session_id: str,
        rule: PolicyRule,
        candidate: RankedSlice,
        pattern_name: str,
    ) -> None:
        if self._provenance is None:
            return
        from context_firewall.provenance.models import PolicyEnforcementEvent
        event = PolicyEnforcementEvent(
            request_id=request_id,
            session_id=session_id,
            rule_name=rule.name,
            action=rule.action,
            file_path=candidate.file_path,
            node_id=candidate.node_id,
            reason=rule.reason,
            pattern_name=pattern_name,
            occurred_at=datetime.now(timezone.utc),
        )
        await self._provenance.emit_policy_enforcement(event)

    async def _emit_dsl_enforcement(
        self,
        request_id: str,
        session_id: str,
        rule,
        candidate: RankedSlice,
    ) -> None:
        """Emit enforcement event with compliance_mapping passthrough."""
        if self._provenance is None:
            return
        from context_firewall.provenance.models import PolicyEnforcementEvent
        compliance_note = ""
        if rule.compliance_mapping:
            cm = rule.compliance_mapping
            compliance_note = f" [{cm.framework}: {cm.control_id}]"
        event = PolicyEnforcementEvent(
            request_id=request_id,
            session_id=session_id,
            rule_name=rule.name,
            action=rule.action,
            file_path=candidate.file_path,
            node_id=candidate.node_id,
            reason=f"{rule.reason}{compliance_note}",
            pattern_name=rule.layer,
            occurred_at=datetime.now(timezone.utc),
        )
        await self._provenance.emit_policy_enforcement(event)
