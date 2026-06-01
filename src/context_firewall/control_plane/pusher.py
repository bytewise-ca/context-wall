"""Control plane telemetry pusher.

Runs two background loops:
  - Telemetry push:  every push_interval_seconds (default 60s)
  - Heartbeat push:  every heartbeat_interval_seconds (default 30s)

Reads Prometheus counter deltas from the in-process registry - no content,
no file paths, no prompt text ever leaves the daemon.

The pusher is entirely non-critical: if the control plane is unreachable the
daemon continues operating normally.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import httpx
from prometheus_client import REGISTRY

from context_firewall.config import ControlPlaneConfig, Config
from context_firewall.control_plane.client import ControlPlaneClient
from context_firewall.control_plane.models import (
    HeartbeatPayload,
    RegisterPayload,
    TelemetryBatch,
    TelemetryMetrics,
    ViolationEntry,
)

if TYPE_CHECKING:
    from context_firewall.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)

# Prometheus metric names we track for delta computation
_PROXY_REQUESTS   = "cre_proxy_requests"
_PROXY_VIOLATIONS = "cre_proxy_violations"
_PIPELINE_REQUESTS = "cre_pipeline_requests"
_POLICY_ENFORCEMENTS = "cre_policy_enforcements"
_ACTIVE_SESSIONS  = "cre_active_sessions"
_PROXY_DURATION   = "cre_proxy_request_duration_seconds"

HealthProvider = Callable[[], dict[str, dict[str, Any]]]


def _load_or_create_daemon_id(state_dir: str) -> str:
    """Stable daemon ID persisted across restarts."""
    path = Path(state_dir) / "daemon_id"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text().strip()
    daemon_id = f"daemon_{uuid.uuid4().hex}"
    path.write_text(daemon_id)
    return daemon_id


def _config_hash(config: Config) -> str:
    import yaml, io
    buf = io.StringIO()
    # Use only stable, non-secret fields
    relevant = {
        "detection": config.detection.model_dump(),
        "enforcement": config.enforcement.model_dump(),
        "policy": config.policy.model_dump(),
    }
    yaml.dump(relevant, buf)
    return hashlib.sha256(buf.getvalue().encode()).hexdigest()[:16]


def _collect_counter_samples() -> dict[str, dict[tuple, float]]:
    """Snapshot all tracked counter values from the Prometheus registry."""
    result: dict[str, dict[tuple, float]] = {}
    for metric_family in REGISTRY.collect():
        name = metric_family.name
        if name not in (
            _PROXY_REQUESTS, _PROXY_VIOLATIONS, _PIPELINE_REQUESTS, _POLICY_ENFORCEMENTS
        ):
            continue
        result[name] = {}
        for sample in metric_family.samples:
            if not sample.name.endswith("_total"):
                continue
            key = tuple(sorted(sample.labels.items()))
            result[name][key] = sample.value
    return result


def _collect_gauge(metric_name: str) -> float:
    for mf in REGISTRY.collect():
        if mf.name == metric_name:
            for sample in mf.samples:
                return sample.value
    return 0.0


def _collect_histogram_mean(metric_name: str) -> float | None:
    """Return mean latency in ms from a Histogram (sum/count)."""
    total_sum = 0.0
    total_count = 0.0
    found = False
    for mf in REGISTRY.collect():
        if mf.name == metric_name:
            for sample in mf.samples:
                if sample.name.endswith("_sum"):
                    total_sum += sample.value
                    found = True
                elif sample.name.endswith("_count"):
                    total_count += sample.value
    if not found or total_count == 0:
        return None
    return (total_sum / total_count) * 1000  # convert seconds → ms


def _compute_delta(
    current: dict[str, dict[tuple, float]],
    previous: dict[str, dict[tuple, float]],
) -> dict[str, dict[tuple, float]]:
    delta: dict[str, dict[tuple, float]] = {}
    for name, samples in current.items():
        delta[name] = {}
        prev_samples = previous.get(name, {})
        for key, value in samples.items():
            delta[name][key] = max(0.0, value - prev_samples.get(key, 0.0))
    return delta


def _delta_label(samples: dict[tuple, float], label_key: str) -> dict[str, float]:
    """Flatten a label dimension into name → count dict."""
    result: dict[str, float] = {}
    for key_tuple, count in samples.items():
        labels = dict(key_tuple)
        label_val = labels.get(label_key, "unknown")
        result[label_val] = result.get(label_val, 0.0) + count
    return result


class ControlPlanePusher:
    def __init__(
        self,
        cp_config: ControlPlaneConfig,
        config: Config,
        health_provider: HealthProvider | None = None,
        policy_engine: "PolicyEngine | None" = None,
    ) -> None:
        self._cp = cp_config
        self._config = config
        self._health_provider = health_provider
        self._policy_engine = policy_engine

        state_dir = str(Path(config.storage.db_path).parent)
        self._daemon_id = _load_or_create_daemon_id(state_dir)

        self._client = ControlPlaneClient(cp_config.url, cp_config.registration_token)
        self._registered = False
        self._last_samples: dict[str, dict[tuple, float]] = {}
        self._last_duration_sum = 0.0
        self._last_duration_count = 0.0
        self._tasks: list[asyncio.Task] = []
        self._local_policy_version: str = "v0"
        self._policies_url: str = ""

    @property
    def daemon_id(self) -> str:
        return self._daemon_id

    async def start(self) -> None:
        if not self._cp.url or not self._cp.registration_token:
            logger.info("Control plane not configured - running in local-only mode")
            return

        # Register (retry up to 3 times with backoff)
        for attempt in range(3):
            result = await self._client.register(self._build_register_payload())
            if result:
                self._registered = True
                if result.policies_url:
                    self._policies_url = result.policies_url
                break
            await asyncio.sleep(5 * (attempt + 1))

        if not self._registered:
            logger.warning("Could not reach control plane after 3 attempts - will retry in background")

        self._tasks = [
            asyncio.ensure_future(self._telemetry_loop()),
            asyncio.ensure_future(self._heartbeat_loop()),
        ]
        logger.info("Control plane pusher started (daemon_id=%s)", self._daemon_id)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    def _build_register_payload(self) -> RegisterPayload:
        engines = ["policy", "graph", "provenance", "proxy", "analytics", "trust"]
        return RegisterPayload(
            daemon_id=self._daemon_id,
            daemon_name=self._cp.daemon_name or self._daemon_id,
            version="0.1.0",
            engines=engines,
            config_hash=_config_hash(self._config),
        )

    async def _telemetry_loop(self) -> None:
        # Seed baseline on first tick - don't push a spike of "all counters since boot"
        self._last_samples = _collect_counter_samples()
        await asyncio.sleep(self._cp.push_interval_seconds)

        while True:
            try:
                if not self._registered:
                    result = await self._client.register(self._build_register_payload())
                    if result:
                        self._registered = True
                    else:
                        await asyncio.sleep(self._cp.push_interval_seconds)
                        continue

                await self._push_telemetry()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Telemetry loop error (non-fatal): %s", exc)
            await asyncio.sleep(self._cp.push_interval_seconds)

    async def _heartbeat_loop(self) -> None:
        await asyncio.sleep(self._cp.heartbeat_interval_seconds)
        while True:
            try:
                if self._registered:
                    new_version = await self._push_heartbeat()
                    if new_version and new_version != self._local_policy_version:
                        logger.info(
                            "Policy version changed: %s → %s - pulling new rules",
                            self._local_policy_version, new_version,
                        )
                        await self._pull_policies()
                        self._local_policy_version = new_version
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Heartbeat loop error (non-fatal): %s", exc)
            await asyncio.sleep(self._cp.heartbeat_interval_seconds)

    async def _pull_policies(self) -> None:
        if not self._policy_engine or not self._policies_url:
            return
        try:
            daemon_token = self._client._daemon_token
            if not daemon_token:
                return
            timeout = httpx.Timeout(10.0, connect=5.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(
                    self._policies_url,
                    headers={"Authorization": f"Bearer {daemon_token}"},
                )
                resp.raise_for_status()
                data = resp.json()
            rules: list[dict] = data.get("rules", [])
            await self._policy_engine.load_control_plane_rules(rules)
            logger.info("Applied %d rules from control plane", len(rules))
        except Exception as exc:
            logger.debug("Policy pull failed (non-fatal): %s", exc)

    async def _push_telemetry(self) -> None:
        now = datetime.now(timezone.utc)
        period_end = now.isoformat()
        period_start = datetime.fromtimestamp(
            now.timestamp() - self._cp.push_interval_seconds, tz=timezone.utc
        ).isoformat()

        current = _collect_counter_samples()
        delta = _compute_delta(current, self._last_samples)
        self._last_samples = current

        # Proxy request counts - split by result (allowed/blocked)
        proxy_by_result = _delta_label(delta.get(_PROXY_REQUESTS, {}), "result")
        proxy_total   = int(sum(proxy_by_result.values()))
        proxy_blocked = int(proxy_by_result.get("blocked", 0))

        # Pipeline requests
        pipeline_by_status = _delta_label(delta.get(_PIPELINE_REQUESTS, {}), "status")
        pipeline_total = int(sum(pipeline_by_status.values()))

        # Violation types from proxy scanner
        violation_by_type = _delta_label(delta.get(_PROXY_VIOLATIONS, {}), "violation_type")

        # Policy enforcement breakdown - keyed by (action, rule_name)
        policy_delta = delta.get(_POLICY_ENFORCEMENTS, {})
        policy_by_rule: dict[tuple[str, str], int] = {}
        for key_tuple, count in policy_delta.items():
            labels = dict(key_tuple)
            action    = labels.get("action", "unknown")
            rule_name = labels.get("rule_name", "unknown")
            k = (action, rule_name)
            policy_by_rule[k] = policy_by_rule.get(k, 0) + int(count)

        # Merge policy enforcements into violation entries
        # Violations from the proxy scanner take precedence; policy enforcements
        # add "other" category entries not already captured as a violation_type.
        violations: list[ViolationEntry] = []
        for vtype, count in violation_by_type.items():
            if count > 0:
                violations.append(ViolationEntry(
                    type=vtype,
                    rule="proxy_scanner",
                    action="block",
                    count=int(count),
                ))
        for (action, rule_name), count in policy_by_rule.items():
            if count > 0:
                violations.append(ViolationEntry(
                    type="policy_enforcement",
                    rule=rule_name,
                    action=action,
                    count=count,
                ))

        # Average proxy latency (from histogram)
        avg_latency_ms = _collect_histogram_mean(_PROXY_DURATION)

        # Active sessions (gauge - current value)
        active_sessions = int(_collect_gauge(_ACTIVE_SESSIONS))

        batch = TelemetryBatch(
            daemon_id=self._daemon_id,
            period_start=period_start,
            period_end=period_end,
            metrics=TelemetryMetrics(
                proxy_requests_total=proxy_total,
                proxy_blocked_total=proxy_blocked,
                violations=violations,
                active_sessions=active_sessions,
                pipeline_requests_total=pipeline_total,
                avg_proxy_latency_ms=avg_latency_ms,
            ),
        )

        ok = await self._client.push_telemetry(batch)
        if ok:
            logger.debug(
                "Telemetry pushed: requests=%d blocked=%d violations=%d",
                proxy_total, proxy_blocked, len(violations),
            )

    async def _push_heartbeat(self) -> str | None:
        subsystems: dict[str, dict[str, Any]] = {}
        if self._health_provider:
            try:
                subsystems = self._health_provider()
            except Exception:
                pass

        # Derive overall status from subsystems
        statuses = [v.get("status", "unknown") for v in subsystems.values()]
        if all(s == "healthy" for s in statuses) or not statuses:
            overall = "healthy"
        elif any(s == "down" for s in statuses):
            overall = "degraded"
        else:
            overall = "degraded"

        return await self._client.push_heartbeat(HeartbeatPayload(
            daemon_id=self._daemon_id,
            status=overall,
            subsystems=subsystems,
        ))
