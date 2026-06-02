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
from pydantic import BaseModel

from context_firewall.config import ControlPlaneConfig, Config

if TYPE_CHECKING:
    from context_firewall.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wire models - shapes that cross the network boundary (counts/scores, never content)
# ---------------------------------------------------------------------------

class ViolationEntry(BaseModel):
    type: str
    rule: str = ""
    action: str = ""
    count: int = 0


class TelemetryMetrics(BaseModel):
    proxy_requests_total: int = 0
    proxy_blocked_total: int = 0
    violations: list[ViolationEntry] = []
    active_sessions: int = 0
    pipeline_requests_total: int = 0
    avg_proxy_latency_ms: float | None = None


class TelemetryBatch(BaseModel):
    daemon_id: str
    period_start: str
    period_end: str
    metrics: TelemetryMetrics


class HeartbeatPayload(BaseModel):
    daemon_id: str
    status: str
    subsystems: dict[str, dict[str, Any]] = {}


class RegisterPayload(BaseModel):
    daemon_id: str
    daemon_name: str
    version: str = ""
    engines: list[str] = []
    config_hash: str = ""
    capabilities: list[str] = ["telemetry_push", "policy_pull"]


class RegisterResponse(BaseModel):
    daemon_token: str
    policy_version: str = "v0"
    push_url: str = ""
    heartbeat_url: str = ""
    events_url: str = ""
    policies_url: str = ""


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class _ControlPlaneClient:
    def __init__(self, base_url: str, org_token: str) -> None:
        self._base = base_url.rstrip("/")
        self._org_token = org_token
        self.daemon_token: str | None = None

    def _org_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._org_token}"}

    def _daemon_headers(self) -> dict[str, str]:
        if not self.daemon_token:
            raise RuntimeError("Not registered - call register() first")
        return {"Authorization": f"Bearer {self.daemon_token}"}

    async def register(self, payload: RegisterPayload) -> RegisterResponse | None:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{self._base}/api/v1/daemon/register",
                    headers=self._org_headers(),
                    json=payload.model_dump(),
                )
                resp.raise_for_status()
                result = RegisterResponse(**resp.json())
                self.daemon_token = result.daemon_token
                logger.info("Registered with control plane, policy_version=%s", result.policy_version)
                return result
        except Exception as exc:
            logger.warning("Control plane registration failed (non-fatal): %s", exc)
            return None

    async def push_telemetry(self, batch: TelemetryBatch) -> bool:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{self._base}/api/v1/daemon/telemetry",
                    headers=self._daemon_headers(),
                    json=batch.model_dump(),
                )
                resp.raise_for_status()
                return True
        except RuntimeError:
            return False
        except Exception as exc:
            logger.debug("Telemetry push failed (non-fatal): %s", exc)
            return False

    async def push_heartbeat(self, payload: HeartbeatPayload) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{self._base}/api/v1/daemon/heartbeat",
                    headers=self._daemon_headers(),
                    json=payload.model_dump(),
                )
                resp.raise_for_status()
                return resp.json().get("policy_version")
        except RuntimeError:
            return None
        except Exception as exc:
            logger.debug("Heartbeat push failed (non-fatal): %s", exc)
            return None


# ---------------------------------------------------------------------------
# Prometheus helpers
# ---------------------------------------------------------------------------

_PROXY_REQUESTS      = "cre_proxy_requests"
_PROXY_VIOLATIONS    = "cre_proxy_violations"
_PIPELINE_REQUESTS   = "cre_pipeline_requests"
_POLICY_ENFORCEMENTS = "cre_policy_enforcements"
_ACTIVE_SESSIONS     = "cre_active_sessions"
_PROXY_DURATION      = "cre_proxy_request_duration_seconds"

HealthProvider = Callable[[], dict[str, dict[str, Any]]]


def _load_or_create_daemon_id(state_dir: str) -> str:
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
    yaml.dump({
        "detection": config.detection.model_dump(),
        "enforcement": config.enforcement.model_dump(),
        "policy": config.policy.model_dump(),
    }, buf)
    return hashlib.sha256(buf.getvalue().encode()).hexdigest()[:16]


def _collect_counter_samples() -> dict[str, dict[tuple, float]]:
    result: dict[str, dict[tuple, float]] = {}
    for mf in REGISTRY.collect():
        if mf.name not in (_PROXY_REQUESTS, _PROXY_VIOLATIONS, _PIPELINE_REQUESTS, _POLICY_ENFORCEMENTS):
            continue
        result[mf.name] = {}
        for sample in mf.samples:
            if not sample.name.endswith("_total"):
                continue
            result[mf.name][tuple(sorted(sample.labels.items()))] = sample.value
    return result


def _collect_gauge(metric_name: str) -> float:
    for mf in REGISTRY.collect():
        if mf.name == metric_name:
            for sample in mf.samples:
                return sample.value
    return 0.0


def _collect_histogram_mean(metric_name: str) -> float | None:
    total_sum = total_count = 0.0
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
    return (total_sum / total_count) * 1000


def _compute_delta(
    current: dict[str, dict[tuple, float]],
    previous: dict[str, dict[tuple, float]],
) -> dict[str, dict[tuple, float]]:
    return {
        name: {k: max(0.0, v - previous.get(name, {}).get(k, 0.0)) for k, v in samples.items()}
        for name, samples in current.items()
    }


def _delta_label(samples: dict[tuple, float], label_key: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for key_tuple, count in samples.items():
        label_val = dict(key_tuple).get(label_key, "unknown")
        result[label_val] = result.get(label_val, 0.0) + count
    return result


# ---------------------------------------------------------------------------
# Pusher
# ---------------------------------------------------------------------------

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
        self._client = _ControlPlaneClient(cp_config.url, cp_config.registration_token)
        self._registered = False
        self._last_samples: dict[str, dict[tuple, float]] = {}
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
        return RegisterPayload(
            daemon_id=self._daemon_id,
            daemon_name=self._cp.daemon_name or self._daemon_id,
            version="0.1.0",
            engines=["policy", "graph", "provenance", "proxy", "analytics", "trust"],
            config_hash=_config_hash(self._config),
        )

    async def _telemetry_loop(self) -> None:
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
        if not self._policy_engine or not self._policies_url or not self._client.daemon_token:
            return
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    self._policies_url,
                    headers={"Authorization": f"Bearer {self._client.daemon_token}"},
                )
                resp.raise_for_status()
                rules: list[dict] = resp.json().get("rules", [])
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

        proxy_by_result = _delta_label(delta.get(_PROXY_REQUESTS, {}), "result")
        proxy_total   = int(sum(proxy_by_result.values()))
        proxy_blocked = int(proxy_by_result.get("blocked", 0))

        pipeline_total = int(sum(_delta_label(delta.get(_PIPELINE_REQUESTS, {}), "status").values()))

        violation_by_type = _delta_label(delta.get(_PROXY_VIOLATIONS, {}), "violation_type")
        policy_delta = delta.get(_POLICY_ENFORCEMENTS, {})

        violations: list[ViolationEntry] = [
            ViolationEntry(type=vtype, rule="proxy_scanner", action="block", count=int(count))
            for vtype, count in violation_by_type.items() if count > 0
        ]
        policy_by_rule: dict[tuple[str, str], int] = {}
        for key_tuple, count in policy_delta.items():
            labels = dict(key_tuple)
            k = (labels.get("action", "unknown"), labels.get("rule_name", "unknown"))
            policy_by_rule[k] = policy_by_rule.get(k, 0) + int(count)
        violations += [
            ViolationEntry(type="policy_enforcement", rule=rule_name, action=action, count=count)
            for (action, rule_name), count in policy_by_rule.items() if count > 0
        ]

        batch = TelemetryBatch(
            daemon_id=self._daemon_id,
            period_start=period_start,
            period_end=period_end,
            metrics=TelemetryMetrics(
                proxy_requests_total=proxy_total,
                proxy_blocked_total=proxy_blocked,
                violations=violations,
                active_sessions=int(_collect_gauge(_ACTIVE_SESSIONS)),
                pipeline_requests_total=pipeline_total,
                avg_proxy_latency_ms=_collect_histogram_mean(_PROXY_DURATION),
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

        statuses = [v.get("status", "unknown") for v in subsystems.values()]
        overall = "healthy" if (all(s == "healthy" for s in statuses) or not statuses) else "degraded"

        return await self._client.push_heartbeat(HeartbeatPayload(
            daemon_id=self._daemon_id,
            status=overall,
            subsystems=subsystems,
        ))
