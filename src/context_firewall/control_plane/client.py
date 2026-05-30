"""HTTP client for control plane communication.

All outbound calls go here. If the control plane is unreachable the daemon
continues operating normally — the control plane is advisory, not on the
critical path.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from context_firewall.control_plane.models import (
    RegisterPayload,
    RegisterResponse,
    TelemetryBatch,
    HeartbeatPayload,
    SessionEventsPayload,
)

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class ControlPlaneClient:
    def __init__(self, base_url: str, org_token: str) -> None:
        self._base = base_url.rstrip("/")
        self._org_token = org_token
        self._daemon_token: str | None = None

    def _org_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._org_token}"}

    def _daemon_headers(self) -> dict[str, str]:
        if not self._daemon_token:
            raise RuntimeError("Not registered — call register() first")
        return {"Authorization": f"Bearer {self._daemon_token}"}

    async def register(self, payload: RegisterPayload) -> RegisterResponse | None:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{self._base}/api/v1/daemon/register",
                    headers=self._org_headers(),
                    json=payload.model_dump(),
                )
                resp.raise_for_status()
                data = resp.json()
                result = RegisterResponse(**data)
                self._daemon_token = result.daemon_token
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
            return False  # not yet registered
        except Exception as exc:
            logger.debug("Telemetry push failed (non-fatal): %s", exc)
            return False

    async def push_heartbeat(self, payload: HeartbeatPayload) -> str | None:
        """Returns new policy_version hint if one is available, else None."""
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

    async def push_events(self, payload: SessionEventsPayload) -> bool:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{self._base}/api/v1/daemon/events",
                    headers=self._daemon_headers(),
                    json=payload.model_dump(),
                )
                resp.raise_for_status()
                return True
        except RuntimeError:
            return False
        except Exception as exc:
            logger.debug("Events push failed (non-fatal): %s", exc)
            return False
