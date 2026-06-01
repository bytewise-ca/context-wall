"""Policy DSL - four-layer stack loader.

Layers: fleet → org → team → repo  (deny-wins: fleet deny cannot be overridden).
Stack is computed at daemon startup; invalidated and recomputed within 5s on any
policy file change under the watched directories.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

import yaml

from context_firewall.policy.dsl.evaluator import parse_rule, validate_policy_file
from context_firewall.policy.dsl.types import DSLPolicyRule

logger = logging.getLogger(__name__)

# Ordered from highest to lowest priority
LAYER_NAMES = ("fleet", "org", "team", "repo")


class PolicyStack:
    """Resolved multi-layer policy stack with deny-wins semantics."""

    def __init__(self, layers: dict[str, list[DSLPolicyRule]]) -> None:
        self._layers = layers
        # Flat ordered list: fleet first, then org, team, repo
        self.rules: list[DSLPolicyRule] = []
        for layer in LAYER_NAMES:
            self.rules.extend(layers.get(layer, []))

    @property
    def fleet_rules(self) -> list[DSLPolicyRule]:
        return self._layers.get("fleet", [])

    def total_rules(self) -> int:
        return len(self.rules)


def _load_layer(layer_dir: Path, layer_name: str) -> list[DSLPolicyRule]:
    if not layer_dir.exists():
        return []
    rules: list[DSLPolicyRule] = []
    for yaml_file in sorted(layer_dir.glob("*.yaml")) + sorted(layer_dir.glob("*.yml")):
        try:
            raw: dict[str, Any] = yaml.safe_load(yaml_file.read_text()) or {}
            for rule_raw in raw.get("rules", []):
                rules.append(parse_rule(rule_raw, layer=layer_name))
        except Exception as e:
            logger.warning("Failed to load %s layer file %s: %s", layer_name, yaml_file, e)
    return rules


def build_stack(base_dir: Path) -> PolicyStack:
    """Load all four layers from base_dir/{fleet,org,team,repo}/."""
    layers: dict[str, list[DSLPolicyRule]] = {}
    for layer in LAYER_NAMES:
        layers[layer] = _load_layer(base_dir / layer, layer)
    logger.info(
        "policy stack built: fleet=%d org=%d team=%d repo=%d",
        len(layers["fleet"]), len(layers["org"]),
        len(layers["team"]), len(layers["repo"]),
    )
    return PolicyStack(layers)


class PolicyStackCache:
    """Thread-safe cache with file-watch invalidation.

    Recomputes stack within 5s of any file change in the watched directories.
    """

    DEBOUNCE_SECS = 4.5  # recompute no more than once per ~5s window

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._stack: PolicyStack | None = None
        self._lock = asyncio.Lock()
        self._dirty = False
        self._last_build: float = 0.0
        self._watcher = None
        self._reloader_task: asyncio.Task | None = None

    async def init(self) -> None:
        async with self._lock:
            self._stack = build_stack(self._base_dir)
            self._last_build = time.monotonic()
        self._start_watcher()
        self._reloader_task = asyncio.create_task(self._reloader_loop())

    def get(self) -> PolicyStack | None:
        return self._stack

    def mark_dirty(self) -> None:
        self._dirty = True

    async def _reloader_loop(self) -> None:
        """Poll dirty flag every second, rebuild if dirty and debounce elapsed."""
        while True:
            try:
                await asyncio.sleep(1)
                if self._dirty and (time.monotonic() - self._last_build) >= self.DEBOUNCE_SECS:
                    async with self._lock:
                        self._stack = build_stack(self._base_dir)
                        self._last_build = time.monotonic()
                        self._dirty = False
                    logger.info("policy stack recomputed from file change")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("policy stack reload error: %s", e)

    def _start_watcher(self) -> None:
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            cache = self

            class _Handler(FileSystemEventHandler):
                def on_modified(self, event):
                    if event.src_path.endswith((".yaml", ".yml")):
                        cache.mark_dirty()

                def on_created(self, event):
                    self.on_modified(event)

                def on_deleted(self, event):
                    self.on_modified(event)

            if self._base_dir.exists():
                observer = Observer()
                observer.schedule(_Handler(), str(self._base_dir), recursive=True)
                observer.daemon = True
                observer.start()
                self._watcher = observer
                logger.info("policy stack file watcher started on %s", self._base_dir)
        except Exception as e:
            logger.warning("policy stack watcher failed to start: %s", e)

    async def shutdown(self) -> None:
        if self._reloader_task:
            self._reloader_task.cancel()
        if self._watcher:
            self._watcher.stop()
