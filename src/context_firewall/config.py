from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SourceDeclaration(BaseModel):
    """Declarative source definition — declared in ctxfw.yaml, registered on startup."""
    id: str
    type: str = "unknown"
    trust_tier: str = "untrusted"
    owner: str = ""
    region: str = ""
    data_classification: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


class DetectionConfig(BaseModel):
    """Injection detector sensitivity knobs."""
    injection_block_threshold: float = 0.55
    injection_warn_threshold: float = 0.35
    default_source_trust_tier: str = "untrusted"


class EnforcementConfig(BaseModel):
    """Trust penalty / reward tuning."""
    penalty_increment: float = 0.15
    decay_half_life_days: float = 1.0
    reward_factor: float = 0.90


class ComplianceFrameworksConfig(BaseModel):
    """Maps data_classification keywords to compliance framework identifiers.

    Override to add custom classifications or additional frameworks.
    Keys are substrings matched against data_classification (case-insensitive).
    """
    classification_frameworks: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "phi": ["hipaa"],
            "pii": ["hipaa", "gdpr"],
            "pci": ["pci-dss"],
            "financial": ["sox", "fedramp"],
            "federal": ["fedramp"],
            "classified": ["fedramp"],
            "sensitive": ["soc2"],
            "internal_code": [],
        }
    )


def _expand_env_vars(text: str) -> str:
    """Expand ${VAR:-default} and ${VAR} patterns using os.environ."""
    def _replace(m: re.Match) -> str:
        var, _, default = m.group(1).partition(":-")
        return os.environ.get(var, default)
    return re.sub(r"\$\{([^}]+)\}", _replace, text)


class DaemonJobConfig(BaseModel):
    schedule: str
    timeout_min: int = 30


class DaemonIndexingConfig(BaseModel):
    debounce_ms: int = 2000
    max_batch_size: int = 100
    max_concurrent_refreshes: int = 2


class DaemonConfig(BaseModel):
    pid_file: str = ".ctxfw/daemon.pid"
    shutdown_timeout_sec: int = 30
    indexing: DaemonIndexingConfig = Field(default_factory=DaemonIndexingConfig)
    jobs: dict[str, DaemonJobConfig] = Field(default_factory=lambda: {
        "entropy_computation": DaemonJobConfig(schedule="0 */6 * * *", timeout_min=30),
        "weight_calibration": DaemonJobConfig(schedule="0 2 * * *", timeout_min=15),
        "provenance_compaction": DaemonJobConfig(schedule="0 3 * * *", timeout_min=60),
        "annotation_invalidation": DaemonJobConfig(schedule="0 * * * *", timeout_min=10),
        "symbol_table_refresh": DaemonJobConfig(schedule="*/15 * * * *", timeout_min=2),
        "runtime_signal_aggregation": DaemonJobConfig(schedule="*/30 * * * *", timeout_min=5),
    })


class RestApiAuthConfig(BaseModel):
    enabled: bool = True
    tokens: list[dict[str, Any]] = Field(default_factory=list)


class RestApiConfig(BaseModel):
    port: int = 8080
    read_timeout_sec: int = 30
    write_timeout_sec: int = 60
    auth: RestApiAuthConfig = Field(default_factory=RestApiAuthConfig)


class McpConfig(BaseModel):
    transport: str = "stdio"


class GraphConfig(BaseModel):
    max_depth: int = 4
    max_nodes: int = 50
    trust_cutoff: float = 0.30
    traversal_timeout_ms: int = 100


class TrustConfig(BaseModel):
    weights: dict[str, float] = Field(default_factory=lambda: {
        "structural_relevance": 0.30,
        "runtime_evidence": 0.25,
        "freshness": 0.10,
        "stability": 0.10,
        "verification": 0.10,
        "consistency": 0.05,
        "injection_risk": -0.05,
        "entropy_contribution": -0.15,
    })
    fallback_score: float = 0.50
    phase2_learning_rate: float = 0.05


class EntropyConfig(BaseModel):
    default_score: float = 0.30
    high_entropy_threshold: float = 0.60
    high_entropy_consecutive: int = 3
    staleness_penalty: float = 0.15
    analysis_cadence_hours: int = 6


class PolicyConfig(BaseModel):
    policy_dir: str = ".ctxfw/policies"
    max_file_size_kb: int = 50
    exempt_private_ips: bool = True
    cross_repo_auth_required: bool = True


class ProvenanceConfig(BaseModel):
    queue_size: int = 10_000
    session_timeout_min: int = 30
    archival_after_days: int = 90


class SynthesizerConfig(BaseModel):
    default_budget: int = 80_000
    reserve_for_summary: int = 500
    per_task_budgets: dict[str, int] = Field(default_factory=lambda: {
        "BUG_FIX": 60_000,
        "NEW_FEATURE": 80_000,
        "REFACTOR": 100_000,
        "SECURITY_REVIEW": 50_000,
        "DEPENDENCY_AUDIT": 40_000,
    })


class OtelConfig(BaseModel):
    enabled: bool = True
    grpc_port: int = 4317
    http_port: int = 4318
    queue_size: int = 10_000
    consumer_workers: int = 4
    trace_assembly_timeout_sec: int = 30
    signal_batch_flush_ms: int = 500
    signal_batch_size: int = 100
    fuzzy_threshold: float = 0.75
    latency_degraded_threshold_ms: int = 2000
    exception_rate_high_threshold: float = 0.10


class AnalyticsConfig(BaseModel):
    enabled: bool = True
    degradation_threshold: float = 0.15
    degradation_window_days: int = 30
    entropy_trend_snapshots: int = 5
    high_entropy_threshold: float = 0.60
    high_entropy_consecutive: int = 3


class StorageConfig(BaseModel):
    db_path: str = ".ctxfw/cre.db"
    object_storage_bucket: str = ""
    object_storage_prefix: str = "cre-provenance/"


class ControlPlaneConfig(BaseModel):
    """Optional connection to the ContextWall control plane.

    Leave url empty to run in fully local mode (no data leaves the host).
    The registration_token is issued from the webapp Settings page.
    """
    url: str = ""
    registration_token: str = ""
    daemon_name: str = ""
    push_interval_seconds: int = 60
    heartbeat_interval_seconds: int = 30
    policy_pull: bool = True


class Config(BaseModel):
    repository_root: str = "."
    compliance_hmac_key: str = ""
    sources: list[SourceDeclaration] = Field(default_factory=list)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    enforcement: EnforcementConfig = Field(default_factory=EnforcementConfig)
    compliance: ComplianceFrameworksConfig = Field(default_factory=ComplianceFrameworksConfig)
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    rest_api: RestApiConfig = Field(default_factory=RestApiConfig)
    mcp: McpConfig = Field(default_factory=McpConfig)
    graph: GraphConfig = Field(default_factory=GraphConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    entropy: EntropyConfig = Field(default_factory=EntropyConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    provenance: ProvenanceConfig = Field(default_factory=ProvenanceConfig)
    synthesizer: SynthesizerConfig = Field(default_factory=SynthesizerConfig)
    otel: OtelConfig = Field(default_factory=OtelConfig)
    analytics: AnalyticsConfig = Field(default_factory=AnalyticsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    control_plane: ControlPlaneConfig = Field(default_factory=ControlPlaneConfig)


def load_config(config_path: str | Path = "ctxfw.yaml") -> Config:
    path = Path(config_path)
    if not path.exists():
        return Config()
    with path.open() as f:
        content = _expand_env_vars(f.read())
    raw = yaml.safe_load(content) or {}
    return Config.model_validate(raw)
