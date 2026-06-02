from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class SourceDeclaration(BaseModel):
    """Declarative source definition - declared in ctxfw.yaml, registered on startup."""
    id: str
    type: str = "unknown"
    trust_tier: str = "untrusted"
    owner: str = ""
    region: str = ""
    data_classification: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


class DetectionConfig(BaseModel):
    injection_block_threshold: float = 0.75
    injection_warn_threshold: float = 0.55
    default_source_trust_tier: str = "untrusted"


class EnforcementConfig(BaseModel):
    penalty_increment: float = 0.15
    decay_half_life_days: float = 1.0
    reward_factor: float = 0.90


class ComplianceFrameworksConfig(BaseModel):
    """Maps data_classification keywords to compliance framework identifiers."""
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


class PolicyConfig(BaseModel):
    policy_dir: str = ".ctxfw/policies"
    max_file_size_kb: int = 50
    exempt_private_ips: bool = True
    cross_repo_auth_required: bool = True


class ProvenanceConfig(BaseModel):
    queue_size: int = 10_000
    session_timeout_min: int = 30
    archival_after_days: int = 90


class StorageConfig(BaseModel):
    db_path: str = ".ctxfw/cre.db"
    object_storage_bucket: str = ""
    object_storage_prefix: str = "cre-provenance/"


class DaemonConfig(BaseModel):
    pid_file: str = ".ctxfw/daemon.pid"
    shutdown_timeout_sec: int = 30


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


def _expand_env_vars(text: str) -> str:
    """Expand ${VAR:-default} and ${VAR} patterns using os.environ."""
    def _replace(m: re.Match) -> str:
        var, _, default = m.group(1).partition(":-")
        return os.environ.get(var, default)
    return re.sub(r"\$\{([^}]+)\}", _replace, text)


class Config(BaseModel):
    repository_root: str = "."
    compliance_hmac_key: str = ""
    sources: list[SourceDeclaration] = Field(default_factory=list)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    enforcement: EnforcementConfig = Field(default_factory=EnforcementConfig)
    compliance: ComplianceFrameworksConfig = Field(default_factory=ComplianceFrameworksConfig)
    rest_api: RestApiConfig = Field(default_factory=RestApiConfig)
    mcp: McpConfig = Field(default_factory=McpConfig)
    graph: GraphConfig = Field(default_factory=GraphConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    provenance: ProvenanceConfig = Field(default_factory=ProvenanceConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    control_plane: ControlPlaneConfig = Field(default_factory=ControlPlaneConfig)


def load_config(config_path: str | Path = "ctxfw.yaml") -> Config:
    path = Path(config_path)
    if not path.exists():
        return Config()
    with path.open() as f:
        content = _expand_env_vars(f.read())
    raw = yaml.safe_load(content) or {}
    return Config.model_validate(raw)
