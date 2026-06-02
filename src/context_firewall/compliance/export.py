"""Compliance export bundle assembler.

Generates signed, Merkle-chained ComplianceExportBundle sliced by session ID,
time range, or framework filter.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from context_firewall.compliance.chain import (
    CHAIN_GENESIS_HASH,
    ChainEntry,
    compute_entry_hash,
    verify_chain,
)
from context_firewall.compliance.control_mappings import (
    ControlMapping,
    resolve_control_mappings,
)
from context_firewall.compliance.keys import load_public_key_pem, sign_bundle

logger = logging.getLogger(__name__)


@dataclass
class ChainProof:
    first_sequence: int
    last_sequence: int
    entry_count: int
    first_hash: str
    last_hash: str
    hmac_algorithm: str = "HMAC-SHA256"
    chain_valid: bool = True
    chain_error: str = ""


@dataclass
class TenantMetadata:
    tenant_id: str = ""
    deployment_mode: str = "self-hosted"
    baa_mode: bool = False
    export_generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cre_version: str = "0.1.0"


@dataclass
class RetentionPolicy:
    retention_days: int = 365
    baa_override_applied: bool = False
    framework: str = ""


@dataclass
class ComplianceExportBundle:
    bundle_id: str
    export_scope: dict[str, Any]
    provenance_entries: list[dict[str, Any]]
    chain_proof: ChainProof
    control_mappings: list[dict[str, Any]]
    tenant_metadata: TenantMetadata
    retention_policy: RetentionPolicy
    public_key_pem: str = ""
    signature: str = ""

    def canonical_json(self) -> bytes:
        """Deterministic JSON for signing - excludes signature field."""
        doc = {
            "bundle_id": self.bundle_id,
            "export_scope": self.export_scope,
            "chain_proof": asdict(self.chain_proof),
            "control_mappings": self.control_mappings,
            "tenant_metadata": asdict(self.tenant_metadata),
            "retention_policy": asdict(self.retention_policy),
            "entry_count": len(self.provenance_entries),
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "export_scope": self.export_scope,
            "provenance_entries": self.provenance_entries,
            "chain_proof": asdict(self.chain_proof),
            "control_mappings": self.control_mappings,
            "tenant_metadata": asdict(self.tenant_metadata),
            "retention_policy": asdict(self.retention_policy),
            "public_key_pem": self.public_key_pem,
            "signature": self.signature,
        }


@dataclass
class ExportScope:
    session_id: str | None = None
    from_ts: str | None = None
    to_ts: str | None = None
    framework: str | None = None


class ComplianceExporter:
    def __init__(
        self,
        hmac_key: str,
        baa_mode: bool = False,
        key_dir: Path | None = None,
        tenant_id: str = "",
    ) -> None:
        self._hmac_key = hmac_key
        self._baa_mode = baa_mode
        self._key_dir = key_dir or Path(".ctxfw/keys")
        self._tenant_id = tenant_id

    async def export(self, scope: ExportScope) -> ComplianceExportBundle:
        """Build and sign a ComplianceExportBundle for the given scope."""
        entries = await self._fetch_entries(scope)
        chain_entries = self._to_chain_entries(entries)
        chain_proof = self._build_chain_proof(chain_entries)

        fired_rules = self._collect_fired_rules(entries)
        control_mappings = resolve_control_mappings(fired_rules, scope.framework)

        bundle_id = str(uuid.uuid4())
        retention = self._build_retention_policy(scope.framework)
        tenant_meta = TenantMetadata(
            tenant_id=self._tenant_id,
            baa_mode=self._baa_mode,
        )

        bundle = ComplianceExportBundle(
            bundle_id=bundle_id,
            export_scope={
                "session_id": scope.session_id,
                "from_ts": scope.from_ts,
                "to_ts": scope.to_ts,
                "framework": scope.framework,
            },
            provenance_entries=entries,
            chain_proof=chain_proof,
            control_mappings=[
                {
                    "framework": cm.framework,
                    "control_id": cm.control_id,
                    "description": cm.description,
                    "satisfied": cm.satisfied,
                    "rule_name": cm.rule_name,
                }
                for cm in control_mappings
            ],
            tenant_metadata=tenant_meta,
            retention_policy=retention,
            public_key_pem=load_public_key_pem(self._key_dir) or "",
        )

        sig = sign_bundle(bundle.canonical_json(), self._key_dir)
        bundle.signature = sig or ""

        return bundle

    async def verify(self, bundle: ComplianceExportBundle) -> tuple[bool, str]:
        """Verify chain integrity and signature of a bundle."""
        chain_entries = self._to_chain_entries(bundle.provenance_entries)
        chain_ok, chain_err = verify_chain(chain_entries, self._hmac_key)
        if not chain_ok:
            return False, f"chain-integrity-violation: {chain_err}"

        if bundle.signature and bundle.public_key_pem:
            from context_firewall.compliance.keys import verify_signature
            sig_ok = verify_signature(
                bundle.canonical_json(), bundle.signature, bundle.public_key_pem
            )
            if not sig_ok:
                return False, "signature-verification-failed"

        return True, "ok"

    async def _fetch_entries(self, scope: ExportScope) -> list[dict[str, Any]]:
        query = """
            SELECT pe.event_id, pe.event_type, pe.session_id, pe.request_id,
                   pe.occurred_at, pe.payload,
                   COALESCE(pc.sequence, 0) AS sequence,
                   COALESCE(pc.prev_hash, ?) AS prev_hash,
                   COALESCE(pc.entry_hash, '') AS entry_hash
            FROM provenance_events pe
            LEFT JOIN provenance_chain pc ON pc.event_id = pe.event_id
        """
        conditions: list[str] = []
        params: list[Any] = [CHAIN_GENESIS_HASH]

        if scope.session_id:
            conditions.append("pe.session_id = ?")
            params.append(scope.session_id)
        if scope.from_ts:
            conditions.append("pe.occurred_at >= ?")
            params.append(scope.from_ts)
        if scope.to_ts:
            conditions.append("pe.occurred_at <= ?")
            params.append(scope.to_ts)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY COALESCE(pc.sequence, 0), pe.occurred_at ASC"

        try:
            from context_firewall.db.connection import get_db
            db = await get_db()
            async with db.execute(query, params) as cur:
                rows = await cur.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error("export fetch failed: %s", e)
            return []

    def _to_chain_entries(self, entries: list[dict[str, Any]]) -> list[ChainEntry]:
        return [
            ChainEntry(
                sequence=e.get("sequence", i),
                event_id=e.get("event_id", ""),
                payload_json=e.get("payload", "{}"),
                prev_hash=e.get("prev_hash", CHAIN_GENESIS_HASH),
                entry_hash=e.get("entry_hash", ""),
            )
            for i, e in enumerate(entries)
        ]

    def _build_chain_proof(self, entries: list[ChainEntry]) -> ChainProof:
        if not entries:
            return ChainProof(
                first_sequence=0, last_sequence=0, entry_count=0,
                first_hash=CHAIN_GENESIS_HASH, last_hash=CHAIN_GENESIS_HASH,
            )
        ok, err = verify_chain(entries, self._hmac_key)
        return ChainProof(
            first_sequence=entries[0].sequence,
            last_sequence=entries[-1].sequence,
            entry_count=len(entries),
            first_hash=entries[0].entry_hash or CHAIN_GENESIS_HASH,
            last_hash=entries[-1].entry_hash or CHAIN_GENESIS_HASH,
            chain_valid=ok,
            chain_error=err,
        )

    def _collect_fired_rules(self, entries: list[dict[str, Any]]) -> set[str]:
        fired: set[str] = set()
        for entry in entries:
            try:
                payload = json.loads(entry.get("payload", "{}"))
                rule_name = payload.get("rule_name", "")
                if rule_name:
                    fired.add(rule_name)
            except (json.JSONDecodeError, TypeError):
                pass
        return fired

    def _build_retention_policy(self, framework: str | None) -> RetentionPolicy:
        from context_firewall.compliance.baa import BAA_MIN_RETENTION_DAYS, enforce_baa_retention
        base_days = 365
        if framework in ("hipaa", "fedramp"):
            base_days = 2190  # 6 years
        elif framework == "soc2":
            base_days = 365  # 1 year typical
        if self._baa_mode:
            effective, overridden = enforce_baa_retention(base_days)
            return RetentionPolicy(
                retention_days=effective,
                baa_override_applied=overridden,
                framework=framework or "",
            )
        return RetentionPolicy(retention_days=base_days, framework=framework or "")
