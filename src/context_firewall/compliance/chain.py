"""HMAC-SHA256 Merkle-style chain for tamper-evident provenance logs.

Tasks 8.1–8.4: hash computation, sequence counter, write-path integration,
and chain verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

CHAIN_GENESIS_HASH = "0" * 64  # sentinel for the first entry


@dataclass
class ChainEntry:
    sequence: int
    event_id: str
    payload_json: str
    prev_hash: str
    entry_hash: str


def compute_entry_hash(
    event_id: str,
    payload_json: str,
    sequence: int,
    prev_hash: str,
    hmac_key: str,
) -> str:
    """Compute HMAC-SHA256 over the canonical entry fields."""
    message = json.dumps(
        {
            "sequence": sequence,
            "event_id": event_id,
            "prev_hash": prev_hash,
            "payload": payload_json,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hmac.new(hmac_key.encode(), message, hashlib.sha256).hexdigest()


def verify_chain(entries: list[ChainEntry], hmac_key: str) -> tuple[bool, str]:
    """Verify chain integrity: no gaps, no reordering, no hash mismatches.

    Returns (ok, error_message). ok=True means chain is intact.
    """
    if not entries:
        return True, ""

    for i, entry in enumerate(entries):
        expected_seq = entries[0].sequence + i
        if entry.sequence != expected_seq:
            return False, f"sequence gap at position {i}: expected {expected_seq}, got {entry.sequence}"

        expected_prev = CHAIN_GENESIS_HASH if i == 0 else entries[i - 1].entry_hash
        if entry.prev_hash != expected_prev:
            return (
                False,
                f"prev_hash mismatch at sequence {entry.sequence}: "
                f"expected {expected_prev[:16]}…, got {entry.prev_hash[:16]}…",
            )

        recomputed = compute_entry_hash(
            entry.event_id,
            entry.payload_json,
            entry.sequence,
            entry.prev_hash,
            hmac_key,
        )
        if recomputed != entry.entry_hash:
            return (
                False,
                f"entry_hash mismatch at sequence {entry.sequence}: hash was tampered",
            )

    return True, ""
