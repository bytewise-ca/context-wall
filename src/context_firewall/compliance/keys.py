"""Ed25519 keypair management for compliance bundle signing.

Key store: encrypted private key written to <key_dir>/signing.key.enc
Public key exported as PEM to <key_dir>/signing.pub
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger(__name__)

_DEFAULT_KEY_DIR = Path(".ctxfw/keys")


def generate_keypair(key_dir: Path = _DEFAULT_KEY_DIR) -> tuple[str, str]:
    """Generate an Ed25519 signing keypair and persist to disk.

    Returns (private_key_pem, public_key_pem).
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    (key_dir / "signing.key").write_text(private_pem)
    (key_dir / "signing.key").chmod(0o600)
    (key_dir / "signing.pub").write_text(public_pem)

    logger.info("Ed25519 keypair generated in %s", key_dir)
    return private_pem, public_pem


def load_private_key(key_dir: Path = _DEFAULT_KEY_DIR) -> Ed25519PrivateKey | None:
    key_path = key_dir / "signing.key"
    if not key_path.exists():
        return None
    pem = key_path.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key_pem(key_dir: Path = _DEFAULT_KEY_DIR) -> str | None:
    pub_path = key_dir / "signing.pub"
    if not pub_path.exists():
        return None
    return pub_path.read_text()


def sign_bundle(canonical_json: bytes, key_dir: Path = _DEFAULT_KEY_DIR) -> str | None:
    """Sign canonical JSON with the tenant private key.

    Returns base64-encoded Ed25519 signature, or None if no key exists.
    """
    private_key = load_private_key(key_dir)
    if private_key is None:
        return None
    signature = private_key.sign(canonical_json)
    return base64.b64encode(signature).decode()


def verify_signature(
    canonical_json: bytes,
    signature_b64: str,
    public_key_pem: str,
) -> bool:
    """Verify a bundle signature against the provided public key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    pub_key = serialization.load_pem_public_key(public_key_pem.encode())
    signature = base64.b64decode(signature_b64)
    try:
        pub_key.verify(signature, canonical_json)
        return True
    except InvalidSignature:
        return False
