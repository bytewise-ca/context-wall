"""CRE proxy token management.

CRE issues its own tokens (sk-cre-xxx) that map to real upstream API keys.
Developers point ANTHROPIC_BASE_URL / OPENAI_BASE_URL at CRE and never
handle the real provider key directly.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
from datetime import datetime, timezone
from typing import Literal

import aiosqlite
from pydantic import BaseModel

ALPHABET = string.ascii_letters + string.digits
_PREFIX = "sk-cre-"


def _generate_raw() -> str:
    return _PREFIX + "".join(secrets.choice(ALPHABET) for _ in range(40))


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class ProxyToken(BaseModel):
    key_id: str
    project_id: str
    project_name: str
    provider: Literal["anthropic", "openai", "any"]
    upstream_key: str
    scopes: list[str]
    created_at: datetime
    revoked: bool = False

    def masked(self) -> str:
        return self.key_id[:12] + "..." + self.key_id[-4:]


class TokenStore:
    """SQLite-backed store for CRE proxy tokens."""

    def __init__(self, db: aiosqlite.Connection | None = None) -> None:
        self._db: aiosqlite.Connection | None = db

    def set_db(self, db: aiosqlite.Connection) -> None:
        self._db = db

    def _require_db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("TokenStore not initialized — DB not set")
        return self._db

    async def create(
        self,
        project_id: str,
        project_name: str,
        upstream_key: str,
        provider: str = "any",
        scopes: list[str] | None = None,
    ) -> tuple[str, "ProxyToken"]:
        """Returns (raw_key, token_record). raw_key is shown once — caller must store it."""
        import json
        db = self._require_db()
        raw = _generate_raw()
        key_hash = _hash_key(raw)
        now = datetime.now(timezone.utc)
        token = ProxyToken(
            key_id=raw,
            project_id=project_id,
            project_name=project_name,
            provider=provider,  # type: ignore[arg-type]
            upstream_key=upstream_key,
            scopes=scopes or ["proxy"],
            created_at=now,
        )
        await db.execute(
            """
            INSERT INTO proxy_tokens
              (key_id, key_hash, project_id, project_name, provider, upstream_key, scopes, created_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (raw, key_hash, project_id, project_name, provider, upstream_key,
             json.dumps(token.scopes), now.isoformat()),
        )
        await db.commit()
        return raw, token

    async def lookup(self, raw_key: str) -> "ProxyToken | None":
        """Authenticate a raw CRE key. Returns None if invalid or revoked."""
        import json
        db = self._require_db()
        key_hash = _hash_key(raw_key)
        async with db.execute(
            "SELECT * FROM proxy_tokens WHERE key_hash = ? AND revoked = 0",
            (key_hash,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return ProxyToken(
            key_id=row["key_id"],
            project_id=row["project_id"],
            project_name=row["project_name"],
            provider=row["provider"],
            upstream_key=row["upstream_key"],
            scopes=json.loads(row["scopes"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            revoked=bool(row["revoked"]),
        )

    async def list_tokens(self, project_id: str | None = None) -> list[dict]:
        import json
        db = self._require_db()
        query = "SELECT * FROM proxy_tokens WHERE revoked = 0"
        params: tuple = ()
        if project_id:
            query += " AND project_id = ?"
            params = (project_id,)
        query += " ORDER BY created_at DESC"
        async with db.execute(query, params) as cur:
            rows = await cur.fetchall()
        return [
            {
                "key_id": r["key_id"][:12] + "..." + r["key_id"][-4:],
                "project_id": r["project_id"],
                "project_name": r["project_name"],
                "provider": r["provider"],
                "scopes": json.loads(r["scopes"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    async def revoke(self, key_prefix: str) -> bool:
        """Revoke by key_id prefix (first 12 chars). Returns True if found."""
        db = self._require_db()
        async with db.execute(
            "SELECT key_id FROM proxy_tokens WHERE key_id LIKE ? AND revoked = 0",
            (key_prefix + "%",),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return False
        await db.execute(
            "UPDATE proxy_tokens SET revoked = 1 WHERE key_id = ?",
            (row["key_id"],),
        )
        await db.commit()
        return True
