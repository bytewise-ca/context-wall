"""Shared aiosqlite connection manager."""

from __future__ import annotations

import aiosqlite

_db: aiosqlite.Connection | None = None
_db_path: str = ".ctxfw/cre.db"


async def get_db() -> aiosqlite.Connection:
    global _db
    if _db is None:
        _db = await aiosqlite.connect(_db_path)
        _db.row_factory = aiosqlite.Row
        await _db.execute("PRAGMA journal_mode=WAL")
        await _db.execute("PRAGMA foreign_keys=ON")
    return _db


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None


def configure_db_path(path: str) -> None:
    global _db_path
    _db_path = path
