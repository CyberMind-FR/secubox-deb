# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Async SQLite (WAL) access + a tiny forward-only migration runner.

aiosqlite is used deliberately: billets is served in-process by the SecuBox
aggregator on a shared event loop, so a blocking DB call would freeze every
module on the board. All DB access is `await`ed off that loop.

Migrations are numbered `NNNN_name.sql` files applied in order; the highest
applied version is recorded in `schema_migrations`. Each file runs in a
transaction and is idempotent at the file level (only files with a version
greater than the stored one run)."""
from __future__ import annotations

import os
import re
from pathlib import Path

import aiosqlite

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
DEFAULT_DB_PATH = os.environ.get("BILLETS_DB", "/var/lib/secubox/billets/billets.db")

_MIGRATION_RE = re.compile(r"^(\d{4})_.+\.sql$")


def _migration_files() -> list[tuple[int, Path]]:
    out: list[tuple[int, Path]] = []
    for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = _MIGRATION_RE.match(p.name)
        if m:
            out.append((int(m.group(1)), p))
    return sorted(out)


async def _current_version(conn: aiosqlite.Connection) -> int:
    await conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    async with conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations") as cur:
        row = await cur.fetchone()
    return int(row[0]) if row else 0


async def run_migrations(conn: aiosqlite.Connection, *, now: str) -> int:
    """Apply every migration newer than the stored version. Returns the version
    the DB is at afterwards. `now` (RFC3339) is injected so it stays testable."""
    version = await _current_version(conn)
    for ver, path in _migration_files():
        if ver <= version:
            continue
        sql = path.read_text(encoding="utf-8")
        await conn.executescript(sql)
        await conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (ver, now),
        )
        await conn.commit()
        version = ver
    return version


async def connect(db_path: str | None = None, *, now: str) -> aiosqlite.Connection:
    """Open (creating the parent dir), set WAL + FK enforcement, migrate, return
    a connection with `row_factory = aiosqlite.Row`."""
    path = db_path or DEFAULT_DB_PATH
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.execute("PRAGMA busy_timeout=5000")
    await run_migrations(conn, now=now)
    return conn
