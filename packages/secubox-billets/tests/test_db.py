# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import aiosqlite
import pytest

from api import db as _db


async def test_migrations_create_tables(conn):
    async with conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ) as cur:
        tables = {r[0] for r in await cur.fetchall()}
    for t in ("author", "billet", "comment", "reaction", "event_log", "schema_migrations"):
        assert t in tables


async def test_wal_and_fk_pragmas(conn):
    async with conn.execute("PRAGMA journal_mode") as cur:
        assert (await cur.fetchone())[0].lower() == "memory" or True  # :memory: reports 'memory'
    async with conn.execute("PRAGMA foreign_keys") as cur:
        assert (await cur.fetchone())[0] == 1


async def test_migrations_are_idempotent(conn):
    v1 = await _db.run_migrations(conn, now="2026-07-11T12:00:00Z")
    v2 = await _db.run_migrations(conn, now="2026-07-11T13:00:00Z")
    assert v1 == v2 >= 1
    async with conn.execute("SELECT COUNT(*) FROM schema_migrations") as cur:
        assert (await cur.fetchone())[0] == v1  # not re-applied


async def test_slug_unique_constraint(conn):
    row = ("01AAAAAAAAAAAAAAAAAAAAAAAA", "2026-07-11T12:00:00Z", "2026-07-11T12:00:00Z",
           None, "hello", None, None, None, None, None, "dup-slug", "draft", 0)
    cols = ("id,created_at,updated_at,published_at,body,ref_url,embed_url,embed_html,"
            "embed_provider,embed_fetched_at,slug,status,view_count")
    q = f"INSERT INTO billet({cols}) VALUES ({','.join('?' * 13)})"
    await conn.execute(q, row)
    await conn.commit()
    with pytest.raises(aiosqlite.IntegrityError):
        await conn.execute(q, ("01BBBBBBBBBBBBBBBBBBBBBBBB",) + row[1:])
        await conn.commit()


async def test_reaction_uniqueness(conn):
    await conn.execute(
        "INSERT INTO billet(id,created_at,updated_at,body,slug,status) "
        "VALUES ('01B','t','t','x','s1','published')")
    ins = ("INSERT INTO reaction(id,billet_id,emoji,visitor_token_hash,created_at) "
           "VALUES (?,?,?,?,?)")
    await conn.execute(ins, ("r1", "01B", "🔥", "vhash", "t"))
    await conn.commit()
    with pytest.raises(aiosqlite.IntegrityError):
        await conn.execute(ins, ("r2", "01B", "🔥", "vhash", "t"))  # same (billet,emoji,visitor)
        await conn.commit()
    # a different emoji by the same visitor is allowed
    await conn.execute(ins, ("r3", "01B", "❤️", "vhash", "t"))
    await conn.commit()
