# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Billet repository: create/read queries over the async connection.

The public feed uses keyset (cursor) pagination on (published_at, id) — never
OFFSET — so deep pages stay O(limit). Cursors are opaque urlsafe tokens holding
the last row's (published_at, id)."""
from __future__ import annotations

import base64
from typing import Any, Optional

import aiosqlite

from .ids import new_ulid
from .models import BilletIn, slugify

_FEED_COLUMNS = ("id,created_at,updated_at,published_at,body,ref_url,embed_url,"
                 "embed_html,embed_provider,embed_fetched_at,slug,status,view_count")


def encode_cursor(published_at: str, billet_id: str) -> str:
    raw = f"{published_at}\x1f{billet_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> Optional[tuple[str, str]]:
    try:
        pad = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(cursor + pad).decode("utf-8")
        published_at, billet_id = raw.split("\x1f", 1)
        return published_at, billet_id
    except Exception:
        return None


async def create_billet(conn: aiosqlite.Connection, data: BilletIn, *, now: str,
                        ulid: Optional[str] = None) -> str:
    """Insert a billet (draft, or published when data.publish). Returns its id."""
    billet_id = ulid or new_ulid()
    slug = slugify(data.body, suffix=billet_id[-8:])
    status = "published" if data.publish else "draft"
    published_at = now if data.publish else None
    await conn.execute(
        "INSERT INTO billet(id,created_at,updated_at,published_at,body,ref_url,"
        "embed_url,slug,status) VALUES (?,?,?,?,?,?,?,?,?)",
        (billet_id, now, now, published_at, data.body, data.ref_url,
         data.embed_url, slug, status),
    )
    await conn.commit()
    return billet_id


async def get_by_slug(conn: aiosqlite.Connection, slug: str) -> Optional[aiosqlite.Row]:
    async with conn.execute(
        f"SELECT {_FEED_COLUMNS} FROM billet WHERE slug = ?", (slug,)
    ) as cur:
        return await cur.fetchone()


async def get_by_id(conn: aiosqlite.Connection, billet_id: str) -> Optional[aiosqlite.Row]:
    async with conn.execute(
        f"SELECT {_FEED_COLUMNS} FROM billet WHERE id = ?", (billet_id,)
    ) as cur:
        return await cur.fetchone()


async def list_published(conn: aiosqlite.Connection, *, limit: int = 20,
                         cursor: Optional[str] = None) -> tuple[list[aiosqlite.Row], Optional[str]]:
    """Return (rows, next_cursor). `next_cursor` is None on the last page."""
    limit = max(1, min(limit, 100))
    params: list[Any] = []
    where = "status = 'published'"
    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            where += " AND (published_at, id) < (?, ?)"
            params.extend(decoded)
    q = (f"SELECT {_FEED_COLUMNS} FROM billet WHERE {where} "
         f"ORDER BY published_at DESC, id DESC LIMIT ?")
    params.append(limit + 1)  # fetch one extra to know if there's a next page
    async with conn.execute(q, params) as cur:
        rows = await cur.fetchall()
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last["published_at"], last["id"])
        rows = rows[:limit]
    return rows, next_cursor


async def increment_view(conn: aiosqlite.Connection, billet_id: str) -> None:
    await conn.execute("UPDATE billet SET view_count = view_count + 1 WHERE id = ?", (billet_id,))
    await conn.commit()


# ── author ────────────────────────────────────────────────────────────────
async def create_author(conn: aiosqlite.Connection, username: str, password_hash: str,
                        *, now: str, totp_secret: Optional[str] = None,
                        author_id: Optional[str] = None) -> str:
    aid = author_id or new_ulid()
    await conn.execute(
        "INSERT INTO author(id, username, password_hash, totp_secret, created_at) "
        "VALUES (?,?,?,?,?)",
        (aid, username, password_hash, totp_secret, now),
    )
    await conn.commit()
    return aid


async def get_author_by_username(conn: aiosqlite.Connection, username: str) -> Optional[aiosqlite.Row]:
    async with conn.execute(
        "SELECT id, username, password_hash, totp_secret, created_at FROM author WHERE username = ?",
        (username,),
    ) as cur:
        return await cur.fetchone()


async def get_author_by_id(conn: aiosqlite.Connection, author_id: str) -> Optional[aiosqlite.Row]:
    async with conn.execute(
        "SELECT id, username, password_hash, totp_secret, created_at FROM author WHERE id = ?",
        (author_id,),
    ) as cur:
        return await cur.fetchone()


# ── admin billet mutations ─────────────────────────────────────────────────
async def list_all(conn: aiosqlite.Connection, *, status: Optional[str] = None,
                   limit: int = 100) -> list[aiosqlite.Row]:
    if status:
        q = f"SELECT {_FEED_COLUMNS} FROM billet WHERE status = ? ORDER BY created_at DESC LIMIT ?"
        params: tuple = (status, limit)
    else:
        q = f"SELECT {_FEED_COLUMNS} FROM billet ORDER BY created_at DESC LIMIT ?"
        params = (limit,)
    async with conn.execute(q, params) as cur:
        return await cur.fetchall()


async def update_billet(conn: aiosqlite.Connection, billet_id: str, *, body: str,
                        ref_url: Optional[str], embed_url: Optional[str], now: str) -> None:
    """Update content (slug/permalink stays stable) + bump updated_at."""
    await conn.execute(
        "UPDATE billet SET body=?, ref_url=?, embed_url=?, updated_at=? WHERE id=?",
        (body, ref_url, embed_url, now, billet_id),
    )
    await conn.commit()


async def set_status(conn: aiosqlite.Connection, billet_id: str, status: str, *, now: str) -> None:
    """Change status. Publishing sets published_at once (never overwrites it)."""
    if status == "published":
        await conn.execute(
            "UPDATE billet SET status='published', updated_at=?, "
            "published_at=COALESCE(published_at, ?) WHERE id=?",
            (now, now, billet_id),
        )
    else:
        await conn.execute(
            "UPDATE billet SET status=?, updated_at=? WHERE id=?", (status, now, billet_id))
    await conn.commit()


async def delete_billet(conn: aiosqlite.Connection, billet_id: str) -> None:
    await conn.execute("DELETE FROM billet WHERE id=?", (billet_id,))
    await conn.commit()
