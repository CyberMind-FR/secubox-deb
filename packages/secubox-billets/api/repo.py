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
from .services.tags import extract as tags_extract

_FEED_COLUMNS = ("id,created_at,updated_at,published_at,body,ref_url,embed_url,"
                 "embed_html,embed_provider,embed_fetched_at,slug,status,"
                 "style,embed_snapshot,view_count")


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
        "embed_url,slug,status,style) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (billet_id, now, now, published_at, data.body, data.ref_url,
         data.embed_url, slug, status, data.style),
    )
    await conn.commit()
    await sync_tags(conn, billet_id, data.body)
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
                         cursor: Optional[str] = None,
                         tag: Optional[str] = None) -> tuple[list[aiosqlite.Row], Optional[str]]:
    """Return (rows, next_cursor). `next_cursor` is None on the last page.

    `tag` restricts the feed to one emoji-hashtag (the quick view). It uses an
    EXISTS against the indexed billet_tag rather than a JOIN, so keyset paging
    stays correct — a JOIN could duplicate a row per matching tag.
    """
    limit = max(1, min(limit, 100))
    params: list[Any] = []
    where = "status = 'published'"
    if tag:
        where += (" AND EXISTS (SELECT 1 FROM billet_tag bt WHERE bt.billet_id = billet.id "
                  "AND bt.tag_slug = ?)")
        params.append(tag)
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


async def update_password(conn: aiosqlite.Connection, author_id: str, password_hash: str) -> None:
    await conn.execute("UPDATE author SET password_hash=? WHERE id=?", (password_hash, author_id))
    await conn.commit()


async def first_author(conn: aiosqlite.Connection) -> Optional[aiosqlite.Row]:
    """The primary (earliest) author — billets is single-author; used by the
    operator password-override path where there is no session."""
    async with conn.execute(
        "SELECT id, username, password_hash, totp_secret, created_at FROM author "
        "ORDER BY created_at, id LIMIT 1") as cur:
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
                        ref_url: Optional[str], embed_url: Optional[str], now: str,
                        style: str = "default") -> None:
    """Update content (slug/permalink stays stable) + bump updated_at."""
    await conn.execute(
        "UPDATE billet SET body=?, ref_url=?, embed_url=?, style=?, updated_at=? WHERE id=?",
        (body, ref_url, embed_url, style, now, billet_id),
    )
    await conn.commit()
    await sync_tags(conn, billet_id, body)   # a #tag removed from the body loses its chip


async def set_embed_snapshot(conn: aiosqlite.Connection, billet_id: str,
                             filename: Optional[str]) -> None:
    """Record (or clear) the captured embed-vignette filename for a billet."""
    await conn.execute(
        "UPDATE billet SET embed_snapshot=? WHERE id=?", (filename, billet_id))
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


async def set_embed(conn: aiosqlite.Connection, billet_id: str, *, html: str,
                    provider: Optional[str], fetched_at: str) -> None:
    """Cache a resolved embed (sanitized HTML) on the billet row."""
    await conn.execute(
        "UPDATE billet SET embed_html=?, embed_provider=?, embed_fetched_at=? WHERE id=?",
        (html or None, provider, fetched_at, billet_id),
    )
    await conn.commit()


# ── media ───────────────────────────────────────────────────────────────────
async def add_media(conn: aiosqlite.Connection, billet_id: str, *, filename: str,
                    thumb: str, mime: str, width: int, height: int, alt: str,
                    now: str, position: Optional[int] = None,
                    ulid: Optional[str] = None) -> str:
    """Attach a processed image to a billet. `position` defaults to append."""
    mid = ulid or new_ulid()
    if position is None:
        async with conn.execute(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM media WHERE billet_id=?",
            (billet_id,)) as cur:
            position = (await cur.fetchone())[0]
    await conn.execute(
        "INSERT INTO media(id,billet_id,filename,thumb,mime,width,height,alt,"
        "position,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (mid, billet_id, filename, thumb, mime, width, height, alt or "", position, now),
    )
    await conn.commit()
    return mid


async def list_media(conn: aiosqlite.Connection, billet_id: str) -> list[aiosqlite.Row]:
    async with conn.execute(
        "SELECT * FROM media WHERE billet_id=? ORDER BY position, created_at, id",
        (billet_id,)) as cur:
        return list(await cur.fetchall())


async def list_media_for(conn: aiosqlite.Connection,
                         billet_ids: list[str]) -> dict[str, list[aiosqlite.Row]]:
    """Batch-fetch media for many billets (avoids N+1 on the feed)."""
    out: dict[str, list[aiosqlite.Row]] = {bid: [] for bid in billet_ids}
    if not billet_ids:
        return out
    placeholders = ",".join("?" for _ in billet_ids)
    async with conn.execute(
        f"SELECT * FROM media WHERE billet_id IN ({placeholders}) "
        "ORDER BY position, created_at, id", billet_ids) as cur:
        for row in await cur.fetchall():
            out[row["billet_id"]].append(row)
    return out


async def get_media(conn: aiosqlite.Connection, media_id: str) -> Optional[aiosqlite.Row]:
    async with conn.execute("SELECT * FROM media WHERE id=?", (media_id,)) as cur:
        return await cur.fetchone()


async def delete_media(conn: aiosqlite.Connection, media_id: str) -> None:
    await conn.execute("DELETE FROM media WHERE id=?", (media_id,))
    await conn.commit()


async def all_media(conn: aiosqlite.Connection) -> list[aiosqlite.Row]:
    """Every attachment (portable export)."""
    async with conn.execute(
        "SELECT * FROM media ORDER BY billet_id, position, created_at, id") as cur:
        return list(await cur.fetchall())


# ── comments ────────────────────────────────────────────────────────────────
async def add_comment(conn: aiosqlite.Connection, billet_id: str, *, author_name: str,
                      email_hash: Optional[str], body: str, ip_hash: str, honeypot: bool,
                      status: str, now: str, ulid: Optional[str] = None) -> str:
    cid = ulid or new_ulid()
    await conn.execute(
        "INSERT INTO comment(id,billet_id,created_at,author_name,author_email,body,"
        "status,ip_hash,honeypot_tripped) VALUES (?,?,?,?,?,?,?,?,?)",
        (cid, billet_id, now, author_name, email_hash, body, status, ip_hash,
         1 if honeypot else 0),
    )
    await conn.commit()
    return cid


async def list_approved_comments(conn: aiosqlite.Connection, billet_id: str) -> list[aiosqlite.Row]:
    async with conn.execute(
        "SELECT id, author_name, body, created_at FROM comment "
        "WHERE billet_id=? AND status='approved' ORDER BY created_at ASC", (billet_id,)
    ) as cur:
        return await cur.fetchall()


async def list_pending_comments(conn: aiosqlite.Connection, *, limit: int = 200) -> list[aiosqlite.Row]:
    async with conn.execute(
        "SELECT id, billet_id, author_name, body, created_at FROM comment "
        "WHERE status='pending' ORDER BY created_at ASC LIMIT ?", (limit,)
    ) as cur:
        return await cur.fetchall()


async def get_comment(conn: aiosqlite.Connection, comment_id: str) -> Optional[aiosqlite.Row]:
    async with conn.execute(
        "SELECT id, billet_id, author_name, ip_hash, status FROM comment WHERE id=?",
        (comment_id,)) as cur:
        return await cur.fetchone()


async def moderate_comment(conn: aiosqlite.Connection, comment_id: str, status: str) -> None:
    await conn.execute("UPDATE comment SET status=? WHERE id=?", (status, comment_id))
    await conn.commit()


async def has_prior_approved(conn: aiosqlite.Connection, ip_hash: str, author_name: str) -> bool:
    """True if this (ip_hash, name) pair already has an approved comment — used
    to auto-approve returning, already-vetted visitors."""
    async with conn.execute(
        "SELECT 1 FROM comment WHERE ip_hash=? AND author_name=? AND status='approved' LIMIT 1",
        (ip_hash, author_name)) as cur:
        return await cur.fetchone() is not None


# ── reactions ───────────────────────────────────────────────────────────────
async def toggle_reaction(conn: aiosqlite.Connection, billet_id: str, emoji: str,
                          visitor_hash: str, *, now: str, ulid: Optional[str] = None) -> str:
    async with conn.execute(
        "SELECT id FROM reaction WHERE billet_id=? AND emoji=? AND visitor_token_hash=?",
        (billet_id, emoji, visitor_hash)) as cur:
        existing = await cur.fetchone()
    if existing:
        await conn.execute("DELETE FROM reaction WHERE id=?", (existing[0],))
        await conn.commit()
        return "removed"
    await conn.execute(
        "INSERT INTO reaction(id,billet_id,emoji,visitor_token_hash,created_at) VALUES (?,?,?,?,?)",
        (ulid or new_ulid(), billet_id, emoji, visitor_hash, now))
    await conn.commit()
    return "added"


async def reaction_counts(conn: aiosqlite.Connection, billet_id: str) -> dict[str, int]:
    async with conn.execute(
        "SELECT emoji, COUNT(*) FROM reaction WHERE billet_id=? GROUP BY emoji", (billet_id,)
    ) as cur:
        return {r[0]: r[1] for r in await cur.fetchall()}


async def visitor_reactions(conn: aiosqlite.Connection, billet_id: str,
                            visitor_hash: str) -> set[str]:
    async with conn.execute(
        "SELECT emoji FROM reaction WHERE billet_id=? AND visitor_token_hash=?",
        (billet_id, visitor_hash)) as cur:
        return {r[0] for r in await cur.fetchall()}


async def stats(conn: aiosqlite.Connection) -> dict:
    """Aggregate counts for the SecuBox webui panel (all public/derived data)."""
    async def _one(sql: str) -> int:
        async with conn.execute(sql) as cur:
            row = await cur.fetchone()
            return int(row[0]) if row and row[0] is not None else 0
    reactions_by = {}
    async with conn.execute("SELECT emoji, COUNT(*) FROM reaction GROUP BY emoji") as cur:
        for emoji, n in await cur.fetchall():
            reactions_by[emoji] = int(n)
    return {
        "billets_published": await _one("SELECT COUNT(*) FROM billet WHERE status='published'"),
        "billets_drafts": await _one("SELECT COUNT(*) FROM billet WHERE status='draft'"),
        "comments_approved": await _one("SELECT COUNT(*) FROM comment WHERE status='approved'"),
        "comments_pending": await _one("SELECT COUNT(*) FROM comment WHERE status='pending'"),
        "reactions_total": await _one("SELECT COUNT(*) FROM reaction"),
        "reactions_by": reactions_by,
    }


# Tags (emoji hashtags) ──────────────────────────────────────────────────
async def sync_tags(conn: aiosqlite.Connection, billet_id: str, body: str) -> list[tuple[str, str]]:
    """Re-extract the body's #hashtags and make billet_tag match it exactly.

    Called on every create/update, so removing a #tag from the body removes the
    chip. The tag row itself is upserted (never deleted here) — other billets may
    still point at it, and an orphan tag is harmless.
    """
    pairs = tags_extract(body)
    for slug, emoji in pairs:
        # Keep the stored emoji stable once a tag exists: a later curation change
        # must not silently restyle billets that already published with it.
        await conn.execute(
            "INSERT INTO tag(slug,emoji,label) VALUES (?,?,?) ON CONFLICT(slug) DO NOTHING",
            (slug, emoji, slug),
        )
    await conn.execute("DELETE FROM billet_tag WHERE billet_id = ?", (billet_id,))
    if pairs:
        await conn.executemany(
            "INSERT OR IGNORE INTO billet_tag(billet_id,tag_slug) VALUES (?,?)",
            [(billet_id, slug) for slug, _ in pairs],
        )
    await conn.commit()
    return pairs


async def tags_for_many(conn: aiosqlite.Connection,
                        billet_ids: list[str]) -> dict[str, list[dict]]:
    """{billet_id: [{slug, emoji}]} for a whole page in ONE query — the feed
    renders chips for every row, so a per-row lookup would be an N+1."""
    if not billet_ids:
        return {}
    marks = ",".join("?" * len(billet_ids))
    q = (f"SELECT bt.billet_id, t.slug, t.emoji FROM billet_tag bt "
         f"JOIN tag t ON t.slug = bt.tag_slug "
         f"WHERE bt.billet_id IN ({marks}) ORDER BY t.slug")
    out: dict[str, list[dict]] = {}
    async with conn.execute(q, billet_ids) as cur:
        for row in await cur.fetchall():
            out.setdefault(row["billet_id"], []).append(
                {"slug": row["slug"], "emoji": row["emoji"]})
    return out


async def list_tags(conn: aiosqlite.Connection) -> list[dict]:
    """Every tag that has at least one PUBLISHED billet, with its count —
    this is the quick-view chip bar, so drafts must not leak into it."""
    q = ("SELECT t.slug, t.emoji, COUNT(*) AS n FROM billet_tag bt "
         "JOIN tag t ON t.slug = bt.tag_slug "
         "JOIN billet b ON b.id = bt.billet_id "
         "WHERE b.status = 'published' "
         "GROUP BY t.slug, t.emoji ORDER BY n DESC, t.slug")
    async with conn.execute(q) as cur:
        return [{"slug": r["slug"], "emoji": r["emoji"], "count": r["n"]}
                for r in await cur.fetchall()]
