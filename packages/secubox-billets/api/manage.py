# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Management CLI: `python -m api.manage <cmd>`.

  create-author <username>   create the (first) author; prompts for a password
  set-password <username>    reset an author's password
  seed                       insert sample published billets
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from datetime import datetime, timezone

from . import db, repo
from .seed import seed_billets
from .services import security as sec
from .services.tags import emoji_for as tags_emoji_for


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _create_author(username: str, password: str) -> int:
    conn = await db.connect(now=_now())
    try:
        if await repo.get_author_by_username(conn, username):
            print(f"author {username!r} already exists", file=sys.stderr)
            return 1
        await repo.create_author(conn, username, sec.hash_password(password), now=_now())
        print(f"author {username!r} created")
        return 0
    finally:
        await conn.close()


async def _set_password(username: str, password: str) -> int:
    conn = await db.connect(now=_now())
    try:
        row = await repo.get_author_by_username(conn, username)
        if not row:
            print(f"no such author {username!r}", file=sys.stderr)
            return 1
        await conn.execute("UPDATE author SET password_hash=? WHERE username=?",
                           (sec.hash_password(password), username))
        await conn.commit()
        print(f"password updated for {username!r}")
        return 0
    finally:
        await conn.close()


async def _seed() -> int:
    conn = await db.connect(now=_now())
    try:
        ids = await seed_billets(conn)
        print(f"seeded {len(ids)} billets")
        return 0
    finally:
        await conn.close()


async def _backfill_tags() -> int:
    """Extract #hashtags from billets written before tags existed.

    Idempotent: sync_tags replaces a billet's tag rows from its body every time,
    so re-running only ever converges. Covers drafts too — publishing one later
    must not need a second backfill.
    """
    conn = await db.connect(now=_now())
    try:
        async with conn.execute("SELECT id, body FROM billet") as cur:
            rows = await cur.fetchall()
        tagged = 0
        for r in rows:
            if await repo.sync_tags(conn, r["id"], r["body"]):
                tagged += 1
        # Re-apply the curated map to tags that already exist. sync_tags never
        # restyles a stored tag (a published billet must not silently change
        # look); doing it here keeps that an explicit, operator-invoked step —
        # run this after editing TAG_EMOJI.
        restyled = 0
        async with conn.execute("SELECT slug, emoji FROM tag") as cur:
            existing = await cur.fetchall()
        for t in existing:
            want = tags_emoji_for(t["slug"])
            if want != t["emoji"]:
                await conn.execute("UPDATE tag SET emoji = ? WHERE slug = ?", (want, t["slug"]))
                restyled += 1
        await conn.commit()
        print(f"backfilled {len(rows)} billets — {tagged} carry at least one tag; "
              f"{restyled} tag(s) restyled from the curated map")
        return 0
    finally:
        await conn.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="billets-manage")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("create-author", "set-password"):
        sp = sub.add_parser(name)
        sp.add_argument("username")
    sub.add_parser("seed")
    sub.add_parser("backfill-tags")
    args = p.parse_args(argv)

    if args.cmd == "backfill-tags":
        return asyncio.run(_backfill_tags())

    if args.cmd in ("create-author", "set-password"):
        pw = getpass.getpass("Password: ")
        if len(pw) < 10:
            print("password too short (min 10)", file=sys.stderr)
            return 2
        fn = _create_author if args.cmd == "create-author" else _set_password
        return asyncio.run(fn(args.username, pw))
    if args.cmd == "seed":
        return asyncio.run(_seed())
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
