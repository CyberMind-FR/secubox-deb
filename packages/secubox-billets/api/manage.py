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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="billets-manage")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("create-author", "set-password"):
        sp = sub.add_parser(name)
        sp.add_argument("username")
    sub.add_parser("seed")
    args = p.parse_args(argv)

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
