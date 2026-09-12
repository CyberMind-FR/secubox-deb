# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Management CLI: `python -m api.manage <cmd>`.

  create-author <username>   create the (first) author; prompts for a password
  set-password <username>    reset an author's password
  seed                       insert sample published billets
  backfill-tags              extract #hashtags from pre-tags billets
  backfill-media             embed BBS /f/NN media into billets published before #1094
  backfill-embeds            promeut en embed les liens vidéo restés dans le corps
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


async def _backfill_media(bbs_db: str, files_root: str) -> int:
    """Réembarque les médias des billets publiés avant le correctif #1094.

    Les octets vivent dans le magasin du BBS ; on les refetch en lecture seule
    via le résolveur, on les ingère par le pipeline validé, on réécrit le corps.
    Idempotent — rejouer après coup ne trouve plus de `/f/…`."""
    from .services import backfill_media as bm
    resolve = bm.bbs_resolver(bbs_db, files_root)
    conn = await db.connect(now=_now())
    try:
        touched, total = await bm.run(conn, resolve, now=_now())
        print(f"réparé {touched} billet(s), {total} média(s) embarqué(s)")
        return 0
    finally:
        await conn.close()


async def _backfill_embeds(dry: bool) -> int:
    """Rattrape les billets dont le lien vidéo est resté DANS LE CORPS (#1268).

    Le relais BBS ne remplit que `body` + `ref_url` : un fil qui contenait une
    vidéo arrivait en texte nu, sans lecteur ni vignette. La promotion se fait
    désormais à l'entrée — reste à réparer ceux déjà publiés. Idempotent : on
    ne touche que les lignes SANS embed_url, et un échec de vignette n'empêche
    pas la promotion (le lecteur, lui, marchera).
    """
    import httpx

    from .models import video_url_in
    from .services import linkcard, snapshot, ssrf
    from .ids import new_ulid

    conn = await db.connect(now=_now())
    promus = vignettes = 0
    try:
        cur = await conn.execute(
            "SELECT id, slug, body, ref_url, style FROM billet "
            "WHERE embed_url IS NULL AND status = 'published'")
        rows = await cur.fetchall()
        cibles = [(r, video_url_in(r["body"])) for r in rows]
        cibles = [(r, u) for r, u in cibles if u]
        print(f"{len(rows)} billet(s) sans embed, {len(cibles)} avec une vidéo dans le corps")
        if dry:
            for r, u in cibles:
                print(f"  [essai] {r['slug']} → {u}")
            return 0
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for r, url in cibles:
                await repo.update_billet(conn, r["id"], body=r["body"],
                                         ref_url=r["ref_url"], embed_url=url, now=_now())
                promus += 1
                try:
                    res = await linkcard.resolve_embed(url, client=client,
                                                       resolver=ssrf._default_resolver)
                    await repo.set_embed(conn, r["id"], html=res["html"],
                                         provider=res["provider"], fetched_at=_now())
                except Exception as exc:  # noqa: BLE001 — l'iframe est un bonus
                    print(f"  ! embed {r['slug']}: {exc}", file=sys.stderr)
                try:
                    og = await linkcard.fetch_og_image(url, client=client,
                                                       resolver=ssrf._default_resolver)
                    got = await asyncio.to_thread(snapshot.capture, url, og, new_ulid(),
                                                  resolver=ssrf._default_resolver)
                    if got:
                        await repo.set_embed_snapshot(conn, r["id"], got[0])
                        vignettes += 1
                except Exception as exc:  # noqa: BLE001 — la vignette est un bonus
                    print(f"  ! vignette {r['slug']}: {exc}", file=sys.stderr)
                print(f"  {r['slug']} → {url}")
        print(f"promus {promus}, vignettes {vignettes}")
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
    spm = sub.add_parser("backfill-media")
    spm.add_argument("--bbs-db", default="/var/lib/secubox/bbs/index.db",
                     help="chemin de l'index SQLite du BBS (lecture seule)")
    spm.add_argument("--files-root", default="/var/lib/secubox/bbs/files",
                     help="racine de l'arbre des fichiers du BBS")
    spe = sub.add_parser("backfill-embeds")
    spe.add_argument("--dry-run", action="store_true",
                     help="montrer ce qui serait promu, sans rien écrire")
    args = p.parse_args(argv)

    if args.cmd == "backfill-tags":
        return asyncio.run(_backfill_tags())
    if args.cmd == "backfill-media":
        return asyncio.run(_backfill_media(args.bbs_db, args.files_root))
    if args.cmd == "backfill-embeds":
        return asyncio.run(_backfill_embeds(args.dry_run))

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
