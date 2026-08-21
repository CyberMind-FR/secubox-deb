# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: billets — réparation des médias non embarqués (#1094)
CyberMind — https://cybermind.fr

POURQUOI CE MODULE EXISTE. Un billet publié depuis le BBS cite ses médias en
`/f/NN.ext` — une référence de fichier DU BBS. billets ne sait pas servir un
`/f/…` (c'est un chemin du BBS, réservé aux membres) : le lecteur voyait donc le
chemin en texte, sans image ni vidéo. Le pont BBS→billets réécrit ces refs à la
PUBLICATION ; les billets publiés AVANT ce correctif gardent leurs `/f/…` figés.

CE QUE FAIT LA RÉPARATION. Pour chaque billet dont le corps cite encore `/f/NN`,
on refetch l'octet-source auprès du BBS (via un `resolve` injecté — le magasin
du BBS est le seul à détenir les octets), on l'ingère par le MÊME pipeline
validé qu'un téléversement direct (`process_upload` : ré-encodage image / épingle
octets-magiques pour a/v/pdf), puis on réécrit le corps vers le `/media/…`
billets-relatif que le rendu embarque. IDEMPOTENT : un corps réécrit n'a plus de
`/f/` à réparer, donc rejouer ne fait rien.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Callable, Optional

import aiosqlite

from .. import repo
from ..ids import new_ulid
from . import media

# `/f/NN.ext` — NN est l'identifiant `files.id` du BBS, ext l'extension citée.
_FREF = re.compile(r"/f/(\d+)\.([A-Za-z0-9]{1,5})")

# resolve(num, ext) -> (octets, mime) | None. Injecté : le magasin du BBS est la
# seule source des octets, et l'injection rend la réparation testable.
Resolver = Callable[[str, str], Optional[tuple[bytes, str]]]


async def repair_billet(conn: aiosqlite.Connection, row: aiosqlite.Row,
                        resolve: Resolver, *, now: str) -> int:
    """Répare UN billet : transfère chaque `/f/NN` résoluble, réécrit le corps.
    Retourne le nombre de médias embarqués (0 si rien à faire)."""
    body: str = row["body"] or ""
    # dict : dédoublonne une même ref citée deux fois ; str.replace couvre alors
    # toutes ses occurrences en une passe.
    refs: dict[str, tuple[str, str]] = {
        m.group(0): (m.group(1), m.group(2).lower()) for m in _FREF.finditer(body)
    }
    if not refs:
        return 0

    new_body = body
    n = 0
    for ref, (num, ext) in refs.items():
        got = resolve(num, ext)
        if not got:
            continue                      # supprimé côté BBS / introuvable : on laisse la ref
        raw, mime = got
        try:
            processed = media.process_upload(raw, mime)
        except media.MediaError:
            continue                      # refusé (type/borne) : le corps garde sa ref, pas de perte
        mid = new_ulid()
        if processed["kind"] == "image":
            fn, thumb = media.store(mid, processed)
            await repo.add_media(conn, row["id"], filename=fn, thumb=thumb,
                                 mime=processed["mime"], width=processed["width"],
                                 height=processed["height"], alt="", now=now, ulid=mid)
        else:
            fn = media.store_raw(mid, processed["ext"], processed["data"])
            await repo.add_media(conn, row["id"], filename=fn, thumb="",
                                 mime=processed["mime"], width=0, height=0,
                                 alt="", now=now, ulid=mid)
        new_body = new_body.replace(ref, f"/media/{fn}")
        n += 1

    if n:
        # On préserve ref_url/embed_url/style existants : la réparation ne touche
        # QUE le corps (et, via update_billet, resynchronise les #tags).
        await repo.update_billet(conn, row["id"], body=new_body,
                                 ref_url=row["ref_url"], embed_url=row["embed_url"],
                                 now=now, style=row["style"])
    return n


async def run(conn: aiosqlite.Connection, resolve: Resolver, *, now: str) -> tuple[int, int]:
    """Répare tous les billets citant encore des `/f/…`. Retourne
    (billets_touchés, médias_embarqués)."""
    async with conn.execute(
        "SELECT id, body, ref_url, embed_url, style FROM billet "
        "WHERE body LIKE '%/f/%'"
    ) as cur:
        rows = await cur.fetchall()
    touched = 0
    total = 0
    for r in rows:
        n = await repair_billet(conn, r, resolve, now=now)
        if n:
            touched += 1
            total += n
    return touched, total


def bbs_resolver(bbs_db: str, files_root: str) -> Resolver:
    """Résolveur réel : lit le magasin du BBS (index.db + arbre `files/`).

    Ouverture en LECTURE SEULE (`mode=ro`) : la réparation ne modifie jamais le
    BBS. `deleted_at IS NULL` respecte la suppression douce — un média retiré par
    la modération ne doit pas ressusciter dans un billet public."""
    root = Path(files_root)

    def resolve(num: str, ext: str) -> Optional[tuple[bytes, str]]:
        con = sqlite3.connect(f"file:{bbs_db}?mode=ro", uri=True)
        try:
            cur = con.execute(
                "SELECT path, mime FROM files WHERE id=? AND deleted_at IS NULL",
                (int(num),))
            hit = cur.fetchone()
        finally:
            con.close()
        if not hit:
            return None
        path, mime = hit
        fp = root / path
        if not fp.is_file():
            return None
        return fp.read_bytes(), (mime or "application/octet-stream")

    return resolve
