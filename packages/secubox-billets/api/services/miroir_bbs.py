# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Miroir des réponses PUBLIQUES des fils BBS liés à un billet (#2778).

Un billet est lié à un fil du BBS de CETTE box par son `ref_url` (https://bbs.<domaine>/t/<id>) ou par un lien du même BBS cité dans son corps (au plus
MAX_FILS). Chaque post PUBLIC d'un fil PUBLIC, non supprimé, devient un commentaire SYSTÈME approuvé du billet (`source='bbs'`, auteur en référence
`author_ref='bbs:<handle>'`), à l'heure de la réponse : il fait donc remonter le billet dans le fil (`bumped_at` ne recule jamais).

Lecture seule du BBS (index SQLite ouvert en `mode=ro`, corps lus sous le dossier de contenu, jamais en dehors). Rien de local, de privé ni de supprimé.
Idempotent : le post d'origine (`bbs:<id>`) est l'identité de la ligne. Une réponse qui cesse d'être publique disparaît ; un commentaire que l'administrateur a
rejeté n'est jamais ressuscité."""
from __future__ import annotations

import calendar
import html as _html
import re
import sqlite3
import time
from pathlib import Path
from typing import Optional

import aiosqlite

from .. import repo

MAX_FILS = 3
MAX_CORPS = 2000
MAX_LECTURE = 64 * 1024
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FICHIER = re.compile(r"(?<![\w/])/f/(\d{1,9}(?:\.\w{1,8})?)")


def _iso(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def fils_lies(ref_url: Optional[str], corps: Optional[str], domaine: str) -> list:
    """Identifiants des fils du BBS de cette box liés au billet : `ref_url` d'abord, puis les liens du corps ; sans doublon, bornés à MAX_FILS."""
    if not domaine:
        return []
    motif = re.compile(r"https://bbs\." + re.escape(domaine) + r"/t/(\d{1,9})(?!\d)")
    out: list = []
    for texte in (ref_url or "", corps or ""):
        for m in motif.finditer(texte):
            n = int(m.group(1))
            if n not in out:
                out.append(n)
    return out[:MAX_FILS]


def _corps_du_disque(racine_bbs: Path, contenu: Path, body_path: str) -> Optional[str]:
    try:
        p = (racine_bbs / body_path).resolve()
        if contenu not in p.parents:                           # jamais en dehors du dossier de contenu
            return None
        with open(p, "rb") as f:
            brut = f.read(MAX_LECTURE).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    if brut.startswith("---\n"):
        fin = brut.find("\n---\n", 4)
        if fin != -1:
            brut = brut[fin + 5:]
    return brut


def _nettoie(texte: str, hote_bbs: Optional[str]) -> str:
    t = _CTRL.sub("", texte).strip()
    if hote_bbs:
        t = _FICHIER.sub(lambda m: f"https://{hote_bbs}/f/{m.group(1)}", t)       # « /f/126.png » devient un lien absolu vers le BBS
    return t[:MAX_CORPS]


def lire_fil(db_bbs: str, dossier_contenu: str, thread_id: int, hote_bbs: Optional[str] = None) -> list:
    """Posts publics non supprimés d'un fil PUBLIC : [{post_id, auteur, corps, quand, premier}], dans l'ordre. [] si le BBS est absent, illisible ou le fil non public."""
    contenu = Path(dossier_contenu).resolve()
    racine = contenu.parent
    try:
        con = sqlite3.connect(f"file:{db_bbs}?mode=ro", uri=True, timeout=3)
        try:
            lignes = con.execute(
                "SELECT p.id, u.handle, p.body_path, p.created_at, "
                "(p.id = (SELECT MIN(id) FROM posts WHERE thread_id = p.thread_id)) FROM posts p "
                "JOIN threads t ON t.id = p.thread_id JOIN users u ON u.id = p.author_id "
                "WHERE p.thread_id = ? AND t.visibility = 'public' AND p.visibility = 'public' AND p.deleted_at IS NULL "
                "ORDER BY p.created_at, p.id LIMIT 500", (int(thread_id),)).fetchall()
        finally:
            con.close()
    except (sqlite3.Error, OSError):
        return []
    out = []
    for pid, handle, chemin, quand, premier in lignes:
        corps = _corps_du_disque(racine, contenu, str(chemin))
        if corps is None:
            continue
        out.append({"post_id": int(pid), "auteur": str(handle), "corps": _nettoie(corps, hote_bbs), "quand": _iso(int(quand)), "premier": bool(premier)})
    return out


async def synchroniser(conn: aiosqlite.Connection, db_bbs: str, dossier_contenu: str, domaine: str, *, maintenant: Optional[str] = None,
                       limite: int = 50, billet_id: Optional[str] = None) -> int:
    """Recopie les réponses publiques des fils liés (tous les billets publiés qui en citent, ou un seul) ; rend le nombre de commentaires ajoutés."""
    hote = f"bbs.{domaine}"
    requete = ("SELECT id, body, ref_url FROM billet WHERE status='published' AND (ref_url LIKE '%/t/%' OR body LIKE '%/t/%')"
               + (" AND id = ?" if billet_id else "") + " ORDER BY COALESCE(bumped_at, published_at) DESC LIMIT ?")
    args = ((billet_id,) if billet_id else ()) + (limite,)
    async with conn.execute(requete, args) as cur:
        billets = await cur.fetchall()
    ajoutes = 0
    for bid, corps_billet, ref_url in billets:
        fils = fils_lies(ref_url, corps_billet, domaine)
        voulus: dict = {}
        for tid in fils:
            for p in lire_fil(db_bbs, dossier_contenu, tid, hote):
                # Le PREMIER post du fil (plus petit identifiant, public ou non) est la source du billet : jamais recopié (#2780). Un billet relayé en porte une copie
                # locale (/media/…), l'égalité de corps ne la reconnaît pas. Les corps vides ou déjà présents dans le billet restent écartés.
                if p["premier"] or not p["corps"] or p["corps"] in (corps_billet or ""):
                    continue
                voulus[f"bbs:{p['post_id']}"] = p
        async with conn.execute("SELECT source_ref, status FROM comment WHERE billet_id=? AND source='bbs'", (bid,)) as cur:
            existants = {r[0]: r[1] for r in await cur.fetchall()}
        for ref, p in voulus.items():
            if ref in existants:
                continue                                    # déjà là (ou rejeté par l'administrateur : jamais ressuscité)
            await repo.add_comment(conn, bid, author_name=p["auteur"], email_hash=None, body=p["corps"], ip_hash="systeme", honeypot=False,
                                   status="approved", now=p["quand"], source="bbs", source_ref=ref, author_ref=f"bbs:{p['auteur']}")
            ajoutes += 1
        perdus = [r for r, s in existants.items() if r not in voulus and s != "rejected"]
        if perdus:
            await conn.executemany("DELETE FROM comment WHERE billet_id=? AND source='bbs' AND source_ref=?", [(bid, r) for r in perdus])
            await conn.commit()
    return ajoutes


_IMAGES = ("png", "jpg", "jpeg", "gif", "webp")
_VIDEOS = ("mp4", "webm", "mov")


def rendre_corps(corps: str, domaine: str) -> str:
    """Corps d'un commentaire système du BBS -> HTML sûr (#2782) : une URL de FICHIER du BBS de cette box (https://bbs.<domaine>/f/<n>.<ext>) devient une
    vignette cliquable (image) ou un lien « ▶ vidéo » ; tout le reste est du texte échappé, avec ses liens (linkify_plain). Jamais d'image d'un autre hôte."""
    from .render import linkify_plain
    if not domaine:
        return linkify_plain(corps)
    motif = re.compile(r"https://bbs\." + re.escape(domaine) + r"/f/(\d{1,9})\.(" + "|".join(_IMAGES + _VIDEOS) + r")(?![\w.])", re.I)
    out, pos = [], 0
    for m in motif.finditer(corps or ""):
        out.append(linkify_plain((corps or "")[pos:m.start()]))
        url = _html.escape(m.group(0), quote=True)
        if m.group(2).lower() in _IMAGES:
            out.append(f'<a class="vig" href="{url}" rel="nofollow ugc noopener noreferrer"><img class="vignette" src="{url}" alt="" loading="lazy"></a>')
        else:
            out.append(f'<a class="vid" href="{url}" rel="nofollow ugc noopener noreferrer">▶ vidéo</a>')
        pos = m.end()
    out.append(linkify_plain((corps or "")[pos:]))
    return "".join(out)
