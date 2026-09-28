# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: SBX Identity — COLLECTE des activités (#1560, P4)
CyberMind — https://cybermind.fr

sbxid seul écrit sbx.db : plutôt que d'ouvrir une porte d'écriture à chaque
module (une surface d'authentification de plus, et le BBS en Go à modifier),
il VA CHERCHER ce qui s'est passé, en lecture seule, toutes les minutes :

  bbs_post     un NOUVEAU fil du BBS (pas chaque réponse : 900 messages
               noieraient le flux) ; jamais d'un compte DÉSACTIVÉ — la
               « passerelle » qui importe radio et billets en est un : sur
               gk2, 40 des 53 fils du mois étaient les siens, aucun un geste ;
  file_shared  un fichier déposé au BBS ;
  radio_live   une diffusion lancée au Hall (broadcast_hist.json). Les
               morceaux de la radio — une ligne par morceau — ne sont pas
               des gestes de personne : ils n'y entrent pas.

La VISIBILITÉ suit celle du salon : privé et ouvert à des communautés → une
activité par communauté ; privé sans communauté → rien (personne d'autre
n'y a droit) ; public, lisible des invités, et fil public → public ; sinon
→ node. Un curseur par source ; le premier passage remonte 30 jours au plus.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from secubox_core import sbxid as S

BBS_DB = Path("/var/lib/secubox/bbs/index.db")
DIFFUSIONS = Path("/var/cache/secubox/webos/broadcast_hist.json")
CURSEURS = Path("/var/lib/secubox/sbxid/activites-curseurs.json")
PREMIER_PASSAGE_S = 30 * 86400
LOT = 200


def visibilites(prive: bool, min_role_read: str, visibilite_objet: str,
                communautes: List[str]) -> List[Tuple[str, Optional[str]]]:
    """[(visibility, community_uuid)] d'un objet du BBS, d'après son salon."""
    if prive:
        return [("community", c) for c in communautes]
    if visibilite_objet == "public" and (min_role_read or "guest") == "guest":
        return [("public", None)]
    return [("node", None)]


def _curseurs() -> Dict[str, Any]:
    try:
        return json.loads(CURSEURS.read_text())
    except (OSError, ValueError):
        return {}


def _sauve(c: Dict[str, Any]) -> None:
    tmp = CURSEURS.with_suffix(".tmp")
    tmp.write_text(json.dumps(c))
    os.replace(tmp, CURSEURS)


def _auteurs(sbx: sqlite3.Connection) -> Dict[str, str]:
    """handle BBS (minuscule) → user_uuid de la personne liée."""
    return {str(h).lower(): u for u, h in sbx.execute(
        "SELECT user_uuid, app_id FROM sbx_app_links WHERE app='bbs'")}


def collecte(sbx: sqlite3.Connection, origine: str, *, bbs_db: Path = None,
             diffusions: Path = None, curseurs: Optional[Dict[str, Any]] = None,
             maintenant: Optional[int] = None) -> Tuple[Dict[str, int], Dict[str, Any]]:
    """Un passage. Rend ({genre: nombre émis}, curseurs à jour)."""
    bbs_db, diffusions = bbs_db or BBS_DB, diffusions or DIFFUSIONS
    cur = dict(curseurs if curseurs is not None else _curseurs())
    maintenant = maintenant or int(time.time())
    plancher = maintenant - PREMIER_PASSAGE_S
    emis = {"bbs_post": 0, "file_shared": 0, "radio_live": 0}
    auteurs = _auteurs(sbx)

    def auteur(handle: str) -> str:
        return auteurs.get((handle or "").lower()) or f"bbs:{handle}"

    if bbs_db.exists():
        b = sqlite3.connect(f"file:{bbs_db}?mode=ro", uri=True, timeout=5)
        try:
            salons = {r[0]: r for r in b.execute(
                "SELECT id, slug, title, COALESCE(prive,0), COALESCE(min_role_read,'guest') FROM categories")}
            comms: Dict[int, List[str]] = {}
            for cat, cu in b.execute("SELECT category_id, community_uuid FROM salon_communautes"):
                comms.setdefault(cat, []).append(cu)

            def emet(kind, objet_id, cat_id, vis_objet, at, handle, ctx):
                s = salons.get(cat_id)
                if s:
                    ctx = {**ctx, "salon": s[1], "salon_titre": s[2]}
                    vs = visibilites(bool(s[3]), s[4], vis_objet, comms.get(cat_id, []))
                else:                                   # hors salon (fichier personnel)
                    vs = visibilites(False, "guest", vis_objet, [])
                for v, c in vs:
                    S.emet_activite(sbx, kind, author=auteur(handle), visibility=v, community_uuid=c,
                                    origin_node=origine, context=ctx, at=at)
                    emis[kind] += 1

            # nouveaux FILS
            dernier = cur.get("fils")
            q = ("SELECT t.id, t.category_id, u.handle, t.title, t.visibility, t.created_at "
                 "FROM threads t JOIN users u ON u.id=t.author_id WHERE u.disabled_at IS NULL AND ")
            rows = b.execute(q + ("t.id > ? ORDER BY t.id LIMIT ?" if dernier is not None
                                  else "t.created_at >= ? ORDER BY t.id LIMIT ?"),
                             (dernier if dernier is not None else plancher, LOT)).fetchall()
            for tid, cat, h, titre, vis, at in rows:
                emet("bbs_post", tid, cat, vis, at, h, {"titre": titre, "lien": f"/bbs/t/{tid}"})
            if rows:
                cur["fils"] = rows[-1][0]
            elif dernier is None:
                cur["fils"] = b.execute("SELECT COALESCE(MAX(id),0) FROM threads").fetchone()[0]

            # fichiers déposés
            dernier = cur.get("fichiers")
            q = ("SELECT f.id, f.category_id, u.handle, f.name, f.visibility, f.created_at "
                 "FROM files f JOIN users u ON u.id=f.owner_id WHERE f.deleted_at IS NULL "
                 "AND u.disabled_at IS NULL AND ")
            rows = b.execute(q + ("f.id > ? ORDER BY f.id LIMIT ?" if dernier is not None
                                  else "f.created_at >= ? ORDER BY f.id LIMIT ?"),
                             (dernier if dernier is not None else plancher, LOT)).fetchall()
            for fid, cat, h, nom, vis, at in rows:
                emet("file_shared", fid, cat, vis, at, h, {"nom": nom, "lien": f"/bbs/f/{fid}"})
            if rows:
                cur["fichiers"] = rows[-1][0]
            elif dernier is None:
                cur["fichiers"] = b.execute("SELECT COALESCE(MAX(id),0) FROM files").fetchone()[0]
        finally:
            b.close()

    # diffusions du Hall (auteur libre, non authentifié : « diffusion »)
    try:
        hist = json.loads(diffusions.read_text())
    except (OSError, ValueError):
        hist = []
    dernier = cur.get("diffusions", plancher)
    nouveaux = sorted((h for h in hist if isinstance(h, dict) and float(h.get("ts", 0)) > dernier),
                      key=lambda h: float(h["ts"]))
    for h in nouveaux:
        S.emet_activite(sbx, "radio_live", author="diffusion", visibility="node", origin_node=origine,
                        context={"titre": str(h.get("titre", ""))[:200], "url": str(h.get("url", ""))[:500]},
                        at=int(float(h["ts"])))
        emis["radio_live"] += 1
    if nouveaux:
        cur["diffusions"] = float(nouveaux[-1]["ts"])
    else:
        cur.setdefault("diffusions", float(maintenant))
    return emis, cur
