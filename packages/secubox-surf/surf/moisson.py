# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: Surf — la moisson (garder chez soi ce qu'on a écouté)
CyberMind — https://cybermind.fr

L'IDÉE. Un média embarqué dans une page relayée est déjà passé PAR LA BOX : le
relais l'a cherché, inspecté, servi. Le laisser repartir sans trace oblige à le
redemander à chaque écoute — au site, qui peut le retirer, le déplacer, ou
disparaître. La moisson en garde une copie LOCALE, sous l'origine de la box, et
la sert ensuite sans sortir.

CE N'EST PAS UN CACHE. Un cache se vide tout seul et n'appartient à personne.
Ici, c'est un GESTE : quelqu'un a décidé de garder ceci. Rien n'est moissonné
en passant, rien n'expire de soi-même, et ce qui est gardé porte d'où il vient.

CE QUE ÇA N'EST PAS NON PLUS : un aspirateur. Une seule pièce à la fois, sur
demande explicite, avec un plafond de taille — la board a 15 Go de carte et
une moisson silencieuse la remplirait sans que personne ne comprenne pourquoi.
"""
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import time
from pathlib import Path

# Le SSD, pas la carte SD : un média pèse, et /var/lib/secubox est monté sur
# /data depuis la migration (#1323). On reste donc sous ce chemin.
RACINE = Path(os.environ.get("SURF_MOISSON", "/var/lib/secubox/surf/moisson"))
INDEX = RACINE / "index.json"

# Un média, pas une page : on refuse le reste plutôt que de constituer une
# copie d'Internet par mégarde.
TYPES = ("audio/", "video/", "image/", "application/ogg", "application/x-mpegurl",
         "application/vnd.apple.mpegurl")
# 2 Gio : large pour un épisode ou un film, étroit pour une bêtise.
PLAFOND = int(os.environ.get("SURF_MOISSON_MAX", str(2 * 1024 * 1024 * 1024)))

_SALE = re.compile(r"[^A-Za-z0-9._-]+")


def _nom_sur(titre: str, ext: str) -> str:
    """Un nom de fichier LISIBLE mais inoffensif.

    Le titre vient d'une page distante : il peut porter des barres obliques,
    des points d'ascension, des octets nuls. On le réduit à un alphabet sûr et
    on le borne — le chemin final ne doit pas pouvoir sortir de la moisson.
    """
    base = _SALE.sub("-", (titre or "media").strip())[:80].strip("-.") or "media"
    return base + ext


def _index() -> list:
    try:
        return json.loads(INDEX.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — index absent ou abîmé : on repart d'une liste
        return []


def _ecris_index(entrees: list) -> None:
    RACINE.mkdir(parents=True, exist_ok=True)
    tmp = INDEX.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(entrees, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, INDEX)


def liste() -> list:
    """Ce qui est gardé, du plus récent au plus ancien."""
    return sorted(_index(), key=lambda e: e.get("quand", 0), reverse=True)


def deja(url: str) -> dict | None:
    """Cette adresse a-t-elle déjà été gardée ? (pour ne pas la reprendre)"""
    cle = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return next((e for e in _index() if e.get("cle") == cle), None)


def range_media(url: str, titre: str, mime: str, corps: bytes,
                origine: str = "") -> dict:
    """Garde UNE pièce et rend sa fiche.

    Le fichier est nommé par son titre pour qu'on le reconnaisse, mais préfixé
    d'une empreinte de l'URL : deux épisodes homonymes ne doivent pas s'écraser,
    et re-garder la même adresse doit retomber sur la même pièce.
    """
    # UN SERVEUR MUET NE DOIT PAS BLOQUER UNE PIECE LEGITIME. Beaucoup de
    # serveurs omettent `content-type` ou rendent `application/octet-stream` :
    # refuser sur ce seul motif écarterait des médias parfaitement valides
    # (constaté sur un favicon servi sans type). On retombe alors sur
    # l'extension de l'URL, qui est une DEUXIEME source, pas une invention.
    if not mime or mime == "application/octet-stream":
        devine, _ = mimetypes.guess_type(url.split("?")[0])
        if devine:
            mime = devine
    if not any(mime.startswith(t) for t in TYPES):
        raise ValueError(f"type refusé : {mime or 'inconnu'}")
    if len(corps) > PLAFOND:
        raise ValueError(f"trop volumineux : {len(corps)} octets (plafond {PLAFOND})")
    if not corps:
        raise ValueError("corps vide")

    cle = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    ext = mimetypes.guess_extension(mime.split(";")[0].strip()) or ".bin"
    nom = f"{cle}-{_nom_sur(titre, ext)}"
    RACINE.mkdir(parents=True, exist_ok=True)
    chemin = RACINE / nom
    # Écriture atomique : la liste ne doit jamais désigner un fichier à moitié
    # écrit, qu'un lecteur ouvrirait au milieu d'un téléchargement.
    tmp = chemin.with_suffix(chemin.suffix + ".part")
    tmp.write_bytes(corps)
    os.replace(tmp, chemin)

    fiche = {"cle": cle, "nom": nom, "titre": titre or nom, "source": url,
             "origine": origine, "mime": mime, "taille": len(corps),
             "quand": int(time.time())}
    entrees = [e for e in _index() if e.get("cle") != cle]
    entrees.append(fiche)
    _ecris_index(entrees)
    return fiche


def chemin_de(cle: str) -> Path | None:
    """Le fichier d'une pièce, ou None. Le nom vient de l'index, jamais de
    l'appelant : c'est ce qui interdit de remonter hors de la moisson."""
    e = next((x for x in _index() if x.get("cle") == cle), None)
    if not e:
        return None
    p = (RACINE / e["nom"]).resolve()
    try:
        p.relative_to(RACINE.resolve())
    except ValueError:
        return None
    return p if p.is_file() else None


def oublie(cle: str) -> bool:
    """Retire une pièce — le fichier ET sa fiche."""
    e = next((x for x in _index() if x.get("cle") == cle), None)
    if not e:
        return False
    p = chemin_de(cle)
    if p:
        try:
            p.unlink()
        except OSError:
            pass
    _ecris_index([x for x in _index() if x.get("cle") != cle])
    return True
