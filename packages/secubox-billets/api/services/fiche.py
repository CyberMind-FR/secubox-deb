# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Fiche média d'un billet relayé (#1268).

POURQUOI. Les billets venus du miroir portent tous la même fiche dans leur
corps — titre répété, ligne chaîne/durée, puis trois libellés suivis d'URLS
NUES. Rendue telle quelle, ça donne une page où le contenu principal est une
liste d'adresses de deux cents caractères : illisible, et faux, puisque ce sont
des BOUTONS déguisés en texte. 199 billets sont dans ce cas.

CE QU'ON FAIT. On reconnaît cette forme, on en extrait des données (chaîne,
durée, liens typés) que la page rend en pastilles, et on rend le RESTE comme
prose. Rien n'est réécrit en base : la transformation est une lecture.

PRUDENCE. Si le corps ne ressemble pas à une fiche, on ne touche à rien et la
prose sort intacte — mieux vaut une page ordinaire qu'une page mutilée par un
extracteur trop sûr de lui.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# `👤 Chaîne · ⏱ 9:40` — la durée est facultative, la chaîne aussi.
_META = re.compile(r"^[ \t]*👤[ \t]*(?P<chaine>[^·\n]*?)"
                   r"(?:[ \t]*·[ \t]*⏱[ \t]*(?P<duree>[0-9:]{1,9}))?[ \t]*$", re.M)
# `🎬 **Source :** https://…` — libellé en gras, adresse nue.
_LIEN = re.compile(r"^[ \t]*(?P<ico>[^\s*])[ \t]*\*\*(?P<label>[^*:]{2,40}?)[ \t]*:\*\*"
                   r"[ \t]*(?P<url>https?://\S+)[ \t]*$", re.M)
_TITRE = re.compile(r"\A\s*#[^\n]*\n")
_REGLE = re.compile(r"^[ \t]*---[ \t]*$", re.M)


def _genre(url: str) -> str:
    """Type de lien, d'après l'hôte — c'est lui qui dit la nature, pas le libellé."""
    h = (urlparse(url).hostname or "").lower()
    if "youtube" in h or "youtu.be" in h:
        return "yt"
    if "peertube" in h:
        return "pt"
    if "ytsas" in h:
        return "box"
    return "autre"


def extraire(body: str) -> tuple[dict, str]:
    """(fiche, reste). `fiche` est vide si le corps n'en est pas une."""
    if not body:
        return {}, body or ""
    liens = []
    for m in _LIEN.finditer(body):
        url = m.group("url").rstrip(".,;)")
        liens.append({"ico": m.group("ico"), "label": m.group("label").strip(),
                      "url": url, "genre": _genre(url),
                      "hote": (urlparse(url).hostname or "")})
    meta = _META.search(body)
    if not liens and not meta:
        return {}, body

    reste = _LIEN.sub("", body)
    if meta:
        reste = reste[:meta.start()] + reste[meta.end():] if meta.end() <= len(reste) else reste
        reste = _META.sub("", reste)
    reste = _TITRE.sub("", reste, count=1)
    reste = _REGLE.sub("", reste)
    reste = re.sub(r"\n{3,}", "\n\n", reste).strip()

    fiche = {
        "chaine": (meta.group("chaine").strip() if meta and meta.group("chaine") else ""),
        "duree": (meta.group("duree") if meta and meta.group("duree") else ""),
        "liens": liens,
    }
    return fiche, reste


def secondes(duree: str) -> int | None:
    """`9:40` → 580. None si ce n'est pas une durée — sert à situer les messages
    ancrés dans la longueur de la vidéo."""
    if not duree:
        return None
    parts = duree.split(":")
    if not all(p.isdigit() for p in parts) or not 1 < len(parts) <= 3:
        return None
    t = 0
    for p in parts:
        t = t * 60 + int(p)
    return t
