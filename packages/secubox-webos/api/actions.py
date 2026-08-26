# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: WebOS — actions des modules depuis une carte
CyberMind — https://cybermind.fr

POURQUOI CE MODULE EXISTE PLUTÔT QU'UN RELAIS.

Les cartes d'accès rapide lisent déjà l'état de leur module par un relais nginx
restreint à `/status`. Pour AGIR, ce chemin ne convient pas : l'API
d'administration répond `400` — et non `401` — à un `POST /torrent/add` sans
jeton. Elle n'est donc pas authentifiée, et la relayer telle quelle ouvrirait
l'ajout de torrents à tout le réseau local, sur un Hall joignable sans se
connecter.

L'autorisation est donc la NÔTRE, et elle est explicite : la route exige un
jeton, et la liste des actions est CLOSE. Un module ne peut pas se voir
adresser une action qui n'est pas écrite ici, quand bien même son API l'offre.

CE QUI N'EST PAS FAIT ICI. On ne valide pas le CONTENU d'une action au-delà de
sa forme : c'est le module qui sait ce qu'est un magnet valable, et lui mentir
sur ce point serait dupliquer une règle qui vivra deux vies.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

# L'API d'administration est servie par le nginx local, sur le vhost admin.
AMONT = os.environ.get("SECUBOX_ADMIN_AMONT", "http://127.0.0.1:9080")
HOTE_ADMIN = os.environ.get("SECUBOX_ADMIN_HOTE", "admin.gk2.secubox.in")

# ── LA LISTE CLOSE ─────────────────────────────────────────────────────────
#
# `(méthode, chemin, champs attendus)`. Le chemin peut porter `{id}`, remplacé
# par un identifiant assaini — jamais interpolé tel quel : un identifiant venu
# du réseau qui entre dans une URL est une traversée de chemin en puissance.
ACTIONS: dict[str, dict[str, tuple]] = {
    "torrent": {
        "liste":   ("GET",  "/api/v1/torrent/list", ()),
        "ajouter": ("POST", "/api/v1/torrent/add", ("magnet",)),
        "pause":   ("POST", "/api/v1/torrent/{id}/pause", ()),
        "reprise": ("POST", "/api/v1/torrent/{id}/resume", ()),
    },
    "ytsas": {
        # Rien : sa route d'action n'a pas été trouvée, et un bouton qui ne
        # fait rien est pire qu'un bouton absent.
    },
    "droplet": {
        "liste":   ("GET",  "/api/v1/droplet/list", ()),
    },
}

# Un identifiant de torrent est une empreinte : hexadécimal, rien d'autre.
_ID_OK = "abcdef0123456789"


def _id_sur(v: str) -> str:
    return "".join(c for c in str(v or "").lower() if c in _ID_OK)[:64]


async def agir(module: str, action: str, corps: dict | None = None) -> dict:
    """Exécuter une action nommée, et rien d'autre."""
    m = ACTIONS.get(module)
    if not m:
        return {"ok": False, "detail": "module inconnu"}
    a = m.get(action)
    if not a:
        return {"ok": False, "detail": "action non autorisee"}

    methode, chemin, champs = a
    corps = corps or {}

    if "{id}" in chemin:
        ident = _id_sur(corps.get("id"))
        if not ident:
            return {"ok": False, "detail": "identifiant absent ou invalide"}
        chemin = chemin.replace("{id}", ident)

    charge: dict[str, Any] = {}
    for c in champs:
        v = corps.get(c)
        if v in (None, ""):
            return {"ok": False, "detail": "champ requis : %s" % c}
        # Une borne de taille, pas une validation de fond : un magnet fait
        # quelques centaines d'octets, et accepter un mégaoctet ici ne
        # servirait qu'a remplir le journal de quelqu'un d'autre.
        charge[c] = str(v)[:2048]

    try:
        async with httpx.AsyncClient(timeout=20) as cli:
            r = await cli.request(
                methode, AMONT + chemin,
                headers={"Host": HOTE_ADMIN, "Accept": "application/json"},
                json=charge if methode == "POST" else None,
            )
    except httpx.HTTPError as e:
        return {"ok": False, "detail": "module injoignable : %s" % type(e).__name__}

    try:
        d = r.json()
    except ValueError:
        return {"ok": False, "detail": "reponse illisible (%d)" % r.status_code}

    if r.status_code >= 400:
        # On rend le message du MODULE : c'est lui qui sait pourquoi il refuse,
        # et le réécrire ici en ferait une devinette.
        detail = d.get("error") or d.get("detail") or ("refus %d" % r.status_code)
        return {"ok": False, "detail": str(detail)[:200]}

    return {"ok": True, "donnees": d}
