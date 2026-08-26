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
#
# CHAQUE MODULE DIT SON HÔTE. Tous ne vivent pas sur la console
# d'administration : YTSaS sert la sienne sur son propre vhost, ce qui explique
# pourquoi ses routes semblaient introuvables tant qu'on les cherchait ailleurs.
HOTES: dict[str, str] = {
    "torrent": HOTE_ADMIN,
    "droplet": HOTE_ADMIN,
    "ytsas":   os.environ.get("SECUBOX_YTSAS_HOTE", "ytsas.gk2.secubox.in"),
}

ACTIONS: dict[str, dict[str, tuple]] = {
    "torrent": {
        "liste":   ("GET",  "/api/v1/torrent/list", ()),
        "ajouter": ("POST", "/api/v1/torrent/add", ("magnet",)),
        "pause":   ("POST", "/api/v1/torrent/{id}/pause", ()),
        "reprise": ("POST", "/api/v1/torrent/{id}/resume", ()),
    },
    "ytsas": {
        # UNE SEULE FONCTION, ET C'EST ASSUMÉ : une URL, un bouton. La capture
        # alimente ensuite le podcaster et la radio, qui savent déjà lire ce
        # qu'elle dépose — on ne réinvente pas ce chaînage, on lui donne
        # seulement une porte de plus.
        "liste":     ("GET",  "/api/v1/ytsas/list", ()),
        "ajouter":   ("POST", "/api/v1/ytsas/add", ("url",)),
        "conserver": ("POST", "/api/v1/ytsas/conserve/{id}", ()),
    },
    "droplet": {
        # Le dépôt a mieux que sa liste — souvent vide : son historique dit ce
        # qui a été déposé, son stockage ce qu'il en reste. Ces deux routes
        # sont AUTHENTIFIEES en amont, d'où le passage du jeton.
        "liste":      ("GET",  "/api/v1/droplet/list", ()),
        "stockage":   ("GET",  "/api/v1/droplet/storage", ()),
        # SUPPRIMER EST DESTRUCTIF : la carte demande confirmation avant de
        # l'appeler. On l'expose quand meme, parce qu'un depot ou l'on ne peut
        # que deposer se remplit et ne se vide jamais.
        "supprimer":  ("POST", "/api/v1/droplet/remove", ("name",)),
    },
}

# Deux familles d'identifiants, et les confondre reviendrait à en accepter un
# trop large : un torrent est une empreinte hexadécimale, un média YTSaS porte
# l'identifiant de la plateforme d'origine, qui admet lettres, chiffres, tiret
# et souligné.
# L'HOTE DU DEPOT PUBLIC. Il n'est pas celui de l'admin : `/depot` est servi
# sur le domaine public du service, et c'est voulu — deposer ne demande aucun
# compte, c'est la raison d'etre de cet espace.
HOTE_DEPOT = os.environ.get("SECUBOX_DEPOT_HOTE", "depot.gk2.secubox.in")

_ID_HEX = "abcdef0123456789"
_ID_MEDIA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"


def _id_sur(v: str, module: str = "") -> str:
    permis = _ID_MEDIA if module == "ytsas" else _ID_HEX
    v = str(v or "")
    if permis is _ID_HEX:
        v = v.lower()
    return "".join(c for c in v if c in permis)[:64]


async def agir(module: str, action: str, corps: dict | None = None,
               jeton: str = "") -> dict:
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
        ident = _id_sur(corps.get("id"), module)
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

    entetes = {"Host": HOTES.get(module, HOTE_ADMIN), "Accept": "application/json"}
    # ON TRANSMET LE JETON DE L'APPELANT quand il y en a un. Certains modules
    # protègent leurs routes de lecture ; y aller anonymement rendrait un 401
    # que la carte afficherait sans pouvoir rien y faire.
    #
    # Ce n'est PAS une élévation : c'est la même personne, sur la même box, dans
    # le même domaine d'authentification. On ne fabrique aucun droit, on relaie
    # celui qui a déjà été prouvé.
    if jeton:
        entetes["Authorization"] = "Bearer " + jeton

    try:
        async with httpx.AsyncClient(timeout=20) as cli:
            r = await cli.request(
                methode, AMONT + chemin,
                headers=entetes,
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


# ── LE DEPOT PUBLIC ────────────────────────────────────────────────────────
#
# DEUX VERBES A NE PAS CONFONDRE, et la carte s'y etait trompee :
#   /upload  publie un site ou une application — reserve, authentifie ;
#   /depot   RECOIT un fichier — public, sans compte, rien n'est publie.
#
# Le second est la raison d'etre du service. C'est celui que la carte doit
# offrir : « laissez vos fichiers ici », pas « publiez un site ».

async def reglages_depot() -> dict:
    """Les plafonds, AVANT l'envoi.

    Decouvrir une limite en se la prenant apres dix minutes de televersement
    est la pire facon de l'apprendre — la page du service le dit deja, la
    carte le dira aussi.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as cli:
            r = await cli.get(AMONT + "/api/v1/droplet/depot/reglages",
                              headers={"Host": HOTE_DEPOT, "Accept": "application/json"})
        if r.status_code >= 400:
            return {"ok": False, "detail": "reglages indisponibles"}
        return {"ok": True, "donnees": r.json()}
    except (httpx.HTTPError, ValueError):
        return {"ok": False, "detail": "depot injoignable"}


async def relaie_depot(request) -> tuple:
    """Faire passer un depot du Hall au service, SANS RIEN GARDER AU PASSAGE.

    Le corps est relaye TEL QUEL, en flux. On ne l'analyse pas, on ne le
    tamponne pas : le depot accepte deux gigaoctets, et les mettre en memoire
    ici pour le seul plaisir de les recompter serait une facon sure de tuer
    l'API du Hall avec un seul envoi.

    L'ADRESSE D'ORIGINE EST TRANSMISE. Le service borne son debit par adresse ;
    relayer sans elle ferait de tous les depots ceux d'une seule machine — la
    notre — et le limiteur ne bornerait plus rien.
    """
    ct = request.headers.get("content-type", "")
    if not ct.startswith("multipart/form-data"):
        return 400, {"ok": False, "detail": "envoi multipart attendu"}

    entetes = {"Host": HOTE_DEPOT, "Content-Type": ct, "Accept": "application/json"}
    cl = request.headers.get("content-length")
    if cl:
        entetes["Content-Length"] = cl
    # On preserve la chaine existante si nginx en a pose une, sinon on nomme
    # le client. Le service lit la PREMIERE entree.
    amont = request.headers.get("x-forwarded-for")
    if amont:
        entetes["X-Forwarded-For"] = amont
    elif request.client:
        entetes["X-Forwarded-For"] = request.client.host

    try:
        async with httpx.AsyncClient(timeout=None) as cli:
            r = await cli.post(AMONT + "/api/v1/droplet/depot",
                               headers=entetes, content=request.stream())
    except httpx.HTTPError as e:
        return 502, {"ok": False, "detail": "depot injoignable : %s" % type(e).__name__}

    try:
        d = r.json()
    except ValueError:
        return r.status_code, {"ok": False,
                               "detail": "reponse illisible (%d)" % r.status_code}

    if r.status_code >= 400:
        detail = d.get("error") or d.get("detail") or ("refus %d" % r.status_code)
        return r.status_code, {"ok": False, "detail": str(detail)[:200]}

    return 200, {"ok": True, "donnees": d}
