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
# CE QUE LE DEPOT SAIT PUBLIER. La liste vient de sa propre docstring — page
# HTML seule, archive ZIP ou TAR. Refuser ici, avec le motif, vaut mieux que
# televerser cent megaoctets pour se faire dire non a l'arrivee.
DEPOT_EXTENSIONS = (".html", ".htm", ".zip", ".tar.gz", ".tgz")

# PLAFOND DE TAILLE, cote Hall. Le depot a le sien (`max_upload_mb`), mais il
# ne le fait respecter qu'apres avoir tout recu : sans plafond ici, une carte
# pourrait faire tamponner n'importe quel volume en memoire par l'API du Hall.
DEPOT_MAX = 100 * 1024 * 1024

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


async def depose_fichier(nom_fichier: str, contenu: bytes, mime: str,
                         nom: str = "", jeton: str = "") -> dict:
    """Publier un fichier au depot — la fonction MEME du service.

    La carte listait et retirait, mais ne deposait pas : elle parlait d'un
    service sans savoir faire ce pour quoi il existe. Le trajet est
    multipart, ce que `agir()` ne sait pas faire — d'ou cette fonction a part
    plutot qu'une entree de plus dans ACTIONS, qui ne decrit que du JSON.
    """
    base = (nom_fichier or "").strip().lower()
    if not base:
        return {"ok": False, "detail": "fichier sans nom"}
    if not base.endswith(DEPOT_EXTENSIONS):
        return {"ok": False,
                "detail": "le depot publie des pages et des archives : "
                          + ", ".join(DEPOT_EXTENSIONS)}
    if not contenu:
        return {"ok": False, "detail": "fichier vide"}
    if len(contenu) > DEPOT_MAX:
        return {"ok": False,
                "detail": "%d Mo — au-dela des %d Mo acceptes"
                          % (len(contenu) // (1024 * 1024), DEPOT_MAX // (1024 * 1024))}

    entetes = {"Host": HOTE_ADMIN, "Accept": "application/json"}
    if jeton:
        entetes["Authorization"] = "Bearer " + jeton

    donnees = {}
    # On ne transmet le nom que s'il a ete choisi : sans lui, le depot le
    # derive du fichier, et il le fait mieux que nous ne le devinerions.
    if nom.strip():
        donnees["name"] = nom.strip()

    try:
        async with httpx.AsyncClient(timeout=300) as cli:
            r = await cli.post(
                AMONT + "/api/v1/droplet/upload",
                headers=entetes,
                data=donnees,
                files={"file": (nom_fichier, contenu,
                                mime or "application/octet-stream")},
            )
    except httpx.HTTPError as e:
        return {"ok": False, "detail": "depot injoignable : %s" % type(e).__name__}

    try:
        d = r.json()
    except ValueError:
        return {"ok": False, "detail": "reponse illisible (%d)" % r.status_code}

    if r.status_code >= 400:
        detail = d.get("error") or d.get("detail") or ("refus %d" % r.status_code)
        return {"ok": False, "detail": str(detail)[:200]}

    return {"ok": True, "donnees": d}
