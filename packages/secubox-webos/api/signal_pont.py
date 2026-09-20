# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: WebOS — pont vers SBX-SIGNAL, côté serveur.

MÊME DOCTRINE QUE `nc_super` : le broker (`acces.py`) garde le jeton de session
Signal DANS la box, et cette couche parle au démon `sbx-signald` AU NOM de la
personne. La carte reçoit des états, des compteurs et le résultat de ses
propres actions — jamais le jeton.

POURQUOI UN PONT PLUTÔT QU'UN JETON DANS LE NAVIGATEUR. La page du module
lisait d'abord son jeton dans `localStorage`. C'est la convention de plusieurs
cartes du parc, mais elle place un secret durable dans un stockage que toute
extension, tout XSS et toute personne ayant accès à la machine peut lire — pour
un module qui, lui, commande une messagerie chiffrée de bout en bout.

Ce qui vit dans les identités du profil — `/etc/secubox/secrets/webos-acces/
<qui>/signal`, 0600, derrière le login — est donc l'AUTORISATION, pas un
secret : sa présence dit que cette personne a autorisé la passerelle. Le jeton
présenté au démon est forgé ici, pour un appel, et vaut 60 secondes (#1309).

Le démon n'écoute que sur une socket Unix ; ce pont est le seul à la joindre
pour le compte d'un humain, et il n'expose que ce qu'une carte a le droit de
savoir.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from . import acces

try:
    from secubox_core import auth
except ImportError:  # arbre de developpement
    import sys
    sys.path.insert(0, "/usr/lib/python3/dist-packages")
    from secubox_core import auth

# Le démon n'a pas de port : on parle à sa socket. httpx sait le faire via un
# transport UDS, ce qui évite d'ouvrir quoi que ce soit sur le réseau.
_SOCKET = "/run/secubox/signal.sock"
_BASE = "http://signal/api/v1/signal"
_DELAI = 15.0


def _jeton(qui: str) -> Optional[str]:
    """Un jeton COURT et PORTE, forge pour cet appel-ci.

    CE QUI A CHANGE, ET POURQUOI. La premiere version presentait au demon le
    secret lu dans le coffre. C'etait faux a deux titres : le demon attend un
    JWT du parc, et un secret depose a la main n'en est pas un — l'appel
    echouait sur « jeton mal forme ». Mais surtout, un secret DURABLE presente
    a chaque requete se rejoue ; un jeton de 60 secondes, non.

    Le coffre garde donc ce qu'il sait le mieux garder : l'AUTORISATION. Sa
    presence dit que cette personne a autorise la passerelle, derriere son
    login. Le jeton, lui, est forge ici, pour cet appel, et meurt avec lui.
    """
    if not acces.a_acces(qui, "signal"):
        return None
    # `scope` porte l'intention : un jeton taille pour Signal n'ouvre rien
    # d'autre, et sa duree se compte en secondes parce qu'il ne sert qu'a
    # traverser une socket locale.
    return auth.create_token(qui, expires_in=60, scope="signal")


def _vide(detail: str) -> dict:
    return {"ok": False, "detail": detail}


async def _appel(qui: str, methode: str, chemin: str,
                 corps: Any = None) -> dict:
    """Un appel au démon, au nom de `qui`.

    AUCUNE EXCEPTION NE REMONTE TELLE QUELLE : son texte peut contenir l'URL,
    donc le jeton. On rend une raison courte et typée — la même règle que
    nc_super, et pour la même raison.
    """
    try:
        jeton = _jeton(qui)
    except Exception:
        # create_token leve si aucun secret n'est provisionne. On ne relaie
        # pas le detail : son texte nomme le fichier de configuration.
        return _vide("secret du parc non configuré")
    if not jeton:
        return _vide("aucun accès Signal pour ce profil")
    transport = httpx.AsyncHTTPTransport(uds=_SOCKET)
    try:
        async with httpx.AsyncClient(transport=transport, timeout=_DELAI) as c:
            r = await c.request(methode, _BASE + chemin,
                                headers={"Authorization": "Bearer " + jeton},
                                json=corps)
            if r.status_code == 401:
                return _vide("jeton refusé par le démon — à redéposer")
            if r.status_code >= 500:
                return _vide("démon en erreur")
            return {"ok": True, "data": r.json()}
    except httpx.ConnectError:
        return _vide("démon injoignable")
    except Exception:
        # Volontairement muet sur le detail : voir la docstring.
        return _vide("échec de l'appel")


async def etat(qui: str) -> dict:
    """Ce qu'une carte a le droit de savoir : lié ou non, backend, rétention."""
    return await _appel(qui, "GET", "/status")


async def contacts(qui: str) -> dict:
    return await _appel(qui, "GET", "/contacts")


async def groupes(qui: str) -> dict:
    return await _appel(qui, "GET", "/groups")


async def lier(qui: str) -> dict:
    """Demarrer l'appairage. Le QR revient en SVG, deja trace par le demon :
    l'URI `sgnl://` qu'il encode lie quiconque la scanne, et ne doit donc
    exister nulle part ailleurs que dans cette image."""
    return await _appel(qui, "POST", "/link/start")


async def lier_etat(qui: str) -> dict:
    return await _appel(qui, "GET", "/link/status")


async def delier(qui: str) -> dict:
    """Delier le compte. IRREVERSIBLE — un nouvel appairage sera necessaire."""
    return await _appel(qui, "DELETE", "/link")


async def envoyer(qui: str, dest: str, corps: str) -> dict:
    """Envoyer AU NOM de la personne. La destination et le corps viennent de
    la carte ; le jeton, lui, ne la traverse jamais."""
    if not dest or not corps:
        return _vide("destinataire et corps requis")
    cle = "to" if dest.startswith("+") else "group_id"
    return await _appel(qui, "POST", "/messages", {cle: dest, "body": corps})
