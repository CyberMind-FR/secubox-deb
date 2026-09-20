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
un module qui, lui, commande une messagerie chiffrée de bout en bout. Le jeton
rejoint donc les autres identités du profil : `/etc/secubox/secrets/webos-acces/
<qui>/signal`, en 0600, derrière le login (#1309).

Le démon n'écoute que sur une socket Unix ; ce pont est le seul à la joindre
pour le compte d'un humain, et il n'expose que ce qu'une carte a le droit de
savoir.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from . import acces

# Le démon n'a pas de port : on parle à sa socket. httpx sait le faire via un
# transport UDS, ce qui évite d'ouvrir quoi que ce soit sur le réseau.
_SOCKET = "/run/secubox/signal.sock"
_BASE = "http://signal/api/v1/signal"
_DELAI = 15.0


def _jeton(qui: str) -> Optional[str]:
    """Le jeton de session Signal de cette personne, ou None."""
    d = acces.secret_de(qui, "signal")
    if not d or not d.get("secret"):
        return None
    return str(d["secret"])


def _vide(detail: str) -> dict:
    return {"ok": False, "detail": detail}


async def _appel(qui: str, methode: str, chemin: str,
                 corps: Any = None) -> dict:
    """Un appel au démon, au nom de `qui`.

    AUCUNE EXCEPTION NE REMONTE TELLE QUELLE : son texte peut contenir l'URL,
    donc le jeton. On rend une raison courte et typée — la même règle que
    nc_super, et pour la même raison.
    """
    jeton = _jeton(qui)
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


async def envoyer(qui: str, dest: str, corps: str) -> dict:
    """Envoyer AU NOM de la personne. La destination et le corps viennent de
    la carte ; le jeton, lui, ne la traverse jamais."""
    if not dest or not corps:
        return _vide("destinataire et corps requis")
    cle = "to" if dest.startswith("+") else "group_id"
    return await _appel(qui, "POST", "/messages", {cle: dest, "body": corps})
