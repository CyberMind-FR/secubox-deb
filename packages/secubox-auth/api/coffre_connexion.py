# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: auth — la connexion ouvre le Coffre de l'administrateur, et le
compartiment de toute personne (#1855)
CyberMind — https://cybermind.fr

Pas de phrase propre au Coffre : sa serrure, c'est le mot de passe de
connexion, rejoué en deux temps.

1. `/login`, mot de passe vérifié : on demande au Coffre de PRÉPARER. Il
   revérifie le mot de passe (users.json) et le rôle, déballe sa clé et la
   met en attente ; il rend un ticket. Le mot de passe ne reste pas ici.
2. Le second facteur réussit (`/login/mfa`, `/totp/confirm`, ou une
   connexion LAN sans second facteur exigé) : on CONFIRME le ticket, le
   Coffre s'ouvre. Un mot de passe sans second facteur n'ouvre rien.

Le ticket attend sous le jti du jeton de défi, cinq à quinze minutes, dans CE
processus. Tout échec est muet : le Coffre ne bloque jamais une connexion.
Jamais le mot de passe dans un journal, une ligne de commande ou une erreur.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from typing import Dict, Optional, Tuple

SOCKET = os.environ.get("SECUBOX_COFFRE_SOCKET", "/run/secubox/vault.sock")
_tickets: Dict[str, Tuple[str, bool, float]] = {}
_verrou = threading.Lock()


class _Unix(http.client.HTTPConnection):
    def __init__(self, timeout: float):
        super().__init__("localhost", timeout=timeout)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)


def _appel(chemin: str, corps: dict, delai: float = 10.0) -> Optional[dict]:
    if not os.path.exists(SOCKET):
        return None
    c = _Unix(delai)
    try:
        c.request("POST", chemin, body=json.dumps(corps), headers={"Content-Type": "application/json"})
        r = c.getresponse()
        donnees = r.read()
        return json.loads(donnees) if r.status == 200 else None
    except (OSError, ValueError):
        return None
    finally:
        c.close()


def preparer(utilisateur: str, mot_de_passe: str) -> Optional[str]:
    """Rend un ticket, ou None (Coffre absent, rien à ouvrir).

    Un administrateur prépare l'ouverture du Coffre ET, s'il en a une, celle de
    sa personne. Tout autre compte — utilisateur, invité avec compte — ne
    prépare que SON compartiment : jamais la clé maîtresse (#1855)."""
    try:
        from secubox_core import second_facteur  # noqa: PLC0415
        admin = second_facteur.compte_admin_actif(utilisateur)
    except Exception:  # noqa: BLE001
        return None
    chemin = "/compte/preparer" if admin else "/personne/preparer"
    r = _appel(chemin, {"utilisateur": utilisateur, "mot_de_passe": mot_de_passe})
    return (r or {}).get("ticket")


def garder(jti: str, ticket: Optional[str], distante: bool, duree_s: int) -> None:
    if not ticket or not jti:
        return
    with _verrou:
        t = time.monotonic()
        for k in [k for k, v in _tickets.items() if v[2] < t]:
            _tickets.pop(k, None)
        _tickets[jti] = (ticket, distante, t + duree_s)


def confirmer(ticket: Optional[str], distante: bool) -> bool:
    if not ticket:
        return False
    return bool((_appel("/compte/confirmer", {"ticket": ticket, "distante": distante}) or {}).get("ouvert"))


def confirmer_garde(jti: str) -> bool:
    """Le second facteur a réussi pour ce jeton de défi : on ouvre."""
    with _verrou:
        v = _tickets.pop(jti or "", None)
    if not v or v[2] < time.monotonic():
        return False
    return confirmer(v[0], v[1])


def changer(utilisateur: str, ancien: str, nouveau: str) -> None:
    """Après un changement de mot de passe : réemballer la serrure du compte."""
    def _travail():
        corps = {"utilisateur": utilisateur, "ancien": ancien, "nouveau": nouveau}
        _appel("/compte/changer", corps)        # la serrure d'administrateur, s'il en a une
        _appel("/personne/changer", corps)      # la serrure « compte » de sa personne
    threading.Thread(target=_travail, daemon=True).start()
