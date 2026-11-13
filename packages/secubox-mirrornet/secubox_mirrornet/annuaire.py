# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Client des routes /self/... de l'annuaire LOCAL (#3647), par sa socket Unix — jamais l'agrégateur, jamais le réseau.

MirrorNet ne signe rien lui-même : l'annuaire signe avec node.key, dans le compte qui la détient. Le jeton relayé est
celui de l'ADMINISTRATEUR qui appelle MirrorNet (aucun jeton de service n'est fabriqué ici) ; l'annuaire le revérifie.
"""
from __future__ import annotations

import http.client
import json
import socket
from typing import Any, Dict, Optional, Tuple

from . import config

DELAI = 15.0


class _Connexion(http.client.HTTPConnection):
    def __init__(self, chemin: str, delai: float):
        super().__init__("localhost", timeout=delai)
        self._chemin = chemin

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._chemin)
        self.sock = s


def appeler(chemin: str, corps: Optional[Dict[str, Any]], jeton: Optional[str],
            socket_chemin: Optional[str] = None) -> Tuple[int, Any]:
    """POST vers l'annuaire avec LE jeton validé par la garde de MirrorNet. Rend (statut HTTP, corps JSON).

    503 : connexion impossible — rien n'a été envoyé, rien n'a pu être signé.
    504 : requête envoyée sans réponse lisible (délai, coupure) — le geste a PU être signé : résultat indéterminé."""
    if not jeton:
        return 401, {"detail": "aucun jeton à relayer"}
    cx = _Connexion(socket_chemin or config.ANNUAIRE_SOCK, DELAI)
    try:
        try:
            cx.connect()
        except OSError as e:
            return 503, {"detail": f"annuaire injoignable ({e.__class__.__name__})"}
        try:
            cx.request("POST", chemin, body=json.dumps(corps or {}).encode(), headers={
                "Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {jeton}"})
            r = cx.getresponse()
            brut = r.read(1024 * 1024)
        except (OSError, http.client.HTTPException) as e:
            return 504, {"detail": f"annuaire sans réponse ({e.__class__.__name__}) : résultat indéterminé"}
    finally:
        cx.close()
    try:
        reponse = json.loads(brut) if brut else {}
    except ValueError:
        reponse = {"detail": "réponse illisible de l'annuaire"}
    return r.status, reponse
