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
from typing import Any, Dict, Iterable, Optional, Tuple

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


def appeler(chemin: str, corps: Optional[Dict[str, Any]], jetons: Iterable[str],
            socket_chemin: Optional[str] = None) -> Tuple[int, Any]:
    """POST vers l'annuaire avec le premier jeton accepté (un Bearer périmé ne masque pas le cookie valide).
    Rend (statut HTTP, corps JSON ou texte). Annuaire injoignable : (503, message)."""
    statut, reponse = 401, {"detail": "aucun jeton à relayer"}
    for jeton in jetons:
        try:
            cx = _Connexion(socket_chemin or config.ANNUAIRE_SOCK, DELAI)
            donnees = json.dumps(corps or {}).encode()
            cx.request("POST", chemin, body=donnees, headers={
                "Content-Type": "application/json", "Accept": "application/json",
                "Authorization": f"Bearer {jeton}"})
            r = cx.getresponse()
            brut = r.read(1024 * 1024)
            cx.close()
        except OSError as e:
            return 503, {"detail": f"annuaire injoignable ({e.__class__.__name__})"}
        try:
            reponse = json.loads(brut) if brut else {}
        except ValueError:
            reponse = {"detail": "réponse illisible de l'annuaire"}
        statut = r.status
        if statut != 401:
            break
    return statut, reponse
