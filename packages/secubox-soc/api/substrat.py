# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lecteur du substrat SADE : GET sur les sockets Unix d'actord, du WAF et de threatmesh (#3839).

Aucune exception ne sort de `lire` : tout échec devient `{"ok": False, "donnees": None, "erreur": <motif>}`.
Seule une source inconnue lève `KeyError` (erreur de programmation, pas d'exploitation).
"""
import http.client
import json
import os
import socket
from typing import Any, Dict, Optional

# `actord` : l'API de lecture est actor.sock ; actord.sock est le socket d'ingestion des capteurs (voir RELEVE.md).
SOURCES: Dict[str, str] = {
    "actord": "/run/secubox/actor.sock",
    "waf": "/run/secubox/waf.sock",
    "threatmesh": "/run/secubox/threatmesh.sock",
}

CORPS_MAX = 4 * 1024 * 1024  # octets lus au plus par réponse


class _Connexion(http.client.HTTPConnection):
    def __init__(self, chemin_socket: str, delai: float):
        super().__init__("localhost", timeout=delai)
        self._chemin_socket = chemin_socket

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin_socket)


def _ko(erreur: str) -> Dict[str, Any]:
    return {"ok": False, "donnees": None, "erreur": erreur}


def lire(source: str, chemin: str, entetes: Optional[Dict[str, str]] = None, delai: float = 3.0) -> Dict[str, Any]:
    """GET `chemin` sur le socket de `source`. Rend `{"ok", "donnees", "erreur"}`."""
    sock = SOURCES[source]  # KeyError si source inconnue
    if not os.path.exists(sock):
        return _ko("socket absent")
    conn = None
    try:
        conn = _Connexion(sock, delai)
        conn.request("GET", chemin, headers=dict(entetes or {}))
        rep = conn.getresponse()
        corps = rep.read(CORPS_MAX + 1)
        if rep.status != 200:
            return _ko(f"http {rep.status}")
        if len(corps) > CORPS_MAX:
            return _ko("réponse trop grande")
        try:
            donnees = json.loads(corps.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return _ko("réponse illisible")
        return {"ok": True, "donnees": donnees, "erreur": None}
    except (TimeoutError, socket.timeout):
        return _ko("délai")
    except OSError as e:
        return _ko(f"socket injoignable : {type(e).__name__}")
    except Exception as e:  # noqa: BLE001 — jamais d'exception vers l'appelant
        return _ko(f"erreur : {type(e).__name__}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
