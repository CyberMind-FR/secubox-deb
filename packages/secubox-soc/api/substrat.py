# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lecteur du substrat SADE : GET sur les sockets Unix d'actord, du WAF et de threatmesh (#3839).

Aucune exception ne sort de `lire` ni d'`ecrire` : tout échec devient `{"ok": False, "donnees": None, "erreur": <motif>}`.
`ecrire` (POST JSON) ne sert qu'au geste approuvé en REACTIVE (`POST /ban` du WAF) ; sur un refus, le `detail` renvoyé
par le service est repris dans `erreur` (borné, sans caractère de contrôle).
Seule une source inconnue lève `KeyError` (erreur de programmation, pas d'exploitation).
"""
import http.client
import json
import logging
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


def _detail(corps: bytes) -> str:
    """`detail` (ou `error`) d'un corps d'erreur JSON, assaini et borné ; chaîne vide sinon."""
    try:
        d = json.loads(corps.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ""
    v = (d.get("detail") or d.get("error")) if isinstance(d, dict) else None
    if not isinstance(v, str):
        return ""
    return "".join(c if c.isprintable() else " " for c in v)[:200]


def lire(source: str, chemin: str, entetes: Optional[Dict[str, str]] = None, delai: float = 3.0) -> Dict[str, Any]:
    """GET `chemin` sur le socket de `source`. Rend `{"ok", "donnees", "erreur"}`."""
    return _requete("GET", source, chemin, None, entetes, delai)


def ecrire(source: str, chemin: str, corps: Any, entetes: Optional[Dict[str, str]] = None,
           delai: float = 10.0) -> Dict[str, Any]:
    """POST `corps` (JSON) sur `chemin` du socket de `source`. Rend `{"ok", "donnees", "erreur"}`."""
    return _requete("POST", source, chemin, corps, entetes, delai)


def _requete(methode: str, source: str, chemin: str, corps_json: Any, entetes: Optional[Dict[str, str]],
             delai: float) -> Dict[str, Any]:
    sock = SOURCES[source]  # KeyError si source inconnue
    conn = None
    try:
        h = dict(entetes or {})
        brut = None
        if methode == "POST":
            brut = json.dumps(corps_json).encode("utf-8")
            h["Content-Type"] = "application/json"
        conn = _Connexion(sock, delai)
        conn.request(methode, chemin, body=brut, headers=h)
        rep = conn.getresponse()
        corps = rep.read(CORPS_MAX + 1)
        if rep.status != 200:
            d = _detail(corps[:CORPS_MAX]) if methode == "POST" else ""
            return _ko(f"http {rep.status}" + (f" : {d}" if d else ""))
        if len(corps) > CORPS_MAX:
            return _ko("réponse trop grande")
        try:
            donnees = json.loads(corps.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return _ko("réponse illisible")
        if not isinstance(donnees, (dict, list)):  # scalaire ou null : jamais une réponse exploitable
            return _ko("réponse inattendue")
        return {"ok": True, "donnees": donnees, "erreur": None}
    except (TimeoutError, socket.timeout):
        return _ko("délai")
    except FileNotFoundError:
        return _ko("socket absent")
    except PermissionError:
        return _ko("accès refusé")
    except OSError as e:
        return _ko(f"socket injoignable : {type(e).__name__}")
    except Exception as e:  # noqa: BLE001 — jamais d'exception vers l'appelant
        return _ko(f"erreur : {type(e).__name__}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError as e:
                logging.getLogger("secubox.soc.substrat").debug("fermeture du socket : %s", type(e).__name__)
