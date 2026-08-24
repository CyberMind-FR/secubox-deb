# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — adaptateurs cardlets (résumés vivants par service).

Un adaptateur traduit l'API RÉELLE d'un service (lue côté serveur, DANS la box,
via sa socket /run/secubox/<id>.sock) en un payload cardlet normalisé (brief §6).
Souverain : aucune donnée n'est une capture figée, le client ne contacte jamais
le service directement. Radio = cardlet de référence.
"""
import json
import socket
from typing import Callable, Optional

RADIO_SOCK = "/run/secubox/radio.sock"


def uds_get(sock_path: str, path: str, timeout: float = 2.0) -> dict:
    """GET JSON minimal sur une socket Unix HTTP (sans dépendance externe)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        req = "GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" % path
        s.sendall(req.encode("ascii"))
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    _, _, body = buf.partition(b"\r\n\r\n")
    return json.loads(body.decode("utf-8", "replace"))


def radio_cardlet(sock: str = RADIO_SOCK, _get: Optional[Callable] = None) -> dict:
    """Résumé « now-playing » de la Radio → payload cardlet normalisé (brief §6)."""
    get = _get or uds_get
    cur = get(sock, "/api/v1/radio/current") or {}
    try:
        st = get(sock, "/api/v1/radio/stats") or {}
    except Exception:
        st = {}
    piste = cur.get("piste") or {}
    silence = bool(cur.get("silence"))
    title = piste.get("titre") or ("— silence à l'antenne —" if silence else "Radio souveraine")
    return {
        "id": "radio",
        "kind": "radio-now-playing",
        "status": "online",
        "content": {
            "title": title,
            "subtitle": piste.get("auteur") or "",
            "station": "Radio souveraine",
        },
        "metrics": [
            {"id": "listeners", "value": int(st.get("auditeurs", 0) or 0)},
            {"id": "tracks", "value": int(st.get("pistes", 0) or 0)},
        ],
        "silence": silence,
    }


def radio_cardlet_safe(sock: str = RADIO_SOCK, _get: Optional[Callable] = None) -> dict:
    """radio_cardlet() avec repli `offline` si la Radio est injoignable."""
    try:
        return radio_cardlet(sock, _get)
    except Exception:
        return {
            "id": "radio", "kind": "radio-now-playing", "status": "offline",
            "content": {"title": "Radio", "subtitle": "", "station": "Radio souveraine"},
            "metrics": [], "silence": False,
        }
