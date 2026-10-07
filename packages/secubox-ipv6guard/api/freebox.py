# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: ipv6guard :: lecture du pare-feu IPv6 de la Freebox (phase 2)

Le Guardian n'a ni réseau ni jeton Freebox : il interroge `secubox-freebox` par sa socket Unix et lui RELAIE les identifiants de
l'appelant (jeton, cookie de session, en-tête LAN). La garde de lecture de secubox-freebox s'applique donc exactement comme si
l'appelant l'avait interrogé lui-même : le Guardian n'élève aucun droit. Tout échec rend None, et le verdict dit « à vérifier ».
"""
import http.client
import json
import socket

SOCKET = "/run/secubox/freebox.sock"
DELAI_S = 8
RELAYES = {"authorization": "Authorization", "cookie": "Cookie", "x-secubox-lan": "X-SecuBox-LAN"}


class _Unix(http.client.HTTPConnection):
    def __init__(self, chemin, delai):
        super().__init__("freebox", timeout=delai)
        self._chemin = chemin

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin)


def transport_socket(chemin, entetes):
    c = _Unix(SOCKET, DELAI_S)
    try:
        c.request("GET", chemin, headers=entetes)
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"{}")
    finally:
        c.close()


def lire_pare_feu(entetes_appelant, transport=transport_socket):
    """{"pare_feu_actif", "exceptions": [{appareil, port}], "exceptions_lues"} ou None si on ne sait pas."""
    relayes = {nom: valeur for k, nom in RELAYES.items() for kk, valeur in entetes_appelant.items() if kk.lower() == k}
    try:
        statut, d = transport("/pare-feu", relayes)
    except (OSError, ValueError):
        return None
    if statut != 200 or not isinstance(d, dict) or d.get("pare_feu_actif") is None:
        return None
    exc = [{"appareil": e.get("appareil", ""), "port": e.get("port_debut")} for e in d.get("exceptions") or []]
    return {"pare_feu_actif": bool(d["pare_feu_actif"]), "exceptions": exc, "exceptions_lues": bool(d.get("exceptions_lues"))}
