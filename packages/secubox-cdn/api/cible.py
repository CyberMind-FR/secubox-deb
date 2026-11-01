# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: cdn — cible d'un pré-chargement (#3284).

`/preload_url` va chercher une URL fournie par l'administrateur (ou par une page
compromise) : sans contrôle, le serveur visait le LAN, 127.0.0.1 ou les sockets
internes derrière un nom (SSRF). On n'accepte qu'une URL http(s) sans identifiants,
sur un port web, dont le nom résout EXCLUSIVEMENT vers des adresses publiques
(une seule adresse privée suffit à refuser). Les redirections ne sont pas suivies
par l'appelant. Risque résiduel : un nom qui change de réponse entre ce contrôle
et la connexion (rebinding) ; la route reste réservée aux administrateurs."""
import ipaddress
import socket
from urllib.parse import urlsplit

PORTS_WEB = {80, 443, 8080, 8443}


def verifier(url) -> tuple:
    """(True, "") si la cible est publique, sinon (False, raison)."""
    if not isinstance(url, str):
        return False, "url http(s) attendue"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False, "url invalide"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False, "url http(s) attendue"
    if parts.username is not None or parts.password is not None:
        return False, "identifiants refusés dans l'url"
    port = port or (443 if parts.scheme == "https" else 80)
    if port not in PORTS_WEB:
        return False, "port non web refusé"
    try:
        infos = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return False, "nom introuvable"
    if not infos:
        return False, "nom introuvable"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not ip.is_global or ip.is_multicast:
            return False, "adresse non publique refusée"
    return True, ""
