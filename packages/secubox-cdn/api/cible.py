# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: cdn — cible d'un pré-chargement (#3284).

`/preload_url` va chercher une URL fournie par l'administrateur (ou par une page
compromise) : sans contrôle, le serveur visait le LAN, 127.0.0.1 ou les sockets
internes derrière un nom (SSRF). On n'accepte qu'une URL http(s) sans identifiants,
sur un port web, dont le nom résout EXCLUSIVEMENT vers des adresses publiques
(une seule adresse non publique suffit à refuser).

La connexion se fait ensuite sur l'adresse VALIDÉE (`url_epinglee`, avec `Host` et
SNI d'origine) : pas de seconde résolution, donc pas de rebinding DNS entre le
contrôle et la connexion. Les redirections ne sont pas suivies par l'appelant."""
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

PORTS_WEB = {80, 443, 8080, 8443}
MESSAGE_REFUS = "cible refusée (url http(s) publique attendue)"
# Préfixes qui encapsulent une IPv4 et que `is_global` peut laisser passer.
ENCAPSULANTS = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


class CibleRefusee(ValueError):
    """La cible n'est pas une URL http(s) publique ; `raison` pour le journal seulement."""

    def __init__(self, raison: str):
        super().__init__(MESSAGE_REFUS)
        self.raison = raison


@dataclass(frozen=True)
class Cible:
    url: str
    hote: str
    ip: str
    url_epinglee: str
    entete_host: str


def _publique(ip) -> bool:
    if ip.version == 6:
        if any(ip in n for n in ENCAPSULANTS):
            return False
        if ip.ipv4_mapped is not None:
            return _publique(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return _publique(ip.sixtofour)
    return ip.is_global and not ip.is_multicast


def cible(url) -> Cible:
    """Cible validée et épinglée ; lève CibleRefusee sinon. Bloquant (résolution DNS) :
    l'appeler hors de la boucle d'événements."""
    if not isinstance(url, str):
        raise CibleRefusee("url absente")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise CibleRefusee("url invalide") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise CibleRefusee("schéma ou hôte")
    if parts.username is not None or parts.password is not None:
        raise CibleRefusee("identifiants dans l'url")
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if port not in PORTS_WEB:
        raise CibleRefusee("port non web")
    try:
        infos = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise CibleRefusee("nom introuvable") from None
    adresses = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not _publique(ip):
            raise CibleRefusee("adresse non publique")
        adresses.append(ip)
    if not adresses:
        raise CibleRefusee("nom introuvable")
    ip = adresses[0]
    hote_ip = f"[{ip}]" if ip.version == 6 else str(ip)
    chemin = parts.path or "/"
    if parts.query:
        chemin += "?" + parts.query
    nom = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    defaut = 443 if parts.scheme == "https" else 80
    return Cible(url=url, hote=parts.hostname, ip=str(ip),
                 url_epinglee=f"{parts.scheme}://{hote_ip}:{port}{chemin}",
                 entete_host=nom if port == defaut else f"{nom}:{port}")


def verifier(url) -> tuple:
    """(True, "") si la cible est publique, sinon (False, MESSAGE_REFUS)."""
    try:
        cible(url)
    except CibleRefusee:
        return False, MESSAGE_REFUS
    return True, ""
