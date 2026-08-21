# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: BBS urlshot :: egress
CyberMind — https://cybermind.fr

Garde-fou SSRF + fabrique de client HTTP passant par l'égress toolbox/WAF
(proxy sbxmitm). AUCUNE requête sortante ne doit contourner ce proxy — voir
Global Constraints du plan #1120.

`url_interdite()` n'a besoin que de la stdlib (ipaddress, urllib.parse,
socket) pour rester utilisable même là où httpx n'est pas installé (httpx
n'est qu'un `Recommends` Debian, pas une dépendance dure du paquet).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Domaines internes SecuBox — jamais de capture de nos propres services,
# quelle que soit leur résolution IP.
_DOMAINES_INTERNES = (".secubox.in", ".gk2.net")

# Réseaux privés / loopback / link-local / ULA interdits en cible (SSRF).
_RESEAUX_INTERDITS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _ip_interdite(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # non parsable : refuser par prudence
    return any(ip in reseau for reseau in _RESEAUX_INTERDITS)


def url_interdite(u: str) -> str | None:
    """Renvoie une raison (str, en français) si l'URL DOIT être refusée,
    sinon None. Défense SSRF y compris contre le DNS-rebinding : le ou les
    hôtes RÉSOLUS sont vérifiés, pas seulement le littéral de l'URL."""
    try:
        parsed = urlparse((u or "").strip())
    except ValueError:
        return "URL non analysable"

    if parsed.scheme not in ("http", "https"):
        return f"schéma non autorisé : {parsed.scheme!r}"

    host = parsed.hostname
    if not host:
        return "hôte absent"

    host_l = host.lower()

    if any(host_l.endswith(suffixe) or host_l == suffixe.lstrip(".") for suffixe in _DOMAINES_INTERNES):
        return f"domaine interne SecuBox : {host_l}"

    if host_l in ("localhost",):
        return "hôte localhost"

    # Littéral IP direct dans l'URL (avec ou sans crochets IPv6 déjà retirés
    # par urlparse via .hostname).
    try:
        ipaddress.ip_address(host_l)
        est_ip_litterale = True
    except ValueError:
        est_ip_litterale = False

    if est_ip_litterale:
        if _ip_interdite(host_l):
            return f"IP interne/privée : {host_l}"
        return None

    # Hôte nommé : résoudre TOUTES les adresses (défense anti DNS-rebinding)
    # et refuser si UNE SEULE tombe dans une plage interdite.
    try:
        infos = socket.getaddrinfo(host_l, None)
    except socket.gaierror as exc:
        return f"résolution DNS impossible : {exc}"

    adresses = {info[4][0] for info in infos}
    if not adresses:
        return "résolution DNS vide"

    for adresse in adresses:
        # getaddrinfo peut renvoyer une adresse IPv6 avec un suffixe de
        # zone (%scope) — ipaddress ne l'accepte pas, le retirer.
        adresse_nue = adresse.split("%", 1)[0]
        if _ip_interdite(adresse_nue):
            return f"{host_l} résout vers une IP interne/privée : {adresse_nue}"

    return None


def client():
    """Construit un httpx.Client routé via le proxy d'égress sbxmitm, en
    faisant confiance à sa CA — jamais d'accès direct à Internet (Global
    Constraints #1120).

    Import de httpx VOLONTAIREMENT paresseux : httpx n'est qu'un
    `Recommends` Debian du paquet secubox-bbs (le worker est best-effort),
    donc `url_interdite()` doit rester utilisable même sans httpx installé.

    NOTE redirections : httpx suit les redirections en interne
    (follow_redirects=True) ; l'appelant DOIT re-vérifier `url_interdite()`
    à chaque saut si le hop final compte (le garde SSRF ici ne protège que
    l'URL de départ — la vérification par-hop est la responsabilité des
    tâches suivantes, ex. ogimage.py/capture.py, pas de ce client générique).
    """
    import inspect

    import httpx

    proxy_url = "http://127.0.0.1:8090"
    kwargs = {
        "verify": "/usr/share/secubox/egress-ca.pem",
        "timeout": 15,
        "follow_redirects": True,
        "headers": {"User-Agent": "SecuBox-URLShot/1.0"},
    }

    # Compat large : httpx >= 0.28 n'accepte que `proxy=`, les versions plus
    # anciennes utilisaient `proxies=`. Détecter via la signature réelle.
    params = inspect.signature(httpx.Client.__init__).parameters
    if "proxy" in params:
        kwargs["proxy"] = proxy_url
    else:
        kwargs["proxies"] = proxy_url

    return httpx.Client(**kwargs)
