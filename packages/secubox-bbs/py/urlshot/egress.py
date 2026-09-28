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
import json
import socket
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

# Domaines internes SecuBox — jamais de capture de nos propres services,
# quelle que soit leur résolution IP.
_DOMAINES_INTERNES = (".secubox.in", ".gk2.net")

# LA SORTIE NE MÈNE QU'À L'EXTÉRIEUR (#1609) — même règle que la sortie du
# relais surf : ni la box, ni son réseau local, ni ses conteneurs
# (10.100.0.0/24), ni la boucle locale. Refusés d'office, quelle que soit la
# version de Python (dont les drapeaux `is_private`/`is_global` ont varié) ;
# les drapeaux restent consultés EN PLUS, jamais à la place.
_RESEAUX_INTERDITS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::/96", "64:ff9b:1::/48", "100::/64",
    "2001:db8::/32", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

# Les adresses de la box et leurs réseaux attenants (une adresse IPv6 publique
# du LAN reste le LAN), relues au plus toutes les _PROPRES_TTL secondes.
_PROPRES_TTL = 30.0
_IF_INET6 = Path("/proc/net/if_inet6")
_verrou = threading.Lock()
_propres: dict = {"t": -1e9, "adresses": frozenset(), "reseaux": ()}


def _lit_interfaces() -> list:
    """(adresse, préfixe) de chaque interface : `ip -j addr` d'abord ; à
    défaut (unité restreinte à AF_INET/AF_INET6/AF_UNIX, sans netlink)
    /proc/net/if_inet6 pour l'IPv6 et le nom d'hôte pour l'IPv4."""
    vues: list = []
    try:
        sortie = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True,
                                text=True, timeout=3).stdout
        for iface in json.loads(sortie or "[]"):
            for ai in iface.get("addr_info", []):
                if ai.get("local"):
                    vues.append((ai["local"], ai.get("prefixlen")))
    except (OSError, ValueError, subprocess.SubprocessError):
        vues = []
    if vues:
        return vues
    try:
        for ligne in _IF_INET6.read_text().splitlines():
            champs = ligne.split()
            if len(champs) >= 3:
                h = champs[0]
                vues.append((":".join(h[i:i + 4] for i in range(0, 32, 4)),
                             int(champs[2], 16)))
    except (OSError, ValueError):
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            vues.append((info[4][0], None))
    except OSError:
        pass
    return vues


def _adresses_de_la_box() -> tuple:
    with _verrou:
        maintenant = time.monotonic()
        if maintenant - _propres["t"] < _PROPRES_TTL:
            return _propres["adresses"], _propres["reseaux"]
        adresses, reseaux = set(), []
        for brute, prefixe in _lit_interfaces():
            try:
                ip = ipaddress.ip_address(str(brute).split("%", 1)[0])
            except ValueError:
                continue
            adresses.add(ip)
            # Réseau attenant, s'il est assez étroit pour n'être que le LAN.
            if prefixe is not None and ((ip.version == 4 and prefixe >= 20)
                                        or (ip.version == 6 and prefixe >= 48)):
                net = ipaddress.ip_network(f"{ip}/{prefixe}", strict=False)
                if net not in reseaux:
                    reseaux.append(net)
        _propres.update(t=maintenant, adresses=frozenset(adresses),
                        reseaux=tuple(reseaux))
        return _propres["adresses"], _propres["reseaux"]


def _ip_interdite(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(ip_str).split("%", 1)[0])
    except ValueError:
        return True  # non parsable : refuser par prudence
    if ip.version == 6:
        # Une enveloppe (IPv4 mappée, 6to4, NAT64) se juge sur ce qu'elle porte.
        portees = [a for a in (ip.ipv4_mapped, ip.sixtofour) if a is not None]
        if ip in _NAT64:
            portees.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if any(_ip_interdite(str(a)) for a in portees):
            return True
    if any(reseau.version == ip.version and ip in reseau for reseau in _RESEAUX_INTERDITS):
        return True
    if (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_private or not ip.is_global):
        return True
    adresses, reseaux = _adresses_de_la_box()
    return ip in adresses or any(r.version == ip.version and ip in r for r in reseaux)


class DestinationRefusee(ValueError):
    """Un saut (redirection comprise) mène à une destination refusée."""


def _garde_saut(request) -> None:
    """Crochet httpx `request` : appelé à CHAQUE saut, redirections suivies
    comprises — la garde ne dépend d'aucun appelant."""
    raison = url_interdite(str(request.url))
    if raison:
        raise DestinationRefusee(raison)


def url_interdite(u: str) -> str | None:
    """Renvoie une raison (str, en français) si l'URL DOIT être refusée,
    sinon None. Le ou les hôtes RÉSOLUS sont vérifiés, TOUTES leurs adresses,
    pas seulement le littéral de l'URL (la connexion, elle, est ouverte par
    le proxy d'égress : cf. `client()`)."""
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

    if host_l == "localhost" or host_l.endswith(".localhost"):
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

    Redirections : httpx les suit en interne (follow_redirects=True), et le
    crochet `request` repasse `url_interdite()` à CHAQUE saut (#1609) — un
    saut refusé lève DestinationRefusee, l'appelant n'a rien à y ajouter.
    La connexion elle-même est ouverte par le proxy d'égress, qui résout le
    nom de son côté : la vérification au moment même de la connexion relève
    de sbxmitm.
    """
    import inspect

    import httpx

    proxy_url = "http://127.0.0.1:8090"
    kwargs = {
        "verify": "/usr/share/secubox/egress-ca.pem",
        "timeout": 15,
        "follow_redirects": True,
        "headers": {"User-Agent": "SecuBox-URLShot/1.0"},
        "event_hooks": {"request": [_garde_saut]},
    }

    # Compat large : httpx >= 0.28 n'accepte que `proxy=`, les versions plus
    # anciennes utilisaient `proxies=`. Détecter via la signature réelle.
    params = inspect.signature(httpx.Client.__init__).parameters
    if "proxy" in params:
        kwargs["proxy"] = proxy_url
    else:
        kwargs["proxies"] = proxy_url

    return httpx.Client(**kwargs)
