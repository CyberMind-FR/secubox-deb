# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Surf — l'égress commutable
CyberMind — https://cybermind.fr

PAR OÙ LE RELAIS SORT. Trois modes, un seul point de choix :

  DIRECT  — la box sort déjà ; le plus rapide, le moins discret.
  TOR     — SOCKS5h vers 127.0.0.1:9050. Indispensable pour le `.onion`
            (résolution DANS le tunnel, d'où le `h`), et pour l'anti-censure :
            le site distant voit un nœud de sortie Tor, pas la box.
  TORRENT — NOTE DE CONCEPTION, non implémentée ici. Le torrent n'est pas du
            HTTP : c'est BitTorrent (µTP/TCP) qu'il faut encapsuler, pas
            réécrire. La brique existe déjà (`secubox-torrent`) ; l'encapsuler
            revient à lui imposer le MÊME égress — le SOCKS de Tor pour les
            trackers et les pairs, ou un tunnel WireGuard. Cf. `docs/POC-SURF.md`
            §Torrent. On le cite ici pour que le point de branchement soit
            nommé, pas pour le livrer ce soir.

Le `h` de `socks5h` compte : sans lui, le client résout le nom AVANT le tunnel,
ce qui fuite la requête DNS en clair ET rend `.onion` impossible (aucun
résolveur public ne connaît `.onion`). C'est l'erreur classique.
"""

from __future__ import annotations

import httpx

import os

# LE SOCKS DE TOR N'EST PAS TOUJOURS SUR LOOPBACK. Sur gk2 il est lié aux IP
# LAN et mesh (192.168.1.200, 10.10.0.1), pas à 127.0.0.1 — le POC doit donc
# pouvoir viser l'hôte réel. On garde loopback par défaut (le cas courant) et
# on laisse l'environnement corriger.
_TOR_HOTE = os.environ.get("SECUBOX_TOR_SOCKS", "127.0.0.1:9050")
# `socks5://` et non `socks5h://` : httpx (via socksio) resout DEJA le nom au
# bout du tunnel, ce qui est le comportement du `h`. La forme `socks5h` que
# comprennent curl et consorts n'est pas reconnue par httpx 0.23 — mais le
# resultat, resolution distante et `.onion` joignable, est le meme.
TOR_SOCKS = "socks5://" + _TOR_HOTE

# En-têtes de navigateur crédible. Un `User-Agent` de client HTTP se fait
# reconnaître et éconduire par les gros SaaS avant même la première ligne utile.
# EN-TETES DE NAVIGATION CREDIBLE (#1341). Un filtre anti-robot SIMPLE regarde
# d'abord l'allure des en-tetes : un client HTTP nu se fait renvoyer avant la
# premiere ligne utile. On imite une navigation Firefox reelle — User-Agent
# COHERENT avec les Sec-CH-UA, et les Sec-Fetch d'une navigation de premier
# niveau.
#
# CE QUE CELA NE FAIT PAS, ET IL FAUT LE DIRE : un challenge ACTIF — Cloudflare
# « verification du navigateur », Turnstile, reCAPTCHA — execute du JavaScript
# et mesure le vrai moteur. Aucun jeu d'en-tetes ne le passe : cote serveur, on
# n'a pas de moteur a lui montrer. Et via Tor, la reputation du noeud de sortie
# DECLENCHE souvent le challenge plutot que de l'eviter. On ameliore les
# chances sur les filtres passifs ; on ne promet pas l'impossible.
ENTETES_NAV = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
                   "Gecko/20100101 Firefox/128.0"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.6,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Priority": "u=0, i",
}


def _client_proxy(proxy: str, timeout: float, verify: bool) -> httpx.Client:
    """httpx a renomme `proxies=` en `proxy=` selon la version. Le POC doit
    tourner sur celle de la box (0.23) comme sur une recente : on essaie la
    forme moderne, on retombe sur l'ancienne."""
    commun = dict(timeout=timeout, verify=verify, follow_redirects=False,
                  headers=ENTETES_NAV)
    try:
        return httpx.Client(proxy=proxy, **commun)          # httpx >= 0.26
    except TypeError:
        return httpx.Client(proxies=proxy, **commun)        # httpx < 0.26


def _onion(hote: str) -> bool:
    return hote.lower().rstrip(".").endswith(".onion")


def client_pour(hote: str, mode: str = "auto", timeout: float = 25.0) -> httpx.Client:
    """Le client httpx adapté à l'hôte et au mode.

    `auto` : Tor si l'hôte est en `.onion` (aucun autre chemin n'y mène),
    direct sinon. Un mode explicite l'emporte.
    """
    if mode == "auto":
        mode = "tor" if _onion(hote) else "direct"

    if mode == "tor":
        # `.onion` n'a pas de certificat vérifiable publiquement ; Tor garantit
        # l'authenticité par l'adresse elle-même. On ne vérifie donc pas le TLS
        # pour ces hôtes — et UNIQUEMENT pour eux.
        verify = not _onion(hote)
        return _client_proxy(TOR_SOCKS, timeout, verify)

    return httpx.Client(timeout=timeout, follow_redirects=False,
                        headers=ENTETES_NAV)


def tor_vivant() -> bool:
    """Le SOCKS de Tor répond-il ? On teste vite, pour un message clair."""
    import socket
    h, _, port = _TOR_HOTE.partition(":")
    try:
        s = socket.create_connection((h, int(port or 9050)), timeout=2)
        s.close()
        return True
    except OSError:
        return False
