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

LA SORTIE NE MÈNE QU'À L'EXTÉRIEUR (#1609). Quel que soit le mode, le relais
ne s'adresse ni à la box, ni à son réseau local, ni à ses conteneurs : cf.
§« La sortie gardée » plus bas. Tout client du relais se fabrique ICI.
"""

from __future__ import annotations

import httpx
import httpcore

import asyncio
import ipaddress
import json
import logging
import os
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

from . import relais

# LE SOCKS DE TOR N'EST PAS TOUJOURS SUR LOOPBACK. Sur gk2 il est lié aux IP
# LAN et mesh (192.168.1.200, 10.10.0.1), PAS à 127.0.0.1. Supposer loopback
# rendait `.onion` injoignable dès que l'env n'était pas posé (CLI, sous-process,
# rendu headless). On résout donc ROBUSTEMENT : l'env explicite gagne ; sinon on
# SONDE des candidats (loopback, puis l'IP LAN réelle de la board auto-détectée)
# et on retient le premier dont le port 9050 répond ; fallback loopback.


def _sonde_socks(hote_port: str, delai: float = 0.4) -> bool:
    h, _, p = hote_port.partition(":")
    try:
        s = socket.create_connection((h, int(p or 9050)), timeout=delai)
        s.close()
        return True
    except OSError:
        return False


def _ip_locale() -> str | None:
    """IP sortante primaire, sans émettre de trafic — donne l'IP LAN de la board."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))          # TEST-NET-1, jamais routé
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def _resout_tor_socks() -> str:
    env = os.environ.get("SECUBOX_TOR_SOCKS")
    if env:
        return env
    candidats = ["127.0.0.1:9050"]
    ip = _ip_locale()
    if ip and ip != "127.0.0.1":
        candidats.append(f"{ip}:9050")
    for c in candidats:
        if _sonde_socks(c):
            return c
    return candidats[0]


_TOR_HOTE = _resout_tor_socks()
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


# ── LA POIGNÉE DE MAIN (#1323) ──────────────────────────────────────────────
#
# CE QU'ON A VU. `edge.api.brightcove.com` rendait 200 à curl, 200 à urllib, et
# 404 au relais — même adresse, même seconde, même machine, mêmes en-têtes. Ni
# le jeton, ni la query, ni le `Host` : le chemin sur le fil était identique
# octet pour octet. Le 404 venait d'AVANT la requête HTTP.
#
# LA CAUSE. httpx n'utilise pas les réglages TLS du système : il impose sa
# propre liste de suites (`DEFAULT_CIPHERS`, 42 suites contre 60). Ce choix
# donne au ClientHello une empreinte reconnaissable, et les bordures qui
# profilent leurs clients — Fastly ici, mais Cloudflare et Akamai font pareil —
# répondent à cette empreinte par un refus poli. Preuve par substitution : le
# contexte système rend 200, le même contexte AVEC les suites de httpx rend
# 404, ALPN et paquet de certificats inchangés.
#
# CE QU'ON FAIT. On sort avec la poignée de main du SYSTÈME, celle de tous les
# autres outils de la box. Ce n'est pas un déguisement : c'est cesser d'en
# porter un. Un relais dont la sortie est signée « bibliothèque Python » n'est
# pas un relais — la moitié du web lui répond autre chose qu'au navigateur
# qu'il sert.
#
# Le paquet de certificats reste celui du système (`ca-certificates`), déjà
# géré par la distribution : le contexte par défaut le prend.
def contexte_tls() -> ssl.SSLContext:
    """Le contexte TLS du système, vérification comprise."""
    return ssl.create_default_context()


# ── LA SORTIE GARDÉE (#1609) ────────────────────────────────────────────────
#
# LA RÈGLE. Le relais va chercher des pages POUR des personnes : sa sortie ne
# mène qu'à l'extérieur. Jamais à la box elle-même, ni à son réseau local, ni à
# ses conteneurs (10.100.0.0/24), ni à la boucle locale. Le relais tourne SUR la
# box : ce qu'il y demanderait arriverait avec une adresse du LAN, que la box
# traite en voisin de confiance. Il ne s'y présente donc jamais.
#
# COMMENT ELLE TIENT. La garde vit dans la couche réseau de httpcore, là où se
# fait CHAQUE connexion — redirections suivies comprises. Aucun appelant ne
# peut l'oublier, aucune requête ne la contourne. Trois temps, dans l'ordre :
#
#   1. on résout le nom UNE fois ;
#   2. on refuse si UNE SEULE des adresses obtenues est interne ;
#   3. on se connecte à l'adresse vérifiée — jamais au nom, qui serait résolu
#      une seconde fois et pourrait alors répondre autre chose.
#
# Le nom reste celui de la requête pour l'en-tête `Host`, le SNI et la
# vérification du certificat : seule la connexion TCP vise l'adresse retenue.
#
# EN MODE TOR, le nom est résolu au bout du tunnel, hors de la box : on ne le
# résout pas ici (ce serait sortir la requête DNS en clair). On refuse alors ce
# qui se juge sans résolution — adresse littérale interne, `localhost`, nom de
# la box — et le client Tor refuse de lui-même les adresses internes.
#
# L'ADRESSE PUBLIQUE DE LA BOX. Derrière un routeur, elle n'est sur aucune
# interface : rien de local ne la donne. Elle se déclare dans CONFIG, clé
# `refuse` (adresses ou réseaux, en plus de ce qui est refusé d'office) :
#
#     # /etc/secubox/surf/egress.toml
#     refuse = ["203.0.113.7"]

CONFIG = Path("/etc/secubox/surf/egress.toml")

_journal = logging.getLogger("surf.egress")


class DestinationRefusee(httpcore.ConnectError):
    """La destination mène à la box ou à son réseau : la sortie ne l'ouvre pas.

    Sous-classe de `httpcore.ConnectError` : httpx la rend en
    `httpx.ConnectError` (cause chaînée), comme une connexion impossible. Le
    message ne cite que l'hôte demandé ; l'adresse et la raison restent en
    attributs, pour le journal et les tests.
    """

    def __init__(self, hote: str, adresse: str = "", raison: str = ""):
        self.hote, self.adresse, self.raison = hote, adresse, raison
        super().__init__(f"destination interne refusée : {hote}")


# Refusés d'office, quelle que soit la version de Python (dont les drapeaux
# `is_private`/`is_global` ont varié d'une version à l'autre). Les drapeaux
# restent consultés EN PLUS, jamais à la place.
_RESEAUX_REFUSES = tuple((ipaddress.ip_network(n), r) for n, r in (
    ("0.0.0.0/8", "adresse non spécifiée"),
    ("10.0.0.0/8", "réseau privé"),          # dont 10.100.0.0/24, les conteneurs
    ("100.64.0.0/10", "CGNAT"),
    ("127.0.0.0/8", "boucle locale"),
    ("169.254.0.0/16", "lien-local"),
    ("172.16.0.0/12", "réseau privé"),
    ("192.0.0.0/24", "réservée"),
    ("192.0.2.0/24", "réservée"),
    ("192.168.0.0/16", "réseau privé"),
    ("198.18.0.0/15", "réservée"),
    ("198.51.100.0/24", "réservée"),
    ("203.0.113.0/24", "réservée"),
    ("224.0.0.0/4", "multidiffusion"),
    ("240.0.0.0/4", "réservée"),             # dont 255.255.255.255
    ("::/128", "adresse non spécifiée"),
    ("::1/128", "boucle locale"),
    ("::/96", "réservée"),                   # IPv4 « compatible », obsolète
    ("64:ff9b:1::/48", "réservée"),
    ("100::/64", "réservée"),
    ("2001:db8::/32", "réservée"),
    ("fc00::/7", "ULA"),
    ("fe80::/10", "lien-local"),
    ("fec0::/10", "lien-local"),             # site-local, obsolète
    ("ff00::/8", "multidiffusion"),
))

_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _ipv4_portees(ip) -> list:
    """Les IPv4 qu'une adresse IPv6 enveloppe (mappée, 6to4, NAT64) : une
    enveloppe se juge sur ce qu'elle contient."""
    if ip.version != 6:
        return []
    portees = [a for a in (ip.ipv4_mapped, ip.sixtofour) if a is not None]
    if ip in _NAT64:
        portees.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return portees


# ── Les adresses de la box ──────────────────────────────────────────────────
# Lues sur ses interfaces, avec leurs réseaux attenants : une adresse IPv6
# publique du LAN reste le LAN. Relues au plus toutes les _PROPRES_TTL
# secondes — une adresse change (DHCP, adresses temporaires IPv6).
_PROPRES_TTL = 30.0
_IF_INET6 = Path("/proc/net/if_inet6")
_verrou = threading.Lock()
_propres: dict = {"t": -1e9, "adresses": frozenset(), "reseaux": ()}
_config: dict = {"cle": None, "reseaux": ()}


def _attenant(ip, prefixe: int):
    """Le réseau attenant d'une adresse, s'il est assez étroit pour n'être que
    le réseau local (pas un /8 entier)."""
    if prefixe is None:
        return None
    if (ip.version == 4 and prefixe < 20) or (ip.version == 6 and prefixe < 48):
        return None
    return ipaddress.ip_network(f"{ip}/{prefixe}", strict=False)


def _lit_interfaces() -> list[tuple[str, int | None]]:
    """(adresse, préfixe) de chaque interface. `ip -j addr` d'abord ; à défaut
    /proc/net/if_inet6 pour l'IPv6 et le nom d'hôte pour l'IPv4."""
    vues: list[tuple[str, int | None]] = []
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
    ip = _ip_locale()
    if ip:
        vues.append((ip, None))
    return vues


def _adresses_de_la_box() -> tuple[frozenset, tuple]:
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
            net = _attenant(ip, prefixe)
            if net is not None and net not in reseaux:
                reseaux.append(net)
        _propres.update(t=maintenant, adresses=frozenset(adresses),
                        reseaux=tuple(reseaux))
        return _propres["adresses"], _propres["reseaux"]


def _refus_configures() -> tuple:
    """Les réseaux de la clé `refuse` de CONFIG, relus quand le fichier change."""
    try:
        st = CONFIG.stat()
    except OSError:
        return ()
    cle = (st.st_mtime_ns, st.st_size)
    with _verrou:
        if _config["cle"] == cle:
            return _config["reseaux"]
        reseaux = []
        try:
            import tomllib
            with CONFIG.open("rb") as f:
                entrees = tomllib.load(f).get("refuse", [])
            for e in entrees if isinstance(entrees, list) else []:
                try:
                    reseaux.append(ipaddress.ip_network(str(e).strip(), strict=False))
                except ValueError:
                    _journal.warning("egress.toml : entrée `refuse` illisible : %r", e)
        except (OSError, ValueError, ImportError) as exc:
            _journal.warning("egress.toml illisible (%s) : refus d'office seuls", exc)
        _config.update(cle=cle, reseaux=tuple(reseaux))
        return _config["reseaux"]


def raison_refus(adresse) -> str | None:
    """Pourquoi la sortie refuse cette adresse — ou None si elle est publique
    et n'appartient pas à la box."""
    try:
        ip = ipaddress.ip_address(str(adresse).split("%", 1)[0])
    except ValueError:
        return "adresse illisible"
    for v4 in _ipv4_portees(ip):
        r = raison_refus(v4)
        if r:
            return r
    for reseau, raison in _RESEAUX_REFUSES:
        if reseau.version == ip.version and ip in reseau:
            return raison
    if ip.is_loopback:
        return "boucle locale"
    if ip.is_unspecified:
        return "adresse non spécifiée"
    if ip.is_link_local:
        return "lien-local"
    if ip.is_multicast:
        return "multidiffusion"
    if ip.is_reserved:
        return "réservée"
    if ip.is_private or not ip.is_global:
        return "non routable publiquement"
    adresses, reseaux = _adresses_de_la_box()
    if ip in adresses:
        return "adresse de la box"
    for reseau in reseaux:
        if reseau.version == ip.version and ip in reseau:
            return "réseau local de la box"
    for reseau in _refus_configures():
        if reseau.version == ip.version and ip in reseau:
            return "refusée par la configuration"
    return None


def _nom_refuse(hote: str) -> str | None:
    """Ce qui se refuse sur le NOM, avant toute résolution."""
    if hote == "localhost" or hote.endswith(".localhost"):
        return "boucle locale"
    if hote == relais.SUFFIXE or hote.endswith("." + relais.SUFFIXE):
        return "service de la box"
    return None


def _refuse(hote: str, adresse: str, raison: str) -> DestinationRefusee:
    _journal.warning("sortie refusée : %s → %s (%s)", hote, adresse or "-", raison)
    return DestinationRefusee(hote, adresse, raison)


# Le résolveur, isolé pour que les tests le remplacent sans réseau.
_resoudre = socket.getaddrinfo


def adresses_sures(hote: str, port: int) -> list[str]:
    """Résout `hote` UNE fois et rend ses adresses, toutes vérifiées, dans
    l'ordre du résolveur. Lève DestinationRefusee si une seule est interne ;
    `httpcore.ConnectError` si le nom ne se résout pas (injoignable, pas
    refusé)."""
    h = (hote or "").strip().strip("[]").lower().rstrip(".")
    if not h:
        raise _refuse(hote, "", "hôte absent")
    raison = _nom_refuse(h)
    if raison:
        raise _refuse(h, "", raison)
    try:
        infos = _resoudre(h, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise httpcore.ConnectError(str(exc)) from exc
    sures: list[str] = []
    for info in infos:
        brute = str(info[4][0]).split("%", 1)[0]
        raison = raison_refus(brute)
        if raison:
            raise _refuse(h, brute, raison)
        ip = str(ipaddress.ip_address(brute))
        if ip not in sures:
            sures.append(ip)
    if not sures:
        raise httpcore.ConnectError(f"{h} : aucune adresse")
    return sures


# Une adresse qui ne répond pas ne doit pas priver les suivantes de leur
# chance : chaque essai qui n'est pas le dernier est borné.
_ESSAI_MAX = 5.0


def _delai_essai(timeout, rang: int, total: int):
    if rang == total - 1:
        return timeout
    return _ESSAI_MAX if timeout is None else min(timeout, _ESSAI_MAX)


class _SortieGardee:
    """Couche réseau async de httpcore : résout, vérifie, se connecte à
    l'adresse vérifiée. Tout le reste est délégué à la couche d'origine."""

    def __init__(self, interne):
        self._interne = interne

    async def connect_tcp(self, host, port, timeout=None, local_address=None, **kw):
        boucle = asyncio.get_running_loop()
        adresses = await boucle.run_in_executor(None, adresses_sures, host, port)
        echec = None
        for rang, ip in enumerate(adresses):
            try:
                return await self._interne.connect_tcp(
                    ip, port, timeout=_delai_essai(timeout, rang, len(adresses)),
                    local_address=local_address, **kw)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                echec = exc
        raise echec

    async def connect_unix_socket(self, path, timeout=None, **kw):
        raise _refuse(str(path), "", "socket locale")

    async def sleep(self, seconds):
        await self._interne.sleep(seconds)


class _SortieGardeeSync:
    """Pendant synchrone de _SortieGardee (harnais `mesure`)."""

    def __init__(self, interne):
        self._interne = interne

    def connect_tcp(self, host, port, timeout=None, local_address=None, **kw):
        adresses = adresses_sures(host, port)
        echec = None
        for rang, ip in enumerate(adresses):
            try:
                return self._interne.connect_tcp(
                    ip, port, timeout=_delai_essai(timeout, rang, len(adresses)),
                    local_address=local_address, **kw)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                echec = exc
        raise echec

    def connect_unix_socket(self, path, timeout=None, **kw):
        raise _refuse(str(path), "", "socket locale")

    def sleep(self, seconds):
        self._interne.sleep(seconds)


def _arme(transport):
    """Pose la garde sur la couche réseau du transport. Si httpcore ne
    l'expose pas comme attendu, on REFUSE de fabriquer le client : une sortie
    non gardée ne part pas."""
    pool = getattr(transport, "_pool", None)
    interne = getattr(pool, "_network_backend", None)
    if interne is None or getattr(pool, "_proxy", None) is not None:
        raise RuntimeError("sortie du relais : couche réseau de httpcore introuvable")
    garde = (_SortieGardee if isinstance(transport, httpx.AsyncHTTPTransport)
             else _SortieGardeeSync)
    pool._network_backend = garde(interne)
    return transport


def _refus_sans_resolution(request: httpx.Request) -> None:
    """Mode Tor : refuse ce qui se juge sans résoudre (cf. plus haut)."""
    h = (request.url.host or "").strip("[]").lower().rstrip(".")
    raison, adresse = _nom_refuse(h), ""
    if not raison:
        try:
            ipaddress.ip_address(h.split("%", 1)[0])
        except ValueError:
            return                      # un nom : résolu au bout du tunnel
        raison, adresse = raison_refus(h), h
    if raison:
        cause = _refuse(h, adresse, raison)
        raise httpx.ConnectError(str(cause), request=request) from cause


class _TorGarde(httpx.BaseTransport):
    def __init__(self, interne: httpx.BaseTransport):
        self._interne = interne

    def handle_request(self, request):
        _refus_sans_resolution(request)
        return self._interne.handle_request(request)

    def close(self):
        self._interne.close()


class _TorGardeAsync(httpx.AsyncBaseTransport):
    def __init__(self, interne: httpx.AsyncBaseTransport):
        self._interne = interne

    async def handle_async_request(self, request):
        _refus_sans_resolution(request)
        return await self._interne.handle_async_request(request)

    async def aclose(self):
        await self._interne.aclose()


def _transport(mode: str, asynchrone: bool, verify: bool):
    """Le transport gardé du mode. `verify` : vérifier le TLS (poignée de main
    du système, #1323) ; faux seulement pour un `.onion` (cf. client_pour)."""
    classe = httpx.AsyncHTTPTransport if asynchrone else httpx.HTTPTransport
    tls = contexte_tls() if verify else False
    if mode == "tor":
        # Transport explicite : `httpx.Proxy` est compris de la 0.23 de la box
        # comme des versions récentes, sans le détour `proxies=`/`proxy=`.
        interne = classe(verify=tls, proxy=httpx.Proxy(TOR_SOCKS))
        return (_TorGardeAsync if asynchrone else _TorGarde)(interne)
    return _arme(classe(verify=tls))


def _commun(timeout: float) -> dict:
    # `trust_env=False` : un proxy posé dans l'environnement ne doit pas
    # remplacer la sortie gardée par la sienne.
    return dict(timeout=timeout, follow_redirects=False, headers=ENTETES_NAV,
                trust_env=False)


def _onion(hote: str) -> bool:
    return hote.lower().rstrip(".").endswith(".onion")


def schema_pour(hote: str) -> str:
    """Schéma par défaut vers la cible : http pour un .onion, https sinon.

    Un service caché n'expose en général pas de TLS (l'adresse authentifie déjà le
    service) : forcer https:// sur le service caché de gk2, qui n'ouvre que le port 80,
    donnait « destination refusée » côté Tor, donc un 502/504 dans le surfer.
    """
    return "http" if _onion(hote) else "https"


def client_pour(hote: str, mode: str = "auto", timeout: float = 25.0) -> httpx.Client:
    """Le client httpx adapté à l'hôte et au mode — sortie gardée.

    `auto` : Tor si l'hôte est en `.onion` (aucun autre chemin n'y mène),
    direct sinon. Un mode explicite l'emporte.
    """
    if mode == "auto":
        mode = "tor" if _onion(hote) else "direct"

    if mode == "tor":
        # `.onion` n'a pas de certificat vérifiable publiquement ; Tor garantit
        # l'authenticité par l'adresse elle-même. On ne vérifie donc pas le TLS
        # pour ces hôtes — et UNIQUEMENT pour eux.
        return httpx.Client(transport=_transport("tor", False, not _onion(hote)),
                            **_commun(timeout))

    return httpx.Client(transport=_transport("direct", False, True), **_commun(timeout))


def client_async(mode: str = "direct", timeout: float = 25.0) -> httpx.AsyncClient:
    """Le client async du serveur de relais — sortie gardée, TLS du système
    vérifié dans les deux modes (comportement du relais inchangé)."""
    return httpx.AsyncClient(transport=_transport(mode, True, True), **_commun(timeout))


def refus_de(exc: BaseException | None) -> DestinationRefusee | None:
    """La DestinationRefusee à l'origine de `exc` (httpx la chaîne en cause),
    ou None si l'échec est d'une autre nature."""
    vus = 0
    while exc is not None and vus < 8:
        if isinstance(exc, DestinationRefusee):
            return exc
        exc = exc.__cause__ or exc.__context__
        vus += 1
    return None


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
