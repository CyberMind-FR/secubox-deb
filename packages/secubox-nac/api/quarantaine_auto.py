# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-nac — quarantaine AUTOMATIQUE d'un appareil du LAN (#2274).

Actord publie, pour chaque acteur, la mesure de l'échelle de réponse. Quand un appareil du réseau local atteint le cran QUARANTINE (niveau BLOCK : risque ≥ 75,
confiance ≥ 80, deux capteurs distincts au moins), c'est le NAC — et lui seul — qui l'isole, dans sa zone de quarantaine EXISTANTE : le même isolement qu'un appareil
inconnu (DNS et le reste comme aujourd'hui). Il reste isolé jusqu'à ce qu'un administrateur le reconnaisse et le valide : pas de libération automatique.

Le NAC lit lui-même la socket d'actord (vue complète, adresses comprises : elle n'est servie qu'à la RACINE, `GET /mesures`, jamais sous /api/v1/actor/) : sbxwaf, exposé à internet, ne détient ni le secret de flotte ni de raison de toucher au LAN.

GARDE-FOUS : seule une mesure QUARANTINE active, marquée LAN, sur une adresse privée ; jamais la box, un routeur, un équipement OpenWrt/SecuBox, ni une adresse MAC déclarée
protégée ; un appareil absent depuis plus de 3 h n'est pas isolé (l'adresse a pu changer de main) ; une mesure isole une seule fois — un appareil libéré par
l'administrateur n'est pas ré-isolé par la même mesure.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import socket
import time
from typing import Callable, Dict, Iterable, List, Optional, Set

logger = logging.getLogger("secubox.nac.quarantaine_auto")

ACTOR_SOCK = "/run/secubox/actor.sock"
ABSENCE_MAX_S = 3 * 3600


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, chemin: str, timeout: float):
        super().__init__("actord", timeout=timeout)
        self._chemin = chemin

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin)


def lire_mesures(chemin: str = ACTOR_SOCK, timeout: float = 3.0) -> List[dict]:
    """Les mesures actives publiées par actord (vue complète). Toute panne donne une liste vide : sans actord, rien n'est isolé."""
    try:
        c = _UnixHTTP(chemin, timeout)
        c.request("GET", "/mesures", headers={"X-Sbx-Vue": "complete", "Accept": "application/json"})
        r = c.getresponse()
        corps = r.read(1 << 22)
        c.close()
        if r.status != 200:
            return []
        m = json.loads(corps).get("mesures")
        return m if isinstance(m, list) else []
    except (OSError, ValueError, http.client.HTTPException):
        return []


# Plages du réseau local, énumérées : `ipaddress.is_private` range aussi les plages de documentation (203.0.113.0/24…), ce qui n'a rien d'un LAN.
_LAN = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def _prive(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _LAN)


def choisir(mesures: Iterable[dict], appareils_par_ip: Dict[str, dict], dejas: Set[str], now: int, zone_de: Callable[[str], str],
            protegees: Optional[Set[str]] = None) -> List[dict]:
    """Fonction PURE : les appareils à isoler maintenant. Chaque élément porte sa `cle` (mac|départ de la mesure) pour qu'une mesure n'isole qu'une fois."""
    protegees = {p.lower() for p in (protegees or set())}
    out: List[dict] = []
    vus: Set[str] = set()
    for m in mesures or []:
        if m.get("niveau") != "QUARANTINE" or not m.get("lan") or int(m.get("expire") or 0) <= now:
            continue
        for ip in m.get("ips") or []:
            if not _prive(ip):
                continue
            d = appareils_par_ip.get(ip)
            if not d:
                continue
            mac = (d.get("mac") or "").lower()
            if not mac or mac in protegees or d.get("is_router") or d.get("is_secubox") or d.get("is_openwrt"):
                continue
            if now - int(d.get("last_seen") or 0) > ABSENCE_MAX_S:
                continue
            cle = "%s|%d" % (mac, int(m.get("depuis") or 0))
            if cle in dejas or cle in vus or zone_de(mac) == "quarantine":
                continue
            vus.add(cle)
            out.append({"mac": mac, "ip": ip, "actor": m.get("actor", ""), "raison": m.get("raison", ""), "cle": cle, "risque": m.get("risque"),
                        "confiance": m.get("confiance"), "capteurs": m.get("capteurs")})
    return out


class QuarantaineAuto:
    """Un tour = lire les mesures, choisir, isoler (mode `auto`) ou seulement consigner le candidat (mode `propose`). Mode `off` : rien."""

    def __init__(self, mode: Callable[[], str], *, lire: Callable[[], List[dict]] = lire_mesures, isoler: Callable[[str, str, str, str], None],
                 zone_de: Callable[[str], str], trouver: Callable[[], Dict[str, dict]], now: Callable[[], float] = time.time,
                 protegees: Callable[[], Set[str]] = lambda: set()):
        self.mode, self.lire, self.isoler, self.zone_de, self.trouver, self.now, self.protegees = mode, lire, isoler, zone_de, trouver, now, protegees
        self.dejas: Set[str] = set()
        self.candidats: List[dict] = []

    def tick(self) -> int:
        mode = self.mode()
        if mode not in ("propose", "auto"):
            self.candidats = []
            return 0
        try:
            mesures = self.lire()
        except Exception:  # noqa: BLE001 - sans actord, rien n'est isolé
            logger.warning("quarantaine auto : mesures illisibles", exc_info=True)
            return 0
        a_isoler = choisir(mesures, self.trouver(), self.dejas, int(self.now()), self.zone_de, self.protegees())
        self.candidats = [{**c, "decision": "a_isoler" if mode == "propose" else "en_cours"} for c in a_isoler]
        if mode != "auto":
            return 0
        n = 0
        for c in a_isoler:
            try:
                self.isoler(c["mac"], c["ip"], c["actor"], c["raison"])
            except Exception:  # noqa: BLE001 - nouvel essai au prochain tour, jamais marqué fait
                logger.warning("quarantaine auto : isolement de %s impossible", c["mac"], exc_info=True)
                continue
            self.dejas.add(c["cle"])
            n += 1
        return n
