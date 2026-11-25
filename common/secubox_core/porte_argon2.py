# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: porte des vérifications de mot de passe (#3708)

Une vérification argon2 prend 64 Mio et un cœur, et n'importe qui peut en demander : sans borne, une rafale de connexions
remplit la mémoire et les 40 fils de l'API. Toutes (vraies et leurres) passent par UNE porte par processus :

- 3 vérifications à la fois (192 Mio), dont 2 AU PLUS hors de la zone de confiance : la troisième place reste toujours
  au propriétaire sur son LAN, au kiosque ou au maillage, même sous une rafale venue d'internet ;
- 2 demandes par source (en cours et en attente) : une seule adresse ne tient jamais les trois places ;
- l'attente est bornée (nombre et durée, comptés à part pour la zone de confiance) : au-delà, refus immédiat, donc des
  fils toujours libres. Le propriétaire sur internet attend son tour : aucune réserve ne le distingue d'un inconnu.

Le refus ne dépend que de la charge et de l'adresse, jamais du compte demandé. Le compteur par source ne garde que les
demandes présentes : il ne grossit pas avec le nombre d'adresses vues.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from contextlib import contextmanager
from typing import Dict, Iterator

#: Au-delà, le mot de passe n'est pas examiné (le Coffre et la politique s'arrêtent bien avant).
LONGUEUR_MAX = 1024


class Saturee(Exception):
    """`statut` : 429 (cette source) ou 503 (la box)."""

    def __init__(self, statut: int):
        super().__init__("trop de connexions en cours")
        self.statut = statut


def _source(adresse: str) -> str:
    try:
        ip = ipaddress.ip_address(str(adresse).strip())
    except ValueError:
        return "?"
    if ip.version == 6 and ip.ipv4_mapped is None:
        return str(ipaddress.ip_network((ip, 64), strict=False))      # un abonné = un /64
    return str(ip)


class Porte:
    def __init__(self, total: int = 3, hors_zone: int = 2, par_source: int = 2, attente_max: int = 8,
                 delai: float = 4.0):
        self.total, self.hors_zone, self.par_source = total, hors_zone, par_source
        self.attente_max, self.delai = attente_max, delai
        self._c = threading.Condition()
        self._cours = {True: 0, False: 0}
        self._attente = {True: 0, False: 0}
        self._sources: Dict[str, int] = {}

    def _libre(self, confiance: bool) -> bool:
        if self._cours[True] + self._cours[False] >= self.total:
            return False
        return confiance or self._cours[False] < self.hors_zone

    @contextmanager
    def passage(self, adresse: str, confiance: bool) -> Iterator[None]:
        src, zone = _source(adresse), bool(confiance)
        with self._c:
            if self._sources.get(src, 0) >= self.par_source:
                raise Saturee(429)
            if not self._libre(zone) and self._attente[zone] >= self.attente_max:
                raise Saturee(503)
            self._sources[src] = self._sources.get(src, 0) + 1
            try:
                fin = time.monotonic() + self.delai
                self._attente[zone] += 1
                try:
                    while not self._libre(zone):
                        reste = fin - time.monotonic()
                        if reste <= 0:
                            raise Saturee(503)
                        self._c.wait(reste)
                finally:
                    self._attente[zone] -= 1
            except BaseException:
                self._rendre_source(src)
                raise
            self._cours[zone] += 1
        try:
            yield
        finally:
            with self._c:
                self._cours[zone] -= 1
                self._rendre_source(src)
                self._c.notify_all()

    def _rendre_source(self, src: str) -> None:
        n = self._sources.get(src, 0) - 1
        if n > 0:
            self._sources[src] = n
        else:
            self._sources.pop(src, None)


#: La porte du processus.
PORTE = Porte()
