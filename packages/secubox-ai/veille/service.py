# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Service de la veille (V2 § 5.2) : boucles asynchrones, garde d'espace, mesures. Aucune collecte encore.

Une boucle qui lève est journalisée et réessayée au tour suivant, jamais fatale. Les appels SQLite passent par
asyncio.to_thread (RULES-CODE § 6) ; les écritures sont sérialisées par un verrou (Veille.sql). La collecte se suspend sous le seuil d'espace libre de /var/lib (1 Gio) et le dit.
"""
import asyncio
import logging
import shutil
import threading
from dataclasses import dataclass
from typing import Awaitable, Callable

log = logging.getLogger("secubox-ai-veille")

SEUIL_OCTETS = 2**30
PARTITION = "/var/lib"


@dataclass
class Boucle:
    nom: str
    intervalle_s: float
    fonction: Callable[[], Awaitable[None]]
    collecte: bool = False        # suspendue par la garde d'espace


def _libre_octets():
    return shutil.disk_usage(PARTITION).free


class Veille:
    def __init__(self, db, horloge, boucles, libre_octets=_libre_octets, seuil_octets=SEUIL_OCTETS):
        self.db = db
        self.horloge = horloge
        self.boucles = list(boucles)
        self._libre = libre_octets
        self.seuil = seuil_octets
        self.suspendue = False
        self.erreurs = {b.nom: 0 for b in self.boucles}
        self._arret = asyncio.Event()
        self._verrou = threading.Lock()

    async def sql(self, fonction, *args):
        """Exécute fonction(db, *args) hors de la boucle, une écriture à la fois (transactions courtes)."""
        def _faire():
            with self._verrou:
                return fonction(self.db, *args)
        return await asyncio.to_thread(_faire)

    def arreter(self):
        self._arret.set()

    def etat(self):
        return {"espace": "suspendu" if self.suspendue else "ok", "erreurs": dict(self.erreurs)}

    def verifier_espace(self):
        """Met à jour la suspension ; journalise chaque changement d'état."""
        try:
            suspendre = self._libre() < self.seuil
        except OSError:
            log.exception("espace libre illisible : collecte suspendue par prudence")
            suspendre = True
        if suspendre != self.suspendue:
            self.suspendue = suspendre
            if suspendre:
                log.error("espace libre sous le seuil (%d octets) : collecte suspendue", self.seuil)
            else:
                log.warning("espace libre rétabli : collecte reprise")
        return self.suspendue

    async def _tourner(self, boucle):
        while not self._arret.is_set():
            self.verifier_espace()
            if not (boucle.collecte and self.suspendue):
                try:
                    await boucle.fonction()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.erreurs[boucle.nom] += 1
                    log.exception("boucle %s en erreur, nouvel essai au prochain tour", boucle.nom)
            try:
                await asyncio.wait_for(self._arret.wait(), boucle.intervalle_s)
            except asyncio.TimeoutError:
                pass

    async def executer(self):
        taches = [asyncio.create_task(self._tourner(b), name=b.nom) for b in self.boucles]
        try:
            await asyncio.gather(*taches)
        finally:
            for t in taches:
                t.cancel()
