# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Service de la veille (V2 § 5.2) : boucles asynchrones, garde d'espace, mesures. Aucune collecte encore.

Une boucle qui lève est journalisée et réessayée au tour suivant, jamais fatale. Les appels SQLite passent par
asyncio.to_thread (RULES-CODE § 6) ; les écritures sont sérialisées par un verrou (Veille.sql). Garde d'espace (#3725) : sous le seuil d'espace libre de la partition qui porte veille.db (statvfs sur SON dossier,
pas sur /var/lib), TOUTES les boucles qui écrivent (collecte, corrélation et dossiers, propositions, analyse,
réponses, apprentissage, pays) se suspendent ; seule la rétention tourne (et plus souvent), pour récupérer de la place.
Reprise automatique au-dessus du seuil + marge (hystérésis). L'état est écrit dans veille.db (`garde_espace`) pour
`/veille/etat`.
"""
import asyncio
import json
import logging
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

from veille import decisions

log = logging.getLogger("secubox-ai-veille")

SEUIL_OCTETS = 2**30
MARGE_OCTETS = 2**28                 # hystérésis : reprise au-dessus de seuil + 256 Mio
RETENTION_SUSPENDUE_S = 300          # la rétention revient plus souvent tant que la garde tient
CLE_GARDE = "garde_espace"


@dataclass
class Boucle:
    nom: str
    intervalle_s: float
    fonction: Callable[[], Awaitable[None]]
    collecte: bool = False        # conservé (étiquette) : TOUTE boucle non exempte se suspend sous la garde
    exempte: bool = False         # la rétention : seule boucle qui tourne quand l'espace manque


def _libre_octets(dossier):
    return shutil.disk_usage(str(dossier)).free      # statvfs du dossier de veille.db


def _dossier_base(db):
    chemin = db.execute("PRAGMA database_list").fetchone()[2]
    return Path(chemin).parent if chemin else Path(".")


class Veille:
    def __init__(self, db, horloge, boucles, libre_octets=None, seuil_octets=SEUIL_OCTETS, marge_octets=MARGE_OCTETS):
        self.db = db
        self.horloge = horloge
        self.boucles = list(boucles)
        if libre_octets is None:
            dossier = _dossier_base(db)
            libre_octets = lambda: _libre_octets(dossier)      # noqa: E731
        self._libre = libre_octets
        self.seuil = seuil_octets
        self.marge = marge_octets
        self.libre = None
        self._publie = None
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
        return {"espace": "suspendu" if self.suspendue else "ok", "erreurs": dict(self.erreurs),
                "libre_octets": self.libre, "seuil_octets": self.seuil, "reprise_octets": self.seuil + self.marge,
                "boucles_suspendues": sorted(b.nom for b in self.boucles if self._suspend(b))}

    def _suspend(self, boucle):
        return self.suspendue and not boucle.exempte

    def verifier_espace(self):
        """Met à jour la suspension (hystérésis : suspend sous le seuil, reprend au-dessus de seuil + marge) ;
        journalise chaque changement d'état."""
        try:
            self.libre = libre = self._libre()
            if self.suspendue:
                suspendre = libre < self.seuil + self.marge
            else:
                suspendre = libre < self.seuil
        except OSError:
            log.exception("espace libre illisible : écritures suspendues par prudence")
            suspendre = True
        if suspendre != self.suspendue:
            self.suspendue = suspendre
            if suspendre:
                log.error("espace libre sous le seuil (%d octets) : toutes les boucles d'écriture suspendues, "
                          "seule la rétention tourne", self.seuil)
            else:
                log.warning("espace libre rétabli (au-dessus de %d octets) : boucles reprises", self.seuil + self.marge)
        return self.suspendue

    def _publier(self, db):
        """Écrit l'état de la garde pour /veille/etat (une écriture par changement ; un échec ne bloque rien)."""
        valeur = json.dumps({"etat": "suspendu" if self.suspendue else "ok", "libre_octets": self.libre,
                             "seuil_octets": self.seuil, "reprise_octets": self.seuil + self.marge}, sort_keys=True)
        maintenant = self.horloge()
        db.execute("BEGIN IMMEDIATE")
        try:
            decisions.poser_etat(db, CLE_GARDE, valeur, maintenant)
            db.execute("COMMIT")
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    async def _annoncer(self):
        if self._publie == self.suspendue:
            return
        try:
            await self.sql(self._publier)
            self._publie = self.suspendue
        except Exception:
            log.warning("état de la garde d'espace non écrit (disque plein ?) : nouvel essai au prochain tour")

    async def _tourner(self, boucle):
        while not self._arret.is_set():
            self.verifier_espace()
            await self._annoncer()
            if not self._suspend(boucle):
                try:
                    await boucle.fonction()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.erreurs[boucle.nom] += 1
                    log.exception("boucle %s en erreur, nouvel essai au prochain tour", boucle.nom)
            attente = boucle.intervalle_s
            if boucle.exempte and self.suspendue:
                attente = min(attente, RETENTION_SUSPENDUE_S)
            try:
                await asyncio.wait_for(self._arret.wait(), attente)
            except asyncio.TimeoutError:
                pass

    async def executer(self):
        taches = [asyncio.create_task(self._tourner(b), name=b.nom) for b in self.boucles]
        try:
            await asyncio.gather(*taches)
        finally:
            for t in taches:
                t.cancel()
