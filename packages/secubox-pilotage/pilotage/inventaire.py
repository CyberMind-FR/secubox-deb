# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: relève périodique de l'inventaire (#3126)

Toutes les 60 s, pour chaque box vue depuis moins de 90 s, un GET `["Device."]` est déposé dans sa file ; la réponse est rangée par
`StockageSqlite.inventaire_enregistrer` (un relevé tronqué ou en erreur n'efface jamais un relevé complet). Une box n'a jamais deux GET
d'inventaire en vol : tant que le précédent n'a ni reçu de réponse ni expiré, elle est sautée. Les événements de plus de 30 jours sont
purgés au plus une fois par heure ; au même rythme, les box sans contact depuis 30 jours sont oubliées et l'oubli est audité (M12).
Chaque tour attend aussi ses crochets (`a_chaque_tour`) : le canal y écrit les décomptes de refus
d'identité en attente (M7). L'horloge et l'attente sont injectables (les tests n'attendent pas 60 s).
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Optional

from .files import FileDeBoxPleine, Files
from .identite import Box
from .stockage import HORS_LIGNE_S, OUBLI_JOURS, StockageSqlite

INTERVALLE_S = 60.0
PURGE_INTERVALLE_S = 3600.0

log = logging.getLogger("pilotage.inventaire")


def box_de_ligne(b: dict) -> Box:
    return Box(nom=b["nom"], adresse=b["adresse"], reseau=b["reseau"], client=b["client"], abonnement=b["abonnement"])


class Inventaire:
    def __init__(self, files: Files, stockage: StockageSqlite, *, horloge: Callable[[], float] = time.time,
                 intervalle_s: float = INTERVALLE_S, attente: Callable[[float], Awaitable] = asyncio.sleep,
                 audit: Optional[Callable[[str, dict], None]] = None) -> None:
        self.files, self.stockage, self.horloge = files, stockage, horloge
        self.intervalle_s, self._attente = intervalle_s, attente
        self.audit = audit               # oubli d'une box (M12) ; None : journalisé seulement (tests anciens)
        self._en_vol: set = set()        # Box.cle ayant un GET d'inventaire en vol
        self._taches: set = set()
        self._boucle: Optional[asyncio.Task] = None
        self._derniere_purge: Optional[float] = None
        self._usagers = 0
        self._suspendu_le: Optional[float] = None   # dernière ligne « oubli suspendu » (R-L2-45) : une par heure au plus
        self._crochets: list = []        # coroutines appelées à chaque tour (vidage des refus tus du canal, M7)

    def a_chaque_tour(self, crochet: Callable[[], Awaitable]) -> None:
        """`crochet()` est attendu à chaque tour, après le dépôt des GET ; une exception est journalisée, jamais propagée."""
        self._crochets.append(crochet)

    # --- un tour ---

    async def tour(self) -> int:
        """Lance un GET pour chaque box en ligne qui n'en a pas déjà un en vol (sans attendre les réponses). Rend le nombre lancé."""
        boites = await asyncio.to_thread(self.stockage.boites_vues_depuis, HORS_LIGNE_S)
        lances = 0
        for b in boites:
            if b["cle"] in self._en_vol:
                continue
            box = box_de_ligne(b)
            try:
                futur = self.files.deposer(box.cle, {"type": "GET", "body": {"paths": ["Device."]}})
            except FileDeBoxPleine:
                continue
            self._en_vol.add(box.cle)
            t = asyncio.create_task(self._attendre(box, futur))
            self._taches.add(t)
            t.add_done_callback(self._taches.discard)
            lances += 1
        for crochet in self._crochets:
            try:
                await crochet()
            except Exception:
                log.exception("crochet du tour d'inventaire en échec")
        maintenant = self.horloge()
        if self._derniere_purge is None or maintenant - self._derniere_purge >= PURGE_INTERVALLE_S:
            self._derniere_purge = maintenant
            try:
                await asyncio.to_thread(self.stockage.purger)
            except Exception:
                log.exception("purge des événements impossible")
            await self._oublier()
        return lances

    async def _oublier(self) -> None:
        """M12 : box sans contact depuis OUBLI_JOURS jours oubliées par le stockage ; chaque oubli est audité (décision sur l'état de la
        flotte), après l'effacement : l'audit ne dit jamais oubliée une box qu'un sondage concurrent a gardée."""
        try:
            oubliees = await asyncio.to_thread(self.stockage.oublier, OUBLI_JOURS)
        except Exception:
            log.exception("oubli des box sans contact impossible")
            return
        if getattr(oubliees, "suspendu", None):
            # R-L2-45 : plus de la moitié de la flotte muette d'un coup = horloge du maître suspecte ; rien n'est oublié, réévalué
            # au passage suivant ; une ligne de journal et d'audit par heure au plus
            maintenant = self.horloge()
            if self._suspendu_le is None or maintenant - self._suspendu_le >= PURGE_INTERVALLE_S:
                self._suspendu_le = maintenant
                n = oubliees.suspendu
                log.warning("oubli suspendu : %d box sur %d sans contact depuis %d jours (horloge du maître ?)", n["candidates"], n["total"],
                            OUBLI_JOURS)
                if self.audit is not None:
                    try:
                        await asyncio.to_thread(self.audit, "pilotage_oubli_suspendu", dict(n))
                    except Exception:
                        log.exception("audit de l'oubli suspendu impossible")
            return
        for o in oubliees:
            log.info("box %s oubliée : aucun contact depuis %d jours", o["cle"], OUBLI_JOURS)
            if self.audit is None:
                continue
            try:
                await asyncio.to_thread(self.audit, "pilotage_box_oubliee", {"box": o["nom"], "cle": o["cle"], "reseau": o["reseau"],
                                                                            "dernier_contact": o["dernier_contact"], "jours": OUBLI_JOURS})
            except Exception:
                log.exception("audit de l'oubli de %s impossible", o["cle"])

    async def _attendre(self, box: Box, futur: asyncio.Future) -> None:
        try:
            rep = await futur  # la file borne l'attente (30 s non servie, 120 s servie)
            if rep.get("type") == "GET_RESP" and isinstance(rep.get("body"), dict):
                await asyncio.to_thread(self.stockage.inventaire_enregistrer, box, rep["body"])
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            futur.cancel()
            raise
        except Exception:
            log.exception("inventaire de %s non rangé", box.cle)
        finally:
            self._en_vol.discard(box.cle)

    async def attendre_fin(self) -> None:
        """Attend les GET en vol (tests)."""
        while self._taches:
            await asyncio.gather(*list(self._taches), return_exceptions=True)

    # --- boucle ---

    async def _tourner(self) -> None:
        while True:
            try:
                await self.tour()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("tour d'inventaire en échec")
            await self._attente(self.intervalle_s)

    def demarrer(self) -> None:
        """Lance l'unique boucle (sans effet si elle tourne déjà). À appeler dans la boucle asyncio."""
        if self._boucle is None or self._boucle.done():
            self._boucle = asyncio.create_task(self._tourner())

    @asynccontextmanager
    async def utiliser(self):
        """Cycle de vie partagé par les applications qui servent la même instance : la boucle démarre avec la première et ne
        s'arrête que quand la dernière s'arrête (compteur)."""
        self._usagers += 1
        self.demarrer()
        try:
            yield
        finally:
            self._usagers -= 1
            if self._usagers <= 0:
                self._usagers = 0
                await self.arreter()

    async def arreter(self) -> None:
        tout = [t for t in [self._boucle, *self._taches] if t is not None]
        for t in tout:
            t.cancel()
        await asyncio.gather(*tout, return_exceptions=True)
        self._boucle = None
