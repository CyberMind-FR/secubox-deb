# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Temps réel vers la page (#3126, L2 tâche 7) : diffusion des événements d'une box aux flux `text/event-stream` des administrateurs.

Tout vit dans la boucle asyncio du service (les deux applications partagent le processus) : `publier` est synchrone, ne bloque jamais et
ne lève jamais. Chaque abonné a sa file, BORNÉE ; si la page lit moins vite que les événements arrivent, les plus vieux sont abandonnés
(et comptés : la page reçoit alors `etat {perte: n}` et se resynchronise par GET /operations). Un abonnement se compte par login
d'administrateur (4 au plus) et se libère à la fin du flux, quelle qu'en soit la cause (idempotent).

Événements (noms fermés) : `notify` (toute notification de la box, forme épurée du canal), `operation` (progression, fin, demande d'action),
`etat` (mains liées, consentement, support, connexion du flux, perte). Aucun secret : seules passent les clés déjà épurées par le canal."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque

PLAFOND_PAR_LOGIN = 4
FILE_MAX = 64
NOMS = ("notify", "operation", "etat")
TYPES_OPERATION = ("X_SECUBOX_OperationProgress", "X_SECUBOX_OperationDone")
TYPES_ETAT = ("X_SECUBOX_HandsTied", "X_SECUBOX_Consent", "X_SECUBOX_Support")

log = logging.getLogger("pilotage.diffusion")

FIN = object()   # rendu par Abonnement.suivant quand le service s'arrête


class LimiteAtteinte(Exception):
    """Le login a déjà `PLAFOND_PAR_LOGIN` flux ouverts."""


def formater(nom: str, data: dict) -> str:
    """Un événement SSE : `event:` + UNE ligne `data:` de JSON. json.dumps échappe tout saut de ligne, retour chariot, U+2028/2029 et
    caractère de contrôle (ensure_ascii) : une valeur venue de la box ou de l'administrateur ne peut ni couper ni forger un événement."""
    if nom not in NOMS:
        raise ValueError("nom d'événement inconnu")
    return f"event: {nom}\ndata: {json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(',', ':'))}\n\n"


class Abonnement:
    def __init__(self, login: str, cle: str, file_max: int) -> None:
        self.login, self.cle, self.file_max = login, cle, file_max
        self._file: deque = deque()
        self._reveil = asyncio.Event()
        self._perdus = 0
        self._ferme = False

    def poser(self, nom: str, data: dict) -> None:
        """Ajoute un événement ; file pleine : le plus vieux est abandonné. Ne bloque ni ne lève."""
        if self._ferme:
            return
        if len(self._file) >= self.file_max:
            self._file.popleft()
            self._perdus += 1
        self._file.append((nom, data))
        self._reveil.set()

    def clore(self) -> None:
        self._ferme = True
        self._reveil.set()

    async def suivant(self, delai: float):
        """Le prochain événement `(nom, data)`, `None` au bout de `delai` secondes sans rien, `FIN` si le service s'arrête."""
        loop = asyncio.get_running_loop()
        limite = loop.time() + max(0.0, delai)
        while True:
            if self._perdus:
                n, self._perdus = self._perdus, 0
                return ("etat", {"perte": n})
            if self._file:
                return self._file.popleft()
            if self._ferme:
                return FIN
            reste = limite - loop.time()
            if reste <= 0:
                return None
            self._reveil.clear()
            try:
                await asyncio.wait_for(self._reveil.wait(), reste)
            except asyncio.TimeoutError:
                pass


class Diffusion:
    def __init__(self, plafond_par_login: int = PLAFOND_PAR_LOGIN, file_max: int = FILE_MAX) -> None:
        self.plafond, self.file_max = plafond_par_login, file_max
        self._abonnes: set = set()
        self._par_login: dict = {}

    def abonner(self, login: str, cle: str) -> Abonnement:
        if self._par_login.get(login, 0) >= self.plafond:
            raise LimiteAtteinte(login)
        ab = Abonnement(login, cle, self.file_max)
        self._abonnes.add(ab)
        self._par_login[login] = self._par_login.get(login, 0) + 1
        return ab

    def liberer(self, ab: Abonnement) -> None:
        """Idempotent."""
        if ab not in self._abonnes:
            return
        self._abonnes.discard(ab)
        n = self._par_login.get(ab.login, 1) - 1
        if n > 0:
            self._par_login[ab.login] = n
        else:
            self._par_login.pop(ab.login, None)
        ab.clore()

    def compte(self, login: str) -> int:
        return self._par_login.get(login, 0)

    def total(self) -> int:
        return len(self._abonnes)

    def publier(self, cle: str, nom: str, data: dict) -> None:
        for ab in list(self._abonnes):
            if ab.cle == cle:
                ab.poser(nom, data)

    def fermer(self) -> None:
        """Arrêt du service : chaque flux se termine après avoir vidé sa file."""
        for ab in list(self._abonnes):
            ab.clore()

    def diffuser_notification(self, box, ev: dict) -> None:
        """Appelée par le canal après le rangement d'une notification (déjà épurée). Ne lève jamais."""
        try:
            data = {"box": box.nom, "cle": box.cle, **ev}
            self.publier(box.cle, "notify", data)
            if ev.get("type") in TYPES_OPERATION:
                self.publier(box.cle, "operation", data)
            elif ev.get("type") in TYPES_ETAT:
                self.publier(box.cle, "etat", data)
        except Exception:
            log.exception("diffusion d'une notification impossible")
