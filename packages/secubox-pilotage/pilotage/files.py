# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: files de requêtes cloisonnées par box (#3126)

Une requête est déposée pour UNE box ; seule cette box la reçoit, et seule elle peut y répondre (le msg_id est tiré au hasard, 64 bits,
et lié à la box). Tout est en asyncio, sans verrou. Bornes : `max_par_box` requêtes en vie par box (refus net au-delà) ;
une requête non servie expire à 30 s, une requête servie sans réponse à `expiration_reponse_s` (le Future reçoit TimeoutError).
"""
from __future__ import annotations

import asyncio
import secrets
from collections import deque
from typing import Awaitable, Callable, Optional

EXPIRATION_S = 30.0
EXPIRATION_REPONSE_S = 120.0
MAX_PAR_BOX = 64
MAX_PAR_SONDAGE = 32
COMMANDE_MESURE = "Device.X_SECUBOX_Releve.Mesurer()"
DUREE_DEFAUT_S, DUREE_MIN_S, DUREE_MAX_S = 60, 10, 300
MARGE_MESURE_S = 30


def delai_reponse_pour(requete: dict, defaut: float) -> float:
    """Délai d'attente de la réponse : celui du relevé (duree_s + 30 s) pour Mesurer(), sinon le défaut."""
    corps = requete.get("body")
    if requete.get("type") == "OPERATE" and isinstance(corps, dict) and corps.get("command") == COMMANDE_MESURE:
        args = corps.get("args")
        duree = args.get("duree_s", DUREE_DEFAUT_S) if isinstance(args, dict) else DUREE_DEFAUT_S
        if isinstance(duree, bool) or not isinstance(duree, (int, float)):
            duree = DUREE_DEFAUT_S
        return min(max(duree, DUREE_MIN_S), DUREE_MAX_S) + MARGE_MESURE_S
    return defaut


class FileDeBoxPleine(Exception):
    """Trop de requêtes en vie pour cette box."""


class _Entree:
    __slots__ = ("box", "requete", "futur", "minuteur", "servie", "delai")

    def __init__(self, box, requete, futur, delai):
        self.box, self.requete, self.futur, self.minuteur, self.servie, self.delai = box, requete, futur, None, False, delai


class Files:
    def __init__(self, expiration_s: float = EXPIRATION_S, expiration_reponse_s: float = EXPIRATION_REPONSE_S,
                 max_par_box: int = MAX_PAR_BOX) -> None:
        self.expiration_s = expiration_s
        self.expiration_reponse_s = expiration_reponse_s
        self.max_par_box = max_par_box
        self._attente: dict = {}   # box -> deque de msg_id non servis
        self._entrees: dict = {}   # msg_id -> _Entree
        self._par_box: dict = {}   # box -> nombre de requêtes en vie
        self._reveil: dict = {}    # box -> asyncio.Event
        self._gen: dict = {}       # box -> numéro du sondage actif

    def en_attente(self, box: str) -> int:
        """Requêtes en vie (non servies ou servies sans réponse) pour cette box."""
        return self._par_box.get(box, 0)

    def deposer(self, box: str, requete: dict, delai_reponse: Optional[float] = None) -> asyncio.Future:
        """Dépose une requête `{type, body}` pour la box ; rend le Future de sa réponse. À appeler dans la boucle.
        `delai_reponse` : attente maximale de la réponse une fois la requête servie (défaut : selon la requête, voir delai_reponse_pour)."""
        if self._par_box.get(box, 0) >= self.max_par_box:
            raise FileDeBoxPleine(box)
        boucle = asyncio.get_running_loop()
        msg_id = secrets.token_hex(8)
        while msg_id in self._entrees:
            msg_id = secrets.token_hex(8)
        futur = boucle.create_future()
        e = _Entree(box, {**requete, "msg_id": msg_id}, futur,
                    delai_reponse if delai_reponse is not None else delai_reponse_pour(requete, self.expiration_reponse_s))
        # un Future annulé par l'appelant retire sa requête ; un Future expiré ne laisse pas d'exception « jamais lue »
        futur.add_done_callback(lambda f: self._termine(msg_id, f))
        e.minuteur = boucle.call_later(self.expiration_s, self._expirer, msg_id)
        self._entrees[msg_id] = e
        self._par_box[box] = self._par_box.get(box, 0) + 1
        self._attente.setdefault(box, deque()).append(msg_id)
        self._reveil.setdefault(box, asyncio.Event()).set()
        return futur

    def _termine(self, msg_id: str, futur: asyncio.Future) -> None:
        if futur.cancelled():
            self._expirer(msg_id, lever=False)
        else:
            futur.exception()

    def _retirer(self, msg_id: str):
        e = self._entrees.pop(msg_id, None)
        if e is None:
            return None
        if e.minuteur is not None:
            e.minuteur.cancel()
        n = self._par_box.get(e.box, 0) - 1
        if n > 0:
            self._par_box[e.box] = n
        else:
            self._par_box.pop(e.box, None)
        if not e.servie:
            file = self._attente.get(e.box)
            if file is not None:
                try:
                    file.remove(msg_id)
                except ValueError:
                    pass
                if not file:
                    self._attente.pop(e.box, None)
        return e

    def _expirer(self, msg_id: str, lever: bool = True) -> None:
        e = self._retirer(msg_id)
        if e is not None and lever and not e.futur.done():
            e.futur.set_exception(asyncio.TimeoutError("la box n'a pas répondu à temps"))

    def _prendre(self, box: str) -> list:
        file = self._attente.get(box)
        out = []
        boucle = asyncio.get_running_loop()
        while file and len(out) < MAX_PAR_SONDAGE:
            e = self._entrees.get(file.popleft())
            if e is None:
                continue
            e.servie = True
            e.minuteur.cancel()
            e.minuteur = boucle.call_later(e.delai, self._expirer, e.requete["msg_id"])
            out.append(e.requete)
        if not file:
            self._attente.pop(box, None)
        return out

    async def attendre_requetes(self, box: str, delai: float,
                                valide: Optional[Callable[[], Awaitable[bool]]] = None) -> list:
        """Les requêtes en attente de cette box (au plus 32), sinon attend jusqu'à `delai` secondes ; liste vide si rien.
        Un seul sondage est actif par box : un sondage plus récent fait rendre [] à l'ancien, sans rien prendre.
        `valide` (async) est interrogée juste avant de prendre : faux (client parti, box révoquée) → [] et rien n'est pris."""
        boucle = asyncio.get_running_loop()
        fin = boucle.time() + max(0.0, delai)
        ma_gen = self._gen[box] = self._gen.get(box, 0) + 1
        ev = self._reveil.setdefault(box, asyncio.Event())
        ev.set()    # réveille le sondage supplanté (déjà prévenu) ...
        ev.clear()  # ... sans que le nouveau tourne à vide
        while True:
            if self._gen.get(box) != ma_gen:
                return []
            if self._attente.get(box):
                if valide is not None and not await valide():
                    return []
                if self._gen.get(box) != ma_gen:
                    return []
                pris = self._prendre(box)
                if pris:
                    return pris
                continue
            reste = fin - boucle.time()
            if reste <= 0:
                return []
            ev.clear()
            try:
                await asyncio.wait_for(ev.wait(), reste)
            except asyncio.TimeoutError:
                return []

    def livrer_reponse(self, box: str, reponse: dict) -> bool:
        """Remet la réponse au Future de sa requête. Faux si le msg_id est inconnu, expiré, déjà livré, non servi ou émis pour une autre box."""
        msg_id = reponse.get("msg_id") if isinstance(reponse, dict) else None
        if not isinstance(msg_id, str):
            return False
        e = self._entrees.get(msg_id)
        if e is None or e.box != box or not e.servie:
            return False
        self._retirer(msg_id)
        if not e.futur.done():
            e.futur.set_result(reponse)
        return True
