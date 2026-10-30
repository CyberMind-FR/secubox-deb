# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: files de requêtes cloisonnées par box (#3126)

Une requête est déposée pour UNE box ; seule cette box la reçoit, et seule elle peut y répondre (le msg_id est tiré au hasard, 64 bits,
et lié à la box). Tout est en asyncio, sans verrou. Bornes : `max_par_box` requêtes en vie par box (refus net au-delà) ;
une requête non servie expire à 30 s, une requête servie sans réponse à `expiration_reponse_s` (le Future reçoit TimeoutError).

L5 tâche 3 : `demander_http` émet un message HTTP vers l'agent d'une box et attend sa HTTP_RESP (fonction réutilisée par le service
qui sert les pages). Un sondage ne porte jamais plus de TAILLE_LOT_MAX octets (l'agent lit au plus ~5,8 Mo) ; la présence de l'agent
est connue par ses sondages (en cours, ou fini depuis moins de `en_ligne_s`).
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import re
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
EN_LIGNE_S = 10.0              # un agent dont le dernier sondage a fini il y a plus longtemps est hors ligne (il en refait un aussitôt)
# L5 tâche 3 : message HTTP. Bornes alignées sur l'agent Go (internal/canal/http.go) et le relais (relais.CorpsMax).
CORPS_HTTP_MAX = 4 << 20
TAILLE_LOT_MAX = 5_800_000     # octets JSON d'un sondage ; l'agent en lit au plus (4 Mio en base64) + 256 Kio = 5 854 552
DELAI_HTTP_S = 40.0            # agent : relais 30 s + 5 s ; ici 5 s de plus pour le trajet
METHODES_HTTP = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
ECRITURES_HTTP = ("POST", "PUT", "PATCH", "DELETE")
PORTEES = ("lecture", "admin")
CHEMIN_HTTP_MAX = 4096
VERSION_PAGE_MAX = 64
ENTETE_HTTP_MAX = 1024
# Motifs du vérificateur (secubox_core.auth : _RE_ACTEUR, _RE_MAITRE), repris par le relais et l'agent.
RE_ACTEUR = re.compile(r"[a-z0-9._-]{1,64}")
RE_MAITRE = re.compile(r"[a-z0-9-]{1,63}")
_RE_CHEMIN = re.compile(r"/api/v1/[a-z0-9][a-z0-9_-]{0,63}/[\x21-\x7e]*")

log = logging.getLogger("pilotage.files")


def requete_modele() -> dict:
    """GetSupportedDM : la requête que le maître dépose pour lire le modèle de données déclaré par la box. Le maître ne l'émet pas
    encore en production (le bonjour porte déjà le modèle) ; sa forme est figée par le contrat maître → agent (N5)."""
    return {"type": "GET_SUPPORTED_DM", "body": {}}


def delai_reponse_pour(requete: dict, defaut: float) -> float:
    """Délai d'attente de la réponse : celui du relevé (duree_s + 30 s) pour Mesurer(), sinon le défaut."""
    corps = requete.get("body")
    if requete.get("type") == "OPERATE" and isinstance(corps, dict) and corps.get("command") == COMMANDE_MESURE:
        args = corps.get("args")
        duree = args.get("duree_s", DUREE_DEFAUT_S) if isinstance(args, dict) else DUREE_DEFAUT_S
        if isinstance(duree, bool) or not isinstance(duree, (int, float)) or not math.isfinite(duree):
            duree = DUREE_DEFAUT_S
        return min(max(duree, DUREE_MIN_S), DUREE_MAX_S) + MARGE_MESURE_S
    return defaut


class FileDeBoxPleine(Exception):
    """Trop de requêtes en vie pour cette box."""


class _Entree:
    __slots__ = ("box", "requete", "futur", "minuteur", "servie", "delai", "taille")

    def __init__(self, box, requete, futur, delai):
        self.box, self.requete, self.futur, self.minuteur, self.servie, self.delai = box, requete, futur, None, False, delai
        # taille JSON, comptée pour borner un sondage (seul un message HTTP peut être gros)
        self.taille = len(json.dumps(requete)) if requete.get("type") == "HTTP" else 0


class Files:
    def __init__(self, expiration_s: float = EXPIRATION_S, expiration_reponse_s: float = EXPIRATION_REPONSE_S,
                 max_par_box: int = MAX_PAR_BOX, en_ligne_s: float = EN_LIGNE_S, taille_lot_max: int = TAILLE_LOT_MAX) -> None:
        self.en_ligne_s = en_ligne_s
        self.taille_lot_max = taille_lot_max
        self._sondages: dict = {}  # box -> sondages en cours
        self._sonde_le: dict = {}  # box -> instant (boucle) de la fin du dernier sondage
        self.expiration_s = expiration_s
        self.expiration_reponse_s = expiration_reponse_s
        self.max_par_box = max_par_box
        self._attente: dict = {}   # box -> deque de msg_id non servis
        self._entrees: dict = {}   # msg_id -> _Entree
        self._par_box: dict = {}   # box -> nombre de requêtes en vie
        self._reveil: dict = {}    # box -> asyncio.Event
        self._gen: dict = {}       # box -> numéro du sondage actif

    def agent_en_ligne(self, box: str) -> bool:
        """L'agent de la box sonde en ce moment, ou a fini un sondage il y a moins de `en_ligne_s` (le client Go enchaîne)."""
        if self._sondages.get(box):
            return True
        fin = self._sonde_le.get(box)
        return fin is not None and asyncio.get_running_loop().time() - fin < self.en_ligne_s

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
        taille = 0
        while file and len(out) < MAX_PAR_SONDAGE:
            e = self._entrees.get(file[0])
            if e is None:
                file.popleft()
                continue
            if out and taille + e.taille > self.taille_lot_max:
                break   # au sondage suivant : l'agent refuserait tout le lot
            file.popleft()
            taille += e.taille
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
        self._sondages[box] = self._sondages.get(box, 0) + 1
        try:
            return await self._attendre(box, delai, valide, boucle)
        finally:
            n = self._sondages.get(box, 0) - 1
            if n > 0:
                self._sondages[box] = n
            else:
                self._sondages.pop(box, None)
            self._sonde_le[box] = boucle.time()

    async def _attendre(self, box, delai, valide, boucle) -> list:
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
        # une HTTP_RESP ne répond qu'à un message HTTP, et un message HTTP qu'à une HTTP_RESP (ou une ERROR)
        if (reponse.get("type") == "HTTP_RESP") != (e.requete.get("type") == "HTTP") and reponse.get("type") != "ERROR":
            return False
        self._retirer(msg_id)
        if not e.futur.done():
            e.futur.set_result(reponse)
        return True


# --- L5 tâche 3 : message HTTP vers l'agent d'une box --------------------------------------------------------------------

class DemandeHTTPInvalide(ValueError):
    """Demande refusée avant tout envoi ; `statut` : 400 (forme) ou 413 (corps > 4 Mio)."""

    def __init__(self, statut: int, motif: str) -> None:
        super().__init__(motif)
        self.statut = statut


class AgentHorsLigne(Exception):
    """Aucun sondage récent de l'agent de cette box : rien n'est déposé."""


class DelaiHTTPDepasse(asyncio.TimeoutError):
    """L'agent n'a pas rendu la HTTP_RESP à temps (la requête est retirée de la file)."""


class ReponseHTTPInvalide(Exception):
    """L'agent a répondu autre chose qu'une HTTP_RESP de forme sûre (ERROR d'un agent ancien, champs bancals)."""


class AuditIndisponible(Exception):
    """Une écriture n'est pas envoyée si sa ligne d'audit n'a pu être écrite."""


def portee_permise(reseau: str, mains_liees: Optional[bool], support_ouvert: bool, demandee: str) -> str:
    """Portée envoyée à l'agent : `demandee` (ce que la session du maître autorise) réduite par ce que le contrôleur sait de la box —
    mains liées (ou inconnues) ⇒ lecture ; box cliente ⇒ admin seulement pendant un support ouvert. L'agent réduit encore (il ne croit
    jamais cette valeur)."""
    if demandee not in PORTEES:
        raise ValueError("portée invalide")
    if demandee == "lecture" or mains_liees is not False:
        return "lecture"
    if reseau != "maillage" and not support_ouvert:
        return "lecture"
    return "admin"


def _imprimable_ascii(s: str) -> bool:
    return all(0x20 <= ord(c) < 0x7f for c in s)


def demande_http(methode: str, chemin: str, acteur: str, maitre: str, portee: str, entetes: Optional[dict] = None,
                 corps: bytes = b"", version_page: str = "") -> dict:
    """Corps du message HTTP (entrée du relais), validé : mêmes motifs que l'agent et le relais, qui revalident tout."""
    if methode not in METHODES_HTTP:
        raise DemandeHTTPInvalide(400, "méthode refusée")
    if (not isinstance(chemin, str) or len(chemin) > CHEMIN_HTTP_MAX or not _imprimable_ascii(chemin)
            or not _RE_CHEMIN.fullmatch(chemin)):
        raise DemandeHTTPInvalide(400, "chemin refusé")
    if not isinstance(acteur, str) or not RE_ACTEUR.fullmatch(acteur):
        raise DemandeHTTPInvalide(400, "acteur invalide")
    if not isinstance(maitre, str) or not RE_MAITRE.fullmatch(maitre):
        raise DemandeHTTPInvalide(400, "maître invalide")
    if portee not in PORTEES:
        raise DemandeHTTPInvalide(400, "portée invalide")
    if not isinstance(version_page, str) or len(version_page) > VERSION_PAGE_MAX or not _imprimable_ascii(version_page):
        raise DemandeHTTPInvalide(400, "version de page invalide")
    if not isinstance(corps, (bytes, bytearray)):
        raise DemandeHTTPInvalide(400, "corps invalide")
    if len(corps) > CORPS_HTTP_MAX:
        raise DemandeHTTPInvalide(413, "corps trop long (4 Mio au plus)")
    if corps and methode in ("GET", "HEAD"):
        raise DemandeHTTPInvalide(400, "corps refusé pour une lecture")
    # Seuls les en-têtes que le relais transmet (Content-Type, Accept, If-*) : jamais Cookie, Authorization, X-SecuBox-*.
    garde = {}
    for k, v in (entetes or {}).items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        cle = k.lower()
        if not (cle in ("content-type", "accept") or cle.startswith("if-")):
            continue
        if len(k) + len(v) > ENTETE_HTTP_MAX or not _imprimable_ascii(k + v) or len(garde) >= 16:
            raise DemandeHTTPInvalide(400, "en-tête invalide")
        garde[k] = v
    return {"methode": methode, "chemin": chemin, "entetes": garde, "corps_b64": base64.b64encode(bytes(corps)).decode("ascii"),
            "acteur": acteur, "maitre": maitre, "portee": portee, "version_page": version_page}


def lire_reponse_http(rep: dict) -> dict:
    """{statut, entetes, corps (octets)} d'une HTTP_RESP ; toute autre forme : ReponseHTTPInvalide."""
    corps = rep.get("body") if isinstance(rep, dict) else None
    if not isinstance(corps, dict):
        raise ReponseHTTPInvalide("réponse de la box illisible")
    if rep.get("type") != "HTTP_RESP":
        err = corps.get("err")
        raise ReponseHTTPInvalide("la box a refusé : " + ("".join(c for c in err[:200] if c.isprintable()) if isinstance(err, str) else "?"))
    statut, entetes, b64 = corps.get("statut"), corps.get("entetes"), corps.get("corps_b64", "")
    if isinstance(statut, bool) or not isinstance(statut, int) or not 100 <= statut <= 599:
        raise ReponseHTTPInvalide("statut de la box invalide")
    if entetes is None:
        entetes = {}
    if not isinstance(entetes, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in entetes.items()):
        raise ReponseHTTPInvalide("en-têtes de la box invalides")
    try:
        brut = base64.b64decode(b64, validate=True) if isinstance(b64, str) else None
    except ValueError:
        brut = None
    if brut is None:
        raise ReponseHTTPInvalide("corps de la box invalide")
    return {"statut": statut, "entetes": entetes, "corps": brut}


async def demander_http(files: Files, box: str, *, methode: str, chemin: str, acteur: str, maitre: str, portee: str,
                        entetes: Optional[dict] = None, corps: bytes = b"", version_page: str = "", delai: float = DELAI_HTTP_S,
                        audit: Optional[Callable[[str, dict], None]] = None) -> dict:
    """Émet un message HTTP vers l'agent de la box `box` (Box.cle) et rend {statut, entetes, corps}.

    `portee` : déjà réduite par l'appelant (portee_permise) ; l'agent la réduit encore. Lève DemandeHTTPInvalide (400/413) avant tout
    envoi, AgentHorsLigne, FileDeBoxPleine, AuditIndisponible (écriture non auditée = non envoyée), DelaiHTTPDepasse (la requête est
    retirée de la file), ReponseHTTPInvalide. Une annulation de l'appelant (page fermée) retire aussi la requête. `audit(evenement,
    champs)` : chaque ÉCRITURE (POST/PUT/PATCH/DELETE) est auditée avant l'envoi puis à la réponse — jamais le corps ni la requête `?…`.
    """
    d = demande_http(methode, chemin, acteur, maitre, portee, entetes, corps, version_page)
    if not files.agent_en_ligne(box):
        raise AgentHorsLigne(box)
    champs = None
    if audit is not None and methode in ECRITURES_HTTP:
        champs = {"box": box, "methode": methode, "chemin": chemin.split("?", 1)[0], "acteur": acteur, "maitre": maitre, "portee": portee}
        try:
            await asyncio.to_thread(audit, "pilotage_http", {**champs, "etat": "demande"})
        except Exception:
            log.exception("audit pilotage_http impossible : écriture non envoyée")
            raise AuditIndisponible() from None
    futur = files.deposer(box, {"type": "HTTP", "body": d}, delai_reponse=delai)
    del d
    try:
        rep = await asyncio.wait_for(futur, delai)   # annule le Future (donc retire la requête) au délai
    except asyncio.TimeoutError:
        raise DelaiHTTPDepasse("la box n'a pas répondu à temps") from None
    sortie = lire_reponse_http(rep)
    if champs is not None:
        try:
            await asyncio.to_thread(audit, "pilotage_http", {**champs, "etat": "rendu", "statut": sortie["statut"]})
        except Exception:
            log.exception("audit pilotage_http (réponse) impossible")
    return sortie
