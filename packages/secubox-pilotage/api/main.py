# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: API d'administration (#3126)

Servie sur `/run/secubox/pilotage.sock` (l'agrégateur relaie /api/v1/pilotage/… en retirant le préfixe). TOUTES les routes sont gardées
par `require_jwt` (administrateur réel) : aucune n'est publique. Une box se désigne par sa clé `<reseau>:<nom>` ou par son nom s'il est
unique parmi les box connues (ambigu → 409).

  GET  /boxes                       liste résumée (une ligne par box)
  GET  /boxes/{x}                   inventaire complet de la box
  GET  /boxes/{x}/lire?chemin=…     Get en direct (Device.…) ; 15 s puis 504 ; hors ligne → 409
  POST /boxes/{x}/releve {duree_s}  demande un relevé (10..300 s) ; 202, audit pilotage_releve_demande
  GET  /boxes/{x}/releve            dernier relevé reçu et état
  GET  /evenements?nom=&depuis=&limite=
L2 « Agir » (tâche 6) :
  POST   /boxes/{x}/actions/{action} {args, confirmation?, support?}   action du catalogue (pilotage/operations.py) ; confirmation
                                    forte (= nom exact de la box) pour reboot, service-arreter, renouveler, renommer sur une box du
                                    propriétaire (400 sinon) ; box cliente (réseau ≠ maillage) : `support` exigé, session
                                    ouverte et non échue de CETTE box (409 sinon) ; OPERATE_RESP renvoyé tel quel (accepte,
                                    consentement, refuse) ; audit pilotage_action (demande, puis réponse avec le job)
  GET    /operations?nom=&limite=   journal des opérations (fin, progression, résultat succes|echec|inconnu)
  POST   /boxes/{x}/support {duree_min}   demande d'une session de support (1..240 min, 30 par défaut) ; audit pilotage_support
  GET    /boxes/{x}/support         sessions de la box (une session ouverte passée sa fin est « expire », R-L2-33)
  DELETE /boxes/{x}/support/{id}    fermeture (effective sur le maître tout de suite, puis envoyée à la box) ; audit pilotage_support_fermeture
L2 « Agir » (tâche 7) :
  GET    /boxes/{x}/flux            temps réel (text/event-stream) : événements notify | operation | etat, battement toutes les 15 s ;
                                    4 flux au plus par administrateur (429) ; box cliente : seulement pendant une session de support
                                    ouverte et non échue (403 sinon, flux clos à son terme), box du propriétaire : toujours (R-L2-31)
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from secubox_core.auth import require_jwt, session_toujours_admin

from api.vhost import ajouter_routes_vhost
from pilotage import vhosts as V

from pilotage.diffusion import FIN, Diffusion, LimiteAtteinte, formater
from pilotage.files import COMMANDE_MESURE, DUREE_DEFAUT_S, DUREE_MAX_S, DUREE_MIN_S, FileDeBoxPleine, Files
from pilotage.inventaire import Inventaire, box_de_ligne
from pilotage.operations import (CATALOGUE, COMMANDE_SUPPORT_FERMER, COMMANDE_SUPPORT_OUVRIR, RE_IDENT, Suivi, arguments,
                                 corps_operate)
from pilotage.stockage import HORS_LIGNE_S, SUPPORT_DUREE_MAX_MIN, StockageSqlite

DELAI_LECTURE_S = 15.0
DELAI_ACTION_S = 90.0          # OPERATE_RESP d'une action : plus que l'agent n'attend le ctl (60 s, delaiCtl), moins que la file (120 s)
SUPPORT_DUREE_DEFAUT_MIN = 30
ETATS_REPONSE = ("accepte", "consentement", "refuse")
CHEMIN_MAX = 256
_CHEMIN = re.compile(r"Device\.[A-Za-z0-9_.\-]*")
IDENT_MAX = 128
ERREUR_MAX = 300

log = logging.getLogger("pilotage.admin")


class ReponseFlux(StreamingResponse):
    """Flux SSE dont l'abonnement est libéré quoi qu'il arrive : fin normale, déconnexion, écriture en échec (battement), annulation, ou
    corps jamais démarré. Starlette ne ferme pas le générateur quand l'envoi échoue (il attend le ramasse-miettes) : on le ferme ici."""

    def __init__(self, corps, liberer: Callable[[], None], **kw) -> None:
        super().__init__(corps, **kw)
        self._corps, self._liberer = corps, liberer

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                await self._corps.aclose()
            finally:
                self._liberer()


class ReleveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duree_s: StrictInt = Field(DUREE_DEFAUT_S, ge=DUREE_MIN_S, le=DUREE_MAX_S)  # entier strict : 60.0, "60", true et NaN sont refusés


class ActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    args: dict = Field(default_factory=dict)
    confirmation: Optional[str] = Field(None, max_length=IDENT_MAX)
    support: Optional[str] = Field(None, pattern="^(?:" + RE_IDENT.pattern + ")$", max_length=64)  # action demandée dans une session de support


class SupportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duree_min: StrictInt = Field(SUPPORT_DUREE_DEFAUT_MIN, ge=1, le=SUPPORT_DUREE_MAX_MIN)


def _borne(v, n: int = ERREUR_MAX) -> str:
    return "".join(c for c in str(v)[:n] if c.isprintable())


def creer_app_admin(stockage: StockageSqlite, files: Files, inventaire: Inventaire, audit: Callable[[str, dict], None], *,
                    horloge: Callable[[], float] = time.time, delai_lecture_s: float = DELAI_LECTURE_S,
                    suivi: Optional[Suivi] = None, noms_pris: Callable[[], set] = set,
                    delai_action_s: float = DELAI_ACTION_S, diffusion=None, battement_s: float = 15.0,
                    maitre: Optional[str] = None, debit=None, plan_vhosts: Optional[Path] = None,
                    racine_pages: Optional[Path] = None) -> FastAPI:
    """`suivi` : fin des opérations (partagé avec le canal) ; `noms_pris()` : noms portés au maillage hors table des box (pairs
    de peers.json, nom du maître), appelée hors boucle. L5 tâche 5 : routes du vhost admin.<box> (api/vhost.py) ; `plan_vhosts` :
    fichier relu par le ctl root secubox-pilotage-vhost, réécrit à chaque tour d'inventaire s'il change."""
    suivi = suivi or Suivi(stockage, files, audit)
    diffusion = diffusion if diffusion is not None else Diffusion()

    @asynccontextmanager
    async def vie(app):
        try:
            async with inventaire.utiliser():
                yield
        finally:
            diffusion.fermer()   # les flux ouverts se terminent (sinon uvicorn attendrait leur fin)
            for t in list(taches):
                t.cancel()
            await asyncio.gather(*list(taches), return_exceptions=True)
            await suivi.arreter()

    app = FastAPI(title="SecuBox Pilotage", docs_url=None, redoc_url=None, openapi_url=None, lifespan=vie)

    @app.exception_handler(RequestValidationError)
    async def _invalide(request: Request, exc: RequestValidationError):
        """422 sans l'écho de la valeur reçue (un NaN dans le corps fait échouer la sérialisation de l'erreur par défaut : 500)."""
        return JSONResponse({"detail": [{"loc": [_borne(x, 64) for x in e.get("loc", [])], "msg": str(e.get("msg", ""))[:200]} for e in exc.errors()]}, status_code=422)

    garde = [Depends(require_jwt)]
    taches: set = set()
    releves_en_cours: set = set()   # Box.cle ayant un relevé demandé et pas encore rendu

    async def trouver(ident: str) -> dict:
        if not ident or len(ident) > IDENT_MAX or not ident.isprintable():
            raise HTTPException(404, "box inconnue")
        b = await asyncio.to_thread(stockage.boite, ident)
        if b is not None:
            return b
        lignes = await asyncio.to_thread(stockage.boites_par_nom, ident)
        if not lignes:
            raise HTTPException(404, "box inconnue")
        if len(lignes) > 1:
            raise HTTPException(409, {"erreur": "nom ambigu : désigner la box par sa clé", "cles": [b["cle"] for b in lignes]})
        return lignes[0]

    def en_ligne(b: dict) -> bool:
        return horloge() - b["vu_le"] < HORS_LIGNE_S

    @app.get("/boxes", dependencies=garde)
    async def boxes():
        return await asyncio.to_thread(stockage.resumes)

    @app.get("/boxes/{ident}", dependencies=garde)
    async def une_box(ident: str):
        b = await trouver(ident)
        inv = await asyncio.to_thread(stockage.inventaire, b["cle"])
        return {"cle": b["cle"], "nom": b["nom"], "reseau": b["reseau"], "client": b["client"], "adresse": b["adresse"],
                "agent_version": b["agent_version"] or None, "vu_le": b["vu_le"], "en_ligne": en_ligne(b),
                "inventaire_le": inv["releve_le"], "inventaire_partiel": inv["partiel"], "inventaire_tronques": inv["tronques"],
                "inventaire": inv["valeurs"]}

    @app.get("/boxes/{ident}/lire", dependencies=garde)
    async def lire(ident: str, chemin: str = Query("", max_length=1024)):
        if not chemin.startswith("Device.") or len(chemin) > CHEMIN_MAX or not _CHEMIN.fullmatch(chemin):
            raise HTTPException(422, "chemin invalide : Device.… (lettres, chiffres, « _ », « - » et « . », 256 caractères au plus)")
        b = await trouver(ident)
        if not en_ligne(b):
            raise HTTPException(409, "box hors ligne")
        box = box_de_ligne(b)
        try:
            futur = files.deposer(box.cle, {"type": "GET", "body": {"paths": [chemin]}})
        except FileDeBoxPleine:
            raise HTTPException(429, "trop de requêtes en attente pour cette box") from None
        try:
            rep = await asyncio.wait_for(futur, delai_lecture_s)  # annule le Future (donc retire la requête) au délai
        except asyncio.TimeoutError:
            raise HTTPException(504, "la box n'a pas répondu à temps") from None
        corps = rep.get("body") if isinstance(rep.get("body"), dict) else {}
        if rep.get("type") != "GET_RESP":
            raise HTTPException(502, {"erreur": "la box a refusé la lecture", "err": _borne(corps.get("err", ""))})
        return {"cle": b["cle"], "chemin": chemin, "results": corps.get("results", []), "tronque": corps.get("tronque") is True}

    @app.post("/boxes/{ident}/releve", status_code=202)
    async def releve(ident: str, corps: ReleveIn = ReleveIn(), jwt: dict = Depends(require_jwt)):
        b = await trouver(ident)
        if not en_ligne(b):
            raise HTTPException(409, "box hors ligne")
        if b["cle"] in releves_en_cours:
            raise HTTPException(409, "un relevé est déjà en cours pour cette box")
        releves_en_cours.add(b["cle"])  # réservé avant tout await : pas de second relevé concurrent
        try:
            try:
                await asyncio.to_thread(audit, "pilotage_releve_demande", {"cle": b["cle"], "acteur": _borne(jwt.get("sub", "?"), 64), "duree_s": corps.duree_s})
            except Exception:
                log.exception("audit du relevé impossible : relevé refusé")
                raise HTTPException(503, "audit indisponible") from None
            try:
                futur = files.deposer(b["cle"], {"type": "OPERATE", "body": {"command": COMMANDE_MESURE, "args": {"duree_s": corps.duree_s}}})
            except FileDeBoxPleine:
                raise HTTPException(429, "trop de requêtes en attente pour cette box") from None
        except BaseException:
            releves_en_cours.discard(b["cle"])
            raise
        t = asyncio.create_task(suivre_releve(b["cle"], corps.duree_s, futur))
        taches.add(t)
        t.add_done_callback(taches.discard)
        return {"cle": b["cle"], "nom": b["nom"], "duree_s": corps.duree_s, "statut": "demande"}

    async def suivre_releve(cle: str, duree_s: int, futur: asyncio.Future) -> None:
        try:
            try:
                rep = await futur   # la file borne l'attente (duree_s + 30 s)
            except asyncio.TimeoutError:
                statut, sortie = "expire", {"err": "la box n'a pas rendu le relevé à temps"}
            else:
                corps = rep.get("body") if isinstance(rep.get("body"), dict) else {}
                if rep.get("type") == "OPERATE_RESP":
                    statut, sortie = "ok", corps.get("output")
                else:
                    statut, sortie = "erreur", {"err": _borne(corps.get("err", ""))}
            await asyncio.to_thread(stockage.releve_enregistrer, cle, duree_s, statut, sortie)
        except asyncio.CancelledError:
            futur.cancel()
            raise
        except Exception:
            log.exception("relevé de %s non rangé", cle)
        finally:
            releves_en_cours.discard(cle)

    @app.get("/boxes/{ident}/releve", dependencies=garde)
    async def dernier_releve(ident: str):
        b = await trouver(ident)
        return {"cle": b["cle"], "en_cours": b["cle"] in releves_en_cours, "releve": await asyncio.to_thread(stockage.releve_lire, b["cle"])}

    # --- L2 « Agir » : actions, journal des opérations, support (tâche 6) ---

    async def auditer_ou_503(evenement: str, champs: dict) -> None:
        try:
            await asyncio.to_thread(audit, evenement, champs)
        except Exception:
            log.exception("audit %s impossible : demande refusée", evenement)
            raise HTTPException(503, "audit indisponible") from None

    async def auditer(evenement: str, champs: dict) -> None:
        """Après coup (la demande est partie) : un échec d'audit est journalisé, la réponse de la box est rendue quand même."""
        try:
            await asyncio.to_thread(audit, evenement, champs)
        except Exception:
            log.exception("audit %s impossible", evenement)

    async def operer(cle: str, corps: dict) -> Optional[dict]:
        """Dépose l'Operate et attend l'OPERATE_RESP ; None au délai (la requête est retirée de la file si elle n'a pas été servie).
        Rend {etat, job, raison} : la réponse de l'agent telle quelle, ou un refus pour une ERROR (agent de L1, sans exécuteur)."""
        try:
            futur = files.deposer(cle, {"type": "OPERATE", "body": corps})
        except FileDeBoxPleine:
            raise HTTPException(429, "trop de requêtes en attente pour cette box") from None
        try:
            rep = await asyncio.wait_for(futur, delai_action_s)
        except asyncio.TimeoutError:
            return None
        c = rep.get("body") if isinstance(rep.get("body"), dict) else {}
        if rep.get("type") == "OPERATE_RESP" and c.get("etat") in ETATS_REPONSE:
            job = c.get("job") if isinstance(c.get("job"), str) and RE_IDENT.fullmatch(c.get("job") or "") else ""
            return {"etat": c["etat"], "job": job, "raison": _borne(c.get("raison") or "")}
        return {"etat": "refuse", "job": "", "raison": _borne(c.get("err") or c.get("raison") or "réponse inattendue de la box")}

    def acteur_de(jwt: dict) -> str:
        return _borne(jwt.get("sub", "?"), 64)

    @app.post("/boxes/{ident}/actions/{action}")
    async def agir(ident: str, action: str, corps: ActionIn = ActionIn(), jwt: dict = Depends(require_jwt)):
        a = CATALOGUE.get(action)
        if a is None:
            raise HTTPException(404, "action inconnue")
        args = arguments(a, corps.args)
        if args is None:
            raise HTTPException(422, {"erreur": "paramètres invalides", "attendus": list(a.parametres)})
        b = await trouver(ident)
        if not en_ligne(b):
            raise HTTPException(409, "box hors ligne")
        # confirmation forte (box du propriétaire) : retaper EXACTEMENT le nom de la box ; une confirmation fausse est refusée partout
        if (a.forte and b["reseau"] == "maillage") or corps.confirmation is not None:
            if corps.confirmation != b["nom"]:
                raise HTTPException(400, "confirmation : retapez exactement le nom de la box")
        if b["reseau"] != "maillage" and corps.support is None:
            # I3 (R-L2-47, R-L2-38) : le catalogue d'une box cliente n'est servi que pendant une session de support ouverte et non
            # échue de cette box ; la garde est ici, pas seulement dans la page
            raise HTTPException(409, "box cliente : action seulement pendant une session de support ouverte (champ support)")
        if corps.support is not None and await asyncio.to_thread(stockage.support_ouvert, b["cle"], corps.support) is None:
            raise HTTPException(409, "session de support non ouverte ou échue")
        if action == "renommer":
            pris = await asyncio.to_thread(lambda: {x["nom"] for x in stockage.boites()} | set(noms_pris()))
            if args["nom"] in pris:
                raise HTTPException(409, "nom déjà porté par une box ou un pair connu")
        acteur = acteur_de(jwt)
        # M3 : les paramètres, déjà validés par motif (unité, nom), ne sont jamais secrets : audités
        champs = {"box": b["nom"], "cle": b["cle"], "action": action, "acteur": acteur,
                  "args": json.dumps(args, ensure_ascii=False, sort_keys=True)}
        if corps.support is not None:
            champs["support"] = corps.support
        await auditer_ou_503("pilotage_action", {**champs, "job": None, "etat": "demande"})   # pas d'audit, pas d'action
        op = await asyncio.to_thread(stockage.operation_demander, b["cle"], action, args, acteur, corps.support)
        try:
            rep = await operer(b["cle"], corps_operate(a.commande, args, jwt.get("sub")))
        except HTTPException as e:   # file pleine : rien n'est parti, la demande ne reste pas « demande »
            await asyncio.to_thread(stockage.operation_reponse, op, "refuse", None, "file de la box pleine")
            await auditer("pilotage_action", {**champs, "job": None, "etat": "refuse", "operation": op})
            raise e
        if rep is None:
            await asyncio.to_thread(stockage.operation_sans_reponse, op)
            await auditer("pilotage_action", {**champs, "job": None, "etat": "sans_reponse", "operation": op})
            raise HTTPException(504, "la box n'a pas répondu à temps")
        ligne = await asyncio.to_thread(stockage.operation_reponse, op, rep["etat"], rep["job"] or None, rep["raison"])
        await auditer("pilotage_action", {**champs, "job": rep["job"] or None, "etat": rep["etat"], "operation": op})
        if ligne is not None and ligne["etat"] == "termine":
            # la fin est arrivée avant cette réponse (orpheline fusionnée) : son résultat est audité MAINTENANT, avec l'action
            # désormais connue, une seule fois (I1), puis la suite part
            await suivi.apres_fin(box_de_ligne(b), ligne)
        diffusion.publier(b["cle"], "operation", {"box": b["nom"], "cle": b["cle"], "operation": op, "action": action, "args": args,
                                                   "acteur": acteur, "etat": rep["etat"], "job": rep["job"], "raison": rep["raison"]})
        return {"operation": op, "box": b["nom"], "cle": b["cle"], "action": action, **rep,
                "operation_etat": ligne["etat"] if ligne else rep["etat"]}

    @app.get("/operations", dependencies=garde)
    async def operations(nom: Optional[str] = Query(None, max_length=IDENT_MAX), limite: int = Query(200, ge=1, le=1000)):
        cle = (await trouver(nom))["cle"] if nom else None
        return await asyncio.to_thread(stockage.operations, cle, limite)

    @app.post("/boxes/{ident}/support")
    async def support_ouvrir(ident: str, corps: SupportIn = SupportIn(), jwt: dict = Depends(require_jwt)):
        b = await trouver(ident)
        if not en_ligne(b):
            raise HTTPException(409, "box hors ligne")
        sid, acteur = secrets.token_hex(8), acteur_de(jwt)
        champs = {"box": b["nom"], "cle": b["cle"], "acteur": acteur, "id": sid, "duree_min": corps.duree_min}
        await auditer_ou_503("pilotage_support", {**champs, "etat": "demande"})
        await asyncio.to_thread(stockage.support_demander, b["cle"], sid, corps.duree_min, acteur)
        try:
            rep = await operer(b["cle"], corps_operate(COMMANDE_SUPPORT_OUVRIR, {"id": sid, "duree_min": corps.duree_min}, jwt.get("sub")))
        except HTTPException:
            await asyncio.to_thread(stockage.support_noter, b["cle"], sid, "refuse", None)
            await auditer("pilotage_support", {**champs, "etat": "refuse"})
            raise
        if rep is None:
            await asyncio.to_thread(stockage.support_sans_reponse, b["cle"], sid)
            await auditer("pilotage_support", {**champs, "etat": "sans_reponse"})
            raise HTTPException(504, "la box n'a pas répondu à temps")
        if rep["etat"] == "refuse":
            await asyncio.to_thread(stockage.support_noter, b["cle"], sid, "refuse", None)
        await auditer("pilotage_support", {**champs, "etat": rep["etat"]})
        diffusion.publier(b["cle"], "etat", {"box": b["nom"], "cle": b["cle"], "type": "X_SECUBOX_Support", "id": sid, "etat": rep["etat"]})
        return {"id": sid, "box": b["nom"], "cle": b["cle"], "duree_min": corps.duree_min, **rep}

    @app.get("/boxes/{ident}/support", dependencies=garde)
    async def support_lire(ident: str):
        b = await trouver(ident)
        return await asyncio.to_thread(stockage.supports, b["cle"])

    @app.delete("/boxes/{ident}/support/{sid}")
    async def support_fermer(ident: str, sid: str, jwt: dict = Depends(require_jwt)):
        if not RE_IDENT.fullmatch(sid):
            raise HTTPException(422, "identifiant de session invalide")
        b = await trouver(ident)
        if not any(s["id"] == sid for s in await asyncio.to_thread(stockage.supports, b["cle"])):
            raise HTTPException(404, "session inconnue")
        acteur = acteur_de(jwt)
        await auditer_ou_503("pilotage_support_fermeture", {"box": b["nom"], "cle": b["cle"], "acteur": acteur, "id": sid})
        await asyncio.to_thread(stockage.support_fermer_local, b["cle"], sid)   # révocable côté maître, box jointe ou non
        diffusion.publier(b["cle"], "etat", {"box": b["nom"], "cle": b["cle"], "type": "X_SECUBOX_Support", "id": sid, "etat": "ferme"})
        if not en_ligne(b):
            return {"id": sid, "box": b["nom"], "etat": "hors_ligne", "job": "", "raison": "fermée sur le maître ; la box l'apprendra à son retour"}
        rep = await operer(b["cle"], corps_operate(COMMANDE_SUPPORT_FERMER, {"id": sid}, jwt.get("sub")))
        if rep is None:
            return {"id": sid, "box": b["nom"], "etat": "sans_reponse", "job": "", "raison": "fermée sur le maître"}
        return {"id": sid, "box": b["nom"], **rep}

    @app.get("/boxes/{ident}/flux")
    async def flux(ident: str, jwt: dict = Depends(require_jwt)):
        """Temps réel (tâche 7). R-L2-31 : la vue en direct d'une box CLIENTE n'est servie que pendant une session de support ouverte et non
        échue (403 sinon) ; le flux est re-vérifié à chaque battement et clos à la fin de la session. Une box du propriétaire (maillage) est
        toujours servie à l'administrateur. Un flux se compte par login (4 au plus, 429), libéré à la fin du flux quelle qu'en soit la cause."""
        b = await trouver(ident)
        cliente = b["reseau"] != "maillage"
        session = await asyncio.to_thread(stockage.support_ouvert, b["cle"]) if cliente else None
        if cliente and session is None:
            raise HTTPException(403, "vue en direct d'une box cliente : session de support ouverte requise")
        try:
            ab = diffusion.abonner(acteur_de(jwt), b["cle"])
        except LimiteAtteinte:
            raise HTTPException(429, "trop de flux ouverts pour cet administrateur") from None

        fin_support = session["fin"] if session else None
        exp = jwt.get("exp") if isinstance(jwt.get("exp"), (int, float)) and not isinstance(jwt.get("exp"), bool) else None

        async def controles(session: bool = True) -> Optional[dict]:
            """None si tout va bien, sinon le contenu de l'événement de coupure : jeton (fil) puis session de support."""
            nonlocal fin_support
            if session and not await asyncio.to_thread(session_toujours_admin, jwt):
                return {"session": "expiree"}
            if cliente:
                s = await asyncio.to_thread(stockage.support_ouvert, b["cle"])
                if s is None:
                    return {"support": "termine"}
                fin_support = s["fin"]
            return None

        async def corps():
            try:
                yield formater("etat", {"box": b["nom"], "cle": b["cle"], "connecte": True, "en_ligne": en_ligne(b),
                                        "support": session["id"] if session else None})
                loop = asyncio.get_running_loop()
                echeance = loop.time() + battement_s
                while True:
                    # prochaine vérification : le battement, l'échéance du jeton ou la fin de la session de support, la plus proche
                    prochaine = echeance
                    if exp is not None and math.isfinite(exp):
                        prochaine = min(prochaine, loop.time() + max(0.0, exp - time.time()))
                    if cliente and fin_support is not None:
                        prochaine = min(prochaine, loop.time() + max(0.0, fin_support - horloge()))
                    e = await ab.suivant(max(0.0, prochaine - loop.time()))
                    if e is FIN:
                        return
                    if e is None or loop.time() >= prochaine:
                        # échéance atteinte : contrôles AVANT de servir quoi que ce soit (les événements déjà en file attendent derrière)
                        coupure = await controles()
                        if coupure is not None:
                            yield formater("etat", {"box": b["nom"], "cle": b["cle"], **coupure})
                            return
                        if loop.time() >= echeance:
                            echeance = loop.time() + battement_s
                            if e is None:
                                yield ": battement\n\n"
                    if e is not None:
                        yield formater(*e)
                        if cliente and e[1].get("type") == "X_SECUBOX_Support":
                            # un changement de session de support : relu AVANT tout autre événement (M2), la fermeture coupe tout de suite
                            coupure = await controles(session=False)
                            if coupure is not None:
                                yield formater("etat", {"box": b["nom"], "cle": b["cle"], **coupure})
                                return
            finally:
                diffusion.liberer(ab)

        return ReponseFlux(corps(), lambda: diffusion.liberer(ab), media_type="text/event-stream",
                           headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/evenements", dependencies=garde)
    async def evenements(nom: Optional[str] = Query(None, max_length=IDENT_MAX), depuis: Optional[int] = Query(None, ge=0, le=1 << 40),
                         limite: int = Query(200, ge=1, le=1000)):
        cle = (await trouver(nom))["cle"] if nom else None
        return await asyncio.to_thread(stockage.evenements, cle, depuis, limite)

    # --- L5 tâche 5 : vhost admin.<box> d'une box légère ---
    ajouter_routes_vhost(app, stockage, files, audit, horloge=horloge, maitre=maitre, debit=debit, racine_pages=racine_pages)
    if plan_vhosts is not None:
        def ecrire_plan() -> None:
            boites = [(b["nom"], stockage.inventaire(b["cle"])["valeurs"]) for b in stockage.boites()]
            if V.ecrire_plan(plan_vhosts, V.plan(boites)):
                log.info("plan des vhosts de box légère réécrit")

        async def crochet_plan() -> None:
            await asyncio.to_thread(ecrire_plan)

        inventaire.a_chaque_tour(crochet_plan)

    return app
