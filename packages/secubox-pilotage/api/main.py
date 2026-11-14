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
                                    4 flux au plus par administrateur (le plus ancien est clos, #3308) ; box cliente : seulement pendant une session de support
                                    ouverte et non échue (403 sinon, flux clos à son terme), box du propriétaire : toujours (R-L2-31)
"""
from __future__ import annotations

import asyncio
import logging
import math
import re
import secrets
import time
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Callable, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from secubox_core.auth import require_jwt, session_toujours_admin

from api import actions
from api.actions import DELAI_ACTION_S, ERREUR_MAX, ETATS_REPONSE, IDENT_MAX, ActionIn, Contexte, ReleveIn, borne as _borne  # noqa: F401  (ré-exportés)
from api.vhost import ajouter_routes_vhost
from pilotage import exposition as EXPO
from pilotage import vhosts as V

from pilotage.diffusion import FIN, Diffusion, LimiteAtteinte, formater
from pilotage.files import FileDeBoxPleine, Files
from pilotage.inventaire import Inventaire, box_de_ligne
from pilotage.operations import (COMMANDE_SUPPORT_FERMER, COMMANDE_SUPPORT_OUVRIR, RE_IDENT, Suivi, corps_operate)
from pilotage.stockage import SUPPORT_DUREE_MAX_MIN, StockageSqlite

OUBLI_EN_LIGNE_S = 600     # #3335 : une box vue depuis moins de 10 min ne s'oublie qu'avec `force`

DELAI_LECTURE_S = 15.0
SUPPORT_DUREE_DEFAUT_MIN = 30
CHEMIN_MAX = 256
_CHEMIN = re.compile(r"Device\.[A-Za-z0-9_.\-]*")

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


class SupportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duree_min: StrictInt = Field(SUPPORT_DUREE_DEFAUT_MIN, ge=1, le=SUPPORT_DUREE_MAX_MIN)


def creer_app_admin(stockage: StockageSqlite, files: Files, inventaire: Inventaire, audit: Callable[[str, dict], None], *,
                    horloge: Callable[[], float] = time.time, delai_lecture_s: float = DELAI_LECTURE_S,
                    suivi: Optional[Suivi] = None, noms_pris: Callable[[], set] = set,
                    delai_action_s: float = DELAI_ACTION_S, diffusion=None, battement_s: float = 15.0,
                    maitre: Optional[str] = None, debit=None, plan_vhosts: Optional[Path] = None,
                    racine_pages: Optional[Path] = None, plan_exposition: Optional[Path] = None) -> FastAPI:
    """`suivi` : fin des opérations (partagé avec le canal) ; `noms_pris()` : noms portés au maillage hors table des box (pairs
    enrôlés de la projection p2p-public/pairs-enroles.json, nom du maître), appelée hors boucle. L5 tâche 5 : routes du vhost admin.<box> (api/vhost.py) ; `plan_vhosts` :
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
    ctx = Contexte(stockage=stockage, files=files, audit=audit, suivi=suivi, diffusion=diffusion, horloge=horloge, noms_pris=noms_pris,
                   delai_action_s=delai_action_s)
    app.state.contexte = ctx
    taches, releves_en_cours = ctx.taches, ctx.releves_en_cours
    trouver, en_ligne = partial(actions.trouver, ctx), partial(actions.en_ligne, ctx)
    auditer_ou_503, auditer, operer = (partial(f, ctx) for f in (actions.auditer_ou_503, actions.auditer, actions.operer))
    acteur_de = actions.acteur_de

    @app.get("/boxes", dependencies=garde)
    async def boxes():
        return await asyncio.to_thread(stockage.resumes)

    @app.post("/boxes/{ident}/oublier", dependencies=garde)
    async def oublier_box(ident: str, corps: dict = Body(...)):
        """#3335 : « Oublier ce nœud » — retire une box obsolète de la Flotte. Confirmation : le nom retapé ; une box vue
        depuis moins de 10 min exige `force`. Audité (`pilotage_box_oubliee`). Le registre p2p et wg-mesh sont oubliés
        par secubox-p2p (`POST /api/v1/p2p/master-link/oublier`), appelé par la page de la Flotte."""
        b = await trouver(ident)
        if not isinstance(corps, dict) or corps.get("confirmation") != b["nom"]:
            raise HTTPException(400, "confirmation : retapez exactement le nom de la box")
        force = corps.get("force") is True
        if not force and horloge() - b["vu_le"] < OUBLI_EN_LIGNE_S:
            raise HTTPException(409, "box vue il y a moins de 10 min : confirmer l'oubli d'une box active (force)")
        await asyncio.to_thread(audit, "pilotage_box_oubliee", {"box": b["nom"], "cle": b["cle"], "force": force})
        await asyncio.to_thread(stockage.oublier_boite, b["cle"])
        return {"oublie": b["cle"]}

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
        await actions.lancer_releve(ctx, b, corps.duree_s, acteur_de(jwt))
        return {"cle": b["cle"], "nom": b["nom"], "duree_s": corps.duree_s, "statut": "demande"}

    @app.get("/boxes/{ident}/releve", dependencies=garde)
    async def dernier_releve(ident: str):
        b = await trouver(ident)
        return {"cle": b["cle"], "en_cours": b["cle"] in releves_en_cours, "releve": await asyncio.to_thread(stockage.releve_lire, b["cle"])}

    # --- L2 « Agir » : actions, journal des opérations, support (tâche 6) ---

    @app.post("/boxes/{ident}/actions/{action}")
    async def agir(ident: str, action: str, corps: ActionIn = ActionIn(), jwt: dict = Depends(require_jwt)):
        return await actions.executer_action(ctx, ident, action, corps, jwt)

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
        toujours servie à l'administrateur. Un flux se compte par login (4 au plus : le plus ancien est clos, #3308 ; 429 au plafond global), libéré à la fin du flux quelle qu'en soit la cause."""
        b = await trouver(ident)
        cliente = b["reseau"] != "maillage"
        session = await asyncio.to_thread(stockage.support_ouvert, b["cle"]) if cliente else None
        if cliente and session is None:
            raise HTTPException(403, "vue en direct d'une box cliente : session de support ouverte requise")
        try:
            ab = diffusion.abonner(acteur_de(jwt), b["cle"])
        except LimiteAtteinte:
            raise HTTPException(429, "trop de flux ouverts") from None

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
    ajouter_routes_vhost(app, stockage, files, audit, horloge=horloge, maitre=maitre, debit=debit, racine_pages=racine_pages,
                         agir=lambda box, unite, p: actions.executer_action(ctx, box, "service-demarrer", ActionIn(args={"unite": unite}), p))
    if plan_vhosts is not None:
        def ecrire_plan() -> None:
            boites = [(b["nom"], stockage.inventaire(b["cle"])["valeurs"]) for b in stockage.boites()]
            if V.ecrire_plan(plan_vhosts, V.plan(boites)):
                log.info("plan des vhosts de box légère réécrit")

        async def crochet_plan() -> None:
            await asyncio.to_thread(ecrire_plan)

        inventaire.a_chaque_tour(crochet_plan)
    # --- L5 tâche 6 (E4) : noms et ports déclarés par les agents, relus par secubox-relais-maillage (root) ---
    if plan_exposition is not None:
        def ecrire_exposition() -> None:
            lignes = [{**b, "inventaire": stockage.inventaire(b["cle"])} for b in stockage.boites()]
            if EXPO.ecrire_plan(plan_exposition, EXPO.plan(lignes)):
                log.info("plan d'exposition réécrit")

        async def crochet_exposition() -> None:
            await asyncio.to_thread(ecrire_exposition)

        inventaire.a_chaque_tour(crochet_exposition)

    return app
