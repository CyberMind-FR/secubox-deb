# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: API d'administration (#3126)

Servie sur `/run/secubox/pilotage.sock` (l'agrégateur relaie /api/v1/pilotage/… en retirant le préfixe). TOUTES les routes sont gardées
par `require_jwt` (administrateur réel) : aucune n'est publique. Une box se désigne par sa clé `<reseau>:<nom>` ou par son nom s'il est
unique parmi les box connues (ambigu → 409). Lecture seule, hormis la demande de relevé de performance (Operate `Mesurer()`).

  GET  /boxes                       liste résumée (une ligne par box)
  GET  /boxes/{x}                   inventaire complet de la box
  GET  /boxes/{x}/lire?chemin=…     Get en direct (Device.…) ; 15 s puis 504 ; hors ligne → 409
  POST /boxes/{x}/releve {duree_s}  demande un relevé (10..300 s) ; 202, audit pilotage_releve_demande
  GET  /boxes/{x}/releve            dernier relevé reçu et état
  GET  /evenements?nom=&depuis=&limite=
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import asynccontextmanager
from typing import Callable, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from secubox_core.auth import require_jwt

from pilotage.files import COMMANDE_MESURE, DUREE_DEFAUT_S, DUREE_MAX_S, DUREE_MIN_S, FileDeBoxPleine, Files
from pilotage.inventaire import Inventaire, box_de_ligne
from pilotage.stockage import HORS_LIGNE_S, StockageSqlite

DELAI_LECTURE_S = 15.0
CHEMIN_MAX = 256
_CHEMIN = re.compile(r"Device\.[A-Za-z0-9_.\-]*")
IDENT_MAX = 128
ERREUR_MAX = 300

log = logging.getLogger("pilotage.admin")


class ReleveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duree_s: StrictInt = Field(DUREE_DEFAUT_S, ge=DUREE_MIN_S, le=DUREE_MAX_S)  # entier strict : 60.0, "60", true et NaN sont refusés


def _borne(v, n: int = ERREUR_MAX) -> str:
    return "".join(c for c in str(v)[:n] if c.isprintable())


def creer_app_admin(stockage: StockageSqlite, files: Files, inventaire: Inventaire, audit: Callable[[str, dict], None], *,
                    horloge: Callable[[], float] = time.time, delai_lecture_s: float = DELAI_LECTURE_S) -> FastAPI:
    @asynccontextmanager
    async def vie(app):
        try:
            async with inventaire.utiliser():
                yield
        finally:
            for t in list(taches):
                t.cancel()
            await asyncio.gather(*list(taches), return_exceptions=True)

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
                "inventaire_le": inv["releve_le"], "inventaire_partiel": inv["partiel"], "inventaire": inv["valeurs"]}

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

    @app.get("/evenements", dependencies=garde)
    async def evenements(nom: Optional[str] = Query(None, max_length=IDENT_MAX), depuis: Optional[int] = Query(None, ge=0, le=1 << 40),
                         limite: int = Query(200, ge=1, le=1000)):
        cle = (await trouver(nom))["cle"] if nom else None
        return await asyncio.to_thread(stockage.evenements, cle, depuis, limite)

    return app
