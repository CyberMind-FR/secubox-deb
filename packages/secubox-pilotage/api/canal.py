# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: application du canal des box (#3126)

Servie sur `/run/secubox/pilotage-canal.sock` derrière nginx (10.10.0.1:8472 et 10.64.0.1:8472). L'identité d'une box est son adresse
dans le tunnel, lue UNIQUEMENT dans `X-Real-IP` (posé par nginx) : jamais l'adresse du pair de la socket (c'est nginx). En-tête absent,
multiple ou adresse inconnue → 403 et une ligne d'audit `pilotage_identite_refusee` (adresse seule).

Protocole (le client Go `sbx-pilotage-agent` fait foi) :
  POST /canal/v1/bonjour     {agent_version, boot_id, modele[]}                        → 200 {"ok": true}
  GET  /canal/v1/requetes    ?attente=N (borné à 25 s)                                 → 200 [{msg_id,type,body}] | 204
  POST /canal/v1/reponses    [{msg_id,type,body}]  (≤ 64)                              → 200 {"ignore": n}
  POST /canal/v1/notifs      [{"type":"NOTIFY","body":{"event":{…}}}]  (≤ 16)          → 200 {"ignore": n}
Corps limité à 256 Kio (413, refusé dès l'en-tête ou en cours de lecture, jamais lu en entier avant). Une réponse inconnue, expirée ou
d'une autre box est comptée dans « ignore » : jamais une erreur.
"""
from __future__ import annotations

import asyncio
import json
from typing import Callable, Optional

from fastapi import FastAPI, HTTPException, Request, Response

from pilotage.files import Files
from pilotage.identite import Box
from pilotage.stockage import StockageCanal

ATTENTE_MAX_S = 25.0
TAILLE_MAX = 256 << 10
MAX_REPONSES = 64
MAX_NOTIFS = 16
TYPES_REPONSE = ("GET_RESP", "GET_SUPPORTED_DM_RESP", "OPERATE_RESP", "ERROR")
_MODELE_MAX = 4096
_CHAINE_MAX = 128


def _adresse_pour_audit(valeur: str) -> str:
    """L'adresse reçue, bornée et imprimable : c'est tout ce que l'audit garde d'un refus."""
    return "".join(c for c in valeur[:64] if c.isprintable())


def creer_app_canal(files: Files, identifier: Callable[[str], Optional[Box]], stockage: StockageCanal,
                    audit: Callable[[str, dict], None], *, attente_max: float = ATTENTE_MAX_S,
                    taille_max: int = TAILLE_MAX) -> FastAPI:
    """`identifier(adresse)` rend la Box ou None (appelée hors boucle) ; `audit(evenement, champs)` écrit une ligne dans l'audit."""
    app = FastAPI(title="SecuBox Pilotage — canal", docs_url=None, redoc_url=None, openapi_url=None)

    async def box_de(request: Request) -> Box:
        valeurs = request.headers.getlist("x-real-ip")
        brut = valeurs[0] if len(valeurs) == 1 else ""
        box = None
        if brut:
            try:
                box = await asyncio.to_thread(identifier, brut)
            except Exception:  # identité indéterminée = personne
                box = None
        if box is None:
            audit("pilotage_identite_refusee", {"adresse": _adresse_pour_audit(brut or "-")})
            raise HTTPException(403, "box inconnue")
        return box

    async def corps_json(request: Request):
        declare = request.headers.get("content-length")
        if declare is not None:
            try:
                if int(declare) > taille_max:
                    raise HTTPException(413, "corps trop gros")
            except ValueError:
                raise HTTPException(400, "Content-Length invalide")
        morceaux, total = [], 0
        async for m in request.stream():
            total += len(m)
            if total > taille_max:
                raise HTTPException(413, "corps trop gros")
            morceaux.append(m)
        try:
            return json.loads(b"".join(morceaux))
        except (ValueError, RecursionError):
            raise HTTPException(400, "JSON invalide")

    def chaine(v, n=_CHAINE_MAX) -> str:
        return v[:n] if isinstance(v, str) else ""

    @app.post("/canal/v1/bonjour")
    async def bonjour(request: Request):
        box = await box_de(request)
        doc = await corps_json(request)
        if not isinstance(doc, dict):
            raise HTTPException(400, "objet attendu")
        modele = doc.get("modele")
        modele = [chaine(p, 256) for p in modele[:_MODELE_MAX] if isinstance(p, str)] if isinstance(modele, list) else []
        infos = {"agent_version": chaine(doc.get("agent_version")), "boot_id": chaine(doc.get("boot_id")), "modele": modele}
        await asyncio.to_thread(stockage.vu, box, infos)
        return {"ok": True}

    @app.get("/canal/v1/requetes")
    async def requetes(request: Request):
        box = await box_de(request)
        try:
            attente = float(request.query_params.get("attente", attente_max))
        except ValueError:
            attente = 0.0
        if attente != attente:  # NaN
            attente = 0.0
        attente = min(max(attente, 0.0), attente_max)
        await asyncio.to_thread(stockage.vu, box, {})
        lot = await files.attendre_requetes(box.cle, attente)
        if not lot:
            return Response(status_code=204)
        return lot

    @app.post("/canal/v1/reponses")
    async def reponses(request: Request):
        box = await box_de(request)
        doc = await corps_json(request)
        if not isinstance(doc, list):
            raise HTTPException(400, "liste attendue")
        if len(doc) > MAX_REPONSES:
            raise HTTPException(413, "trop de réponses")
        ignore = 0
        for r in doc:
            ok = (isinstance(r, dict) and isinstance(r.get("msg_id"), str) and r.get("type") in TYPES_REPONSE
                  and isinstance(r.get("body"), dict))
            if ok and files.livrer_reponse(box.cle, r):
                await asyncio.to_thread(stockage.resultat, box, r["msg_id"], r)
            else:
                ignore += 1
        return {"ignore": ignore}

    @app.post("/canal/v1/notifs")
    async def notifs(request: Request):
        box = await box_de(request)
        doc = await corps_json(request)
        if not isinstance(doc, list):
            raise HTTPException(400, "liste attendue")
        if len(doc) > MAX_NOTIFS:
            raise HTTPException(413, "trop de notifications")
        ignore = 0
        for n in doc:
            ev = n.get("body", {}).get("event") if isinstance(n, dict) and n.get("type") == "NOTIFY" and isinstance(n.get("body"), dict) else None
            if isinstance(ev, dict):
                await asyncio.to_thread(stockage.notification, box, ev)
            else:
                ignore += 1
        return {"ignore": ignore}

    return app
