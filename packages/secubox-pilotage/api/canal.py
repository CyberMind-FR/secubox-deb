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
import logging
import time
from typing import Callable, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from starlette.requests import ClientDisconnect

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
UNITE_MAX = 256  # un nom d'unité systemd va jusqu'à 255 caractères
VU_INTERVALLE_S = 10.0
AUDIT_INTERVALLE_S = 60.0
AUDIT_ADRESSES_MAX = 1024
NOTIFS_PAR_MINUTE = 60
NOTIFS_FENETRE_S = 60.0

log = logging.getLogger("pilotage.canal")


def _imprimable(v, n: int = _CHAINE_MAX) -> str:
    """Chaîne tronquée sans caractère de contrôle (journaux, terminaux, affichages) ; vide si ce n'est pas une chaîne."""
    return "".join(c for c in v[:n] if c.isprintable()) if isinstance(v, str) else ""


def _evenement(n):
    """Forme Go de notifs.Evenement : {type, unit?, value?, ts}. Rend l'événement épuré ou None."""
    ev = n.get("body", {}).get("event") if isinstance(n, dict) and n.get("type") == "NOTIFY" and isinstance(n.get("body"), dict) else None
    if not isinstance(ev, dict):
        return None
    typ, ts = ev.get("type"), ev.get("ts")
    if not isinstance(typ, str) or not typ or len(typ) > 64 or _imprimable(typ, 64) != typ:
        return None
    if isinstance(ts, bool) or not isinstance(ts, int) or not 0 <= ts < 1 << 62:
        return None
    out = {"type": typ, "ts": ts}
    if "unit" in ev:
        u = ev["unit"]
        if not isinstance(u, str) or len(u) > UNITE_MAX or _imprimable(u, UNITE_MAX) != u:
            return None
        out["unit"] = u
    if "value" in ev:
        v = ev["value"]
        if isinstance(v, bool) or not isinstance(v, int) or abs(v) >= 1 << 62:
            return None
        out["value"] = v
    return out


def _adresse_pour_audit(valeur: str) -> str:
    """L'adresse reçue, bornée et imprimable : c'est tout ce que l'audit garde d'un refus."""
    return _imprimable(valeur, 64)


def creer_app_canal(files: Files, identifier: Callable[[str], Optional[Box]], stockage: StockageCanal,
                    audit: Callable[[str, dict], None], *, attente_max: float = ATTENTE_MAX_S,
                    taille_max: int = TAILLE_MAX, vu_intervalle_s: float = VU_INTERVALLE_S,
                    audit_intervalle_s: float = AUDIT_INTERVALLE_S, horloge: Callable[[], float] = time.monotonic,
                    notifs_par_minute: int = NOTIFS_PAR_MINUTE) -> FastAPI:
    """`identifier(adresse)` rend la Box ou None (appelée hors boucle) ; `audit(evenement, champs)` écrit une ligne dans l'audit."""
    app = FastAPI(title="SecuBox Pilotage — canal", docs_url=None, redoc_url=None, openapi_url=None)

    refus: dict = {}  # adresse -> [instant de la dernière ligne, refus tus depuis] ; bornée à AUDIT_ADRESSES_MAX

    async def auditer_refus(adresse: str) -> None:
        """Une ligne d'audit par adresse et par audit_intervalle_s ; les refus tus sont comptés dans la ligne suivante."""
        maintenant = time.monotonic()
        etat = refus.get(adresse)
        if etat is not None and maintenant - etat[0] < audit_intervalle_s:
            etat[1] += 1
            return
        champs = {"adresse": adresse}
        if etat is not None and etat[1]:
            champs["tus"] = etat[1]
        refus.pop(adresse, None)
        if len(refus) >= AUDIT_ADRESSES_MAX:
            refus.pop(next(iter(refus)))
        refus[adresse] = [maintenant, 0]
        try:
            await asyncio.to_thread(audit, "pilotage_identite_refusee", champs)
        except Exception:
            log.exception("audit du refus d'identité impossible")

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
            await auditer_refus(_adresse_pour_audit(brut or "-"))
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
        try:
            async for m in request.stream():
                total += len(m)
                if total > taille_max:
                    raise HTTPException(413, "corps trop gros")
                morceaux.append(m)
        except ClientDisconnect:
            raise HTTPException(400, "client déconnecté")
        try:
            return json.loads(b"".join(morceaux))
        except (ValueError, RecursionError):
            raise HTTPException(400, "JSON invalide")

    chaine = _imprimable
    vu_le: dict = {}  # Box.cle -> instant de la dernière écriture de « vu » d'un sondage

    async def signe_de_vie(box: Box) -> None:
        maintenant = time.monotonic()
        if maintenant - vu_le.get(box.cle, -1e18) >= vu_intervalle_s:
            vu_le[box.cle] = maintenant
            await asyncio.to_thread(stockage.vu, box, {})

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
        await signe_de_vie(box)

        async def valide() -> bool:
            if await request.is_disconnected():
                return False
            try:  # la box a pu être révoquée ou renommée pendant l'attente
                actuelle = await asyncio.to_thread(identifier, box.adresse)
            except Exception:
                return False
            return actuelle is not None and actuelle.cle == box.cle

        lot = await files.attendre_requetes(box.cle, attente, valide)
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
                try:
                    await asyncio.to_thread(stockage.resultat, box, r["msg_id"], r)
                except Exception:
                    log.exception("stockage de la réponse %s impossible", r["msg_id"])
            else:
                ignore += 1
        return {"ignore": ignore}

    fenetres: dict = {}  # Box.cle -> [début de la fenêtre, acceptées, ignorées depuis la dernière ligne, instant de la dernière ligne] ; bornée

    def admis(box: Box) -> bool:
        """Au plus `notifs_par_minute` événements par box et par fenêtre de 60 s ; le surplus est ignoré, compté, et journalisé au plus une fois par minute."""
        maintenant = horloge()
        f = fenetres.get(box.cle)
        if f is None:
            if len(fenetres) >= AUDIT_ADRESSES_MAX:
                fenetres.pop(next(iter(fenetres)))
            f = fenetres[box.cle] = [maintenant, 0, 0, -1e18]
        elif maintenant - f[0] >= NOTIFS_FENETRE_S:
            f[0], f[1] = maintenant, 0
        if f[1] < notifs_par_minute:
            f[1] += 1
            return True
        f[2] += 1
        if maintenant - f[3] >= NOTIFS_FENETRE_S:
            log.warning("notifications de %s au-delà du plafond de %d/min : %d ignorée(s)", box.cle, notifs_par_minute, f[2])
            f[2], f[3] = 0, maintenant
        return False

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
            ev = _evenement(n)
            if ev is None:
                ignore += 1
                continue
            if not admis(box):
                ignore += 1
                continue
            try:
                await asyncio.to_thread(stockage.notification, box, ev)
            except Exception:
                log.exception("stockage de la notification impossible")
        return {"ignore": ignore}

    return app
