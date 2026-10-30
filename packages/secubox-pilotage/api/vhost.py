# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: routes du vhost admin.<box>.secubox.in (#3126, L5 tâche 5)

Servies sur /run/secubox/pilotage.sock, jointes UNIQUEMENT par le server nginx généré pour la box (pilotage/vhosts.py), qui pose
`X-SecuBox-Pilotage-Box` ; sur l'administration du maître, /api/v1/pilotage/relais/ et /vhost/ rendent 404 (nginx/pilotage.conf).

  POST /vhost/auth/login, /vhost/auth/login/mfa
        identifiants DU MAÎTRE relayés à secubox-auth (/run/secubox/auth.sock). Un `access_token` reçu est vérifié (session vivante,
        administrateur réel) puis ÉCHANGÉ contre un jeton à portée du vhost (vhosts.frapper_jeton) : le jeton du maître ne sort jamais
        du contrôleur, aucun cookie n'est posé (la page garde son jeton dans le localStorage de SON origine). Première configuration
        et enrôlement TOTP : refusés ici (403), ils se font sur l'administration du maître. Toute autre étape : 404.
  GET|HEAD|POST|PUT|PATCH|DELETE /relais/{box}/api/v1/{…}
        jeton à portée de CETTE box (Bearer seul) ; acteur = `sub` de cette session, portée demandée = admin (administrateur réel),
        réduite par portee_permise (mains liées, box cliente sans support) puis par l'agent ; jamais un champ du client.
        404 box inconnue, ambiguë ou non « distante » ; 403 non administrateur, box cliente sans session de support ouverte ;
        409 `X-SecuBox-Version-Page` ≠ version déclarée ; 413 corps > 4 Mio ; 429 débit (administrateur, box) ; 501 agent < 0.4.0.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Awaitable, Callable, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from secubox_core import auth

from pilotage import vhosts as V
from pilotage.files import (CORPS_HTTP_MAX, RE_ACTEUR, AgentHorsLigne, AgentTropAncien, AuditIndisponible, DelaiHTTPDepasse,
                            DemandeHTTPInvalide, FileDeBoxPleine, ReponseHTTPInvalide, agent_sait_http, demander_http,
                            portee_permise)

AUTH_SOCK = "/run/secubox/auth.sock"
ETAPES_AUTH = ("login", "login/mfa")
CORPS_AUTH_MAX = 16 << 10
ENTETES_REPONSE = ("content-type", "etag", "last-modified", "content-disposition")

log = logging.getLogger("pilotage.vhost")


async def appeler_auth_socket(etape: str, corps: bytes, entetes: dict, chemin_socket: str = AUTH_SOCK,
                              delai: float = 15.0) -> tuple:
    """POST /<etape> sur la socket de secubox-auth (HTTP/1.1 minimal, réponse bornée à 64 Kio) ; rend (statut, JSON)."""
    async def echange():
        r, w = await asyncio.open_unix_connection(chemin_socket)
        try:
            tete = [f"POST /{etape} HTTP/1.1", "Host: localhost", "Content-Type: application/json",
                    f"Content-Length: {len(corps)}", "Connection: close"]
            for k in ("X-Forwarded-For", "User-Agent"):
                v = entetes.get(k.lower())
                if v and v.isprintable() and len(v) < 512:
                    tete.append(f"{k}: {v}")
            w.write(("\r\n".join(tete) + "\r\n\r\n").encode("latin-1") + corps)
            await w.drain()
            brut = await r.read(64 << 10)
        finally:
            w.close()
        tete_rep, _, contenu = brut.partition(b"\r\n\r\n")
        statut = int(tete_rep.split(b" ", 2)[1])
        return statut, json.loads(contenu or b"{}")
    return await asyncio.wait_for(echange(), delai)


def ajouter_routes_vhost(app: FastAPI, stockage, files, audit: Callable[[str, dict], None], *, horloge: Callable[[], float] = time.time,
                         maitre: Optional[str] = None, appeler_auth: Optional[Callable[..., Awaitable[tuple]]] = None,
                         debit: Optional[V.Debit] = None) -> None:
    appeler_auth = appeler_auth or appeler_auth_socket
    debit = debit or V.Debit()

    def nom_maitre() -> str:
        return maitre if maitre is not None else auth.nom_box_locale()

    async def auditer_ou_503(evenement: str, champs: dict) -> None:
        try:
            await asyncio.to_thread(audit, evenement, champs)
        except Exception:
            log.exception("audit %s impossible : demande refusée", evenement)
            raise HTTPException(503, "audit indisponible") from None

    async def box_distante(nom: str) -> tuple:
        """(ligne de la box, valeurs d'inventaire) d'une box « distante » de nom unique ; 404 sinon (jamais de détail)."""
        if not isinstance(nom, str) or not V.RE_BOX.fullmatch(nom):
            raise HTTPException(404, "box inconnue")
        lignes = await asyncio.to_thread(stockage.boites_par_nom, nom)
        if len(lignes) != 1:
            raise HTTPException(404, "box inconnue")
        b = lignes[0]
        valeurs = (await asyncio.to_thread(stockage.inventaire, b["cle"]))["valeurs"]
        if not V.interface_distante(valeurs):
            raise HTTPException(404, "box inconnue")
        return b, valeurs

    def box_de_l_entete(request: Request, attendue: Optional[str] = None) -> str:
        nom = request.headers.get(V.ENTETE_BOX, "")
        if not V.RE_BOX.fullmatch(nom) or (attendue is not None and nom != attendue):
            raise HTTPException(404, "box inconnue")
        return nom

    # --- connexion ---

    async def connexion(etape: str, request: Request):
        nom = box_de_l_entete(request)
        await box_distante(nom)
        corps = await request.body()
        if len(corps) > CORPS_AUTH_MAX:
            raise HTTPException(413, "corps trop long")
        try:
            statut, rep = await appeler_auth(etape, corps, dict(request.headers))
        except Exception:
            log.exception("secubox-auth injoignable")
            raise HTTPException(502, "authentification du maître injoignable") from None
        if not isinstance(rep, dict):
            raise HTTPException(502, "réponse de l'authentification illisible")
        if statut != 200:
            return JSONResponse({"detail": str(rep.get("detail", "refusé"))[:200]}, status_code=statut if 400 <= statut < 600 else 502)
        if rep.get("setup_required") or rep.get("enrollment_required"):
            raise HTTPException(403, "première configuration ou enrôlement du second facteur : à faire sur l'administration du maître")
        if "access_token" not in rep:
            if rep.get("mfa_required") and isinstance(rep.get("mfa_token"), str):
                return {"mfa_required": True, "mfa_token": rep["mfa_token"]}
            raise HTTPException(502, "réponse de l'authentification inattendue")
        payload = auth._validate_token(rep["access_token"]) if isinstance(rep["access_token"], str) else None
        if payload is None:
            raise HTTPException(502, "jeton du maître invalide")
        if not auth.est_admin_reel(payload):
            log.warning("vhost %s : connexion refusée à %s (pas administrateur réel)", nom, payload.get("sub"))
            raise HTTPException(403, "réservé aux administrateurs du maître")
        acteur = str(payload["sub"])[:64]
        await auditer_ou_503("pilotage_vhost_session", {"box": nom, "acteur": acteur, "etat": "ouverte"})
        jeton, duree = V.frapper_jeton(payload, nom, auth._secret(), horloge=time.time)
        return {"access_token": jeton, "token_type": "bearer", "expires_in": duree}

    @app.post("/vhost/auth/login")
    async def vhost_login(request: Request):
        return await connexion("login", request)

    @app.post("/vhost/auth/login/mfa")
    async def vhost_login_mfa(request: Request):
        return await connexion("login/mfa", request)

    # --- relais ---

    def session_vhost(request: Request, box: str) -> dict:
        h = request.headers.get("authorization", "")
        jeton = h[7:].strip() if h[:7].lower() == "bearer " else ""
        p = V.lire_jeton(jeton, box, auth._secret()) if jeton else None
        if p is None or not auth._session_validator(p["jti"]) or not auth.porteur_reconnu(p["sub"]):
            raise HTTPException(401, "session absente ou expirée", headers={"WWW-Authenticate": "Bearer"})
        if not auth.est_admin_reel(p):
            raise HTTPException(403, "réservé aux administrateurs du maître")
        return p

    async def lire_corps(request: Request) -> bytes:
        cl = request.headers.get("content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > CORPS_HTTP_MAX):
            raise HTTPException(413, "corps trop long (4 Mio au plus)")
        morceaux, n = [], 0
        async for m in request.stream():
            n += len(m)
            if n > CORPS_HTTP_MAX:
                raise HTTPException(413, "corps trop long (4 Mio au plus)")
            morceaux.append(m)
        return b"".join(morceaux)

    @app.api_route("/relais/{box}/api/v1/{reste:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
    async def relais(box: str, reste: str, request: Request):
        box_de_l_entete(request, attendue=box)
        p = session_vhost(request, box)
        b, valeurs = await box_distante(box)
        acteur = str(p["sub"]).lower()
        if not RE_ACTEUR.fullmatch(acteur):
            raise HTTPException(403, "nom d'administrateur non transmissible à la box")
        if not debit.autoriser((acteur, b["cle"])):
            raise HTTPException(429, "trop de requêtes pour cette box")
        cliente = b["reseau"] != "maillage"
        support = await asyncio.to_thread(stockage.support_ouvert, b["cle"]) if cliente else None
        if cliente and support is None:
            # R-L2-31 / R-L5-3 : une box cliente n'est servie que pendant une session de support ouverte (accord du détenteur)
            raise HTTPException(403, "box cliente : session de support ouverte requise")
        paquet, _, version = request.headers.get(V.ENTETE_VERSION, "").partition("=")
        declaree = V.pages_declarees(valeurs).get(paquet)
        if not version or declaree != version:
            raise HTTPException(409, "la box a changé de version : rechargez la page")
        if not agent_sait_http(b.get("agent_version")):
            raise HTTPException(501, "agent de la box trop ancien : 0.4.0 au moins pour servir ses pages")
        corps = await lire_corps(request)
        brut = request.scope.get("raw_path") or request.url.path.encode()
        prefixe = f"/relais/{box}".encode()
        chemin = brut[len(prefixe):].decode("ascii", "replace") if brut.startswith(prefixe + b"/api/v1/") else "/api/v1/" + reste
        if request.url.query:
            chemin += "?" + request.url.query
        portee = portee_permise(b["reseau"], V.mains_liees(valeurs), support is not None, "admin")
        try:
            rep = await demander_http(files, b["cle"], methode=request.method, chemin=chemin, acteur=acteur, maitre=nom_maitre(),
                                      portee=portee, agent_version=b.get("agent_version"), audit=audit,
                                      entetes=dict(request.headers), corps=corps, version_page=version)
        except DemandeHTTPInvalide as e:
            raise HTTPException(e.statut, str(e)) from None
        except AgentTropAncien:
            raise HTTPException(501, "agent de la box trop ancien : 0.4.0 au moins pour servir ses pages") from None
        except AgentHorsLigne:
            raise HTTPException(503, "box hors ligne") from None
        except FileDeBoxPleine:
            raise HTTPException(429, "trop de requêtes en attente pour cette box") from None
        except AuditIndisponible:
            raise HTTPException(503, "audit indisponible") from None
        except DelaiHTTPDepasse:
            raise HTTPException(504, "la box n'a pas répondu à temps") from None
        except ReponseHTTPInvalide as e:
            raise HTTPException(502, str(e)[:200]) from None
        entetes = {k: v for k, v in rep["entetes"].items() if k.lower() in ENTETES_REPONSE}
        return Response(content=rep["corps"], status_code=rep["statut"], headers=entetes)
