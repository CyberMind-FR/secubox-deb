# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: routes du vhost admin.<box>.secubox.in (#3126, L5 tâche 5)

Servies sur /run/secubox/pilotage.sock. Les routes /vhost/ et /relais/ ne sont jointes QUE par le server nginx généré pour la box
(pilotage/vhosts.py), qui pose `X-SecuBox-Pilotage-Box` ; sur l'administration du maître, /api/v1/pilotage/relais/ et /vhost/ rendent 404.

  GET  /boxes/{box}/connexion-vhost?retour=/<module>/      (administration DU MAÎTRE, require_jwt)
        les identifiants du maître ne sont saisis QUE sur l'origine du maître (R-L5-25 C1c) : un code à usage unique (≤ 60 s, lié à la
        box, à l'administrateur et à sa session) est émis puis 303 vers https://admin.<box>.secubox.in/pilotage-connexion/#code=…
  POST /vhost/auth/echanger {code}                          (vhost de la box)
        code consommé à la première présentation → jeton à portée du vhost (clé dérivée, aud admin.<box>, iss propre). Aucune
        saisie d'identifiants, aucun cookie sur l'origine de la box. Débit propre par adresse (I3).
  GET|HEAD|POST|PUT|PATCH|DELETE /relais/{box}/api/v1/{module}/…
        jeton à portée de CETTE box (Bearer seul) ; acteur = `sub` de cette session, portée demandée = admin (administrateur réel),
        réduite par portee_permise (mains liées, box cliente sans support) puis par l'agent ; jamais un champ du client.
        404 box inconnue, ambiguë ou non « distante » ; 403 non administrateur, box cliente sans session de support ouverte ;
        409 `X-SecuBox-Version-Page` ≠ version déclarée, ou module hors du paquet annoncé (I6) ; 413 corps > 4 Mio ;
        429 débit (administrateur, box) ; 501 agent < 0.4.0. Réponse jamais exécutable (C1a) : JSON annoncé ⇒ application/json,
        sinon application/octet-stream + attachment + CSP sandbox ; nosniff partout.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
import time
from pathlib import Path
from typing import Callable, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response

from secubox_core import auth

from pilotage import vhosts as V
from pilotage.files import (CORPS_HTTP_MAX, RE_ACTEUR, AgentHorsLigne, AgentTropAncien, AuditIndisponible, DelaiHTTPDepasse,
                            DemandeHTTPInvalide, FileDeBoxPleine, ReponseHTTPInvalide, agent_sait_http, demander_http,
                            portee_permise)

ENTETES_REPONSE = ("etag", "last-modified")
ECHANGES_PAR_MINUTE = 10

log = logging.getLogger("pilotage.vhost")


def entetes_surs(entetes_box: dict) -> tuple:
    """(media, en-têtes) d'une réponse relayée (R-L5-25 C1a) : seul du JSON est rendu comme tel ; tout le reste part en pièce
    jointe opaque, bac à sable, jamais text/html ni JavaScript de cette origine."""
    ct = next((v for k, v in entetes_box.items() if k.lower() == "content-type"), "")
    base = ct.split(";", 1)[0].strip().lower()
    h = {k: v for k, v in entetes_box.items() if k.lower() in ENTETES_REPONSE}
    h.update({"X-Content-Type-Options": "nosniff", "Content-Security-Policy": V.CSP_API, "Cache-Control": "no-store"})
    if base == "application/json" or (base.startswith("application/") and base.endswith("+json")):
        return "application/json", h
    h["Content-Disposition"] = "attachment"
    return "application/octet-stream", h


def modules_servis(racine: Path, paquet: str, version: str) -> set:
    """Modules (dossiers) de www/<paquet>/<version>/ (arbre root lisible, I6) ; vide si absent ou douteux. Jamais de lien suivi."""
    if not (V.RE_PAQUET.fullmatch(paquet) and V.RE_VERSION.fullmatch(version)):
        return set()
    d = racine / paquet / version
    try:
        noms = os.listdir(d)
    except OSError:
        return set()
    res = set()
    for n in noms:
        try:
            st = os.stat(d / n, follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and V.RE_MODULE.fullmatch(n):
            res.add(n)
    if paquet == "secubox-hub" and res:
        res.add("hub")        # #3302 : l'accueil (racine du paquet hub) appelle /api/v1/hub/…
        res.add("health-doctor")   # #3324 : la page Santé du hub appelle /api/v1/health-doctor/…
    return res


def ajouter_routes_vhost(app: FastAPI, stockage, files, audit: Callable[[str, dict], None], *, horloge: Callable[[], float] = time.time,
                         maitre: Optional[str] = None, debit: Optional[V.Debit] = None, racine_pages: Optional[Path] = None,
                         codes: Optional[V.Codes] = None, agir: Optional[Callable] = None) -> None:
    debit = debit or V.Debit()
    debit_echange = V.Debit(par_minute=ECHANGES_PAR_MINUTE, horloge=horloge)
    codes = codes or V.Codes(horloge=horloge)
    racine_pages = Path(racine_pages or V.RACINE_PAGES)

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

    # --- connexion : code émis par l'administration du maître ---

    @app.get("/boxes/{box}/connexion-vhost")
    async def connexion_vhost(request: Request, box: str, retour: Optional[str] = Query(None, max_length=80),
                              jwt: dict = Depends(auth.require_jwt)):
        # Final I1 : la route accepte le cookie du maître ; un navigateur envoie toujours Sec-Fetch-Site, un lien posé par un site
        # tiers (cross-site, ou un sous-domaine en same-site) n'émet aucun code. Absent : client non navigateur, require_jwt seul.
        site = request.headers.get("sec-fetch-site")
        if site is not None and site not in ("same-origin", "none"):
            raise HTTPException(403, "demande de connexion hors de l'origine du maître")
        if retour is not None and not V.RE_RETOUR.fullmatch(retour):
            raise HTTPException(422, "retour : /<module>/ seulement")
        await box_distante(box)
        if not all(isinstance(jwt.get(k), t) for k, t in (("sub", str), ("jti", str))) or isinstance(jwt.get("exp"), bool) \
                or not isinstance(jwt.get("exp"), (int, float)):
            raise HTTPException(401, "session du maître sans identifiant")
        if not debit_echange.autoriser(("code", jwt["sub"])):
            raise HTTPException(429, "trop de demandes de connexion")
        try:
            code = codes.emettre(box, jwt)
        except OverflowError:
            raise HTTPException(429, "trop de connexions en attente") from None
        await auditer_ou_503("pilotage_vhost_code", {"box": box, "acteur": str(jwt["sub"])[:64]})
        frag = f"code={code}" + (f"&retour={retour}" if retour else "")
        return RedirectResponse(f"https://{V.domaine(box)}/pilotage-connexion/#{frag}", status_code=303,
                                headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @app.post("/vhost/auth/echanger")
    async def vhost_echanger(request: Request):
        nom = box_de_l_entete(request)
        if not debit_echange.autoriser(("echange", request.headers.get("x-real-ip", "?"))):
            raise HTTPException(429, "trop d'essais")
        brut = await request.body()
        if len(brut) > 1024:
            raise HTTPException(413, "corps trop long")
        try:
            code = json.loads(brut).get("code")
        except (ValueError, AttributeError):
            code = None
        e = codes.consommer(code, nom)
        if e is None:
            raise HTTPException(401, "code de connexion invalide, déjà utilisé ou expiré")
        await box_distante(nom)
        if not auth._session_validator(e["jti"]) or not auth.porteur_reconnu(e["sub"]):
            raise HTTPException(401, "session du maître close")
        if not auth.est_admin_reel({"sub": e["sub"], "jti": e["jti"]}):
            raise HTTPException(403, "réservé aux administrateurs du maître")
        await auditer_ou_503("pilotage_vhost_session", {"box": nom, "acteur": str(e["sub"])[:64], "etat": "ouverte"})
        jeton, duree = V.frapper_jeton(e, nom, auth._secret(), horloge=horloge)
        return {"access_token": jeton, "token_type": "bearer", "expires_in": duree}

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

    # --- #3324 : état des modules de la box et « Démarrer » (profil léger : seuls quelques modules tournent) ---

    @app.get("/vhost/modules")
    async def modules_de_la_box(request: Request):
        box = box_de_l_entete(request)
        session_vhost(request, box)
        b, valeurs = await box_distante(box)
        return {"box": box, "modules": V.etat_modules(valeurs)}

    @app.post("/vhost/modules/{module}/demarrer")
    async def demarrer_module(request: Request, module: str):
        box = box_de_l_entete(request)
        p = session_vhost(request, box)
        if agir is None or not V.RE_MODULE.fullmatch(module) or module in ("auth", "api") or module.startswith("pilotage"):
            raise HTTPException(404, "module inconnu")
        b, _ = await box_distante(box)
        return await agir(b["cle"], f"secubox-{module}.service", p)

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
        module = reste.split("/", 1)[0]
        if module not in await asyncio.to_thread(modules_servis, racine_pages, paquet, version):
            # I6 : la version annoncée ne vaut que pour les modules de CE paquet
            raise HTTPException(409, "module hors du paquet de la page")
        if not agent_sait_http(b.get("agent_version")):
            raise HTTPException(501, "agent de la box trop ancien : 0.4.0 au moins pour servir ses pages")
        corps = await lire_corps(request)
        # Certaines versions de serveur ou de client de test laissent la requête dans raw_path : on ne garde que le chemin.
        brut = (request.scope.get("raw_path") or request.url.path.encode()).split(b"?", 1)[0]
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
        media, entetes = entetes_surs(rep["entetes"])
        return Response(content=rep["corps"], status_code=rep["statut"], headers=entetes, media_type=media)
