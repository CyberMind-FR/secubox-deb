# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Branchement de l'atelier des émissions dans le relais du POC gk0 (#4058).

Copié dans ~/poc-secubox-ai/relais/ ; relais.py l'appelle en fin de fichier, comme `agents_relais` :

    import emissions_relais  # noqa: E402
    emissions_relais.brancher(app, _local)

- garde GPU (Task 9) : tant que le verrou de voix existe (voix sur GPU seulement, réglage `voix_gpu`), les routes
  qui font travailler (ou réveillent) Gemma répondent 503 `{"detail": "voix en cours"}` ; la relance de l'atelier
  passe en portant la clé du verrou ;
- `GET /emissions` : le panneau ; `/api/v1/ai/emissions/<chemin>` : relayé vers le socket Unix du service
  `secubox-ai-emissions` (Task 14), comme `agents_relais` : LOCAL SEULEMENT (`local` du relais, Host
  127.0.0.1:8098), corps borné à `CORPS_MAX`, jeton local du compte posé par le relais (jamais vu du navigateur).
"""
from __future__ import annotations

import hmac
import json
import os
import re
from pathlib import Path

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

VERROU = Path(os.environ.get("SECUBOX_AI_EMISSIONS_VERROU")
              or Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-emissions/voix.verrou")
ENTETE_CLE = "X-Emissions-Cle"
SOCKET = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-emissions/emissions.sock"
JETON = Path.home() / ".config/secubox-ai-jeton/jeton"
PAGE = Path(__file__).parent / "emissions.html"
API = "/api/v1/ai/emissions"
CHEMIN_RE = re.compile(r"^[A-Za-z0-9/_.-]{1,160}$")
CORPS_MAX = 256 * 1024
# Routes du relais qui sollicitent ou réveillent le moteur (relais.py : chat, essai, agents, analyse de document,
# démarrage du moteur ; jarvis = agents OpenJarvis sur le même moteur).
ROUTES_LLM = re.compile(r"^(?:/api/v1/ai)?/v1/chat/completions$|^/api/v1/ai/(?:essai/flux|agents/[^/]+"
                        r"|documents/[^/]+/analyser|moteur/demarrer|jarvis(?:/.*)?)$")


def voix_en_cours() -> bool:
    return VERROU.exists()


def _cle() -> str:
    try:
        d = json.loads(VERROU.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(d.get("cle") or "") if isinstance(d, dict) else ""


def _jeton() -> str:
    try:
        st = JETON.lstat()
    except OSError:
        raise HTTPException(503, "jeton du service absent")
    if st.st_mode & 0o077 or not JETON.is_file():
        raise HTTPException(503, "jeton du service mal protégé")
    return JETON.read_text(encoding="utf-8").strip()


def brancher(app, local) -> None:
    @app.middleware("http")
    async def _garde_voix(request, appel_suivant):
        if ROUTES_LLM.match(request.url.path) and voix_en_cours():
            cle, donnee = _cle(), request.headers.get(ENTETE_CLE, "")
            if not (cle and donnee and request.url.path.endswith("/moteur/demarrer")
                    and hmac.compare_digest(cle, donnee)):
                return JSONResponse({"detail": "voix en cours"}, status_code=503)
        return await appel_suivant(request)

    @app.get("/emissions")
    def page(request: Request):
        local(request)
        return FileResponse(PAGE, headers={"Cache-Control": "no-store"})

    @app.api_route(API + "/{chemin:path}", methods=["GET", "POST", "DELETE"])
    async def relayer(chemin: str, request: Request):
        local(request)
        if not CHEMIN_RE.match(chemin) or ".." in chemin or "//" in chemin:
            raise HTTPException(404, "introuvable")
        corps = await request.body()
        if len(corps) > CORPS_MAX:
            raise HTTPException(413, "trop long")
        if not SOCKET.is_socket():
            raise HTTPException(503, "secubox-ai-emissions arrêté")
        client = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(SOCKET)), base_url="http://emissions",
                                   timeout=httpx.Timeout(600, connect=5), trust_env=False)
        entetes = {"Authorization": f"Bearer {_jeton()}"}
        if request.headers.get("content-type"):
            entetes["Content-Type"] = request.headers["content-type"]
        req = client.build_request(request.method, "/" + chemin, params=request.query_params, content=corps,
                                   headers=entetes)
        try:
            rep = await client.send(req, stream=True)
        except httpx.TransportError as exc:
            await client.aclose()
            raise HTTPException(503, "secubox-ai-emissions injoignable") from exc

        async def suite():
            try:
                async for bloc in rep.aiter_raw():
                    yield bloc
            finally:
                await rep.aclose()
                await client.aclose()

        garder = {k: v for k, v in rep.headers.items() if k.lower() in ("content-type", "cache-control",
                                                                         "content-length")}
        return StreamingResponse(suite(), status_code=rep.status_code, headers=garder)
