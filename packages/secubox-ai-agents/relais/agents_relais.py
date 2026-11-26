# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Branchement de secubox-ai-agents dans le relais du POC gk0 (#3986, tranche A).

Copié dans ~/poc-secubox-ai/relais/ ; relais.py l'appelle par deux lignes en fin de fichier :

    import agents_relais  # noqa: E402
    agents_relais.brancher(app, _local)

- `GET /jarvis` : la page de conversation ; `/api/v1/ai/jarvis/<chemin>` : relayé vers le socket Unix du
  service, réponse en flux (SSE) ;
- LOCAL SEULEMENT : `_local` du relais (Host 127.0.0.1:8098 / localhost:8098) ; le nom public et la ZIA n'ont
  pas ces routes (le middleware du relais ne laisse passer que ROUTES_PUBLIQUES / ROUTES_ZIA, qui ne les
  contiennent pas) ;
- le relais pose le jeton local du service (fichier 0600 du compte) : le navigateur ne le voit jamais.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse

SOCKET = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-agents/agents.sock"
JETON = Path.home() / ".config/secubox-ai-jeton/jeton"
PAGE = Path(__file__).parent / "agents.html"
CHEMIN_RE = re.compile(r"^[A-Za-z0-9/_-]{1,120}$")
CORPS_MAX = 256 * 1024
API = "/api/v1/ai/jarvis"   # PAS /agents : le POC sert déjà POST /api/v1/ai/agents/{nom} (relais.py l.3163)


def _jeton() -> str:
    st = JETON.lstat()
    if st.st_mode & 0o077 or not JETON.is_file():
        raise HTTPException(503, "jeton du service mal protégé")
    return JETON.read_text(encoding="utf-8").strip()


def brancher(app, local) -> None:
    transport = httpx.AsyncHTTPTransport(uds=str(SOCKET))

    @app.get("/jarvis")
    def page_agents(request: Request):
        local(request)
        return FileResponse(PAGE, headers={"Cache-Control": "no-store"})

    @app.api_route(API + "/{chemin:path}", methods=["GET", "POST", "DELETE"])
    async def relayer(chemin: str, request: Request):
        local(request)
        if not CHEMIN_RE.match(chemin) or ".." in chemin:
            raise HTTPException(404, "introuvable")
        corps = await request.body()
        if len(corps) > CORPS_MAX:
            raise HTTPException(413, "trop long")
        if not SOCKET.is_socket():
            raise HTTPException(503, "secubox-ai-agents arrêté")
        client = httpx.AsyncClient(transport=transport, base_url="http://agents", timeout=httpx.Timeout(600, connect=5))
        entetes = {"Authorization": f"Bearer {_jeton()}"}
        if request.headers.get("content-type"):
            entetes["Content-Type"] = request.headers["content-type"]
        req = client.build_request(request.method, "/" + chemin, params=request.query_params, content=corps,
                                   headers=entetes)
        try:
            rep = await client.send(req, stream=True)
        except httpx.TransportError as exc:
            await client.aclose()
            raise HTTPException(503, "secubox-ai-agents injoignable") from exc

        async def suite():
            try:
                async for bloc in rep.aiter_raw():
                    yield bloc
            finally:
                await rep.aclose()
                await client.aclose()

        garder = {k: v for k, v in rep.headers.items() if k.lower() in ("content-type", "cache-control")}
        return StreamingResponse(suite(), status_code=rep.status_code, headers=garder)
