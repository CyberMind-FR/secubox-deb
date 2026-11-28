# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Branchement de l'atelier des émissions dans le relais du POC gk0 (#4058).

Copié dans ~/poc-secubox-ai/relais/ ; relais.py l'appelle en fin de fichier, comme `agents_relais` :

    import emissions_relais  # noqa: E402
    emissions_relais.brancher(app, _local)

À ce stade (Task 9) : seulement la garde GPU. Tant que le verrou de voix existe, les routes qui font travailler (ou
réveillent) Gemma répondent 503 `{"detail": "voix en cours"}` ; la relance de l'atelier passe en portant la clé du
verrou. Les routes `/api/v1/ai/emissions/*` viendront avec la Task 14.
"""
from __future__ import annotations

import hmac
import json
import os
import re
from pathlib import Path

from fastapi.responses import JSONResponse

VERROU = Path(os.environ.get("SECUBOX_AI_EMISSIONS_VERROU")
              or Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-emissions/voix.verrou")
ENTETE_CLE = "X-Emissions-Cle"
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


def brancher(app, local) -> None:  # noqa: ARG001 — `local` servira aux routes de la Task 14
    @app.middleware("http")
    async def _garde_voix(request, appel_suivant):
        if ROUTES_LLM.match(request.url.path) and voix_en_cours():
            cle, donnee = _cle(), request.headers.get(ENTETE_CLE, "")
            if not (cle and donnee and request.url.path.endswith("/moteur/demarrer")
                    and hmac.compare_digest(cle, donnee)):
                return JSONResponse({"detail": "voix en cours"}, status_code=503)
        return await appel_suivant(request)
