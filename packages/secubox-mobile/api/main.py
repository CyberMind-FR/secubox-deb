# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-mobile — API locale (socket /run/secubox/mobile.sock, #3467).

  GET  /etat       état de la protection (lecture gardée)
  POST /retirer    rend le DNS à la Freebox, la protection s'arrête jusqu'au prochain démarrage (administrateur)
  POST /reactiver  reprend la protection (administrateur)
  GET  /health     vivacité (publique)

L'API ne touche à rien elle-même : elle délègue à secubox-mobilectl par une règle sudo à argv exact.
"""
from __future__ import annotations

import json
import subprocess
from typing import List

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from secubox_core.auth import require_jwt, require_lecture

app = FastAPI(title="SecuBox Mobile", version="0.3.0")
CTL = "/usr/sbin/secubox-mobilectl"


def _ctl(*args: str) -> JSONResponse:
    cmd: List[str] = ["sudo", "-n", CTL, *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240, check=False)
        corps = json.loads(r.stdout.strip().splitlines()[-1])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return JSONResponse({"erreur": "Contrôleur injoignable."}, status_code=502)
    return JSONResponse(corps, status_code=200 if r.returncode == 0 else 500)


@app.get("/health")
def health():
    return {"status": "ok", "module": "mobile"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status():
    return _ctl("etat")


@app.get("/etat", dependencies=[Depends(require_lecture)])
def etat():
    return _ctl("etat")


@app.post("/retirer", dependencies=[Depends(require_jwt)])
def retirer():
    return _ctl("retirer", "--manuel")


@app.post("/reactiver", dependencies=[Depends(require_jwt)])
def reactiver():
    return _ctl("reactiver")
