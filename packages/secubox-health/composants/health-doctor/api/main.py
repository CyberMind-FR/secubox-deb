#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: health-doctor FastAPI (issue #212)."""
from __future__ import annotations

import json as _json
import os as _os
import re as _re
import time as _time
from pathlib import Path as _Path

from fastapi import FastAPI, HTTPException, Depends
from secubox_core.auth import require_jwt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import checks, runner
from secubox_core.auth import require_lecture

# GARDE JWT SUR LES ECRITURES (#1256). Ce module n'importait pas require_jwt.
# Rien ne rattrapait l'oubli en amont : l'aggregator monte sans middleware, le
# snippet nginx transmet `Authorization` sans le verifier, et auth_request
# teste le LAN, pas un jeton.

app = FastAPI(
    title="SecuBox Health Doctor",
    description="Vital-services health monitor",
    version="1.0.0",
    root_path="/api/v1/health-doctor",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "secubox-health-doctor"}


@app.get("/checks", dependencies=[Depends(require_lecture)])
def list_checks():
    """Read the persisted health state. CORS-open for the portal banner."""
    return JSONResponse(
        content=runner.current(),
        headers={"Cache-Control": "public, max-age=15"},
    )


@app.get("/status/{name}", dependencies=[Depends(require_lecture)])
def status_of(name: str):
    if name not in checks.REGISTRY:
        raise HTTPException(status_code=404, detail=f"unknown check: {name}")
    state = runner.current()
    entry = state.get("checks", {}).get(name)
    if not entry:
        # Run on demand if not yet cached
        ok, details = checks.REGISTRY[name]()
        return {"name": name, "ok": ok, "details": details, "cached": False}
    return {"name": name, **entry, "cached": True}


@app.post("/run", dependencies=[Depends(require_jwt)])
def run():
    """Trigger a fresh check pass. CORS POST allowed for admin UIs."""
    return runner.run_once()


@app.post("/waf-selftest/run", dependencies=[Depends(require_jwt)])
def waf_selftest_run():
    """Rejoue le test WAF tout de suite (ignore le cache de 5 min)."""
    from pathlib import Path as _P
    try:
        _P("/var/cache/secubox/health-doctor-waf-selftest.json").unlink()
    except OSError:
        pass
    return runner.run_once().get("checks", {}).get("waf-selftest", {})


@app.get("/registered", dependencies=[Depends(require_lecture)])
def registered():
    """List all registered check names (for discovery)."""
    return {"checks": sorted(checks.REGISTRY.keys())}


# ── Bouton « Réparer » (#3628) ─────────────────────────────────────────────────────────────────
# L'API (secubox, dans l'agrégateur) ne relance rien elle-même : elle DÉPOSE une demande que
# l'unité root secubox-reparer.path/.service draine (secubox-reparerctl). Le ctl revalide tout
# et n'agit que sur une unité secubox-<id>.service chargée ET en échec ; il écrit l'audit.
REPARER_SPOOL = _Path(_os.environ.get("SECUBOX_REPARER_SPOOL", "/run/secubox/health-reparer"))
REPARER_ETAT = _Path(_os.environ.get("SECUBOX_REPARER_ETAT", "/var/lib/secubox-health-reparer/reparer.json"))
_ID_MODULE = _re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_ACTEUR_SUR = _re.compile(r"[^A-Za-z0-9@._:-]")


def _reparer_etat() -> dict:
    try:
        e = _json.loads(REPARER_ETAT.read_text(encoding="utf-8"))
        if isinstance(e, dict) and isinstance(e.get("modules"), dict):
            return e
    except (OSError, ValueError):
        pass
    return {"modules": {}}


@app.post("/reparer/{module}", status_code=202)
def reparer(module: str, user=Depends(require_jwt)):
    """Demande la réparation d'un module en panne ; le suivi se lit sur GET /reparer."""
    if not _ID_MODULE.fullmatch(module):
        raise HTTPException(status_code=400, detail="identifiant de module invalide")
    sub = user.get("sub", "") if isinstance(user, dict) else ""
    acteur = _ACTEUR_SUR.sub("", str(sub))[:64] or "inconnu"
    demande = REPARER_SPOOL / f"{int(_time.time() * 1000)}-{module}.demande"
    try:
        # O_EXCL : jamais d'écriture à travers un fichier déjà posé (lien compris).
        fd = _os.open(demande, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | _os.O_NOFOLLOW, 0o660)
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"reparer {module} {acteur}\n")
    except OSError as e:
        raise HTTPException(status_code=503,
                            detail="Dépôt de la demande impossible : l'unité secubox-reparer.path est-elle installée ?") from e
    return {"ok": True, "module": module, "suivi": "/api/v1/health-doctor/reparer", "depose": int(_time.time())}


@app.get("/reparer")
def reparer_status(user=Depends(require_jwt)):
    """État des dernières réparations, par module : phase (en_cours | fini), ok, message, étapes."""
    return _reparer_etat()
