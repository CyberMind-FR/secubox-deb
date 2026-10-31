# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: live :: API publique en lecture seule (#3351).

Une seule donnée : l'état agrégé écrit par le collecteur (/var/cache/secubox/live/etat.json), déjà nettoyé de toute
adresse. Aucune authentification (page publique), aucune écriture, aucun paramètre. Le débit est limité par nginx.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

ETAT = Path("/var/cache/secubox/live/etat.json")
_cache = {"mtime": None, "doc": None}

app = FastAPI(title="secubox-live", docs_url=None, redoc_url=None, openapi_url=None)


def lire_etat(chemin: Path | None = None):
    """Relu seulement quand le fichier change ; absent ou illisible : None."""
    chemin = ETAT if chemin is None else chemin
    try:
        m = chemin.stat().st_mtime
    except OSError:
        return None
    if _cache["mtime"] != m:
        try:
            _cache["doc"] = json.loads(chemin.read_text())
            _cache["mtime"] = m
        except (OSError, ValueError):
            return None
    return _cache["doc"]


@app.get("/etat")
def etat():
    doc = lire_etat()
    if doc is None:
        return JSONResponse({"disponible": False}, status_code=503, headers={"Cache-Control": "no-store"})
    age = int(time.time()) - int(doc.get("genere_le") or 0)
    return JSONResponse(doc, headers={"Cache-Control": "public, max-age=15", "X-Live-Age": str(age)})


@app.get("/sante")
def sante():
    return {"ok": lire_etat() is not None}
