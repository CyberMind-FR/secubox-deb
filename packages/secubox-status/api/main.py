# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API locale de Status Live v2 (#3605) sur /run/secubox/status.sock — lecture seule.

L'API ne collecte jamais et ne contacte aucun pair : elle relit ce que le collecteur a écrit. Toutes les routes
portent une garde (arbitrage §11.1 : la page publique est un fichier statique, pas une route anonyme) :
`require_lecture` pour la vue de flotte, `require_jwt` pour le relevé brut et le diagnostic des sources.
Routes `def` : leurs lectures de fichier tournent dans le pool, jamais sur la boucle.
"""
from __future__ import annotations

import logging
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

from secubox_status import config, historique  # noqa: E402
from secubox_status.sources import lire_json_borne  # noqa: E402

ETAT = config.ETAT
log = logging.getLogger("secubox-status")
router = APIRouter(prefix="/api/v1/status")


def _lire(nom: str) -> Dict[str, Any]:
    try:
        d = lire_json_borne(ETAT / nom)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="aucun relevé encore : la collecte n'a pas tourné")
    except (OSError, ValueError, RecursionError) as e:
        log.warning("relevé %s illisible : %s", nom, e)
        raise HTTPException(status_code=500, detail="relevé illisible")
    if not isinstance(d, dict):
        raise HTTPException(status_code=500, detail="relevé mal formé")
    return d


@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "module": "status"}


@router.get("/status", dependencies=[Depends(require_lecture)])
def status() -> Dict[str, Any]:
    """Vue de flotte : la projection publique, telle que la page statique la sert."""
    return _lire("public/public-v2.json")


@router.get("/summary", dependencies=[Depends(require_lecture)])
def summary() -> Dict[str, Any]:
    p = _lire("public/public-v2.json")
    return {k: p.get(k) for k in ("schema", "version", "generated_at", "fleet")}


@router.get("/history", dependencies=[Depends(require_lecture)])
def history(heures: int = Query(24, ge=1, le=24 * 30)) -> Dict[str, Any]:
    noeud = _lire("snapshot.json").get("node", {}).get("id")
    try:
        cx = historique.ouvrir_lecture(ETAT / "status.db")
        if cx is None or not isinstance(noeud, str):
            raise HTTPException(status_code=503, detail="historique absent")
        try:
            return {"hours": historique.heures(cx, noeud, heures)}
        finally:
            cx.close()
    except sqlite3.Error as e:
        log.warning("historique illisible : %s", e)
        raise HTTPException(status_code=503, detail="historique momentanément indisponible")


@router.get("/admin/snapshot", dependencies=[Depends(require_jwt)])
def admin_snapshot() -> Dict[str, Any]:
    return _lire("snapshot.json")


@router.get("/admin/sources", dependencies=[Depends(require_jwt)])
def admin_sources() -> Dict[str, Any]:
    r = _lire("snapshot.json")
    return {"collected_at": r.get("collected_at"), "sources": r.get("sources"), "notes": r.get("source_notes")}


app = FastAPI(title="SecuBox Status", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
