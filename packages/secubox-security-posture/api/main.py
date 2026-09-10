# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — API
CyberMind — https://cybermind.fr

Thin FastAPI surface over the posture engine. All heavy work happens in a
background task that recomputes every 60 s and writes a JSON cache (the project
double-cache pattern); endpoints serve the cached snapshot for instant,
read-only responses. No auth: socket-only, like sibling modules; mounted by the
aggregator under /api/v1/security-posture.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends
from secubox_core.auth import require_jwt
from fastapi.middleware.cors import CORSMiddleware

from .posture import cspn, tpn
from .posture.collectors import collect_all
from .posture.model import DOMAINS
from .posture.scoring import build_domain_scores, defcon, findings_from, overall_score
from secubox_core.auth import require_lecture

log = logging.getLogger("secubox.security-posture")

# Under /var/lib/secubox (the systemd unit's ReadWritePaths) — /var/cache is not
# writable with ProtectSystem=strict.
CACHE_FILE = Path("/var/lib/secubox/security-posture/posture.json")
# Snapshot pour un tableau de bord : 5 min de fraicheur suffisent. Chaque
# rafraichissement est couteux (collecte posture) — a 60s il pesait ~20% CPU en
# continu sur cette board 4 coeurs. Configurable par env si besoin.
REFRESH_INTERVAL = int(os.environ.get("SECUBOX_POSTURE_REFRESH_SEC", "300"))

_state: dict = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def compute() -> dict:
    """Collect every signal and assemble the full posture snapshot."""
    indicators = await collect_all()
    domains = build_domain_scores(indicators)
    overall = overall_score(domains)
    findings = findings_from(domains)
    cspn_rep = await cspn.run_report()
    tpn_rep = await tpn.run_report()

    measured = [d for d in domains if d.coverage > 0]
    coverage = round(sum(d.coverage for d in measured) / len(measured), 3) if measured else 0.0

    return {
        "timestamp": _now(),
        "overall": defcon(overall),
        "coverage": coverage,
        "domains": [d.to_dict() for d in domains],
        "findings": [f.to_dict() for f in findings],
        "cspn": cspn_rep,
        "tpn": tpn_rep,
    }


async def _refresh_once():
    snap = await compute()
    _state["snapshot"] = snap
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(snap))
    except Exception as e:  # cache is best-effort
        log.warning("posture cache write failed: %s", e)


async def _refresh_loop():
    while True:
        try:
            await _refresh_once()
        except Exception as e:
            log.error("posture refresh failed: %s", e)
        await asyncio.sleep(REFRESH_INTERVAL)


def _load_cache_from_disk():
    if CACHE_FILE.exists():
        try:
            _state["snapshot"] = json.loads(CACHE_FILE.read_text())
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_cache_from_disk()           # instant cold-start data if present
    task = asyncio.create_task(_refresh_loop())
    log.info("security-posture started")
    try:
        yield
    finally:
        task.cancel()


# GARDE JWT SUR LES ECRITURES (#1256). Ce module n'importait pas require_jwt.
# Rien ne rattrapait l'oubli en amont : l'aggregator monte sans middleware, le
# snippet nginx transmet `Authorization` sans le verifier, et auth_request
# teste le LAN, pas un jeton.

app = FastAPI(
    title="SecuBox Security Posture",
    description="Honest, board-truthful security posture scorecard.",
    version="2.0.0",
    root_path="/api/v1/security-posture",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"],
)


def _snapshot() -> dict:
    snap = _state.get("snapshot")
    if not snap:
        raise HTTPException(status_code=503, detail="posture not computed yet")
    return snap


@app.get("/overview", dependencies=[Depends(require_lecture)])
async def overview():
    return _snapshot()


@app.get("/defcon", dependencies=[Depends(require_lecture)])
async def get_defcon():
    snap = _snapshot()
    return {"timestamp": snap["timestamp"], "overall": snap["overall"],
            "coverage": snap["coverage"]}


@app.get("/domains/{domain}", dependencies=[Depends(require_lecture)])
async def get_domain(domain: str):
    if domain not in DOMAINS:
        raise HTTPException(status_code=404, detail=f"unknown domain '{domain}'")
    snap = _snapshot()
    for d in snap["domains"]:
        if d["domain"] == domain:
            return d
    raise HTTPException(status_code=404, detail="domain not in snapshot")


@app.get("/findings", dependencies=[Depends(require_lecture)])
async def get_findings():
    snap = _snapshot()
    return {"timestamp": snap["timestamp"], "findings": snap["findings"]}


@app.get("/cspn", dependencies=[Depends(require_lecture)])
async def get_cspn():
    return _snapshot()["cspn"]


@app.get("/tpn", dependencies=[Depends(require_lecture)])
async def get_tpn():
    return _snapshot()["tpn"]


@app.post("/refresh", dependencies=[Depends(require_jwt)])
async def refresh():
    await _refresh_once()
    return {"status": "refreshed", "timestamp": _state["snapshot"]["timestamp"]}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-security-posture", "version": "2.0.0",
            "computed": "snapshot" in _state}
