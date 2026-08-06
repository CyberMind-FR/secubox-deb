# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-media — supports externes (plan de contrôle)
CyberMind — https://cybermind.fr

FastAPI sur /run/secubox/media.sock, proxifié par nginx sur /api/v1/media/.

CETTE API NE TOUCHE RIEN ELLE-MÊME. Elle tourne en `secubox` et délègue chaque
opération — monter, lister, copier — à `sudo -n /usr/sbin/mediactl`, la seule
surface privilégiée du module (webui -> ctl confiné). Le confinement des
chemins, la lecture seule et le refus de supprimer vivent dans le ctl, pas ici :
une garde posée dans la couche HTTP serait contournable par tout autre appelant.

Les VERBES D'ACTION exigent un jeton. La détection et la navigation n'en
demandent pas — elles ne modifient rien, et le panneau doit pouvoir s'afficher
avant toute authentification. Monter, démonter et transférer, si.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from typing import Any, Dict

from fastapi import Body, Depends, FastAPI, HTTPException
from pydantic import BaseModel

from secubox_core.auth import require_jwt

VERSION = "1.2.2"
CTL = "/usr/sbin/mediactl"

log = logging.getLogger("secubox-media")

app = FastAPI(
    title="SecuBox Media",
    version=VERSION,
    root_path="/api/v1/media",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


async def _ctl(*args: str, timeout: int = 60) -> Dict[str, Any]:
    """`sudo -n mediactl <args>` hors boucle d'événements.

    Les arguments sont passés en LISTE, jamais concaténés dans un shell : ils
    contiennent des chemins choisis par l'utilisateur, et une interpolation
    ferait d'un nom de fichier une injection de commande."""
    def _run() -> Dict[str, Any]:
        try:
            p = subprocess.run(["sudo", "-n", CTL, *args],
                               capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail=f"mediactl introuvable ({CTL})")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504,
                                detail=f"mediactl {args[0]} a dépassé {timeout}s")
        out = (p.stdout or "").strip()
        if not out:
            raise HTTPException(status_code=500,
                                detail=(p.stderr or "mediactl n'a rien renvoyé")[:300])
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            raise HTTPException(status_code=500,
                                detail=f"sortie non JSON : {out[:200]!r}")

    return await asyncio.to_thread(_run)


class PathBody(BaseModel):
    path: str


class MountBody(BaseModel):
    path: str
    # Ecriture = choix explicite. Le defaut protege un support fraichement
    # branche d'une modification non demandee ; l'opt-in sert a exporter.
    rw: bool = False


class TransferBody(BaseModel):
    src: str
    dst: str


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "module": "media"}


@app.get("/detect")
async def detect() -> Dict[str, Any]:
    """Supports détectés + alertes de stabilité du bus.

    Les alertes viennent en premier dans le panneau : proposer de parcourir un
    support dont le port déconnecte en boucle, sans le dire, est un mensonge."""
    return await _ctl("detect", timeout=30)


@app.get("/browse")
async def browse(path: str = "") -> Dict[str, Any]:
    return await _ctl("browse", path, timeout=45)


@app.get("/roots")
async def roots() -> Dict[str, Any]:
    """Racines déclarées : médiathèques des services et destinations.

    Le panneau ne devine aucun chemin — il affiche ce que le ctl déclare, donc
    exactement ce que le confinement autorise."""
    return await _ctl("roots", timeout=30)


@app.post("/mount")
async def mount(body: MountBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Monte un périphérique. Lecture seule sauf `rw` explicite."""
    args = ["mount", body.path] + (["--rw"] if body.rw else [])
    return await _ctl(*args, timeout=60)


@app.post("/unmount")
async def unmount(body: PathBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return await _ctl("unmount", body.path, timeout=60)


@app.post("/copy")
async def copy(body: TransferBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Met une copie en file. Ne transfère pas ici : le drainage s'en charge."""
    return await _ctl("copy", body.src, body.dst, timeout=30)


@app.post("/sync")
async def sync(body: TransferBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Aligne la destination sur la source. Ne supprime jamais à destination."""
    return await _ctl("sync", body.src, body.dst, timeout=30)


@app.post("/compare")
async def compare(body: TransferBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Liste les écarts sans rien écrire."""
    return await _ctl("compare", body.src, body.dst, timeout=120)


@app.get("/jobs")
async def jobs() -> Dict[str, Any]:
    return await _ctl("jobs", timeout=30)
