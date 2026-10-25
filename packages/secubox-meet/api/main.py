# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-meet — API hôte (La Suite Meet en LXC), #3154.

Service dédié (secubox-meet.service, socket /run/secubox/meet.sock). Aucune
opération privilégiée ici : tout changement d'état passe par `sudo -n meetctl`
(root, seule surface privilégiée du module). Le secret OIDC n'est jamais lu,
renvoyé ni journalisé par l'API : meetctl ne l'imprime pas non plus.

Routes (préfixe nginx /api/v1/meet, retiré avant l'application) :
  GET  /health             libre
  GET  /status             lecture, cache 60 s (mémoire puis fichier)
  GET  /media-expose       lecture, état de l'exposition des ports média
  POST /media-expose       {action: apply|revoke, confirmer: "meet"}  (JWT)
  POST /control            {action: start|stop|restart}               (JWT)
  GET  /oidc               meetctl oidc-verifier                       (JWT)
  POST /oidc/enregistrer   sans option (le renouvellement reste à root)   (JWT)
  GET  /logs               ?unit=&lines=                              (JWT)
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

# Aucun repli : sans la bibliothèque d'authentification, l'API ne se charge pas.
from secubox_core.auth import require_jwt, require_lecture

VERSION = "0.1.1"

CTL = "/usr/sbin/meetctl"

CACHE_DIR = Path("/var/cache/secubox/meet")
STATUS_CACHE_FILE = CACHE_DIR / "status.json"
STATUS_TTL = 60.0

# Unités que l'API nomme à meetctl (qui revalide : liste blanche indépendante).
KNOWN_UNITS = ("postgresql", "redis-server", "livekit", "meet-backend", "nginx")

log = logging.getLogger("secubox-meet")

app = FastAPI(
    title="SecuBox Meet",
    version=VERSION,
    root_path="/api/v1/meet",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_status_cache: Dict[str, Any] = {"data": None, "ts": 0.0}


def _run_ctl(*args: str, timeout: int = 30):
    """`sudo -n meetctl <args>` -> (code, stdout, stderr). Ne lève jamais."""
    try:
        p = subprocess.run(["sudo", "-n", CTL, *args],
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"meetctl {' '.join(args)} : délai de {timeout} s dépassé"
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", f"appel de meetctl impossible : {exc}"


def _objet_json(out: str):
    """Le dict JSON que meetctl a écrit sur stdout, ou None."""
    try:
        v = json.loads(out.strip())
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def _detail_echec(out: str, err: str, rc: int) -> str:
    """Message d'un échec de meetctl : son champ « error » (stdout JSON) d'abord,
    puis stderr, puis stdout brut."""
    obj = _objet_json(out)
    if obj is not None and obj.get("error"):
        return str(obj["error"])[:500]
    return (err or out or f"meetctl a rendu le code {rc}").strip()[:500]


def _ctl_json(*args: str, timeout: int = 30, diagnostic: bool = False) -> Dict[str, Any]:
    """meetctl signale ses échecs par un JSON sur stdout et un code non nul.
    Action en échec -> 502 avec le message français du ctl ; sortie qui n'est
    pas du JSON -> 500. `diagnostic` : un KO est une réponse (200), pas une erreur."""
    rc, out, err = _run_ctl(*args, timeout=timeout)
    obj = _objet_json(out)
    if obj is None:
        if rc != 0:
            raise HTTPException(status_code=500, detail=_detail_echec(out, err, rc))
        if not out.strip():
            return {}
        raise HTTPException(status_code=500, detail="meetctl n'a pas rendu du JSON")
    if (rc != 0 or obj.get("success") is False) and not diagnostic:
        raise HTTPException(status_code=502, detail=_detail_echec(out, err, rc))
    return obj


def _invalider_status() -> None:
    """Après une écriture réussie, le statut en cache est périmé."""
    _status_cache["ts"] = 0.0
    try:
        STATUS_CACHE_FILE.unlink()
    except OSError:
        pass


def _refresh_status() -> Dict[str, Any]:
    data = _ctl_json("status")
    _status_cache["data"] = data
    _status_cache["ts"] = time.time()
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        STATUS_CACHE_FILE.write_text(json.dumps(data))
    except OSError as exc:
        log.warning("écriture du cache de statut impossible : %s", exc)
    return data


def _status_frais() -> Dict[str, Any]:
    """Mémoire, puis fichier, puis meetctl ; en cas d'échec, dernière valeur connue."""
    now = time.time()
    if _status_cache["data"] is not None and now - _status_cache["ts"] < STATUS_TTL:
        return _status_cache["data"]
    try:
        st = STATUS_CACHE_FILE.stat()
        if now - st.st_mtime < STATUS_TTL:
            data = json.loads(STATUS_CACHE_FILE.read_text())
            if isinstance(data, dict):
                _status_cache.update(data=data, ts=st.st_mtime)
                return data
    except (OSError, ValueError):
        pass
    try:
        return _refresh_status()
    except HTTPException:
        if _status_cache["data"] is not None:
            return _status_cache["data"]
        raise


# HAProxy coupe à 30 s : au-delà de 25 s on rend la main, le fil continue.
DELAI_REPONSE = 25.0


async def _borne(fn) -> Dict[str, Any]:
    tache = asyncio.ensure_future(asyncio.to_thread(fn))
    try:
        return await asyncio.wait_for(asyncio.shield(tache), timeout=DELAI_REPONSE)
    except asyncio.TimeoutError:
        return {"success": True, "pending": True, "message": "opération en cours"}


class ControlRequest(BaseModel):
    action: str


class MediaRequest(BaseModel):
    action: str = ""
    confirmer: str = ""


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "module": "meet"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status() -> Dict[str, Any]:
    return _status_frais()


@app.get("/media-expose", dependencies=[Depends(require_lecture)])
def media_expose_etat() -> Dict[str, Any]:
    return _ctl_json("media-expose")


@app.post("/media-expose")
async def media_expose(req: MediaRequest, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    # Ouvre des ports entrants : confirmation explicite, comme ACTIONS_CONFIRMEES.
    if req.confirmer != "meet":
        raise HTTPException(status_code=400,
                            detail='confirmation requise : renvoyez confirmer: "meet"')
    if req.action not in ("apply", "revoke"):
        raise HTTPException(status_code=400, detail="l'action doit être apply ou revoke")
    res = await asyncio.to_thread(lambda: _ctl_json("media-expose", f"--{req.action}"))
    _invalider_status()
    return res


@app.post("/control")
async def control(req: ControlRequest, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    if req.action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="l'action doit être start, stop ou restart")

    def _agir():
        res = _ctl_json(req.action, timeout=120)
        _invalider_status()
        return res
    return await _borne(_agir)


@app.get("/oidc")
async def oidc(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return await asyncio.to_thread(lambda: _ctl_json("oidc-verifier", diagnostic=True))


@app.post("/oidc/enregistrer")
async def oidc_enregistrer(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    # argv exact, seul accordé par le sudoers. Un nouveau secret est porté au
    # conteneur par meetctl (nouveau rendu, relance de meet-backend) : délai large.
    def _agir():
        res = _ctl_json("oidc-enregistrer", timeout=120)
        _invalider_status()
        return res
    return await _borne(_agir)


@app.get("/logs")
async def logs(unit: str = "meet-backend", lines: int = 50,
               _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    if unit not in KNOWN_UNITS:
        raise HTTPException(status_code=400,
                            detail=f"l'unité doit être l'une de : {', '.join(KNOWN_UNITS)}")
    lines = max(1, min(int(lines), 500))
    rc, out, err = await asyncio.to_thread(lambda: _run_ctl("logs", unit, str(lines)))
    if rc != 0:
        raise HTTPException(status_code=500, detail=_detail_echec(out, err, rc))
    return {"unit": unit, "lines": out.splitlines()}
