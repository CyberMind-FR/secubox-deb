# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — API registre normalisé (P1)."""
import asyncio
import json
import time
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter, Depends

from secubox_core.auth import require_jwt
from secubox_core.health import systemd_batch
from api.models import Service
from api import registry, flags, cardlets

_cache: dict = {"services": [], "computed_at": None}
_flags: dict = flags.load_flags()
_CACHE_FILE = Path("/var/cache/secubox/webos/services.json")


def _live_sockets(sock_dir: str = "/run/secubox") -> frozenset:
    """Ids joignables via socket (agrégateur ou daemon propre) — signal de santé."""
    try:
        return frozenset(p.stem for p in Path(sock_dir).glob("*.sock"))
    except Exception:
        return frozenset()


def _recompute() -> None:
    """Read menu/health/exposure sources and refresh `_cache` in place."""
    menu = registry.load_menu_cache()
    health = systemd_batch()
    expo = registry.load_exposure_cache()
    svcs = registry.normalize_services(menu, health, expo, sockets=_live_sockets())
    _cache["services"] = [s.model_dump() for s in svcs]
    _cache["computed_at"] = time.time()
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(_cache))
    except Exception:
        pass


async def _refresh_loop() -> None:
    while True:
        try:
            _recompute()
        except Exception:
            pass
        await asyncio.sleep(15)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _flags
    _flags = flags.load_flags()
    if _CACHE_FILE.exists():
        try:
            _cache.update(json.loads(_CACHE_FILE.read_text()))
        except Exception:
            pass
    task = asyncio.create_task(_refresh_loop())
    yield
    task.cancel()


app = FastAPI(title="SecuBox WebOS", root_path="/api/v1/webos", lifespan=lifespan)
public_router = APIRouter(prefix="/public")
router = APIRouter()


def _enabled() -> bool:
    return bool(_flags.get("enabled"))


_PUBLIC_FIELDS = ("id", "name", "description", "category", "icon", "installed", "active")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@public_router.get("/services")
async def public_services():
    """Minimal, unauthenticated projection — never leaks urls/latency/reach."""
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    out = []
    for s in _cache["services"]:
        row = {k: s[k] for k in _PUBLIC_FIELDS if k in s}
        row["health"] = {"state": (s.get("health") or {}).get("state", "unknown")}
        out.append(row)
    return {"services": out, "computed_at": _cache["computed_at"]}


_rc = {"d": None, "t": 0.0}


@public_router.get("/cardlets/radio")
async def cardlet_radio():
    """Cardlet Radio (now-playing) — lue côté serveur via radio.sock, cache 5 s."""
    now = time.time()
    if _rc["d"] and now - _rc["t"] < 5:
        return _rc["d"]
    # radio_cardlet_safe fait de l'I/O socket BLOQUANTE : hors du thread, elle
    # gèle la boucle uvicorn (single-worker) → 502 sur tout le module (#1175).
    d = await asyncio.to_thread(cardlets.radio_cardlet_safe)
    _rc["d"], _rc["t"] = d, now
    return d


@router.get("/services")
async def services(user=Depends(require_jwt)):
    """Full registry — JWT-gated."""
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    return {"services": _cache["services"], "computed_at": _cache["computed_at"]}


app.include_router(public_router)
app.include_router(router)
