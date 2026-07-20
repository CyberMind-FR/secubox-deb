# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-waker : activator (réveil-sur-accès + splash)
CyberMind — https://cybermind.fr

nginx route un vhost on-demand DOWN vers /_wake/<vhost>. Le waker : résout
vhost->module, prend un verrou par-module (UN seul réveil pour N requêtes
concurrentes), et soit signale « up » (nginx re-proxifie), soit tire le réveil
(sudo->secubox-wakectl) et sert le splash 503+Retry-After. Cap de fréquence de
réveil contre les tempêtes. Ne pilote JAMAIS le système en direct (webui->ctl).
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response

from .lifecycle import effective_lifecycle, wake_budget
from .manifest import Manifest, load_all
from .observe import is_on
from .observe import observe as _observe_one

DEFAULT_ROOT = Path("/etc/secubox")
# Lu UNE fois au chargement du module, pas à chaque 503 : le splash s'auto-
# recharge (meta refresh) donc un client qui attend le réveil tape ce chemin
# en boucle — relire le fichier à chaque requête est de l'I/O disque inutile
# dans un chemin chaud.
_TEMPLATE_TEXT = (Path(__file__).resolve().parent.parent / "templates"
                 / "waking.html").read_text(encoding="utf-8")
_WAKE_MIN_INTERVAL_S = 20.0

_locks: dict[str, asyncio.Lock] = {}
_last_wake: dict[str, float] = {}


def _root() -> Path:
    """Racine de config — surchargeable en test via SECUBOX_PROFILES_ROOT
    (même motif que api/web.py::_root)."""
    return Path(os.environ.get("SECUBOX_PROFILES_ROOT", str(DEFAULT_ROOT)))


def _lock(mid: str) -> asyncio.Lock:
    lk = _locks.get(mid)
    if lk is None:
        lk = asyncio.Lock()
        _locks[mid] = lk
    return lk


def _resolve(vhost: str, manifests: dict[str, Manifest]) -> str | None:
    for mid, m in manifests.items():
        if m.portal_domain == vhost:
            return mid
    return None


def _fire_wake(mid: str) -> None:
    # webui->ctl : le réveil privilégié passe par le ctl root, jamais en process.
    p = subprocess.Popen(["sudo", "-n", "/usr/sbin/secubox-wakectl", "wake", mid, "--json"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Reaper : sans .wait(), l'enfant devient un zombie <defunct> permanent
    # (personne n'appelle waitpid) — sur un service long-vécu qui réveille
    # potentiellement des dizaines de modules, ça accumule sans borne (même
    # défaut que l'avalanche perf WireGuard déjà rencontrée sur ce dépôt). Un
    # thread daemon court-vif attend la fin sans bloquer la boucle asyncio.
    threading.Thread(target=p.wait, daemon=True).start()


def _splash(module: str, budget: float, retry: int) -> HTMLResponse:
    html = _TEMPLATE_TEXT.format(module=module, budget=int(budget), retry=retry)
    return HTMLResponse(html, status_code=503,
                        headers={"Retry-After": str(retry), "Cache-Control": "no-store"})


def create_app() -> FastAPI:
    app = FastAPI(title="SecuBox Waker", docs_url=None, redoc_url=None)

    @app.get("/_wake/{vhost}")
    async def wake_vhost(vhost: str) -> Response:
        manifests = load_all(_root() / "modules.d")
        mid = _resolve(vhost, manifests)
        if mid is None:
            return Response(status_code=404)
        m = manifests[mid]
        if effective_lifecycle(m) in ("always-on", "manual"):
            return Response(status_code=502)   # not a sleepable vhost -> real error
        if is_on(_observe_one(m)):
            return Response(status_code=200, headers={"X-Sbx-Wake": "up"})
        async with _lock(mid):
            now = time.monotonic()
            if now - _last_wake.get(mid, 0.0) >= _WAKE_MIN_INTERVAL_S:
                _last_wake[mid] = now
                _fire_wake(mid)
            budget = wake_budget(m)
            return _splash(mid, budget, retry=max(3, int(budget / 5)))

    return app


app = create_app()
