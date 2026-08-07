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
import json
import logging
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

# Chemin partagé avec api.sleeper.WAKE_LOCK_FILE (même valeur littérale — pas
# d'import croisé waker<->sleeper, les deux processus ne communiquent QUE par
# ce fichier). Le sleeper le lit en best-effort (_read_wake_locked) pour ne
# jamais rendormir un module que le waker vient de réveiller. TTL > à la fois
# _WAKE_MIN_INTERVAL_S (20s, sinon l'entrée serait purgée avant la fin de la
# fenêtre anti-rafale ci-dessous) et à l'intervalle de tick par défaut du
# sleeper (api/sleeper_daemon.py DEFAULT_INTERVAL_S=30s), avec une marge pour
# le jitter/latence d'un tick.
_WAKE_ACTIVE_PATH = Path("/run/secubox/waker-active.json")
_WAKE_ACTIVE_TTL_S = 90.0

_locks: dict[str, asyncio.Lock] = {}
_last_wake: dict[str, float] = {}


log = logging.getLogger("secubox-waker")


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
    # systemd-run (PAS sudo nu) : ce service tourne ProtectSystem=strict avec
    # ReadWritePaths réduit à /run/secubox ; un enfant sudo hériterait de ce
    # même sandbox et secubox-wakectl (qui écrit le snapshot 4R + l'audit et
    # pilote systemd/LXC) verrait tout le reste en lecture seule (EROFS) —
    # même leçon que secubox-profilectl 0.6.1 (MODULE-COMPLIANCE.md,
    # « systemd-run » section). --collect --quiet nettoie l'unit transitoire
    # automatiquement. Volontairement PAS --wait/--pipe : contrairement au
    # panel (qui attend le résultat de profilectl), le waker tire le réveil
    # et rend la main tout de suite (fire-and-forget) — il ne bloque jamais
    # une requête HTTP sur l'issue du réveil, sinon le splash lui-même
    # traînerait. Le sudoers grant matche ce préfixe fixe exact.
    p = subprocess.Popen(
        ["sudo", "-n", "/usr/bin/systemd-run", "--collect", "--quiet",
         "/usr/sbin/secubox-wakectl", "wake", mid, "--json"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Reaper : sans .wait(), l'enfant devient un zombie <defunct> permanent
    # (personne n'appelle waitpid) — sur un service long-vécu qui réveille
    # potentiellement des dizaines de modules, ça accumule sans borne (même
    # défaut que l'avalanche perf WireGuard déjà rencontrée sur ce dépôt). Un
    # thread daemon court-vif attend la fin sans bloquer la boucle asyncio.
    threading.Thread(target=p.wait, daemon=True).start()


def _write_wake_active() -> None:
    """Persiste l'ensemble des modules ayant un réveil récent (`_last_wake`)
    dans /run/secubox/waker-active.json — le seul canal par lequel le sleeper
    (api.sleeper._read_wake_locked / WAKE_LOCK_FILE) apprend qu'un réveil est
    en cours et ne doit pas rendormir le module immédiatement après. Purge
    d'abord les entrées plus vieilles que _WAKE_ACTIVE_TTL_S (évite une
    croissance non bornée de _last_wake sur un service long-vécu). Best-
    effort strict : le réveil lui-même (webui->ctl, déjà tiré via
    `_fire_wake`) ne doit JAMAIS échouer à cause d'une panne d'écriture ici —
    une IOError/OSError est donc avalée."""
    now = time.monotonic()
    for stale in [mid for mid, t in _last_wake.items() if now - t >= _WAKE_ACTIVE_TTL_S]:
        del _last_wake[stale]
    try:
        _WAKE_ACTIVE_PATH.write_text(json.dumps(sorted(_last_wake)), encoding="utf-8")
    except OSError:
        pass


def _splash(module: str, budget: float, retry: int) -> HTMLResponse:
    # The splash is static + JS-driven (service name from the vhost hostname,
    # elapsed time from sessionStorage) — the SAME page nginx serves for phase-2
    # (backend up but still booting) — so it needs no server-side substitution.
    # module/budget stay in the signature: `retry` drives the Retry-After header
    # (derived from the wake budget by the caller); the body is served verbatim.
    return HTMLResponse(_TEMPLATE_TEXT, status_code=503,
                        headers={"Retry-After": str(retry), "Cache-Control": "no-store"})


def create_app() -> FastAPI:
    app = FastAPI(title="SecuBox Waker", docs_url=None, redoc_url=None)

    @app.get("/_wake/{vhost}")
    async def wake_vhost(vhost: str) -> Response:
        manifests = load_all(_root() / "modules.d")
        mid = _resolve(vhost, manifests)
        if mid is None:
            # VHOST NON DECLARE. Un 404 ici remontait a nginx comme une page
            # brute — c'est ce que l'utilisateur voyait sur les vhosts tombes
            # apres un redemarrage. On rend la page d'attente, et on JOURNALISE
            # le nom : ce journal est la liste de ce qu'il reste a declarer.
            #
            # On ne reveille rien pour autant : `wake()` refuse les modules
            # inconnus, et c'est une garde voulue — un 5xx ne doit pas devenir
            # un droit de demarrer un service arbitraire.
            log.warning("wake: vhost non declare, aucun reveil possible: %s", vhost)
            return _splash(vhost, 0.0, retry=10)
        m = manifests[mid]
        if effective_lifecycle(m) in ("always-on", "manual"):
            # Backend cense tourner en permanence : ce n'est pas un endormi,
            # c'est une VRAIE panne. La page d'attente mentirait — personne ne
            # va le relever. On laisse remonter l'erreur.
            log.warning("wake: %s est %s, pas un module endormi — panne reelle",
                        mid, effective_lifecycle(m))
            return Response(status_code=502)
        if is_on(_observe_one(m)):
            return Response(status_code=200, headers={"X-Sbx-Wake": "up"})
        async with _lock(mid):
            now = time.monotonic()
            if now - _last_wake.get(mid, 0.0) >= _WAKE_MIN_INTERVAL_S:
                _last_wake[mid] = now
                _fire_wake(mid)
                _write_wake_active()
            budget = wake_budget(m)
            return _splash(mid, budget, retry=max(3, int(budget / 5)))

    return app


app = create_app()
