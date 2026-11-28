# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Verrou GPU (#4058, Task 9) : Gemma (llama-server du relais, unité transitoire `poc-llama`) est suspendu le temps
de la SEULE synthèse vocale, et toujours relancé.

    async with verrou.voix():
        ...  # synthèse vocale

- entrée : le fichier verrou est posé AVANT l'arrêt (le relais répond 503 « voix en cours » dès qu'il le voit, ce qui
  empêche aussi le réveil automatique du moteur), puis `arreter()` ;
- sortie, quoi qu'il arrive (exception, annulation par SIGTERM) : `relancer()` puis retrait du verrou ;
- `reparer()` au démarrage du service : un verrou sans production vivante (service tué net) → relance et retrait.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import AsyncIterator, Awaitable, Callable, Optional

log = logging.getLogger("secubox-ai-emissions.gpu")

VERROU = Path(os.environ.get("SECUBOX_AI_EMISSIONS_VERROU")
              or Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-emissions/voix.verrou")
RELAIS = "http://127.0.0.1:8098/api/v1/ai"
ENTETE_CLE = "X-Emissions-Cle"   # seule la relance portant la clé du verrou passe la garde 503 du relais


def lire_verrou(fichier: Path) -> Optional[dict]:
    try:
        d = json.loads(Path(fichier).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def _vivant(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class VerrouGPU:
    def __init__(self, fichier: Path, arreter: Callable[[], Awaitable[None]],
                 relancer: Callable[[], Awaitable[None]]) -> None:
        self.fichier = Path(fichier)
        self._arreter = arreter
        self._relancer = relancer
        self._actif = False

    def _poser(self) -> None:
        self.fichier.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.fichier.with_name(self.fichier.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(), "quand": int(time.time()), "cle": secrets.token_urlsafe(24)}, f)
        os.replace(tmp, self.fichier)

    def _retirer(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.fichier.unlink()

    @contextlib.asynccontextmanager
    async def voix(self) -> AsyncIterator[None]:
        if self._actif:
            raise RuntimeError("une synthèse vocale est déjà en cours")
        self._actif = True
        self._poser()
        try:
            await self._arreter()
            yield
        finally:
            try:
                await self._relancer()
            except BaseException as e:  # noqa: BLE001 — le verrou est retiré quoi qu'il arrive, l'erreur remonte
                log.error("relance de Gemma en échec : %s", e)
                raise
            finally:
                self._retirer()
                self._actif = False

    async def reparer(self) -> bool:
        """Au démarrage : verrou présent sans production vivante → relance de Gemma et retrait. Vrai si réparé."""
        d = lire_verrou(self.fichier)
        if d is None or self._actif:
            return False
        pid = d.get("pid")
        if pid != os.getpid() and _vivant(pid):
            return False    # une autre instance vivante tient le verrou
        log.warning("verrou de voix orphelin (pid %s) : relance de Gemma", pid)
        try:
            await self._relancer()
        finally:
            self._retirer()
        return True


def _cle(fichier: Path) -> str:
    return str((lire_verrou(fichier) or {}).get("cle") or "")


def par_relais(fichier: Path = VERROU, base: str = RELAIS) -> VerrouGPU:
    """Le verrou réel : arrêt et relance par les routes locales du relais (qui sait relancer l'unité transitoire
    `poc-llama` avec ses réglages) ; la relance porte la clé du verrou pour passer la garde 503."""
    import httpx

    async def _poster(chemin: str) -> None:
        async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(300.0, connect=5.0)) as c:
            r = await c.post(base + chemin, headers={ENTETE_CLE: _cle(fichier)})
            r.raise_for_status()

    async def arreter() -> None:
        await _poster("/moteur/arreter")

    async def relancer() -> None:
        await _poster("/moteur/demarrer")

    return VerrouGPU(fichier, arreter, relancer)


class SansSuspension:
    """Voix sur CPU (réglage `voix_gpu = false`, défaut tant que CUDA est en panne sur gk0) : Gemma n'est PAS
    suspendu, aucun verrou n'est posé, le relais reste disponible. Même interface que `VerrouGPU`."""

    fichier = None

    @contextlib.asynccontextmanager
    async def voix(self) -> AsyncIterator[None]:
        yield

    async def reparer(self) -> bool:
        return False


def selon_reglage(voix_gpu: bool, fichier: Path = VERROU, base: str = RELAIS):
    """Le mécanisme de suspension seulement si la voix occupe le GPU ; sinon `SansSuspension`."""
    return par_relais(fichier, base) if voix_gpu else SansSuspension()
