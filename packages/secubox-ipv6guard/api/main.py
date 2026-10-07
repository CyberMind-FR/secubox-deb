# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: IPv6 Guardian — API de la carte du Hall (socket /run/secubox/ipv6guard.sock).

  GET /status      verdict, quatre étapes, appareils (lecture gardée : require_lecture)
  GET /appareils   la liste des appareils seule
  GET /health      vivacité (publique)

LECTURE SEULE et PASSIVE : la box lit sa table de voisins et les annonces mDNS ; elle n'envoie rien aux appareils et ne modifie
aucun pare-feu. Aucune adresse MAC complète dans les réponses.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI

from secubox_core.auth import require_lecture

from . import service

app = FastAPI(title="SecuBox IPv6 Guardian", version="0.1.0")

_surveillance = service.Surveillance()


def _freebox():
    """Phase 2 : lecture du pare-feu IPv6 de la Freebox. Pas encore connectée : None (le verdict dit « à vérifier »)."""
    return None


@app.get("/health")
async def health():
    return {"status": "ok", "module": "ipv6guard"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status():
    # `def` : FastAPI le passe au pool de threads (la lecture lance `ip`).
    return _surveillance.lecture(freebox=_freebox())


@app.get("/appareils", dependencies=[Depends(require_lecture)])
def appareils():
    return {"appareils": _surveillance.lecture(freebox=_freebox())["appareils"]}
