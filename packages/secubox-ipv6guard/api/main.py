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

from fastapi import Depends, FastAPI, Request

from secubox_core.auth import require_lecture

from . import freebox, service

app = FastAPI(title="SecuBox IPv6 Guardian", version="0.2.0")

_surveillance = service.Surveillance()


def _freebox(request):
    """Pare-feu IPv6 de la Freebox, lu par secubox-freebox avec les identifiants de l'appelant ; None = inconnu (« à vérifier »)."""
    return freebox.lire_pare_feu(dict(request.headers))


@app.get("/health")
async def health():
    return {"status": "ok", "module": "ipv6guard"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status(request: Request):
    # `def` : FastAPI le passe au pool de threads (la lecture lance `ip`).
    return _surveillance.lecture(freebox=_freebox(request))


@app.get("/appareils", dependencies=[Depends(require_lecture)])
def appareils(request: Request):
    return {"appareils": _surveillance.lecture(freebox=_freebox(request))["appareils"]}
