# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: garde commune des chemins d'exposition externe (#3401).

Tant que le mot de passe par défaut du compte admin est actif OU inconnu, toute NOUVELLE exposition (vhost, certificat
ACME, contournement WAF, Tor, reach wan/mesh) est refusée : 409 explicite, audité. Les expositions déjà en place ne
sont pas touchées (pas de modification silencieuse) ; `haproxyctl generate` re-rend la configuration existante.
"""
from __future__ import annotations

import asyncio

from fastapi import HTTPException, Request

from secubox_core import mot_de_passe_defaut as _mdp


async def exiger_mot_de_passe_change(request: Request) -> None:
    """Dépendance FastAPI à poser sur chaque route qui ouvre une exposition externe."""
    message = await asyncio.to_thread(_mdp.refus_exposition, f"{request.method} {request.url.path}"[:128])
    if message:
        raise HTTPException(status_code=409, detail=message)
