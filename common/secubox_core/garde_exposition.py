# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: garde commune des chemins d'exposition externe (#3401).

Tant que le mot de passe par défaut du compte admin est actif OU inconnu, toute NOUVELLE exposition PUBLIQUE (vhost,
certificat ACME, contournement WAF, Tor, reach wan, émancipation) est refusée ; LAN et maillage restent permis : 409 explicite, audité. Les expositions déjà en place ne
sont pas touchées (pas de modification silencieuse) ; `haproxyctl generate` re-rend la configuration existante.
"""
from __future__ import annotations

import asyncio

from typing import Any, Dict

from fastapi import Depends, HTTPException, Request

from secubox_core import mot_de_passe_defaut as _mdp
from secubox_core.auth import require_jwt


async def exiger_mot_de_passe_change(request: Request, user: Dict[str, Any] = Depends(require_jwt)) -> None:
    """Dépendance FastAPI à poser sur chaque route qui ouvre une exposition externe (après require_jwt : même
    dépendance, résolue une seule fois par requête). L'administrateur (`sub`) est écrit dans l'audit du refus."""
    message = await asyncio.to_thread(_mdp.refus_exposition, f"{request.method} {request.url.path}"[:128],
                                      str((user or {}).get("sub", "?")))
    if message:
        raise HTTPException(status_code=409, detail=message)
