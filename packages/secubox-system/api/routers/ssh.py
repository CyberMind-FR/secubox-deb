# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: api.routers.ssh — interrupteur « Accès SSH » de la page Système (#3401).

  GET  /ssh                → état (service, mot de passe permis, garde du mot de passe par défaut)
  POST /ssh/acces          → {"actif": bool} active / désactive le service ssh
  POST /ssh/mot-de-passe   → {"actif": bool} permet / refuse SSH par mot de passe (la clé reste possible)

Toute écriture passe par `secubox-sshctl` (root, sudo, règle à la lettre) : l'API tourne sous `secubox`. Tant que le
mot de passe par défaut est actif, permettre SSH par mot de passe est REFUSÉ (409) ici ET dans le ctl.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core import mot_de_passe_defaut as mdp_defaut
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("system.ssh")
CTL = "/usr/sbin/secubox-sshctl"
REFUS_DEFAUT = "Changez d'abord le mot de passe par défaut : SSH par mot de passe reste refusé tant qu'il est actif."
_ACTEUR = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


class Interrupteur(BaseModel):
    actif: bool


def _ctl(args: List[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["sudo", "-n", CTL, *args], check=False, timeout=60, capture_output=True, text=True)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("secubox-sshctl %s : %s", " ".join(args), e)
        raise HTTPException(status_code=500, detail="secubox-sshctl injoignable") from None


def _acteur(user: Dict[str, Any]) -> str:
    sub = str(user.get("sub") or "")
    return sub if _ACTEUR.match(sub) else "inconnu"


@router.get("/ssh")
def ssh_etat(user: dict = Depends(require_jwt)):
    r = _ctl(["etat"])
    if r.returncode != 0:
        log.error("secubox-sshctl etat : %s", (r.stderr or "").strip()[-200:])
        raise HTTPException(status_code=500, detail="état SSH illisible")
    try:
        return json.loads(r.stdout)
    except ValueError:
        raise HTTPException(status_code=500, detail="état SSH illisible") from None


@router.post("/ssh/acces")
def ssh_acces(body: Interrupteur, user: dict = Depends(require_jwt)):
    r = _ctl(["acces", "on" if body.actif else "off", _acteur(user)])
    if r.returncode != 0:
        log.error("secubox-sshctl acces : %s", (r.stderr or "").strip()[-200:])
        raise HTTPException(status_code=500, detail="accès SSH inchangé")
    return {"success": True, "service": body.actif}


@router.post("/ssh/mot-de-passe")
def ssh_mot_de_passe(body: Interrupteur, user: dict = Depends(require_jwt)):
    if body.actif and mdp_defaut.actif():
        mdp_defaut.audit("ssh_mot_de_passe_refuse", {"acteur": _acteur(user)})
        raise HTTPException(status_code=409, detail=REFUS_DEFAUT)
    r = _ctl(["mot-de-passe", "on" if body.actif else "off", _acteur(user)])
    if r.returncode == 3:
        raise HTTPException(status_code=409, detail=REFUS_DEFAUT)
    if r.returncode != 0:
        log.error("secubox-sshctl mot-de-passe : %s", (r.stderr or "").strip()[-200:])
        raise HTTPException(status_code=500, detail="SSH par mot de passe inchangé")
    return {"success": True, "mot_de_passe": body.actif}
