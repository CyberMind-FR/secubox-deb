# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: api.routers.ssh — interrupteur « Accès SSH » de la page Système (#3401).

  GET  /ssh                → état (service, mot de passe permis, garde du mot de passe par défaut)
  POST /ssh/acces          → {"actif": bool} active / désactive le service ssh
  POST /ssh/mot-de-passe   → {"actif": bool} permet / refuse SSH par mot de passe (la clé reste possible)

L'API (secubox, NoNewPrivileges, ProtectSystem) ne lance rien en root : elle dépose une DEMANDE dans
/run/secubox/system/ssh ; secubox-ssh.path lance `secubox-sshctl traite` (root, unité durcie), qui écrit le résultat
dans /run/secubox/system/ssh-resultats/<id>.json, relu ici. Tant que le mot de passe par défaut est actif (ou inconnu),
permettre SSH par mot de passe est REFUSÉ (409) ici ET dans le ctl (qui vérifie aussi le mot de passe Linux).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core import mot_de_passe_defaut as mdp_defaut
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("system.ssh")
DEMANDES = Path("/run/secubox/system/ssh")
RESULTATS = Path("/run/secubox/system/ssh-resultats")
DELAI = 30.0
REFUS_DEFAUT = ("Changez d'abord le mot de passe par défaut (admin web et Linux) : SSH par mot de passe reste refusé "
                "tant qu'il est actif.")
_ACTEUR = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


class Interrupteur(BaseModel):
    actif: bool


def _ctl(verbe: str, valeur: str = "", acteur: str = "") -> Dict[str, Any]:
    """Dépose une demande, attend le résultat de l'unité root. Route `def` : l'attente tourne dans le pool."""
    ident = secrets.token_hex(8)
    tmp = RESULTATS / f".demande.{ident}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(fd, "w") as f:
            json.dump({"verbe": verbe, "valeur": valeur, "acteur": acteur}, f)
        os.replace(tmp, DEMANDES / f"{ident}.demande")      # même système de fichiers (/run) : atomique
    except OSError as e:
        log.error("demande SSH non déposée : %s", e)
        raise HTTPException(status_code=500, detail="demande SSH non déposée") from None
    res = RESULTATS / f"{ident}.json"
    fin = time.monotonic() + DELAI
    while time.monotonic() < fin:
        try:
            r = json.loads(res.read_text())
        except (OSError, ValueError):
            time.sleep(0.2)
            continue
        res.unlink(missing_ok=True)
        return r
    log.error("secubox-sshctl : pas de résultat pour %s %s", verbe, valeur)
    raise HTTPException(status_code=504, detail="secubox-sshctl n'a pas répondu")


def _acteur(user: Dict[str, Any]) -> str:
    sub = str(user.get("sub") or "")
    return sub if _ACTEUR.match(sub) else "inconnu"


@router.get("/ssh")
def ssh_etat(user: dict = Depends(require_jwt)):
    r = _ctl("etat")
    if r.get("code") != 0:
        raise HTTPException(status_code=500, detail="état SSH illisible")
    try:
        return json.loads(r.get("sortie") or "")
    except ValueError:
        raise HTTPException(status_code=500, detail="état SSH illisible") from None


@router.post("/ssh/acces")
def ssh_acces(body: Interrupteur, user: dict = Depends(require_jwt)):
    r = _ctl("acces", "on" if body.actif else "off", _acteur(user))
    if r.get("code") != 0:
        log.error("secubox-sshctl acces : %s", str(r.get("sortie"))[-200:])
        raise HTTPException(status_code=500, detail="accès SSH inchangé")
    return {"success": True, "service": body.actif}


@router.post("/ssh/mot-de-passe")
def ssh_mot_de_passe(body: Interrupteur, user: dict = Depends(require_jwt)):
    if body.actif and mdp_defaut.garde_requise():
        mdp_defaut.audit("ssh_mot_de_passe_refuse", {"acteur": _acteur(user)})
        raise HTTPException(status_code=409, detail=REFUS_DEFAUT)
    r = _ctl("mot-de-passe", "on" if body.actif else "off", _acteur(user))
    if r.get("code") == 3:
        raise HTTPException(status_code=409, detail=REFUS_DEFAUT)
    if r.get("code") != 0:
        log.error("secubox-sshctl mot-de-passe : %s", str(r.get("sortie"))[-200:])
        raise HTTPException(status_code=500, detail="SSH par mot de passe inchangé")
    return {"success": True, "mot_de_passe": body.actif}
