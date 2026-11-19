# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: webos — relais du NOM DE NŒUD (#3824), interrupteur de l'administrateur.

  GET  /noeud/relais   → état : réglage, ce que sert le vhost, ancienne cible et ses chemins, garde du mot de passe
  POST /noeud/relais   → {"actif": bool} ouvre / ferme le relais des autres chemins vers l'ancienne cible

Le nom public d'une box (`<nœud>.<zone>`) ne sert que le dé et /api/v1/health ; relayer le reste (sur gk2 : l'API
admin, metrics, metablogizer…) est une option FERMÉE par défaut, réservée à l'administrateur réel (`require_jwt`).

L'API (secubox, NoNewPrivileges) ne lance rien en root : elle dépose une DEMANDE dans /run/secubox/webos-noeud ;
secubox-webos-noeud.path lance `webos-noeud traite` (root, unité durcie), qui écrit webos.toml, régénère le vhost
(nginx -t, retour arrière), audite, et rend le résultat dans /run/secubox/webos-noeud-resultats/<id>.json
(root:secubox 0750, relu ici, purgé par le ctl). Ouvrir est refusé (409) tant que le mot de passe admin par défaut
n'est pas prouvé changé (#3401), ici ET dans le ctl.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secubox_core.auth import require_jwt

router = APIRouter()
log = logging.getLogger("webos.noeud")
DEMANDES = Path("/run/secubox/webos-noeud")
RESULTATS = Path("/run/secubox/webos-noeud-resultats")
DELAI = 30.0
_ACTEUR = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
REFUS_DEFAUT = ("Changez d'abord le mot de passe administrateur par défaut : le relais des API du nom de nœud reste "
                "fermé tant qu'il est actif.")


class Interrupteur(BaseModel):
    actif: bool


def _acteur(user: Dict[str, Any]) -> str:
    sub = str((user or {}).get("sub") or "")
    return sub if _ACTEUR.match(sub) else "inconnu"


def _ctl(geste: str, acteur: str = "") -> Dict[str, Any]:
    """Dépose une demande, attend le résultat de l'unité root. Route `def` : l'attente tourne dans le pool."""
    ident = secrets.token_hex(8)
    tmp = DEMANDES / f".tmp.{ident}"       # ignoré par le ctl tant qu'il n'est pas renommé
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        with os.fdopen(fd, "w") as f:
            json.dump({"geste": geste, "acteur": acteur}, f)
        os.replace(tmp, DEMANDES / f"{ident}.demande")      # même dossier : atomique
    except OSError as e:
        log.error("demande du relais non déposée : %s", e)
        raise HTTPException(status_code=503, detail="demande non déposée (secubox-webos-noeud.path inactif ?)") from None
    res = RESULTATS / f"{ident}.json"
    fin = time.monotonic() + DELAI
    while time.monotonic() < fin:
        try:
            return json.loads(res.read_text())
        except (OSError, ValueError):
            time.sleep(0.2)
    log.error("webos-noeud : pas de résultat pour %s", geste)
    raise HTTPException(status_code=504, detail="webos-noeud n'a pas répondu")


def _etat(r: Dict[str, Any]) -> Dict[str, Any]:
    e = r.get("etat")
    if not isinstance(e, dict):
        raise HTTPException(status_code=500, detail="état du relais illisible")
    return e


@router.get("/noeud/relais")
def relais_etat(user: dict = Depends(require_jwt)):
    r = _ctl("etat", _acteur(user))
    if r.get("code") != 0:
        raise HTTPException(status_code=500, detail="état du relais illisible")
    return _etat(r)


@router.post("/noeud/relais")
def relais_basculer(body: Interrupteur, user: dict = Depends(require_jwt)):
    r = _ctl("activer" if body.actif else "desactiver", _acteur(user))
    code = r.get("code")
    if code == 3:
        raise HTTPException(status_code=409, detail=REFUS_DEFAUT)
    if code != 0:
        log.error("webos-noeud relais : code %s", code)
        raise HTTPException(status_code=500, detail="relais inchangé (nginx refuse le vhost, ou réglage illisible)")
    return {"success": True, **_etat(r)}
