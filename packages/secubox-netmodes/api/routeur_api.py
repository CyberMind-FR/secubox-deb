# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Routes du mode routeur durable (#3189) : tout passe par netmodesctl (root, sudo -n), jamais par netplan.

Routes `def` (pool de threads) : elles appellent subprocess. L'acteur est le `sub` du jeton vérifié."""
from __future__ import annotations

import json
import re
import subprocess
from ipaddress import IPv4Interface, ip_address
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from secubox_core.auth import require_jwt, require_lecture
from secubox_core.logger import get_logger

from .routeur_config import ErreurConfig, depuis_dict
from .routeur_rendu import rendre

CTL = "/usr/sbin/netmodesctl"
DELAI_CTL = 150                                 # le contrôleur peut passer 120 s par commande
ACTEUR_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
CLES_CONFIG = ("adresse", "dhcp_debut", "dhcp_fin", "bail", "ports", "wan")
MODELES = (Path("/proc/device-tree/model"), Path("/sys/firmware/devicetree/base/model"))
AVERTISSEMENT = ("Vous appliquez depuis le LAN actuel : vous perdrez la connexion ; "
                 "confirmez depuis la nouvelle adresse sous 3 minutes.")

log = get_logger("netmodes")
router = APIRouter(prefix="/routeur")


def est_mochabin() -> bool:
    """Même test que detect_board : modèle du device tree."""
    for chemin in MODELES:
        try:
            modele = chemin.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        return any(m in modele for m in ("MOCHAbin", "mochabin", "7040"))
    return False


def _acteur(user: Any) -> str:
    sub = str(user.get("sub") or "") if isinstance(user, dict) else ""
    if not ACTEUR_RE.fullmatch(sub):
        raise HTTPException(400, "identité de l'administrateur invalide")
    return sub


def _ctl(verbe: str, acteur: str | None = None, entree: str | None = None) -> dict:
    argv = ["sudo", "-n", CTL, verbe] + ([acteur] if acteur else [])      # routeur-etat : sans acteur (sudoers exact)
    try:
        r = subprocess.run(argv, input=entree, capture_output=True,
                           text=True, timeout=DELAI_CTL, check=False)
    except subprocess.TimeoutExpired:
        raise HTTPException(502, "le contrôleur réseau n'a pas répondu à temps")
    except OSError as e:
        raise HTTPException(502, f"contrôleur réseau injoignable : {e}")
    try:
        sortie = json.loads(r.stdout)
        if not isinstance(sortie, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(502, "réponse illisible du contrôleur réseau")
    if r.returncode == 0:
        return sortie
    msg = str(sortie.get("erreur") or "échec du contrôleur réseau")
    if r.returncode == 3:
        raise HTTPException(409, msg)
    if r.returncode == 4:
        raise HTTPException(409, "une application est déjà en cours")
    if r.returncode == 2:
        raise HTTPException(400, msg)
    raise HTTPException(502, msg)


def _config(corps: dict) -> dict:
    if not isinstance(corps, dict):
        raise HTTPException(400, "corps JSON attendu")
    return {k: corps[k] for k in CLES_CONFIG if k in corps}


def _valider(cfg: dict):
    try:
        return depuis_dict(cfg)
    except ErreurConfig as e:
        raise HTTPException(400, str(e))


def _client(request: Request) -> str:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


@router.get("/etat")
def etat(user=Depends(require_lecture)):
    return _ctl("routeur-etat")                    # lecture : pas d'acteur, un lecteur du LAN peut être anonyme


@router.post("/apercu")
def apercu(corps: dict, user=Depends(require_jwt)):
    return {"fichiers": rendre(_valider(_config(corps)))}


@router.post("/appliquer")
def appliquer(corps: dict, request: Request, user=Depends(require_jwt)):
    if not isinstance(corps, dict) or corps.get("confirmer") != "routeur":
        raise HTTPException(400, 'confirmation requise : "confirmer": "routeur"')
    acteur = _acteur(user)
    cfg = _config(corps)
    nouveau = _valider(cfg).adresse.network
    try:
        actuel = _ctl("routeur-etat")
    except HTTPException as e:                    # l'avertissement est facultatif : on applique quand même
        log.warning("routeur-etat indisponible, avertissement omis : %s", e.detail)
        actuel = {}
    res = _ctl("routeur-appliquer", acteur, json.dumps(cfg))
    try:
        ip = ip_address(_client(request))
        reseaux = [IPv4Interface(a).network for a in actuel.get("adresses_pont", [])]
        if any(ip in r for r in reseaux) and nouveau not in reseaux:
            res["avertissement"] = AVERTISSEMENT
    except ValueError:
        pass                                      # adresse client illisible : pas d'avertissement
    return res


@router.post("/confirmer")
def confirmer(user=Depends(require_jwt)):
    return _ctl("routeur-confirmer", _acteur(user))


@router.post("/retour")
def retour(corps: dict, user=Depends(require_jwt)):
    if not isinstance(corps, dict) or corps.get("confirmer") != "retour":
        raise HTTPException(400, 'confirmation requise : "confirmer": "retour"')
    return _ctl("routeur-retour", _acteur(user))
