# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes des indices du maillage (#3666) — interrupteurs publier / recevoir et vue des producteurs.

Tout en `require_jwt`. L'écriture se fait sous le verrou des règles (comme le moteur), l'audit passe AVANT par le verbe root
`audit-protection` (geste `tv_indices_reglage`) : un audit impossible refuse le réglage (502) ; une écriture de l'état ratée après
l'audit est tracée par un geste `annule` (audit.log ne ment jamais). La publication lue par MirrorNet reçoit aussitôt les nouveaux
interrupteurs (contenu conservé). GET lit le résumé écrit par le moteur (`indices-resume.json`), jamais les livraisons elles-mêmes.
Aucun nom d'appareil ni domaine n'y circule.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

try:
    from . import dnstv, dnstv_indices
    from . import dnstv_routes as _r
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_indices
    from api import dnstv_routes as _r

from secubox_core.auth import require_jwt

router = APIRouter(prefix="/adblock-tv", tags=["adblock-tv-indices"])
logger = logging.getLogger(__name__)


class IndicesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    publier: bool
    recevoir: bool


def _publies() -> int:
    c = dnstv_indices._lire_json(dnstv_indices.PUBLICATION)
    contenu = c.get("contenu") if isinstance(c, dict) else None
    ind = contenu.get("indices") if isinstance(contenu, dict) else None
    return len(ind) if isinstance(ind, dict) else 0


@router.get("/indices", dependencies=[Depends(require_jwt)])
def lire_indices():
    etat = _r._etat()
    r = dnstv_indices.lire_resume(dnstv_indices.RESUME)
    return {"publier": etat["indices_publier"], "recevoir": etat["indices_recevoir"], "recus": r["recus"],
            "producteurs": r["producteurs"], "maj": r["maj"], "publies": _publies()}


def _audit(acteur: str, geste: str, type_):
    _r._ctl_entree("audit-protection", json.dumps({"acteur": acteur, "origine": "admin", "geste": geste, "cibles": ["indices"],
                                                   "minutes": None, "domaine": None, "type": type_, "force": False}))


@router.post("/indices")
def regler_indices(corps: IndicesIn, jeton=Depends(require_jwt)):
    with _r._verrou():
        etat = _r._etat()
        acteur = _r._acteur(jeton)
        _audit(acteur, "tv_indices_reglage", f"publier={'oui' if corps.publier else 'non'},recevoir={'oui' if corps.recevoir else 'non'}")
        etat["indices_publier"], etat["indices_recevoir"] = corps.publier, corps.recevoir
        try:
            dnstv.ecrire_etat(etat)
        except Exception:
            try:
                _audit(acteur, "annule", None)       # le réglage audité n'a pas été écrit : l'annulation est tracée
            except HTTPException as e:
                logger.warning("audit de l'annulation impossible : %s", e.detail)
            raise
        try:
            dnstv_indices.ecrire_drapeaux(corps.publier, corps.recevoir, dnstv_indices.PUBLICATION)
        except OSError as e:                         # le moteur la réécrit à son prochain passage (chaque minute)
            logger.warning("publication des indices non réécrite : %s", type(e).__name__)
    return {"publier": corps.publier, "recevoir": corps.recevoir}
