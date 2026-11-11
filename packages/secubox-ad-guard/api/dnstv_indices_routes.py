# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes des indices du maillage (#3666) — interrupteurs publier / recevoir et vue des producteurs.

Tout en `require_jwt`. L'écriture se fait sous le verrou des règles (comme le moteur), l'audit passe AVANT par le verbe root
`audit-protection` (geste `tv_indices_reglage`) : un audit impossible refuse le réglage (502). Aucun nom d'appareil ni domaine n'y circule.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

try:
    from . import dnstv, dnstv_indices
    from . import dnstv_routes as _r
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_indices
    from api import dnstv_routes as _r

from secubox_core.auth import require_jwt

router = APIRouter(prefix="/adblock-tv", tags=["adblock-tv-indices"])


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
    ix = dnstv_indices.charger(dnstv_indices.LIVRAISONS)
    prod = {}
    for _d, par in ix.confirmes.items():
        for nom in par:
            prod.setdefault(nom, [0, 0])[0] += 1
    for _d, noms in ix.legitimes.items():
        for nom in noms:
            prod.setdefault(nom, [0, 0])[1] += 1
    return {"publier": etat["indices_publier"], "recevoir": etat["indices_recevoir"], "recus": len(ix.confirmes),
            "producteurs": [{"nom": n, "indices": v[0], "legitimes": v[1]} for n, v in sorted(prod.items())],
            "publies": _publies()}


@router.post("/indices")
def regler_indices(corps: IndicesIn, jeton=Depends(require_jwt)):
    with _r._verrou():
        etat = _r._etat()
        acteur = _r._acteur(jeton)
        type_ = f"publier={'oui' if corps.publier else 'non'},recevoir={'oui' if corps.recevoir else 'non'}"
        _r._ctl_entree("audit-protection", json.dumps({"acteur": acteur, "origine": "admin", "geste": "tv_indices_reglage", "cibles": ["indices"],
                                                       "minutes": None, "domaine": None, "type": type_, "force": False}))
        etat["indices_publier"], etat["indices_recevoir"] = corps.publier, corps.recevoir
        dnstv.ecrire_etat(etat)
    return {"publier": corps.publier, "recevoir": corps.recevoir}
