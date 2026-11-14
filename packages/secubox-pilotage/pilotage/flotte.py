# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: regroupement de la flotte (#3702)

Module PUR : matériel déduit du modèle déclaré par la box, et groupes de sélection de la console (matériel, interface, état).
"""
from __future__ import annotations

from typing import Optional

_MATERIELS = (("mochabin", "MOCHAbin"), ("raspberry", "RPi"), ("espressobin", "ESPRESSObin"))


def materiel(modele: Optional[str]) -> str:
    """Sous-chaîne sans casse du modèle : « mochabin » → MOCHAbin, « raspberry » → RPi, « espressobin » → ESPRESSObin, sinon « autre »."""
    bas = modele.lower() if isinstance(modele, str) else ""
    for motif, nom in _MATERIELS:
        if motif in bas:
            return nom
    return "autre"


def groupes(resumes: list) -> dict:
    """Clés des box par matériel, par interface (légère = `distante`) et par état (muette = hors ligne)."""
    par_materiel: dict = {}
    legeres, locales, en_ligne, muettes = [], [], [], []
    for r in resumes:
        par_materiel.setdefault(materiel(r.get("modele")), []).append(r["cle"])
        (legeres if r.get("interface") == "distante" else locales).append(r["cle"])
        (en_ligne if r.get("en_ligne") else muettes).append(r["cle"])
    return {"materiel": par_materiel, "interface": {"legeres": legeres, "locales": locales},
            "etat": {"en_ligne": en_ligne, "muettes": muettes}}
