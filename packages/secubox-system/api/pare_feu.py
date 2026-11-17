# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: system :: lecture du relevé du pare-feu pour la carte « posture » (#3780)."""
import json
import os
import time
from pathlib import Path

PARE_FEU_ETAT = Path(os.environ.get("SECUBOX_PARE_FEU_ETAT", "/var/lib/secubox/system/pare-feu.json"))
PARE_FEU_PERIME_S = 15 * 60


def lire(chemin: Path = None, maintenant: float = None) -> dict:
    """Relevé du pare-feu (#3780) traduit pour la carte : libellé court, relevé, périmé ou absent dit tel quel."""
    try:
        r = json.loads((chemin or PARE_FEU_ETAT).read_text())
    except (OSError, ValueError):
        return {"libelle": "Non relevé", "etat": "inconnu"}
    age = (maintenant or time.time()) - int(r.get("releve") or 0)
    if r.get("actif") is None:
        etat, libelle = "inconnu", "Illisible"
    elif not r.get("actif"):
        etat, libelle = "inactif", "Inactif : aucune règle"
    elif r.get("politique_entree") == "drop":
        etat, libelle = "actif", "Actif, entrée fermée par défaut"
    else:
        etat, libelle = "ouvert", "Actif, mais entrée ouverte par défaut"
    if age > PARE_FEU_PERIME_S:
        etat, libelle = "perime", libelle + " (relevé périmé)"
    return {**r, "libelle": libelle, "etat": etat, "age_s": int(age)}
