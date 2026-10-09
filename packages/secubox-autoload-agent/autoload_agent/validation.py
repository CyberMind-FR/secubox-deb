# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload-agent :: la VALIDATION (#2188, parent #2182, décision D6)

Le moteur (#2187) remet son PLAN à un valideur ; ce module fournit les deux valideurs :

  - AUTO (zero-touch, personne devant la box) : le PRÉ-RAPPORT est écrit (0600) et publié à l'infrastructure, puis un DÉLAI DE GRÂCE
    (15 minutes par défaut) pendant lequel l'opérateur peut refuser. Passé le délai sans refus, on applique. FERMÉ PAR DÉFAUT : si le
    pré-rapport ne peut pas être publié, ou si on ne peut plus savoir s'il a été refusé, on n'applique pas (personne ne pourrait refuser).
  - MANUEL (one-shot, un opérateur est devant) : on applique seulement si l'opérateur confirme CE pré-rapport, c'est-à-dire son EMPREINTE.
    Une confirmation d'un autre plan ne vaut rien. Sans confirmation avant l'échéance : refus.

Le pré-rapport dit ce qui va arriver : profil, paquets, réseau, comptes créés (noms), et seulement QU'il y a des secrets (mot de passe, jeton), jamais leur
valeur ni leur nom de fichier.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict

from .moteur import Plan

GRACE_DEFAUT_MIN = 15
GRACE_MAX_MIN = 24 * 60
SONDE_S = 30
DOSSIER_DEFAUT = Path("/var/lib/secubox/autoload-agent")


def construire(plan: Plan, reponses: Dict, horodatage: int) -> Dict:
    """Le pré-rapport : ce qui va être fait, sans aucun secret."""
    secrets = []
    if "jeton" in (reponses.get("provision") or {}):
        secrets.append("jeton")
    if (reponses.get("admin") or {}).get("mot_de_passe") not in (None, "demander"):
        secrets.append("mot_de_passe")
    reseau = reponses.get("reseau") or {}
    return {"horodatage": int(horodatage), "box": (reponses.get("box") or {}).get("nom", ""), "profil": plan.profil, "mode": plan.mode,
            "paquets": list(plan.paquets), "comptes": ["admin"], "reseau": {"mode": reseau.get("mode", ""), "domaine": reseau.get("domaine", "")},
            "secrets": sorted(secrets)}


def empreinte(pre_rapport: Dict) -> str:
    """SHA-256 du contenu canonique : c'est ce que l'opérateur confirme ou refuse."""
    return hashlib.sha256(json.dumps(pre_rapport, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _ecrit(dossier: Path, pre_rapport: Dict) -> Path:
    dossier.mkdir(parents=True, exist_ok=True)
    chemin = dossier / f"prerapport-{pre_rapport['horodatage']}.json"
    fd, tmp = tempfile.mkstemp(dir=dossier, prefix=".sbx-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps({**pre_rapport, "empreinte": empreinte(pre_rapport)}, ensure_ascii=False, indent=1))
        os.replace(tmp, chemin)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return chemin


def valideur_auto(grace_min: int, publier: Callable[[Dict], None], refuse: Callable[[str], bool], reponses: Dict, dossier: Path = DOSSIER_DEFAUT,
                  horloge: Callable[[], float] = time.time, dormir: Callable[[float], None] = time.sleep) -> Callable[[Plan], bool]:
    if isinstance(grace_min, bool) or not isinstance(grace_min, int) or not 0 <= grace_min <= GRACE_MAX_MIN:
        raise ValueError(f"délai de grâce : un entier de 0 à {GRACE_MAX_MIN} minutes")

    def valider(plan: Plan) -> bool:
        pre = construire(plan, reponses, horloge())
        emp = empreinte(pre)
        try:
            _ecrit(dossier, pre)
            publier({**pre, "empreinte": emp})
        except OSError:
            return False                                                       # fermé par défaut : personne ne pourrait refuser
        fin = horloge() + grace_min * 60
        while horloge() < fin:
            try:
                if refuse(emp):
                    return False
            except OSError:
                return False                                                   # on ne sait plus si l'opérateur a refusé : on n'applique pas
            dormir(min(SONDE_S, max(0.0, fin - horloge())))
        return True
    return valider


def valideur_manuel(lire_confirmation: Callable[[], str], reponses: Dict, attente_max_s: int = 1800, dossier: Path = DOSSIER_DEFAUT,
                    horloge: Callable[[], float] = time.time, dormir: Callable[[float], None] = time.sleep) -> Callable[[Plan], bool]:
    def valider(plan: Plan) -> bool:
        debut = horloge()
        pre = construire(plan, reponses, debut)
        emp = empreinte(pre)
        try:
            _ecrit(dossier, pre)
        except OSError:
            return False
        fin = debut + attente_max_s
        while horloge() < fin:
            if lire_confirmation() == emp:
                return True
            dormir(min(SONDE_S, max(0.0, fin - horloge())))
        return False
    return valider


def pour_mode(mode: str, reponses: Dict, dossier: Path = DOSSIER_DEFAUT, publier=None, refuse=None, lire_confirmation=None,
              horloge: Callable[[], float] = time.time, dormir: Callable[[float], None] = time.sleep) -> Callable[[Plan], bool]:
    """Le valideur que le mode du fichier de réponses désigne (`[provision].mode`)."""
    if mode == "auto":
        grace = (reponses.get("provision") or {}).get("grace_min", GRACE_DEFAUT_MIN)
        return valideur_auto(grace, publier, refuse, reponses, dossier, horloge, dormir)
    if mode == "one-shot":
        return valideur_manuel(lire_confirmation, reponses, dossier=dossier, horloge=horloge, dormir=dormir)
    raise ValueError("mode : auto ou one-shot")
