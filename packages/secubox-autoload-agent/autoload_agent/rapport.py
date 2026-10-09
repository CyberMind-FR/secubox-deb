# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload-agent :: le RAPPORT FINAL (#2192, parent #2182)

Le rapport dit ce qui a été fait (client, profil, paquets, domaine, comptes créés par nom, adresse de tunnel, début, fin, étapes) et rien d'autre : il n'a pas de
champ pour un secret. Il est affiché à l'écran, diffusé à l'infrastructure (qui l'envoie par courrier au client si son contact est renseigné), et gardé sur la box.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict

PROFILS = {"lite": "Lite", "isp": "ISP", "full": "Full"}
PAQUETS_AFFICHES = 30
ISSUE_DEFAUT = Path("/run/issue.d")


def texte(rap: Dict) -> str:
    minutes = max(1, round((rap["fin"] - rap["debut"]) / 60))
    paquets = rap["paquets"]
    lignes = ["Votre boîtier SecuBox est prêt.", "",
              f"  Profil installé : {PROFILS.get(rap['profil'], rap['profil'])}",
              f"  Adresse du boîtier : {rap['domaine']}",
              f"  Comptes créés : {', '.join(rap['comptes']) or 'aucun'}",
              f"  Durée de la mise en service : environ {minutes} minute{'s' if minutes > 1 else ''}",
              f"  Composants installés : {len(paquets)} paquets", ""]
    lignes += [f"    - {p}" for p in paquets[:PAQUETS_AFFICHES]]
    if len(paquets) > PAQUETS_AFFICHES:
        lignes.append(f"    … et {len(paquets) - PAQUETS_AFFICHES} autres ({len(paquets)} paquets)")
    lignes += ["", "Aucun mot de passe n'est affiché ici : il se choisit à la première connexion."]
    return "\n".join(lignes) + "\n"


def ecrire_issue(rap: Dict, dossier: Path = ISSUE_DEFAUT) -> None:
    """Affiche le rapport à l'écran de la console au prochain affichage de connexion (agetty lit /run/issue.d/*.issue). Sans ce dossier, on ne fait rien."""
    dossier = Path(dossier)
    if not dossier.is_dir():
        return
    f = dossier / "50-secubox-autoload.issue"
    f.write_text(texte(rap), encoding="utf-8")
    f.chmod(0o644)
