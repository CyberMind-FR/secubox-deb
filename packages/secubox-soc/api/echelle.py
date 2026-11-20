# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Échelle SADE : projection du score (`priority` d'actord, entier 0..100) sur bandes et phases (#3839).

Fonctions pures, sans E/S. Tout ce qui n'est pas un entier strict dans 0..100 (y compris `bool`,
qui est un sous-type de `int` en Python) devient la bande `inconnu`, jamais une erreur.
"""
from typing import Tuple

# Bornes basses inclusives : un score prend la bande de la plus grande borne qu'il atteint.
BANDES_DEFAUT: Tuple[Tuple[int, str], ...] = (
    (0, "observer"),
    (20, "reactive"),
    (60, "contenir"),
    (80, "usager"),
    (95, "incident"),
)

_PHASES = {"observer": 1, "reactive": 2, "contenir": 3, "usager": 3, "incident": 3}


def bande(score: object, bandes: Tuple[Tuple[int, str], ...] = BANDES_DEFAUT) -> str:
    """Retourne le nom de bande du score, ou `inconnu` si le score n'est pas un entier 0..100."""
    if isinstance(score, bool) or not isinstance(score, int):
        return "inconnu"
    if not 0 <= score <= 100:
        return "inconnu"
    nom = "inconnu"
    for borne, libelle in bandes:
        if score >= borne:
            nom = libelle
    return nom


def phase(b: str) -> int:
    """Phase d'action associée à une bande : 1 à 3, 0 pour `inconnu` ou toute bande inconnue."""
    return _PHASES.get(b, 0)


def exige_validation(b: str) -> bool:
    """Vrai seulement pour la bande `incident` : elle exige une validation humaine."""
    return b == "incident"
