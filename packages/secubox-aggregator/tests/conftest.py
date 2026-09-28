# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-aggregator — harnais de test
CyberMind — https://cybermind.fr

Rend importables le paquet `aggregator` et `secubox_core` (common/) sans les
installer. Aucun module n'est monté : la configuration pointe vers un fichier
absent, l'agrégateur démarre vide et seul le relais vers les sockets dédiés
est exercé.
"""
import sys
from pathlib import Path

_ICI = Path(__file__).resolve()
sys.path.insert(0, str(_ICI.parents[1]))               # packages/secubox-aggregator
sys.path.insert(0, str(_ICI.parents[3] / "common"))    # common/secubox_core
