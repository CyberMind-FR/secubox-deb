# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Compatibilité (#2863) : la bibliothèque de listes de filtres vit désormais dans `secubox_filterlists` (secubox-core), pour que ad-guard et dns-guard
fonctionnent SANS secubox-toolbox (profil minimal). `from secubox_toolbox import filterlists` rend la même bibliothèque."""
import sys

import secubox_filterlists as _bibliotheque

sys.modules[__name__] = _bibliotheque
