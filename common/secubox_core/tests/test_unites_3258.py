# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3258 — un seul chemin pour piloter une unité depuis Python : secubox_core.unites.piloter.

L'ancien `secubox_core.system.service_control` passait le nom tel quel à systemctl (ni motif, ni « -- », ni unité
protégée, ni audit). Sans appelant dans le dépôt, il est retiré : personne ne peut plus le réutiliser par mégarde."""
import secubox_core
from secubox_core import system, unites


def test_l_ancien_service_control_sans_garde_est_retire():
    assert not hasattr(system, "service_control")
    assert not hasattr(secubox_core, "service_control")
    assert "service_control" not in secubox_core.__all__


def test_le_controle_partage_reste_disponible():
    assert callable(unites.piloter)
    assert unites.MOTIF_UNITE.fullmatch("secubox-dpi.service")
    assert not unites.MOTIF_UNITE.fullmatch("--now")
