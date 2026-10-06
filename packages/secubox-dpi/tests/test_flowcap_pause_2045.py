# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2045 — la capture DPI peut espacer ses fenêtres (gk3 saturée).

Le script enchaînait les fenêtres de 60 s sans pause : un cœur occupé en permanence. SECUBOX_DPI_PAUSE
(secondes, défaut 0 = comportement inchangé) ajoute une pause entre deux fenêtres ; l'unité lit un fichier
d'environnement optionnel pour que chaque box règle la sienne."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]


def test_le_script_prevoit_une_pause_entre_les_fenetres_sans_changer_le_defaut():
    s = (PAQUET / "sbin" / "secubox-dpi-flowcap").read_text()
    assert re.search(r'PAUSE="\$\{SECUBOX_DPI_PAUSE:-0\}"', s)
    boucle = s[s.index("while true; do"):]
    assert 'sleep "$PAUSE"' in boucle and '"$PAUSE" -gt 0' in boucle      # inactif tant que PAUSE = 0


def test_l_unite_lit_un_environnement_optionnel():
    u = (PAQUET / "systemd" / "secubox-dpi-flowcap.service").read_text()
    assert re.search(r"(?m)^EnvironmentFile=-/etc/secubox/dpi-flowcap\.env$", u)
