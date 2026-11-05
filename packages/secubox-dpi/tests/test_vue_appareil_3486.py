# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3486 : dpi-vue détaille chaque appareil à partir de /clients, sans inventer de zéro ni injecter de nom."""
from pathlib import Path

VUE = (Path(__file__).resolve().parents[1] / "www/dpi/vue.html").read_text(encoding="utf-8")


def test_panneau_masque_dans_la_carte_du_hall():
    assert '<div class="pan sec"><h3>Détail par appareil' in VUE


def test_mesure_absente_affichee_tiret():
    assert "function octOu(v){return v==null?'—':oct(v);}" in VUE


def test_noms_echappes():
    assert "esc(c.name||c.device)" in VUE and 'title="\'+esc(c.device)+\'"' in VUE
