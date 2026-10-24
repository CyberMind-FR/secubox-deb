# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : le vhost wpad livré ne porte aucun nom propre à une box."""
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
VHOST = PKG / "composants" / "proxypac" / "nginx" / "wpad-vhost.conf"
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")


def test_aucun_nom_de_gk2_dans_le_vhost():
    assert "gk2" not in VHOST.read_text(encoding="utf-8")


def test_server_name_generique():
    assert "server_name wpad.*;" in VHOST.read_text(encoding="utf-8")


def test_installe_par_debian_rules():
    assert "composants/proxypac/nginx/wpad-vhost.conf" in RULES
    assert "sites-available" in RULES
