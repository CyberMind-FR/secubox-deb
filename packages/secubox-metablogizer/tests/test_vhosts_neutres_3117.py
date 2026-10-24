# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : les vhosts livrés ne portent aucun nom propre à une box."""
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
SOURCES = [PKG / "nginx" / "metablogizer.vhost.conf",
           PKG / "composants" / "droplet" / "nginx" / "depot-vhost.conf"]
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")
POSTINST = (PKG / "debian" / "postinst").read_text(encoding="utf-8")


def test_aucun_nom_de_gk2_dans_les_vhosts():
    for f in SOURCES:
        assert "gk2" not in f.read_text(encoding="utf-8"), f


def test_server_name_generique():
    assert "server_name metablogizer.*;" in SOURCES[0].read_text(encoding="utf-8")
    assert "server_name depot.*;" in SOURCES[1].read_text(encoding="utf-8")


def test_noms_installes_neutres():
    assert "sites-available/metablogizer.conf" in RULES
    assert "sites-available/depot.conf" in RULES
    assert "gk2" not in "".join(l for l in RULES.splitlines() if "sites-available" in l)


def test_postinst_active_le_nouveau_nom_et_migre():
    assert "HOTE=metablogizer\n" in POSTINST
    assert "sbx_migrer_vhost metablogizer.gk2.secubox.in.conf metablogizer.conf" in POSTINST
    assert "sbx_migrer_vhost depot.gk2.conf depot.conf" in POSTINST
