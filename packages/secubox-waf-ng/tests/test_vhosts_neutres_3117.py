# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : les vhosts livrés ne portent aucun nom propre à une box."""
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
SOURCES = [PKG / "nginx" / "actor.vhost.conf",
           PKG / "composants" / "waf" / "nginx" / "waf-vhost.conf"]
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")


def test_aucun_nom_de_gk2_dans_les_vhosts():
    for f in SOURCES:
        assert "gk2" not in f.read_text(encoding="utf-8"), f


def test_server_name_generique():
    for f, attendu in zip(SOURCES, ("server_name actor.*;", "server_name waf.*;")):
        assert attendu in f.read_text(encoding="utf-8")


def test_noms_installes_neutres():
    assert "sites-available/actor.conf" in RULES
    assert "sites-available/waf.conf" in RULES
    assert "gk2" not in "".join(l for l in RULES.splitlines() if "sites-available" in l)


def test_postinst_active_les_nouveaux_noms_et_migre():
    for p in (PKG / "debian" / "postinst", PKG / "composants" / "waf" / "debian" / "postinst"):
        t = p.read_text(encoding="utf-8")
        assert "sbx_migrer_vhost" in t
        assert 'ln -sf' in t
    assert 'A_VHOST="actor"' in (PKG / "debian" / "postinst").read_text(encoding="utf-8")
    assert 'VHOST="waf"' in (PKG / "composants/waf/debian/postinst").read_text(encoding="utf-8")
