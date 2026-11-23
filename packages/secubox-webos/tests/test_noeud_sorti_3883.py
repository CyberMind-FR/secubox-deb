# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3883 — l'accueil et le relais du nom de nœud ne sont plus au Hall : secubox-webos ne livre ni programme, ni unité,
ni page, ni route ; il arrête ses anciennes unités à la montée et dépend du cœur qui les porte désormais."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_plus_rien_du_relais_dans_le_paquet():
    for chemin in ("sbin/webos-noeud", "api/noeud.py", "www/noeud", "debian/secubox-webos-noeud.path",
                   "debian/secubox-webos-noeud.service", "tests/banc_noeud.py"):
        assert not (PKG / chemin).exists(), chemin
    rules = (PKG / "debian/rules").read_text()
    assert "webos-noeud" not in rules and "www/noeud" not in rules
    # la SOURCE du dé reste ici : secubox-core (accueil du nœud) et secubox-hub la livrent depuis www/hall
    assert "www/hall/sbx-dice.js" in rules and "www/hall/dice/*.jpg" in rules
    main = (PKG / "api/main.py").read_text()
    assert not re.search(r"\bnoeud\.router\b", main) and not re.search(r"from api import [^\n]*\bnoeud\b", main)
    assert not re.search(r"^\[noeud\]", (PKG / "etc/webos.toml.example").read_text(), re.M)
    assert "webos-noeud" not in (PKG / "debian/prerm").read_text()


def test_montee_arrete_les_anciennes_unites_et_depend_du_coeur():
    preinst = (PKG / "debian/preinst").read_text()
    bloc = preinst[preinst.index("upgrade)", preinst.index("#3883")):preinst.index("#DEBHELPER#")]
    assert 'dpkg --compare-versions "$2" lt 1.21.3-1~trixie1~' in bloc
    assert "systemctl disable --now secubox-webos-noeud.path" in bloc
    assert "systemctl disable --now secubox-webos-noeud.service" in bloc
    postinst = (PKG / "debian/postinst").read_text()
    assert "deb-systemd-helper purge secubox-webos-noeud.path secubox-webos-noeud.service" in postinst
    assert "rm -rf /run/secubox/webos-noeud /run/secubox/webos-noeud-resultats" in postinst
    assert "/usr/sbin/webos-noeud" not in postinst and "enable --now secubox-webos-noeud" not in postinst
    control = (PKG / "debian/control").read_text()
    assert re.search(r"^ secubox-core \(>= 1\.8\.40~\),$", control, re.M)
    # et le cœur refuse de cohabiter avec un webos qui gérerait encore le vhost
    coeur = (PKG.parent / "secubox-core/debian/control").read_text()
    assert "Breaks: " in coeur and "secubox-webos (<< 1.21.3~)" in coeur.split("Breaks: ", 1)[1].splitlines()[0]
    version = (PKG / "debian/changelog").read_text().split("\n", 1)[0]
    assert version.startswith("secubox-webos (1.21.3-1~trixie1)")
