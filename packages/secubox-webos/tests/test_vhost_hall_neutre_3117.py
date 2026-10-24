# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : le vhost du Hall est livré sous un nom et des server_name neutres.

Le corps du vhost garde des références fonctionnelles au parc de gk2 (CSP,
en-têtes Host des relais) : hors périmètre de #3117, seuls le server_name, le
nom du fichier installé et l'en-tête du fichier sont vérifiés ici."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")
POSTINST = (PKG / "debian" / "postinst").read_text(encoding="utf-8")


def test_server_name_sans_gk2():
    noms = re.findall(r"^\s*server_name\s+([^;]+);", VHOST, re.M)
    assert noms
    for n in noms:
        assert "gk2" not in n, n
    assert "server_name hall.localhost hall.*;" in VHOST


def test_entete_neutre():
    assert "gk2" not in "\n".join(VHOST.splitlines()[:10])


def test_installe_sous_hall_conf():
    assert "sites-available/hall.conf" in RULES
    assert "sites-available/hall.gk2.net.conf" not in RULES


def test_postinst_active_hall_conf_et_migre_le_lien():
    assert "ln -s ../sites-available/hall.conf" in POSTINST
    assert "sites-enabled/hall.gk2.net.conf" in POSTINST  # retrait de l'ancien lien


def test_maintscript_deplace_l_ancien_conffile():
    m = (PKG / "debian" / "secubox-webos.maintscript").read_text(encoding="utf-8")
    assert ("mv_conffile /etc/nginx/sites-available/hall.gk2.net.conf "
            "/etc/nginx/sites-available/hall.conf") in m
