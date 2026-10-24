# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3096 — l'API lyrion tourne sur sa socket dédiée (#763), livrée, activée, toujours éveillée.

gk2, 2026-10-24 : après redémarrage, /api/v1/lyrion/* en 404 (l'agrégateur relaie à /run/secubox/lyrion.sock,
qu'aucune unité ne servait : le paquet ne la livrait plus et son postinst la désactivait)."""
import configparser
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
RULES = (ICI / "debian" / "rules").read_text()
POSTINST = (ICI / "debian" / "postinst").read_text()
UNITE = ICI / "debian" / "secubox-lyrion.service"


def test_le_paquet_livre_et_active_l_unite_de_l_api():
    # dh_installsystemd --name=secubox-lyrion prend debian/secubox-lyrion.service ; une copie manuelle en plus la
    # livrait deux fois (/lib et /usr/lib, même fichier sous usrmerge).
    assert any(l.strip() == "dh_installsystemd --name=secubox-lyrion" for l in RULES.splitlines())
    assert "install -m 644 debian/secubox-lyrion.service" not in RULES


def test_le_postinst_ne_desactive_plus_l_api():
    assert "disable secubox-lyrion.service" not in POSTINST


def test_l_unite_ne_touche_pas_au_parent_run_secubox():
    # RuntimeDirectory=secubox/0755 re-chownait /run/secubox (1777 root:root attendu) : 502 sur toute la box (#494, #763)
    c = configparser.ConfigParser(strict=False, interpolation=None)
    c.optionxform = str
    c.read_string(UNITE.read_text())
    assert c["Service"].get("RuntimeDirectory", "") == ""
    assert "RuntimeDirectoryMode" not in c["Service"]
    assert "--uds /run/secubox/lyrion.sock" in c["Service"]["ExecStart"]


def test_le_manifeste_passe_une_fois_en_toujours_eveille_avec_l_unite():
    assert "set-lifecycle lyrion --lifecycle always-on" in POSTINST
    assert '.manifeste-3096' in POSTINST
    assert 'units     = ["secubox-lyrion.service"]' in POSTINST


def test_le_postinst_active_l_api_meme_apres_une_desactivation():
    # gk2, 1.7.5 : deb-systemd-helper garde l'état « disabled » laissé par les anciens postinst (systemctl disable
    # à chaque installation) ; l'unité livrée restait éteinte. Le postinst l'active lui-même, après le témoin.
    i = POSTINST.index("touch \"$temoin3096\"")
    assert "systemctl enable --now secubox-lyrion.service" in POSTINST[i:]
