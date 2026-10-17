# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2872 — /sbxid/ ne renvoie plus vers un Hall ABSENT.

Sur une box sans Hall (profil minimal, ESPRESSObin) : admin.<box>/sbxid/ renvoyait en 302 vers https://hall.<box>/identite/#admin, un site qui n'existe pas. Sans Hall installé,
le gestionnaire d'identité s'ouvre sur l'origine admin (/identite/#admin) ; avec Hall, rien ne change."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
NGINX = (RACINE / "nginx" / "sbxid-routes.conf").read_text(encoding="utf-8")
STUB = (RACINE / "www" / "sbxid" / "index.html").read_text(encoding="utf-8")
USERS = (RACINE.parent / "users" / "www" / "users" / "index.html").read_text(encoding="utf-8")


def _bloc_sbxid():
    return NGINX[NGINX.index("location /sbxid/ {"):]


def test_nginx_sans_hall_garde_l_origine_admin():
    b = _bloc_sbxid()
    assert re.search(r"if \(!-d /usr/share/secubox/www/hall\)\s*\{\s*set \$sbxid_hall \$host;\s*\}", b), b
    # l'ordre compte : la substitution admin -> hall d'abord, le repli sans Hall ensuite (il l'emporte)
    assert b.index("^admin\\.") < b.index("-d /usr/share/secubox/www/hall")
    assert "return 302 https://$sbxid_hall/identite/#admin;" in b


def test_le_repli_de_la_page_sonde_le_hall_de_meme_origine():
    assert "fetch('/hall/'" in STUB and "'HEAD'" in STUB
    assert "location.replace('/identite/#admin')" in STUB.replace(" ", "") or "/identite/#admin" in STUB


def test_la_page_utilisateurs_ne_pointe_pas_vers_un_hall_absent():
    assert "fetch('/hall/'" in USERS and "'HEAD'" in USERS
    assert "function urlIdentite()" in USERS
