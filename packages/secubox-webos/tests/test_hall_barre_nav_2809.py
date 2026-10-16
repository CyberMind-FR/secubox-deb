# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2809 — les pages servies par le Hall (identite, coffre) ont leur barre de navigation.

Constat : sur le vhost du Hall, /shared/sidebar.js retombait sur `location /` (la page d'accueil, du HTML) et /api/v1/hub/public/menu repondait 404.
Les actifs statiques sont servis en lecture seule ; le menu et l'etat de sante ne sont relayes que derriere le MEME double verrou que
l'administration (reseau local + session verifiee) : le Hall est expose, l'inventaire des modules ne l'est pas."""
import re
from pathlib import Path

CONF = (Path(__file__).resolve().parents[1] / "nginx" / "hall.vhost.conf").read_text(encoding="utf8")


def bloc(entete):
    i = CONF.index(entete)
    j = CONF.index("{", i)
    prof, k = 1, j + 1
    while prof:
        prof += {"{": 1, "}": -1}.get(CONF[k], 0)
        k += 1
    return CONF[i:k]


def test_les_actifs_partages_sont_servis_en_lecture_seule():
    b = bloc("location /shared/ {")
    assert "alias /usr/share/secubox/www/shared/;" in b
    assert "try_files $uri =404;" in b
    assert 'X-Content-Type-Options "nosniff"' in b
    assert "proxy_pass" not in b


def test_le_dossier_partage_ne_contient_que_du_statique():
    """Le bloc est un alias : il ne doit jamais etre un relais ni autoriser l'ecriture."""
    b = bloc("location /shared/ {")
    assert "limit_except GET HEAD" in b and "deny all" in b


def test_menu_et_sante_sont_derriere_le_double_verrou():
    for chemin in ("/api/v1/hub/public/menu", "/api/v1/hub/public/health-batch"):
        b = bloc(f"location = {chemin} {{")
        assert "if ($lan_client = 0) { return 403; }" in b, chemin
        assert "auth_request /__sbx_verifie_secubox;" in b, chemin
        assert f"proxy_pass http://unix:/run/secubox/aggregator.sock:{chemin};" in b, chemin
        assert "limit_except GET" in b, chemin


def test_les_nouveaux_blocs_precedent_la_garde_generique_api():
    """`location /api/ { return 404 }` est un prefixe plus court : l'exact (=) gagne de toute facon, mais on le dit."""
    assert CONF.index("location = /api/v1/hub/public/menu") < CONF.index("location /api/ {")
