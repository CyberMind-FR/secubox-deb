# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Carte « Cloud » : plus un lien statique (« Service SecuBox souverain », état « inconnu »), mais l'état réel de Nextcloud."""
import json
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")
QUICK = (PKG / "www" / "hall" / "cardlets" / "quick.html").read_text(encoding="utf-8")
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
AIDE = json.loads((PKG / "api" / "aide_cartes.json").read_text(encoding="utf-8"))


def test_la_carte_cloud_porte_un_cardlet_et_n_apparait_que_si_nextcloud_est_la():
    ligne = re.search(r'\{id:"cloud",[^\n]*\}', HALL).group(0)
    assert 'carte:"/cardlets/quick.html?svc=nextcloud"' in ligne and "auth:true" in ligne
    assert 'si_present:"/adm/api/v1/nextcloud/status"' in ligne


def test_le_gabarit_connait_nextcloud_et_ses_chiffres():
    assert "nextcloud: { ic:'☁️'" in QUICK and "mod:'nextcloud'" in QUICK
    assert "['user_count','👥','comptes']" in QUICK and "['disk_used','💾','espace utilisé']" in QUICK
    assert "/sbx/entrer" in QUICK                      # « Ouvrir » entre avec la session du Hall


def test_l_etat_reel_est_ecrit_en_marche_endormi_ou_absent():
    assert "d.running !== undefined" in QUICK
    for mot in ("en marche", "endormi", "non installé"):
        assert mot in QUICK


def test_sans_session_la_carte_le_dit_au_lieu_d_afficher_des_zeros():
    assert "r.status === 401 || r.status === 403" in QUICK and "connexion requise pour voir" in QUICK


def test_le_relais_de_lecture_inclut_nextcloud_en_get_seulement():
    i = VHOST.index("location ~ ^/adm/api/v1/(droplet|torrent|ytsas|nextcloud)/status$ {")
    corps = VHOST[i:VHOST.index("\n    }", i)]
    assert "limit_except GET { deny all; }" in corps and "status" in corps
    assert "nextcloud" in VHOST[i:i + 120]


def test_l_aide_decrit_la_carte_telle_qu_elle_est():
    f = next(c for c in AIDE["cartes"] if c["id"] == "cloud")
    assert "Mail" not in f["role"] and "endormi" in f["role"] and f["acces"] == "session"
