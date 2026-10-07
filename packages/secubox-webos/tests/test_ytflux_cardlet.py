# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Cardlet « Flux YouTube » : entrée déclarée, route authentifiée (les listes d'un compte ne sont pas publiques), page sûre."""
import json
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")
CARTE = (PKG / "www" / "hall" / "cardlets" / "ytflux.html").read_text(encoding="utf-8")
AIDE = json.loads((PKG / "api" / "aide_cartes.json").read_text(encoding="utf-8"))


def test_le_hall_declare_la_carte_session_et_seulement_si_ytsas_est_la():
    ligne = re.search(r'\{id:"ytflux"[^\n]*\}', HALL).group(0)
    assert 'carte:"/cardlets/ytflux.html"' in ligne and "auth:true" in ligne and "admin:false" in ligne
    assert 'si_present:"/api/v1/ytsas/status"' in ligne      # carte dynamique : absente d'une box sans YouTube SAS


def test_la_route_du_flux_est_authentifiee_en_lecture_seule_et_marque_le_relais():
    i = VHOST.index("location ~ ^/api/v1/ytsas/flux")
    corps = VHOST[i:VHOST.index("\n    }", i)]
    assert "auth_request /__sbx_verifie_secubox;" in corps
    assert "limit_except GET { deny all; }" in corps
    assert "proxy_set_header X-Sbx-Flux      1;" in corps
    assert "[A-Za-z0-9_-]{11}" in corps                      # l'identifiant de vignette est borné dans la route elle-même


def test_la_route_du_flux_precede_le_prefixe_ouvert_ytsas():
    assert VHOST.index("location ~ ^/api/v1/ytsas/flux") < VHOST.index("location /api/v1/ytsas/ {")


def test_le_prefixe_ouvert_ne_pose_jamais_l_en_tete_du_flux():
    i = VHOST.index("location /api/v1/ytsas/ {")
    corps = VHOST[i:VHOST.index("\n    }", i)]
    assert "X-Sbx-Flux" not in corps


def test_la_page_n_injecte_jamais_de_html():
    for interdit in ("innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert interdit not in CARTE, interdit


def test_la_page_ne_parle_qu_a_son_origine_et_ouvre_youtube_sans_opener():
    assert "var API = '/api/v1/ytsas/';" in CARTE
    assert "fetch('http" not in CARTE and 'fetch("http' not in CARTE
    assert "rel = 'noopener noreferrer'" in CARTE


def test_les_quatre_onglets_et_les_etats_honnetes():
    for t in ("envie", "propositions", "abonnements", "historique"):
        assert f"['{t}'," in CARTE
    for etat in ("cookies", "Connexion requise", "données anciennes", "Réessayer"):
        assert etat in CARTE


def test_fiche_d_aide_presente_et_complete():
    f = next(c for c in AIDE["cartes"] if c["id"] == "ytflux")
    assert f["service"] == "ytsas" and f["acces"] == "session" and f["usage"] and f["role"]
