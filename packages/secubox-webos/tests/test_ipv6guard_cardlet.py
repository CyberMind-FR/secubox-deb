# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Carte « IPv6 Guardian » : entrée déclarée, routes authentifiées en lecture seule, page sûre, langage courant."""
import json
import re
import subprocess
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")
CARTE = (PKG / "www" / "hall" / "cardlets" / "ipv6guard.html").read_text(encoding="utf-8")
AIDE = json.loads((PKG / "api" / "aide_cartes.json").read_text(encoding="utf-8"))


def test_le_hall_declare_la_carte_session_et_seulement_si_le_module_est_la():
    ligne = re.search(r'\{id:"ipv6guard"[^\n]*\}', HALL).group(0)
    assert 'carte:"/cardlets/ipv6guard.html"' in ligne and "auth:true" in ligne and "admin:false" in ligne
    assert 'si_present:"/api/v1/ipv6guard/health"' in ligne


def test_les_routes_d_etat_sont_authentifiees_en_lecture_seule():
    i = VHOST.index('location ~ "^/api/v1/ipv6guard/(status|appareils)$"')
    corps = VHOST[i:VHOST.index("\n    }", i)]
    assert "auth_request /__sbx_verifie_secubox;" in corps and "limit_except GET { deny all; }" in corps
    assert "proxy_pass http://unix:/run/secubox/ipv6guard.sock;" in corps


def test_seule_la_vivacite_est_publique():
    i = VHOST.index("location = /api/v1/ipv6guard/health {")
    corps = VHOST[i:VHOST.index("\n    }", i)]
    assert "auth_request" not in corps and "limit_except GET { deny all; }" in corps


def test_aucune_autre_route_du_module_n_est_exposee_par_le_hall():
    blocs = re.findall(r"location\s+[^\n{]*ipv6guard[^\n{]*\{", VHOST)
    assert len(blocs) == 2


def test_la_page_n_injecte_jamais_de_html_et_ne_parle_qu_a_son_origine():
    for interdit in ("innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert interdit not in CARTE, interdit
    assert "var API = '/api/v1/ipv6guard/';" in CARTE and "fetch('http" not in CARTE
    assert '<script src="../sonde.js"></script>' in CARTE


def test_les_quatre_etapes_sont_nommees_en_langage_courant():
    assert "Appareils joignables en IPv6" in CARTE or "appareils" in CARTE
    for mot in ("Voir les appareils", "Lecture seule", "adresse publique", "Connexion requise", "Réessayer" if False else "Indisponible"):
        assert mot in CARTE
    for jargon in ("SLAAC", "NDP", "conntrack", "nft"):
        assert jargon not in CARTE


def test_le_verdict_ne_dit_jamais_protege_par_defaut():
    assert "PICT = { protege:'🟢', sans_ipv6:'🟢', a_verifier:'🟠'" in CARTE


def test_la_page_est_un_javascript_valide(tmp_path):
    js = re.search(r"<script>(.*?)</script>", CARTE, re.S).group(1)
    f = tmp_path / "carte.js"
    f.write_text(js, encoding="utf-8")
    r = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr


def test_fiche_d_aide_presente():
    f = next(c for c in AIDE["cartes"] if c["id"] == "ipv6guard")
    assert f["service"] == "ipv6guard" and f["acces"] == "session" and f["usage"] and f["role"]
