# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Carte « Voix » du Hall (#1917) : relais limité à /usager/, CSP du blob audio, carte honnête, entrée déclarée."""
import json
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")
CARTE = (PKG / "www" / "hall" / "cardlets" / "voicestudio.html").read_text(encoding="utf-8")


def bloc(debut: str) -> str:
    """Le corps du `location` commençant par `debut` (accolades équilibrées)."""
    i = VHOST.index(debut)
    j = VHOST.index("{", i)
    n, k = 1, j + 1
    while n:
        n += {"{": 1, "}": -1}.get(VHOST[k], 0)
        k += 1
    return VHOST[j:k]


def test_le_hall_ne_relaie_que_le_prefixe_usager_du_module():
    """Le Hall n'inclut pas secubox-routes.d : seules les routes d'USAGER sont joignables à son origine."""
    relais = re.findall(r"location\s+[^\n{]*?/api/v1/voicestudio[^\n{]*\{", VHOST)
    assert len(relais) == 1 and "^~ /api/v1/voicestudio/usager/" in relais[0], relais
    corps = bloc("location ^~ /api/v1/voicestudio/usager/")
    assert "proxy_pass http://unix:/run/secubox/voicestudio.sock:/usager/;" in corps
    assert "client_max_body_size 12m;" in corps and "proxy_read_timeout 180s;" in corps
    assert "X-SecuBox-LAN" in corps                      # le verdict LAN du Hall, comme les autres relais


def test_aucune_route_d_administration_n_est_exposee_par_le_hall():
    for interdit in ("/detail", "/cle", "/journal", "/start", "/stop", "/restart", "/config", "/publier",
                     "/installer", "/sauvegarde", "/essai", "/voix"):
        assert f"/api/v1/voicestudio{interdit}" not in VHOST, interdit
    assert "voicestudio.sock:/;" not in VHOST            # jamais la racine du module


def test_la_csp_de_la_carte_autorise_le_blob_audio_et_rien_d_etranger():
    csp = re.search(r'location = /cardlets/voicestudio\.html \{.*?Content-Security-Policy "([^"]+)"', VHOST, re.S).group(1)
    assert "media-src 'self' blob:" in csp and "connect-src 'self'" in csp
    assert "frame-ancestors 'self'" in csp
    assert "http" not in csp and "*" not in csp         # aucune origine tierce
    assert VHOST.index("location = /cardlets/voicestudio.html") < VHOST.index("location /cardlets/ {")   # AVANT la CSP générique


def test_la_carte_est_declaree_dans_le_hall_avec_les_bons_drapeaux():
    m = re.search(r'\{id:"voicestudio",[^\n]*\}', HALL)
    assert m, "entrée FEATURED absente"
    e = m.group(0)
    assert 'carte:"/cardlets/voicestudio.html"' in e
    assert "auth:true" in e                              # une carte d'invité serait une carte vide
    assert "micro_audio:true" in e                       # dictée : micro délégué à CETTE carte
    assert 'admin:"/voicestudio/"' in e                  # la console d'administration par ⚙️
    assert "url:" not in e                               # carte locale : pas de vhost


def test_la_carte_a_son_aide():
    d = json.loads((PKG / "api" / "aide_cartes.json").read_text(encoding="utf-8"))
    [c] = [c for c in d["cartes"] if c["id"] == "voicestudio"]
    assert c["acces"] == "session" and len(c["role"]) > 30 and c["usage"]


def test_la_carte_ne_parle_qu_a_l_api_d_usager_de_son_origine():
    appels = set(re.findall(r"api\('(/[a-z]+)'", CARTE))
    assert appels == {"/etat", "/dire", "/transcrire"}, appels
    assert "var API = '/api/v1/voicestudio/usager';" in CARTE
    assert not re.search(r"https?://", re.sub(r"<!--.*?-->", "", CARTE, flags=re.S))
    for admin in ("/detail", "/cle", "/journal", "/start", "/stop", "/config"):
        assert f"'{admin}" not in CARTE, admin


def test_la_carte_n_a_aucun_champ_mot_de_passe_ni_ecoute_spontanee():
    assert 'type="password"' not in CARTE and "type=password" not in CARTE
    assert "autoplay" not in CARTE and "autofocus" not in CARTE
    # le micro n'est demandé qu'à un clic : getUserMedia n'est appelé que depuis micro(), lui-même lié à un clic
    assert CARTE.count("getUserMedia") == 1
    assert "$('b-mic').addEventListener('click', micro)" in CARTE


def test_la_carte_distingue_absent_indisponible_et_non_connecte():
    """§ 6.4 : trois états, jamais un blanc muet. 502 = socket du module absente = pas installé sur cette box."""
    assert "n'est pas installé sur cette box" in CARTE
    assert "r.status === 502" in CARTE and "r.status === 503" in CARTE and "r.status === 401" in CARTE
    assert "Réservé aux personnes connectées" in CARTE


def test_la_carte_suit_le_theme_du_hall_et_ne_depend_pas_de_load():
    assert 'data-theme="dark"' in CARTE and 'prefers-color-scheme: dark' in CARTE
    assert '<script src="../sonde.js"></script>' in CARTE      # le contrat de la sonde du Hall (annonce, thème)


def test_la_carte_ne_nettoie_pas_ses_urls_audio_a_la_legere():
    assert CARTE.count("revokeObjectURL") == 1 and "createObjectURL" in CARTE
