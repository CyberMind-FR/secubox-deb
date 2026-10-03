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
CARTE_ADMIN = (PKG / "www" / "hall" / "cardlets" / "voicestudio-admin.html").read_text(encoding="utf-8")


def bloc(debut: str) -> str:
    """Le corps du `location` commençant par `debut` (accolades équilibrées)."""
    i = VHOST.index(debut)
    j = VHOST.index("{", i)
    n, k = 1, j + 1
    while n:
        n += {"{": 1, "}": -1}.get(VHOST[k], 0)
        k += 1
    return VHOST[j:k]


def test_le_hall_ne_relaie_que_l_usager_et_l_etat_minimal_du_module():
    """Le Hall n'inclut pas secubox-routes.d : seules DEUX choses du module sont joignables à son origine."""
    relais = sorted(re.findall(r"location\s+[^\n{]*?/api/v1/voicestudio[^\n{]*\{", VHOST))
    assert len(relais) == 2, relais
    assert any("^~ /api/v1/voicestudio/usager/" in r for r in relais) and any("= /api/v1/voicestudio/status" in r for r in relais)
    corps = bloc("location ^~ /api/v1/voicestudio/usager/")
    assert "proxy_pass http://unix:/run/secubox/voicestudio.sock:/usager/;" in corps
    assert "client_max_body_size 12m;" in corps and "proxy_read_timeout 330s;" in corps
    assert "X-SecuBox-LAN" in corps                      # le verdict LAN du Hall, comme les autres relais
    etat = bloc("location = /api/v1/voicestudio/status")
    assert "proxy_pass http://unix:/run/secubox/voicestudio.sock:/status;" in etat and "X-SecuBox-LAN" in etat


def test_aucune_autre_route_d_administration_n_est_exposee_par_le_hall():
    for interdit in ("/detail", "/cle", "/journal", "/start", "/stop", "/restart", "/config", "/publier",
                     "/installer", "/sauvegarde", "/essai", "/voix", "/gate", "/health"):
        assert f"/api/v1/voicestudio{interdit}" not in VHOST, interdit
    assert "voicestudio.sock:/;" not in VHOST            # jamais la racine du module


def test_la_csp_de_la_carte_autorise_le_blob_audio_et_rien_d_etranger():
    csp = re.search(r'location = /cardlets/voicestudio\.html \{.*?Content-Security-Policy "([^"]+)"', VHOST, re.S).group(1)
    assert "media-src 'self' blob:" in csp and "connect-src 'self'" in csp
    assert "frame-ancestors 'self'" in csp
    assert "http" not in csp and "*" not in csp         # aucune origine tierce
    assert VHOST.index("location = /cardlets/voicestudio.html") < VHOST.index("location /cardlets/ {")   # AVANT la CSP générique


def entree(identifiant: str) -> str:
    m = re.search(r'\{id:"' + identifiant + r'",[^\n]*\}', HALL)
    assert m, f"entrée FEATURED « {identifiant} » absente"
    return m.group(0)


def test_les_deux_entrees_du_hall_suivent_le_motif_coffre_mon_coffre():
    adm, usager = entree("voicestudio"), entree("voix")
    # administrateur : la carte d'état, l'interface native agrandie (vhost), la console par ⚙️
    assert 'carte:"/cardlets/voicestudio-admin.html"' in adm and 'url:"voicestudio.gk2.secubox.in"' in adm
    assert 'admin:"/voicestudio/"' in adm and "auth:true" in adm and "micro_audio" not in adm
    # usager : carte locale, pas de vhost, micro délégué à elle seule, pas de ⚙️
    assert 'carte:"/cardlets/voicestudio.html"' in usager and "url:" not in usager
    assert "auth:true" in usager and "micro_audio:true" in usager and "admin:false" in usager


def test_chaque_entree_a_son_aide():
    d = json.loads((PKG / "api" / "aide_cartes.json").read_text(encoding="utf-8"))
    for ident in ("voicestudio", "voix"):
        [c] = [c for c in d["cartes"] if c["id"] == ident]
        assert c["acces"] == "session" and len(c["role"]) > 30 and c["usage"], ident


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


# ── carte d'administration ───────────────────────────────────────────────────────────────────────────────────────
def test_la_carte_d_administration_ne_lit_que_l_etat_minimal():
    assert set(re.findall(r"fetch\('(/api/v1/voicestudio/[a-z/]+)'", CARTE_ADMIN)) == {"/api/v1/voicestudio/status"}
    for interdit in ("/detail", "/cle", "/journal", "/start", "/stop", "/restart", "/config", "/usager"):
        assert f"voicestudio{interdit}" not in CARTE_ADMIN, interdit
    assert "method:" not in CARTE_ADMIN and "POST" not in CARTE_ADMIN       # lecture seule : tout geste passe par la console


def test_la_carte_d_administration_distingue_les_etats_et_dit_absent():
    assert "n'est pas installé sur cette box" in CARTE_ADMIN and "r.status === 502" in CARTE_ADMIN
    assert "Réservé aux administrateurs" in CARTE_ADMIN and "r.status === 401" in CARTE_ADMIN
    for etat in ("répond", "dort", "muet", "à installer", "injoignable"):
        assert etat in CARTE_ADMIN, etat


def test_la_carte_d_administration_ne_montre_ni_adresse_ni_cle():
    assert not re.search(r"https?://", re.sub(r"<!--.*?-->", "", CARTE_ADMIN, flags=re.S))
    for secret in ("api_key", "Bearer", "10.100.", "commit"):
        assert secret not in re.sub(r"<!--.*?-->", "", CARTE_ADMIN, flags=re.S), secret
    assert 'type="password"' not in CARTE_ADMIN


def test_la_carte_d_usager_montre_la_raison_donnee_par_le_module_pour_503_429_413():
    """« Mémoire insuffisante pour la synthèse : il faut ≈ 3,7 Go libres… » est une cause qu'un usager comprend : un message
    générique la cacherait. Le texte est inséré en textContent (jamais en HTML)."""
    assert "function avec_detail(r)" in CARTE and "d.detail.slice(0, 300)" in CARTE
    assert "return avec_detail(r).then(function(m){ note(m); return null; });" in CARTE
    assert "$('note').textContent = t" in CARTE and "innerHTML" not in CARTE
