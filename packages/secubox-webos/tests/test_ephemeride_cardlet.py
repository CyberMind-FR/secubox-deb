# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Cardlet « Éphéméride » du Hall : entrée déclarée, route unique et honnête, page sûre (pas d'injection), trois niveaux."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")
CARTE = (PKG / "www" / "hall" / "cardlets" / "ephemeride.html").read_text(encoding="utf-8")


def test_le_hall_declare_la_carte_ephemeride():
    m = re.search(r'\{id:"ephemeride"[^\n]*\}', HALL)
    assert m, "entrée FEATURED absente"
    ligne = m.group(0)
    assert 'carte:"/cardlets/ephemeride.html"' in ligne and "auth:true" in ligne and "admin:false" in ligne


def test_une_seule_route_vers_la_socket_du_module():
    blocs = re.findall(r"location\s+[^\n{]*?/api/v1/ephemeride[^\n{]*\{", VHOST)
    assert blocs == ["location ^~ /api/v1/ephemeride/ {"]
    i = VHOST.index("location ^~ /api/v1/ephemeride/ {")
    corps = VHOST[i:VHOST.index("}", i)]
    assert "proxy_pass http://unix:/run/secubox/ephemeride.sock:/;" in corps
    assert "X-SecuBox-LAN" in corps and "$lan_client" in corps


def test_la_page_n_injecte_jamais_de_html():
    assert "innerHTML" not in CARTE and "insertAdjacentHTML" not in CARTE and "document.write" not in CARTE
    assert "eval(" not in CARTE and "new Function" not in CARTE


def test_la_page_ne_parle_qu_a_son_origine():
    assert "http://" not in CARTE.replace("http://www.w3.org", "") and "https://" not in CARTE
    assert "API = '/api/v1/ephemeride/'" in CARTE


def test_un_composant_trois_niveaux():
    for n in ("compact", "standard", "etendu"):
        assert f'"{n}"' in CARTE or f"'{n}'" in CARTE
    assert CARTE.count("data-niveau") >= 3 and "n-etendu" in CARTE and "n-standard" in CARTE


def test_accessibilite_de_base():
    assert 'role="region"' in CARTE and 'aria-label="Éphéméride"' in CARTE
    assert 'role="img"' in CARTE and 'aria-label="Lune"' in CARTE and "aria-expanded" in CARTE
    assert "min-height:44px" in CARTE                                # zones tactiles
    assert "prefers-reduced-motion" in CARTE and "focus-visible" in CARTE


def test_l_horloge_utilise_le_fuseau_du_serveur_pas_celui_du_navigateur():
    assert "timeZone: D.fuseau.nom" in CARTE and "serveur_epoch_ms" in CARTE


def test_la_carte_dit_quand_elle_est_absente_ou_hors_ligne():
    assert "non installée" in CARTE and "Hors ligne" in CARTE and "Météo indisponible" in CARTE
    assert "dernière mise à jour" in CARTE


def test_la_carte_tient_dans_la_hauteur_du_hall_soleil_et_lune_cote_a_cote():
    """Densité (#2050) : la carte du Hall fait 430 px ; au-delà de 360 px de large, soleil et Lune partagent une ligne."""
    assert "@container (min-width:360px)" in CARTE and "container-type:inline-size" in CARTE
    assert 'class="duo"' in CARTE and "grid-template-columns:1fr 1fr" in CARTE
    m = re.search(r'\{id:"ephemeride"[^\n]*h:(\d+)', HALL)
    assert m and int(m.group(1)) <= 430
