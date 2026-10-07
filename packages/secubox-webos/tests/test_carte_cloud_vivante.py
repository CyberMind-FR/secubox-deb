# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Carte « Cloud » : un groupe de trois tranches VIVANTES (Cloud, Photos, Mail), plus un lien statique « inconnu »."""
import json
import re
import subprocess
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")
QUICK = (PKG / "www" / "hall" / "cardlets" / "quick.html").read_text(encoding="utf-8")
CUMUL = (PKG / "www" / "hall" / "cardlets" / "cumul.html").read_text(encoding="utf-8")
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
AIDE = json.loads((PKG / "api" / "aide_cartes.json").read_text(encoding="utf-8"))


def test_la_carte_cloud_est_un_groupe_et_n_apparait_que_si_nextcloud_est_la():
    ligne = re.search(r'\{id:"cloud",[^\n]*\}', HALL).group(0)
    assert 'carte:"/cardlets/cumul.html?groupe=cloud"' in ligne and "auth:true" in ligne
    assert 'si_present:"/adm/api/v1/nextcloud/status"' in ligne


def test_le_groupe_cloud_a_trois_tranches_vivantes():
    i = CUMUL.index("    cloud: {")
    corps = CUMUL[i:CUMUL.index("    forums: {")]
    for svc in ("nextcloud", "photoprism", "mail"):
        assert f"quick.html?svc={svc}" in corps
    assert "embed: true" in corps


def test_le_gabarit_connait_les_trois_services_et_leurs_chiffres():
    for svc, mod in (("nextcloud", "nextcloud"), ("photoprism", "photoprism"), ("mail", "mail")):
        assert re.search(rf"{svc}: \{{ ic:'[^']+', nom:'[^']+'", QUICK), svc
        assert f"mod:'{mod}'" in QUICK
    assert "['user_count','👥','comptes']" in QUICK and "['library_stats.total_photos','📷','photos']" in QUICK
    assert "['storage','💾','espace']" in QUICK
    assert "/sbx/entrer" in QUICK


def test_chaque_service_dit_son_etat_reel_par_sa_propre_fonction():
    assert QUICK.count("etat:function(d)") == 3
    assert "typeof c.etat === 'function'" in QUICK
    for mot in ("endormi", "non installé", "serveur et webmail en marche", "comptage en cours"):
        assert mot in QUICK


def test_les_cles_pointees_sont_lues_sans_planter_sur_un_champ_absent():
    prog = ("const d={library_stats:{total_photos:7}}; const lire=m=>m.split('.').reduce(function (o, k) { return (o === undefined || o === null) ? undefined : o[k]; }, d);"
            "console.log(JSON.stringify([lire('library_stats.total_photos'), lire('library_stats.total_videos'), lire('a.b.c')]));")
    r = subprocess.run(["node", "-e", prog], capture_output=True, text=True, timeout=20)
    assert json.loads(r.stdout) == [7, None, None]
    assert "m[0].split('.').reduce(" in QUICK


def test_sans_session_la_carte_le_dit_au_lieu_d_afficher_des_zeros():
    assert "r.status === 401 || r.status === 403" in QUICK and "connexion requise pour voir" in QUICK


def test_le_relais_de_lecture_inclut_les_trois_services_en_get_seulement():
    i = VHOST.index("location ~ ^/adm/api/v1/(droplet|torrent|ytsas|nextcloud|photoprism|mail)/status$ {")
    corps = VHOST[i:VHOST.index("\n    }", i)]
    assert "limit_except GET { deny all; }" in corps


def test_l_aide_decrit_les_trois_tranches():
    f = next(c for c in AIDE["cartes"] if c["id"] == "cloud")
    assert all(mot in f["role"] for mot in ("Cloud", "Photos", "Mail")) and f["acces"] == "session"


def test_un_service_absent_de_la_box_ne_montre_ni_zeros_ni_arrete():
    assert "d.container_status === 'not_installed'" in QUICK
    assert "return 'non installé';" in QUICK
    assert "(c.absent && c.absent(d)) ? [] : c.chiffres" in QUICK
