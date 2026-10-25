# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3150 — vhost boutique.<domaine> : joker, surface d'API réduite, encadrable par le Hall ; entrée du Hall."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
VHOST = (RACINE / "secubox-appstore" / "nginx" / "boutique.vhost.conf").read_text(encoding="utf-8")
HALL = (RACINE / "secubox-webos" / "www" / "hall" / "index.html").read_text(encoding="utf-8")
POSTINST = (RACINE / "secubox-appstore" / "debian" / "postinst").read_text(encoding="utf-8")


def test_vhost_joker_sans_nom_de_box_et_en_9080():
    assert "server_name boutique.*;" in VHOST and "listen 9080;" in VHOST
    assert not re.search(r"gk\d", VHOST.replace("# ", "")), "aucun nom propre à une box n'est livré"


def test_api_limitee_aux_lectures_du_catalogue_et_a_l_installation():
    routes = re.findall(r"location ~ (\S+)", VHOST)
    assert len(routes) == 2
    assert "(catalog|groupes|jobs)$" in routes[0] and routes[1].endswith("/action/install$")
    assert "autoindex" not in VHOST and "alias" not in VHOST
    assert not any(x in " ".join(routes) for x in ("config", "remote", "demandes"))
    assert "location / { return 404; }" in VHOST          # tout le reste, dont l'administration : introuvable


def test_vhost_sert_les_deux_fichiers_de_donnees_a_la_racine():
    assert "location = /boutique-fiches.json" in VHOST and "location = /boutique-besoins.json" in VHOST
    assert "try_files /boutique-besoins.json =404" in VHOST


def test_encadrable_par_le_hall_de_la_box():
    assert "frame-ancestors 'self' $sbx_boutique_hall $sbx_halls_parc" in VHOST
    assert "hall.$sbx_boutique_dom" in VHOST


def test_postinst_pose_vhost_route_waf_et_haproxy_apres_nginx_t():
    i = POSTINST.index("boutique.conf")
    assert POSTINST.index("nginx -t", i) < POSTINST.index("secubox-waf-route") < POSTINST.index("haproxyctl vhost add")
    assert "sbxwaf_inspector" in POSTINST                 # jamais de contournement du WAF


def test_hall_a_une_entree_boutique_et_l_admin_reste_sous_appstore():
    m = re.search(r'\{id:"boutique"[^}]*\}', HALL)
    assert m and 'url:"boutique.gk2.secubox.in"' in m.group(0) and 'admin:"/appstore/"' in m.group(0)
