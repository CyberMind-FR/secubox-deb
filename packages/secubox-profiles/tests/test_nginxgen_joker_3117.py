# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3117 : le réveil retrouve les vhosts livrés en joker générique `<x>.*`."""
from __future__ import annotations

from api import nginxgen
from api.manifest import Manifest

DOM = "peertube.gk2.secubox.in"


def _vhost(noms):
    return (f"server {{\n    listen 0.0.0.0:9080;\n    server_name {noms};\n"
            f"    location / {{\n        proxy_pass http://10.100.0.120:9000/;\n    }}\n}}\n")


def test_nom_exact_trouve(tmp_path):
    (tmp_path / "a.conf").write_text(_vhost(DOM))
    assert nginxgen.find_config(DOM, tmp_path).name == "a.conf"


def test_joker_seul_trouve(tmp_path):
    (tmp_path / "peertube.conf").write_text(_vhost("peertube.*"))
    assert nginxgen.find_config(DOM, tmp_path).name == "peertube.conf"


def test_le_nom_exact_l_emporte_sur_le_joker_meme_dans_un_fichier_trie_apres(tmp_path):
    (tmp_path / "a-joker.conf").write_text(_vhost("peertube.*"))
    (tmp_path / "z-exact.conf").write_text(_vhost(DOM))
    assert nginxgen.find_config(DOM, tmp_path).name == "z-exact.conf"


def test_aucune_correspondance(tmp_path):
    (tmp_path / "radio.conf").write_text(_vhost("radio.*"))
    assert nginxgen.find_config(DOM, tmp_path) is None


def test_un_autre_label_ne_correspond_pas(tmp_path):
    # Ni un autre label, ni un label qui le prolonge, ni un joker de tête.
    (tmp_path / "x.conf").write_text(_vhost("peertubex.* tube.* *.gk2.secubox.in"))
    assert nginxgen.find_config(DOM, tmp_path) is None
    (tmp_path / "y.conf").write_text(_vhost("peertube.*"))
    assert nginxgen.find_config("peertube", tmp_path) is None   # domaine sans point : pas de joker


def test_wire_cable_le_bloc_du_joker(tmp_path):
    p = tmp_path / "multi.conf"
    p.write_text(_vhost("radio.*") + _vhost("peertube.*"))
    assert nginxgen.wire(p, DOM) is True
    lignes = p.read_text().splitlines()
    i = lignes.index("    server_name peertube.*;")
    assert nginxgen.MARKER in lignes[i + 1]
    j = lignes.index("    server_name radio.*;")
    assert nginxgen.MARKER not in lignes[j + 1]
    assert nginxgen.wire(p, DOM) is False                       # idempotent


def test_wire_prefere_la_ligne_exacte(tmp_path):
    p = tmp_path / "v.conf"
    p.write_text(_vhost("peertube.*") + _vhost(DOM))
    assert nginxgen.wire(p, DOM) is True
    lignes = p.read_text().splitlines()
    assert nginxgen.MARKER in lignes[lignes.index(f"    server_name {DOM};") + 1]
    assert nginxgen.MARKER not in lignes[lignes.index("    server_name peertube.*;") + 1]


def test_sync_cable_un_vhost_generique(tmp_path):
    (tmp_path / "peertube.conf").write_text(_vhost("peertube.*"))
    m = Manifest(id="peertube", category="media", runtime="lxc", exposure="public",
                 units=("peertube.service",), portal_domain=DOM, lifecycle="on-demand")
    calls = []
    r = nginxgen.sync_and_reload(manifests={"peertube": m}, sites_dir=tmp_path,
                                 run=lambda argv: (calls.append(argv), (0, ""))[1])
    assert r["wired"] == [DOM] and r["no_config"] == [] and r["reloaded"] is True
