# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Carte Activité : une diffusion de la bibliothèque YouTube SAS (chemin relatif du Hall) est un lien cliquable ; aucun autre
chemin relatif ne l'est."""
import re
import subprocess
from pathlib import Path

CARTE = (Path(__file__).resolve().parents[1] / "www" / "hall" / "cardlets" / "activite.html").read_text(encoding="utf-8")


def _cible_js():
    deb = CARTE.index("function cible(a){")
    fin = CARTE.index("function ligne(a){")
    return CARTE[deb:fin]


def _evalue(contexte, kind="radio_live"):
    prog = ("const window={SBX_DOMAINE:null}; const BBS='bbs.gk2.secubox.in'; const location={origin:'https://hall.gk2.secubox.in'};\n"
            + _cible_js() + "\nconsole.log(JSON.stringify(cible(" + __import__("json").dumps({"kind": kind, "context": contexte}) + ")));")
    r = subprocess.run(["node", "-e", prog], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    import json
    return json.loads(r.stdout)


def test_une_diffusion_de_la_bibliotheque_ytsas_ouvre_le_viewer_sur_l_origine_du_hall():
    c = _evalue({"url": "/api/v1/ytsas/stream/134806-000-A", "titre": "A vos marmites"})
    assert c == {"sbx": "voir", "url": "https://hall.gk2.secubox.in/api/v1/ytsas/stream/134806-000-A"}


def test_une_adresse_absolue_reste_un_lien():
    c = _evalue({"url": "https://peertube.gk2.secubox.in/w/abc"})
    assert c["url"].startswith("https://peertube.gk2.secubox.in/")


def test_aucun_autre_chemin_relatif_ni_schema_douteux_n_est_un_lien():
    for mauvais in ("/api/v1/auth/login", "/api/v1/ytsas/flux?type=historique", "/api/v1/ytsas/stream/", "/api/v1/ytsas/stream/../x",
                    "javascript:alert(1)", "//evil.example/x", "/api/v1/ytsas/stream/a/b", ""):
        assert _evalue({"url": mauvais}) is None, mauvais


def test_les_fils_et_fichiers_du_bbs_gardent_leur_lien():
    assert _evalue({"lien": "/bbs/t/1129"}, kind="bbs_post")["sbx"] == "surf"
