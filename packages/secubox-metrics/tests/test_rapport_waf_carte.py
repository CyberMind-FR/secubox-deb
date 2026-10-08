# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Rapport WAF quotidien : carte du monde et vue d'ensemble des metrics dans le PDF."""
import json
import re
from pathlib import Path

import pytest

import carte_monde

pytest.importorskip("matplotlib")
pytest.importorskip("fpdf")
import rapport  # noqa: E402
import rapport_waf as rw  # noqa: E402

TABLEAU = Path(__file__).resolve().parents[2] / "secubox-waf-ng" / "composants" / "waf" / "www" / "waf" / "tableau.html"
PNG = b"\x89PNG\r\n\x1a\n"


@pytest.mark.skipif(not TABLEAU.exists(), reason="page du Hall absente de l'arbre de test")
def test_la_carte_du_pdf_est_celle_du_tableau_du_hall():
    """Une seule carte : le fond de terre et les centres de pays sont ceux de la page WAF."""
    html = TABLEAU.read_text(encoding="utf-8")
    assert re.search(r'const TERRE = "([^"]+)"', html).group(1) == carte_monde.TERRE
    brut = re.search(r"const CENTRE = \{(.*?)\};", html, re.S).group(1)
    attendu = {c: tuple(float(v) for v in xy.split(","))
               for c, xy in re.findall(r"([A-Z]{2}):\[([^\]]+)\]", brut)}
    assert carte_monde.CENTRE == attendu


def test_le_fond_de_terre_est_une_grille_de_120_colonnes():
    pts = carte_monde.points_terre()
    assert len(pts) > 1000
    assert all(0 <= x < 120 and 0 <= y < 60 for x, y in pts)


def test_les_bulles_ignorent_les_pays_inconnus_et_les_reseaux_locaux():
    b = carte_monde.bulles({"FR": 10, "US": 40, "LAN": 99, "??": 5, "ZZ": 7, "": 3})
    assert {c for c, *_ in b} == {"FR", "US"}
    assert max(r for _, _, _, r in b) > min(r for _, _, _, r in b)


def test_la_carte_se_rend_en_png_meme_sans_donnees():
    assert rw._carte_monde({"FR": 12, "RU": 30, "CN": 80})[:8] == PNG
    assert rw._carte_monde({})[:8] == PNG


def test_la_vue_d_ensemble_lit_le_cache_des_metrics(tmp_path):
    f = tmp_path / "metrics-cache.json"
    f.write_text(json.dumps({"overview": {"uptime": 93784, "load": "1.50 1.20 1.00", "cpu_pct": 12,
                                          "mem_pct": 63, "mem_total_kb": 8000000, "mem_used_kb": 5000000,
                                          "haproxy": True, "mitmproxy": False}}))
    ov = rw._lire_overview(f)
    assert ov["cpu_pct"] == 12 and ov["haproxy"] is True
    assert rw._lire_overview(tmp_path / "absent.json") == {}
    (tmp_path / "casse.json").write_text("{")
    assert rw._lire_overview(tmp_path / "casse.json") == {}


def test_les_tuiles_de_la_vue_d_ensemble_sont_lisibles():
    t = dict(rw._cases_overview({"uptime": 93784, "load": "1.50 1.20 1.00", "cpu_pct": 12, "mem_pct": 63,
                                 "mem_total_kb": 8000000, "mem_used_kb": 5000000}))
    assert t["Disponibilite"] == "1 j 2 h" and t["CPU"] == "12 %" and t["Memoire"] == "63 %" and t["Charge"] == "1.50"
    assert rw._cases_overview({}) == []


def test_le_pdf_porte_la_carte_et_la_vue_d_ensemble(monkeypatch):
    vues = []
    monkeypatch.setattr(rapport, "_lire_waf_stats", lambda *a, **k: {"top_countries": {"RU": 30, "FR": 4}})
    monkeypatch.setattr(rw, "_lire_overview", lambda *a, **k: {"uptime": 3600, "cpu_pct": 5, "mem_pct": 50, "load": "0.1 0.1 0.1"})
    vrai = rw._carte_monde
    monkeypatch.setattr(rw, "_carte_monde", lambda p: vues.append(p) or vrai(p))
    pdf = rw.construire_pdf_waf({"jours": {"2026-10-08": {"total": 5, "categories": {"scanners": 5}, "severites": {"low": 5}}},
                                 "top_ips": {"1.2.3.4": 5}, "total": 5}, 7)
    assert pdf[:5] == b"%PDF-"
    assert vues == [{"RU": 30, "FR": 4}], "la carte doit recevoir les pays vus par le WAF"


def test_aucune_ligne_de_la_carte_n_est_entierement_terre():
    """La ligne -15 degres etait pleine sur les 120 colonnes : une bande de points d'un bord a l'autre,
    en travers du Pacifique et de l'Atlantique, sur la carte du Hall comme sur celle du PDF."""
    for j, ligne in enumerate(carte_monde.TERRE.split("|")):
        assert not (ligne[0] == "1" and ligne[1:] == "120"), f"ligne {j} entierement terre"
