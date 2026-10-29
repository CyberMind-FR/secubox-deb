# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3126 L1 — /fleet/ : panneau « Pilotage » (GET /api/v1/pilotage/boxes), lecture seule, XSS-strict, masqué si le module est absent."""
import json
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_fleet_page_aurora_2487 import PAGE, _nav  # noqa: E402

HTML = PAGE.read_text(encoding="utf-8")


def _js():
    m = re.search(r"// ===== pilotage =====(.*?)// ===== fin pilotage =====", HTML, re.S)
    assert m, "bloc JS pilotage délimité introuvable"
    return m.group(1)


def _html():
    m = re.search(r'<div class="pan" id="pil-pan".*?<!-- fin pil-pan -->', HTML, re.S)
    assert m, "panneau pil-pan introuvable"
    return m.group(0)


def test_panneau_appelle_l_api_pilotage():
    assert "/api/v1/pilotage/boxes" in _js()
    assert "sbx_token" in HTML and "pil-pan" in HTML


def test_panneau_sans_innerhtml_pour_les_donnees():
    bloc = _js() + _html()
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\bon[a-z]+\s*=", bloc)


def test_panneau_masque_si_module_absent():
    js = _js()
    assert "r.ok" in js and ".hidden" in js and "!liste.length" in js
    assert "30000" in js and "visibilityState" in js or "document.hidden" in js


def test_aucun_bouton_d_action_dans_le_bloc_pilotage():
    bloc = _js() + _html()
    assert not re.search(r"<button|<form|<input|type=.submit|method:\s*['\"](POST|PUT|DELETE|PATCH)", bloc, re.I)
    assert not re.search(r"createElement\(['\"](button|form|input)", bloc)
    assert "'button'" not in bloc and '"button"' not in bloc


BOITES = [
    {"cle": "maillage:gk5", "nom": "gk5", "reseau": "maillage", "client": None, "adresse": "10.10.0.5", "en_ligne": True, "vu_le": 4102444800,
     "agent_version": "0.1.1", "mains_liees": True, "memoire_dispo_mo": 812, "swap_utilise_pct": 12, "cpu_pct": 3.4, "services_en_echec": 0,
     "boucles_24h": 2, "inventaire_le": 4102444800, "inventaire_partiel": False},
    {"cle": "autoload:b1", "nom": "<img src=x onerror=alert(1)>", "reseau": "autoload", "client": "lgm", "adresse": "10.64.0.7", "en_ligne": False,
     "vu_le": 1700000000, "agent_version": None, "mains_liees": None, "memoire_dispo_mo": None, "swap_utilise_pct": None, "cpu_pct": None,
     "services_en_echec": None, "boucles_24h": 0, "inventaire_le": None, "inventaire_partiel": False},
]


def _api(status=200, boites=BOITES):
    def api(r):
        if "/pilotage/boxes" in r.request.url:
            return r.fulfill(status=status, content_type="application/json", body=json.dumps(boites))
        return r.fulfill(status=200, content_type="application/json", body=json.dumps({"nodes": []}))
    return api


def test_lignes_null_tiret_hors_ligne_grise_et_texte_brut():
    def sc(pg):
        pg.wait_for_selector("#pil-body tr")
        return (pg.is_visible("#pil-pan"), pg.locator("#pil-body tr").count(), pg.inner_text("#pil-body tr:nth-child(1)"),
                pg.inner_text("#pil-body tr:nth-child(2)"), pg.get_attribute("#pil-body tr:nth-child(2)", "class"),
                pg.locator("#pil-body img").count())
    (vis, n, l1, l2, cls2, imgs), erreurs, natifs = _nav(sc, api=_api())
    assert vis and n == 2 and imgs == 0 and erreurs == [] and natifs == []
    assert "gk5" in l1 and "maillage" in l1 and "812" in l1 and "12" in l1 and "3,4" in l1 and "oui" in l1
    assert "client lgm" in l2 and "inconnu" in l2 and "vu il y a" in l2 and "non" not in l2.replace("inconnu", "")
    assert l2.count("—") >= 4 and "is-stale" in cls2
    assert "0 Mo" not in l2


@pytest.mark.parametrize("statut,corps", [(404, []), (401, []), (200, [])])
def test_panneau_masque_sur_404_401_ou_liste_vide(statut, corps):
    def sc(pg):
        return pg.is_hidden("#pil-pan")
    (cache, erreurs, natifs) = _nav(sc, api=_api(statut, corps))
    assert cache is True and erreurs == [] and natifs == []
