# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2840 — /fleet/ montre aussi les box enrôlées par Auto-Load (GET /api/v1/autoload/boxes), sans dépendre de l'annuaire ; panneau masqué si le module est absent."""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sync_api = pytest.importorskip("playwright.sync_api")
from test_fleet_page_aurora_2487 import _nav  # noqa: E402

BOXES = [
    {"id": 1, "client": "lgm", "profil": "minimal", "lot": None, "serie": None, "statut": "en cours", "progression": 40, "etape": "plan", "maj_le": 1760600000},
    {"id": 2, "client": "<img src=x onerror=alert(1)>", "profil": "lite", "lot": None, "serie": None, "statut": "en attente", "progression": 0, "etape": None, "maj_le": None},
]


def _api(boxes_status=200, boxes=BOXES):
    def api(r):
        u = r.request.url
        if "/autoload/boxes" in u:
            return r.fulfill(status=boxes_status, content_type="application/json", body=json.dumps(boxes))
        return r.fulfill(status=200, content_type="application/json", body=json.dumps({"nodes": []}))
    return api


def test_les_box_autoload_sont_listees_en_texte_brut():
    def sc(pg):
        pg.wait_for_selector("#al-body tr")
        return (pg.is_visible("#al-pan"), pg.locator("#al-body tr").count(), pg.inner_text("#al-body tr:first-child"),
                pg.locator("#al-body img").count(), pg.inner_text("#al-n"))
    (visible, n, premiere, imgs, total), erreurs, natifs = _nav(sc, api=_api())
    assert visible and n == 2 and "lgm" in premiere and "minimal" in premiere and "en cours" in premiere and "40" in premiere
    assert imgs == 0 and total == "2" and erreurs == [] and natifs == []


def test_module_absent_masque_le_panneau_sans_erreur():
    def sc(pg):
        return pg.is_hidden("#al-pan")
    cache, erreurs, _ = _nav(sc, api=_api(boxes_status=404, boxes={}))
    assert cache and erreurs == []


def test_aucune_box_masque_le_panneau():
    cache, erreurs, _ = _nav(lambda pg: pg.is_hidden("#al-pan"), api=_api(boxes=[]))
    assert cache and erreurs == []
