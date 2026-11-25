# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3921 tâche 3 — différence entre deux graphes du paysage."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_datascope.difference import difference  # noqa: E402


def _g(**pops):
    """pops : nom -> dict de métriques (ou None pour un nœud sans métriques)."""
    return {"noeuds": [{"id": f"pop:{k}", "type": "population", "libelle": k, "metriques": v}
                       for k, v in pops.items()], "aretes": []}


def _hausses(d):
    return {(h["id"], h["metrique"], h["de"], h["a"]) for h in d["hausses"]}


def test_difference_apparus_disparus_seuil():
    avant = _g(a={"adresses": 100}, b={"adresses": 100}, c={"adresses": 5}, d={"adresses": 5}, vieux={"adresses": 1})
    apres = _g(a={"adresses": 115}, b={"adresses": 130}, c={"adresses": 16}, d={"adresses": 14},
               neuf={"adresses": 3})
    r = difference(avant, apres)
    assert r["apparus"] == ["pop:neuf"] and r["disparus"] == ["pop:vieux"]
    assert _hausses(r) == {("pop:b", "adresses", 100, 130), ("pop:c", "adresses", 5, 16)}
    assert r["baisses"] == []


def test_difference_baisses_et_metriques():
    avant = _g(a={"adresses": 130, "bans": 50, "reseaux": 20})
    apres = _g(a={"adresses": 100, "bans": 10, "reseaux": 22})
    r = difference(avant, apres)
    assert {(h["metrique"], h["de"], h["a"]) for h in r["baisses"]} == {("adresses", 130, 100), ("bans", 50, 10)}
    assert r["hausses"] == []


def test_difference_sans_avant():
    apres = _g(a={"adresses": 1}, b={"adresses": 2})
    r = difference(None, apres)
    assert r["apparus"] == ["pop:a", "pop:b"]
    assert r["disparus"] == [] and r["hausses"] == [] and r["baisses"] == []
    assert r["rotation_levee"] == [] and r["rotation_tombee"] == []


def test_difference_rotation():
    avant = _g(a={"rotation": False}, b={"rotation": True}, c={"rotation": False})
    apres = _g(a={"rotation": True}, b={"rotation": False}, c={"rotation": False})
    r = difference(avant, apres)
    assert r["rotation_levee"] == ["pop:a"] and r["rotation_tombee"] == ["pop:b"]


def test_difference_tolere_metriques_manquantes():
    avant = {"noeuds": [{"id": "pop:a", "type": "population"}, {"id": "pop:b", "type": "population",
                                                                  "metriques": {"adresses": "x", "bans": None}},
                        {"id": "pop:c", "type": "population", "metriques": {"adresses": 100}}], "aretes": []}
    apres = {"noeuds": [{"id": "pop:a", "type": "population", "metriques": {"adresses": 500}},
                        {"id": "pop:b", "type": "population", "metriques": {"adresses": 500}},
                        {"id": "pop:c", "type": "population"}, {"type": "population"}, "n'importe quoi"]}
    r = difference(avant, apres)
    assert r["hausses"] == [] and r["baisses"] == []
    assert difference({}, {}) == {"apparus": [], "disparus": [], "hausses": [], "baisses": [],
                                  "rotation_levee": [], "rotation_tombee": []}
