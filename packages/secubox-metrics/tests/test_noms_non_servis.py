# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.
"""Tests des noms demandés non servis dans le rapport (#1219)."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# rapport.py trace des graphiques : sans matplotlib le module est inimportable.
# On saute plutôt que de tester une version amputée qui donnerait une fausse
# assurance (la boîte, elle, a la dépendance : elle est dans debian/control).
pytest.importorskip("matplotlib")
pytest.importorskip("fpdf")

from api.rapport import _lire_waf_stats, _noms_non_servis  # noqa: E402


def test_ordonne_du_plus_frequent(tmp_path):
    c = {"noms_non_routes": {"a.example": 5, "b.example": 90, "c.example": 40}}
    noms, distincts, total = _noms_non_servis(c)
    assert [n for n, _ in noms] == ["b.example", "c.example", "a.example"]
    assert distincts == 3 and total == 135


def test_limite_mais_totaux_complets(tmp_path):
    """La liste est tronquée, les totaux ne le sont pas : un décompte partiel
    présenté comme un total serait trompeur."""
    c = {"noms_non_routes": {f"n{i}.example": i for i in range(1, 51)}}
    noms, distincts, total = _noms_non_servis(c, limite=10)
    assert len(noms) == 10
    assert distincts == 50
    assert total == sum(range(1, 51))


def test_absence_de_cle(tmp_path):
    assert _noms_non_servis({}) == ([], 0, 0)


def test_type_inattendu(tmp_path):
    assert _noms_non_servis({"noms_non_routes": "pas un dict"}) == ([], 0, 0)


def test_lecture_fichier(tmp_path):
    f = tmp_path / "stats.json"
    f.write_text(json.dumps({"counters": {"noms_non_routes": {"x.example": 3}}}))
    assert _lire_waf_stats(f)["noms_non_routes"] == {"x.example": 3}


def test_fichier_absent_est_silencieux(tmp_path):
    """Le rapport doit partir même sans WAF installé."""
    assert _lire_waf_stats(tmp_path / "nulle-part.json") == {}


def test_json_casse_est_silencieux(tmp_path):
    f = tmp_path / "casse.json"
    f.write_text("{ pas du json")
    assert _lire_waf_stats(f) == {}
