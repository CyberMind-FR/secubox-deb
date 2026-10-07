# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Métriques des issues de DevWatch (#1585)."""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import issues  # noqa: E402

MAINTENANT = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
BRUT = {
    "open_total": 3, "closed_total": 10, "closed_30d": 4,
    "open": [
        {"n": 1585, "titre": "DevWatch", "labels": ["enhancement"], "cree": "2026-09-28T10:00:00Z"},
        {"n": 1216, "titre": "SBXOS", "labels": ["wip"], "cree": "2026-08-01T10:00:00Z"},
        {"n": 900, "titre": "Vieux", "labels": [], "cree": "2026-06-01T10:00:00Z"},
    ],
    "closed": [
        {"n": 1, "titre": "a", "labels": [], "cree": "2026-09-01T00:00:00Z", "ferme": "2026-09-01T06:00:00Z"},
        {"n": 2, "titre": "b", "labels": [], "cree": "2026-09-01T00:00:00Z", "ferme": "2026-09-03T00:00:00Z"},
    ],
}


def test_branches_de_travail():
    refs = ["refs/heads/feature/1585-devwatch", "refs/heads/fix/1027-x", "refs/heads/master",
            "refs/heads/sauvegarde/1-x", "refs/pull/12/head"]
    assert issues.numeros_des_branches(refs) == {1585, 1027}


def test_rapport_compteurs_et_en_cours():
    r = issues.rapport(BRUT, {1585}, MAINTENANT)
    c = r["compte"]
    assert (c["ouvertes"], c["fermees"], c["total"], c["fermees_30j"]) == (3, 10, 13, 4)
    # branche vivante (1585) OU étiquette wip (1216) ; 900 n'est qu'ouverte
    assert [i["n"] for i in r["listes"]["en_cours"]] == [1585, 1216]
    assert c["en_cours"] == 2 and c["ouvertes_7j"] == 1
    assert r["delai_median_heures"] == 27.0          # médiane de 6 h et 48 h
    assert r["par_etiquette"]["(sans étiquette)"] == 1
    assert r["plus_ancienne_jours"] == 119


def test_sans_donnees():
    assert issues.rapport(None, set()) == {"ok": False}
