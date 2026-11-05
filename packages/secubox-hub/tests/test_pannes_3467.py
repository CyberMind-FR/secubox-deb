# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3467 : le tableau de bord compte les pannes comme la page Santé."""
import re
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "api/main.py").read_text(encoding="utf-8")
_m = re.search(r"def modules_en_panne.*?(?=\n\n\n)", SRC, re.S)
_ns = {}
exec("from __future__ import annotations\n" + _m.group(0), _ns)
pannes = _ns["modules_en_panne"]
STATUTS = {"a": {"active": False}, "b": {"active": False}, "c": {"active": True}, "d": {"active": False}}


def test_repos_et_absents_ne_sont_pas_des_pannes():
    lot = {"a": {"status": "ok", "veille": True}, "c": {"status": "ok"}, "d": {"status": "error"}}
    assert pannes(STATUTS, lot) == ["d"]


def test_sans_releve_l_etat_brut():
    assert pannes(STATUTS, None) == ["a", "b", "d"]
