# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3910 : un geste de garde qui ne change rien ne régénère ni ne recharge Unbound (11-36 s sur gk2, relancé chaque minute)."""
import json

from tests.test_garde_quarantaine_evasion_3794 import TV, ctl, declarer, monde  # noqa: F401 — fixture partagée

# ruff: noqa: F811


def _appels(monde) -> str:
    j = monde["tmp"] / "appels.log"
    return j.read_text() if j.exists() else ""


def test_lever_absent_sans_rendu_ni_rechargement(monde, capsys):
    declarer(monde)
    assert ctl("evasion", "lever", "192.168.1.112") == 0
    r = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert r["ok"] is True and r.get("inchange") is True
    assert _appels(monde) == "" and not monde["conf"].exists()


def test_poser_identique_sans_rechargement(monde, capsys):
    declarer(monde)
    assert ctl("evasion", "poser", TV, "aa:bb:cc:dd:ee:01", "pubs.exemple.fr") == 0
    capsys.readouterr()
    (monde["tmp"] / "appels.log").unlink()
    assert ctl("evasion", "poser", TV, "aa:bb:cc:dd:ee:01", "pubs.exemple.fr") == 0
    r = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert r["ok"] is True and r.get("inchange") is True and _appels(monde) == ""


def test_lever_present_recharge_toujours(monde, capsys):
    declarer(monde)
    ctl("evasion", "poser", TV, "aa:bb:cc:dd:ee:01", "pubs.exemple.fr")
    capsys.readouterr()
    (monde["tmp"] / "appels.log").unlink()
    assert ctl("evasion", "lever", TV) == 0
    r = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert r["ok"] is True and not r.get("inchange") and "control" in _appels(monde)
