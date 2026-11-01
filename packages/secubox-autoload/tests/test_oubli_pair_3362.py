# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3362 : un pair oublié du maillage perd son abonnement (abonnements_maillage), et la projection droits-maillage.json est republiée."""
import json

import pytest

from autoload import jetons as J

from test_droits_maillage_3305 import _ctl  # noqa: F401 (chargeur d'autoloadctl)

T0 = 1_800_000_000


@pytest.fixture
def reg(tmp_path):
    return J.Registre(tmp_path / "j.db", tmp_path / "audit.log", horloge=lambda: float(T0))


def test_oublier_maillage_retire_la_seule_ligne_du_pair(reg, tmp_path):
    reg.fixer_maillage("lgm-ebin", "atelier")
    reg.fixer_maillage("gk4", "atelier")
    assert reg.oublier_maillage("lgm-ebin") is True
    assert [p["nom"] for p in reg.droits_maillage()["pairs"]] == ["gk4"]
    assert reg.oublier_maillage("lgm-ebin") is False                       # idempotent : déjà parti
    assert "maillage-oubli" in (tmp_path / "audit.log").read_text()


def test_oublier_maillage_refuse_un_nom_invalide(reg):
    for nom in ("", "GK;rm", "../x", "a" * 40):
        with pytest.raises(ValueError):
            reg.oublier_maillage(nom)


def test_ctl_maillage_oublier_republie_les_droits(tmp_path, monkeypatch):
    var = tmp_path / "var"
    var.mkdir(mode=0o750)
    monkeypatch.setenv("SECUBOX_AUTOLOAD_DB", str(var / "jetons.db"))
    monkeypatch.setenv("SECUBOX_AUTOLOAD_AUDIT", str(tmp_path / "audit.log"))
    ctl = _ctl()
    assert ctl.main(["maillage", "--nom", "lgm-ebin", "--formule", "atelier"]) == 0
    assert ctl.main(["maillage", "--nom", "gk4", "--formule", "atelier"]) == 0
    assert ctl.main(["maillage-oublier", "--nom", "lgm-ebin"]) == 0
    doc = json.loads((tmp_path / "autoload-public" / "droits-maillage.json").read_text())
    assert [p["nom"] for p in doc["pairs"]] == ["gk4"]
    assert ctl.main(["maillage-oublier", "--nom", "lgm-ebin"]) == 0        # absent : succès, rien à faire
    assert ctl.main(["maillage-oublier", "--nom", "GK;rm"]) == 2
