# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2903 — « Services connectes » lit l'etat du CONTENEUR, pas une unite systemd.

Constat gk2 : email « arrete » alors que mail tourne ; jellyfin et peertube « en marche »
alors que leurs conteneurs sont arretes. Un conteneur « a la demande » endormi se lit
« en veille » : il est disponible au reveil."""
import os
from pathlib import Path

import pytest

import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[5] / "secubox.conf.example"]

main = pytest.importorskip("api.main")


@pytest.fixture
def monde(tmp_path, monkeypatch):
    cg, mods = tmp_path / "cgroup", tmp_path / "modules.d"
    cg.mkdir(); mods.mkdir()
    monkeypatch.setattr(main, "CGROUP_DIR", cg)
    monkeypatch.setattr(main, "MODULES_DIR", mods)

    def pose(conteneur, tourne, cycle=None):
        if tourne:
            (cg / f"lxc.payload.{conteneur}").mkdir()
        if cycle:
            (mods / f"{conteneur}.toml").write_text(f'lifecycle = "{cycle}"\n')
    return pose


def test_conteneur_qui_tourne_est_en_marche(monde):
    monde("mail", True, "always-on")
    assert main.etat_service("email") == "en marche"          # email = conteneur mail


def test_conteneur_arrete_a_la_demande_est_en_veille(monde):
    monde("nextcloud", False, "on-demand")
    assert main.etat_service("nextcloud") == "en veille"


def test_conteneur_arrete_sans_reveil_est_arrete(monde):
    monde("jellyfin", False, "always-on")
    assert main.etat_service("jellyfin") == "arrêté"
    assert main.etat_service("peertube") == "arrêté"          # aucun fichier de cycle de vie


def test_l_unite_systemd_ne_decide_plus(monde, monkeypatch):
    monde("jellyfin", False, "always-on")
    monkeypatch.setattr(main, "check_service", lambda n: True)  # l'unite API tourne : sans effet
    assert main.etat_service("jellyfin") == "arrêté"


def test_la_route_services_expose_running_et_etat(monde):
    import asyncio
    monde("mail", True, "always-on"); monde("nextcloud", False, "on-demand")
    out = asyncio.run(main.list_services())["services"]
    assert out["email"]["running"] is True and out["email"]["etat"] == "en marche"
    assert out["nextcloud"]["running"] is False and out["nextcloud"]["etat"] == "en veille"
