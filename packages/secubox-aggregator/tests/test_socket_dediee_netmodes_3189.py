# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — `netmodes` est à socket dédiée : il appelle `netmodesctl` par sudo, impossible sous l'utilisateur `secubox`
de l'agrégateur (pas de sudo). Le relais transparent l'atteint sur /run/secubox/netmodes.sock."""
import importlib
from pathlib import Path

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"


def test_netmodes_est_a_socket_dediee_et_pas_retire():
    assert "netmodes" in ag.DEDICATED_MODULES
    assert "netmodes" not in ag.RETIRED_MODULES


def test_netmodes_cite_dans_le_toml_n_est_pas_monte(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "netmodes", "waf"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert ag._load_config()["modules"] == ["hub", "waf"]


def test_le_script_de_migration_l_exclut_aussi():
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "netmodes" in ligne.split('"')[1].split()
