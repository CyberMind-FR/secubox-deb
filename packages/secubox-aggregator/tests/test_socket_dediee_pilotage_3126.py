# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 — pilotage tient ses files en mémoire et sert deux sockets dans UN processus : monté dans l'agrégateur il y serait en double
(deux files, deux boucles de relève). Il passe à socket dédiée, comme nac et netmodes."""
import importlib
from pathlib import Path

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"


def test_pilotage_n_est_pas_monte(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "pilotage", "soc"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert "pilotage" in ag.DEDICATED_MODULES and not ag.DEDICATED_MODULES & ag.RETIRED_MODULES
    assert ag._load_config()["modules"] == ["hub", "soc"]


def test_le_script_de_migration_l_exclut_aussi():
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "pilotage" in ligne.split("=", 1)[1].strip('"').split()
