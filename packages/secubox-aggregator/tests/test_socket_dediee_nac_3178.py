# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3178 — nac tournait deux fois : monté ici ET dans secubox-nac.service. Deux collecteurs écrivaient la même base, et la page NAC lisait
l'instantané en mémoire de l'agrégateur (« 0 connecté » sur gk2 pendant que la Vigie voyait 13 appareils). nac passe à socket dédiée."""
import importlib
from pathlib import Path

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"


def test_nac_n_est_plus_monte(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "nac", "soc"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert "nac" in ag.DEDICATED_MODULES and not ag.DEDICATED_MODULES & ag.RETIRED_MODULES
    assert ag._load_config()["modules"] == ["hub", "soc"]


def test_le_script_de_migration_l_exclut_aussi():
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "nac" in ligne.split("=", 1)[1].strip('"').split()
