# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3254 — `system` est à socket dédiée : ses actions (kiosque, redémarrages d'unités) passent par polkit, qui ne les
accorde qu'à `secubox-system.service`. Monté ici, l'appel venait de `secubox-aggregator.service` et systemd répondait
« Interactive authentication required » (gk2, désactivation du kiosque)."""
import importlib
from pathlib import Path

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"
POLKIT = Path(__file__).resolve().parents[2] / "secubox-system" / "polkit" / "50-secubox-system.rules"


def test_system_est_a_socket_dediee_et_pas_retire():
    assert "system" in ag.DEDICATED_MODULES
    assert "system" not in ag.RETIRED_MODULES


def test_la_regle_polkit_ne_vaut_que_pour_le_service_system():
    # La correction passe par le relais, jamais par un élargissement de polkit à l'agrégateur (une centaine de modules).
    regle = POLKIT.read_text(encoding="utf-8")
    assert 'subject.system_unit !== "secubox-system.service"' in regle
    assert "secubox-aggregator" not in regle


def test_system_cite_dans_le_toml_n_est_pas_monte(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "system", "waf"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert ag._load_config()["modules"] == ["hub", "waf"]


def test_le_script_de_migration_l_exclut_aussi():
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "system" in ligne.split('"')[1].split()
