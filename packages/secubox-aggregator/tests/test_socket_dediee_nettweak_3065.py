# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3065 — `nettweak` est à socket dédiée : jamais monté dans l'agrégateur (utilisateur `secubox`).

Son service root (`/run/secubox/nettweak.sock`) écrit `/proc/sys` ; monté en processus, `sysctl -w` s'exécutait sans
privilège : « sysctl: permission denied on key … » pour les 16 clés, à chaque profil appliqué. Même défaut qu'`exposure`
(#3013) : l'agrégateur le relaie à sa socket."""
import importlib
from pathlib import Path

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"


def test_nettweak_cite_dans_le_toml_n_est_pas_monte(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "nettweak", "exposure", "waf"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert ag._load_config()["modules"] == ["hub", "waf"]


def test_nettweak_est_dans_la_liste_des_sockets_dediees():
    assert "nettweak" in ag.DEDICATED_MODULES
    assert not ag.DEDICATED_MODULES & ag.RETIRED_MODULES


def test_le_script_de_migration_l_exclut_aussi():
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "nettweak" in ligne
