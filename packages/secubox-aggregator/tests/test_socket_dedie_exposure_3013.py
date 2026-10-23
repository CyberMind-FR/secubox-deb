# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3013 — un module à socket dédiée n'est JAMAIS monté en processus, même s'il figure dans aggregator.toml.

`exposure` écrit /etc/nginx et torrc et recharge nginx/tor : son paquet livre un service root sur
/run/secubox/exposure.sock. Monté dans l'agrégateur (secubox, ProtectSystem=full), il rendait 500
(PermissionError, Read-only file system). Comme `lyrion` (#763), il reste hors de l'agrégateur, qui
le relaie à sa socket.
"""
import importlib
from pathlib import Path

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"


def test_un_module_a_socket_dediee_cite_dans_le_toml_n_est_pas_monte(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "exposure", "lyrion", "waf"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert ag._load_config()["modules"] == ["hub", "waf"]


def test_la_liste_des_sockets_dediees_est_celle_du_relais():
    assert {"lyrion", "exposure"} <= ag.DEDICATED_MODULES   # nettweak les a rejoints (#3065)
    assert not ag.DEDICATED_MODULES & ag.RETIRED_MODULES


def test_le_script_de_migration_les_exclut_aussi():
    texte = MIGRATE.read_text(encoding="utf-8")
    ligne = [x for x in texte.splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "lyrion" in ligne and "exposure" in ligne
