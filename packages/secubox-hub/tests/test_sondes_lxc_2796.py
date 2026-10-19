# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2796 — YouTube SAS (conteneur LXC) et Glances (page de secubox-metrics) n'ont ni unite ni socket hote : ils s'affichaient a l'arret."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")


def test_glances_suit_le_module_metrics():
    m = {"metrics": {"status": "ok", "msg": "Running"}}
    main.superposer_montes(m, frozenset())
    assert m["glances"] == m["metrics"]


def test_ytsas_est_en_service_si_le_conteneur_ecoute():
    m = {}
    main.superposer_lxc(m, {"ytsas": ("10.100.0.180", 8091)}, lambda h, p: True, presente=lambda mid: True)
    assert m["ytsas"]["status"] == "ok" and "conteneur" in m["ytsas"]["msg"].lower()


def test_ytsas_est_une_alarme_si_le_conteneur_ne_repond_pas():
    m = {}
    main.superposer_lxc(m, {"ytsas": ("10.100.0.180", 8091)}, lambda h, p: False, presente=lambda mid: True)
    assert m["ytsas"]["status"] == "error"


def test_une_sonde_deja_presente_n_est_pas_ecrasee():
    m = {"ytsas": {"status": "warn", "msg": "x"}}
    main.superposer_lxc(m, {"ytsas": ("10.100.0.180", 8091)}, lambda h, p: True, presente=lambda mid: True)
    assert m["ytsas"]["status"] == "warn"


def test_la_sonde_reseau_tombe_a_faux_sans_lever(monkeypatch):
    assert main._tcp_ouvert("127.0.0.1", 1, 0.2) is False
