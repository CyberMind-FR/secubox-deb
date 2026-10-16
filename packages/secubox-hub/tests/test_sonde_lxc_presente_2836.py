# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2836 — la sonde TCP des modules en conteneur (#2796) ne juge QUE les modules installes.

Sans cela, une box sans YouTube SAS (l'ESPRESSObin minimal) affichait « ytsas : Conteneur LXC injoignable » en erreur dans la sante."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")


def test_un_module_absent_n_est_pas_sonde_ni_declare_en_erreur():
    m = {}
    sondes = []
    main.superposer_lxc(m, {"ytsas": ("10.100.0.180", 8091)}, lambda h, p: sondes.append((h, p)) or False, presente=lambda mid: False)
    assert m == {} and sondes == [], "aucune sonde reseau pour un module que la box n'a pas"


def test_un_module_present_et_injoignable_reste_une_erreur():
    m = {}
    main.superposer_lxc(m, {"ytsas": ("10.100.0.180", 8091)}, lambda h, p: False, presente=lambda mid: True)
    assert m["ytsas"]["status"] == "error"


def test_un_module_present_et_joignable_est_ok():
    m = {}
    main.superposer_lxc(m, {"ytsas": ("10.100.0.180", 8091)}, lambda h, p: True, presente=lambda mid: True)
    assert m["ytsas"]["status"] == "ok"


def test_par_defaut_la_presence_est_celle_de_la_page_du_module(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "WWW_MODULES", tmp_path)
    assert main._module_present("ytsas") is False
    (tmp_path / "ytsas").mkdir()
    assert main._module_present("ytsas") is True
