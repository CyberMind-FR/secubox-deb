# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Pastilles de la barre latérale (#2512) : un module monté dans l'agrégateur est en service, sans unité ni socket propres.

Le lot de santé jugeait par unité systemd et par socket : dns-guard, haproxy, hardening restaient absents du lot (pastille grise) alors
qu'ils répondent. R-Level est une page du Toolbox. Une unité réellement en échec reste une alarme."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")


def test_module_monte_absent_du_lot_passe_en_service():
    m = {"ad-guard": {"status": "ok", "msg": "Socket active"}}
    main.superposer_montes(m, frozenset({"dns-guard"}))
    assert m["dns-guard"]["status"] == "ok"
    assert "agrégateur" in m["dns-guard"]["msg"]


def test_unite_inactive_d_un_module_monte_n_est_pas_une_alerte():
    m = {"haproxy": {"status": "warn", "msg": "inactive/dead"}}
    main.superposer_montes(m, frozenset({"haproxy"}))
    assert m["haproxy"]["status"] == "ok"


def test_unite_en_echec_reste_une_alarme():
    m = {"hardening": {"status": "error", "msg": "Failed"}}
    main.superposer_montes(m, frozenset({"hardening"}))
    assert m["hardening"] == {"status": "error", "msg": "Failed"}


def test_module_non_monte_et_absent_reste_absent():
    m = {}
    main.superposer_montes(m, frozenset({"dns-guard"}))
    assert "nac" not in m


def test_etat_deja_ok_inchange():
    m = {"nac": {"status": "ok", "msg": "Running"}}
    main.superposer_montes(m, frozenset({"nac"}))
    assert m["nac"] == {"status": "ok", "msg": "Running"}


def test_rlevel_suit_le_toolbox():
    m = {"toolbox": {"status": "ok", "msg": "Running"}}
    main.superposer_montes(m, frozenset())
    assert m["rlevel"]["status"] == "ok"


def test_rlevel_suit_le_toolbox_meme_en_panne():
    m = {"toolbox": {"status": "error", "msg": "Failed"}}
    main.superposer_montes(m, frozenset())
    assert m["rlevel"]["status"] == "error"


def test_rlevel_sans_toolbox_reste_absent():
    m = {}
    main.superposer_montes(m, frozenset())
    assert "rlevel" not in m


def test_agregateur_injoignable_donne_un_ensemble_vide():
    assert main.modules_montes("/nonexistent/aggregator.sock") == frozenset()


def test_le_lot_de_sante_applique_la_superposition(monkeypatch):
    monkeypatch.setattr(main, "systemd_batch", lambda **k: {"nac": {"status": "ok", "msg": "Running"}})
    monkeypatch.setattr(main, "_load_sleepable_modules", lambda: set())
    monkeypatch.setattr(main, "_unites_au_repos_cache", lambda: (set(), set()))
    monkeypatch.setattr(main, "modules_montes", lambda *a, **k: frozenset({"dns-guard"}))
    main._cache.pop("units_brut", None)
    main._refresh_health_batch()
    assert main._cache["health_batch"]["modules"]["dns-guard"]["status"] == "ok"
