# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3011 — double tampon réel des caches du hub : une passe dégradée n'écrase pas le dernier relevé complet.

Sous charge, `systemctl list-units` expire ; `systemd_batch` dégradait en silence vers un texte vide et
le lot de santé ne gardait que les sockets : les LED de la barre latérale tombaient à « unknown » pendant
un cycle. Le menu pouvait de même être remplacé par un menu à zéro module.
"""
import importlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")

LOT = {"modules": {"hub": {"status": "ok", "msg": "Running"}}, "count": 1}


def _releve_isole(monkeypatch):
    for k in ("units_brut", "etats_units"):
        main._cache.pop(k, None)
    main._cache["units_ts"] = 0
    monkeypatch.setattr(main, "_load_sleepable_modules", lambda: set())
    monkeypatch.setattr(main, "_unites_au_repos_cache", lambda: (frozenset(), frozenset()))
    monkeypatch.setattr(main, "modules_montes", lambda *a, **k: frozenset())
    monkeypatch.setattr(main, "superposer_lxc", lambda *a, **k: None)


def _expire(args, **kw):
    raise subprocess.TimeoutExpired(args, 5)


def test_releve_systemd_en_echec_garde_le_lot_precedent(monkeypatch):
    _releve_isole(monkeypatch)
    main._cache["health_batch"] = dict(LOT)
    main._cache["health_batch_ts"] = 5.0
    monkeypatch.setattr(main.subprocess, "run", _expire)
    main._refresh_health_batch()
    assert main._cache["health_batch"] == LOT
    assert main._cache["health_batch_ts"] == 5.0


def test_releve_systemd_reussi_remplace_le_lot(monkeypatch):
    _releve_isole(monkeypatch)
    main._cache["health_batch"] = dict(LOT)
    main._cache["health_batch_ts"] = 5.0
    monkeypatch.setattr(main.subprocess, "run", lambda args, **kw: subprocess.CompletedProcess(
        args, 0, "secubox-dpi.service loaded active running DPI\n", ""))
    main._refresh_health_batch()
    assert "dpi" in main._cache["health_batch"]["modules"]
    assert main._cache["health_batch_ts"] > 5.0


def test_premier_releve_en_echec_sert_tout_de_meme_un_lot(monkeypatch, tmp_path):
    """Sans relevé précédent, mieux vaut un lot (sockets seules) qu'un `warming` sans fin."""
    _releve_isole(monkeypatch)
    main._cache["health_batch"] = None
    main._cache["health_batch_ts"] = 0
    monkeypatch.setattr(main.subprocess, "run", _expire)
    main._refresh_health_batch()
    assert isinstance(main._cache["health_batch"], dict)


def test_menu_recalcule_vide_garde_le_precedent(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "MENU_CACHE_FILE", tmp_path / "menu.json")
    precedent = {"categories": [{"id": "wall", "items": [{"id": "waf"}]}], "total_installed": 1}
    monkeypatch.setattr(main, "_menu_cache", precedent)
    assert main._bascule_menu({"categories": [], "total_installed": 0}) is False
    assert main._menu_cache is precedent
    assert not (tmp_path / "menu.json").exists()


def test_menu_recalcule_plein_bascule_et_persiste(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "MENU_CACHE_FILE", tmp_path / "menu.json")
    monkeypatch.setattr(main, "_menu_cache", {})
    nouveau = {"categories": [{"id": "wall", "items": [{"id": "waf"}]}], "total_installed": 1}
    assert main._bascule_menu(nouveau) is True
    assert main._menu_cache is nouveau
    assert (tmp_path / "menu.json").exists()


def test_un_premier_menu_vide_est_tout_de_meme_servi(monkeypatch, tmp_path):
    """Au tout premier calcul, un menu vide vaut mieux qu'un `warming` : il n'y a rien à conserver."""
    monkeypatch.setattr(main, "MENU_CACHE_FILE", tmp_path / "menu.json")
    monkeypatch.setattr(main, "_menu_cache", {})
    vide = {"categories": [], "total_installed": 0}
    assert main._bascule_menu(vide) is True
    assert main._menu_cache is vide
