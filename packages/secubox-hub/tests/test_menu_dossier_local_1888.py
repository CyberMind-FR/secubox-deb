# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Entrées de menu en /etc/secubox/menu.d : lues, et la locale l'emporte (#1888)."""
import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")


def _poser(dossier, nom, contenu):
    dossier.mkdir(parents=True, exist_ok=True)
    (dossier / nom).write_text(json.dumps(contenu))


def test_entree_locale_lue(tmp_path, monkeypatch):
    sysd, loc = tmp_path / "usr", tmp_path / "etc"
    _poser(sysd, "100-a.json", {"id": "a", "name": "A", "category": "root"})
    _poser(loc, "590-p2p.json", {"id": "p2p", "name": "P2P", "category": "mesh"})
    monkeypatch.setattr(main, "MENU_DIR", sysd)
    monkeypatch.setattr(main, "MENU_DIR_LOCAL", loc)
    ids = {e["id"] for e in main._load_menu_definitions()}
    assert ids == {"a", "p2p"}                    # avant : p2p était ignoré


def test_locale_remplace_a_id_egal(tmp_path, monkeypatch):
    sysd, loc = tmp_path / "usr", tmp_path / "etc"
    _poser(sysd, "1.json", [{"id": "x", "name": "Livré"}])
    _poser(loc, "1.json", [{"id": "x", "name": "Local"}])
    monkeypatch.setattr(main, "MENU_DIR", sysd)
    monkeypatch.setattr(main, "MENU_DIR_LOCAL", loc)
    defs = main._load_menu_definitions()
    assert [e["name"] for e in defs] == ["Local"]


def test_json_casse_ne_vide_pas_le_menu(tmp_path, monkeypatch):
    sysd, loc = tmp_path / "usr", tmp_path / "etc"
    _poser(sysd, "1.json", {"id": "ok", "name": "OK"})
    loc.mkdir()
    (loc / "casse.json").write_text("{pas du json")
    monkeypatch.setattr(main, "MENU_DIR", sysd)
    monkeypatch.setattr(main, "MENU_DIR_LOCAL", loc)
    assert [e["id"] for e in main._load_menu_definitions()] == ["ok"]
