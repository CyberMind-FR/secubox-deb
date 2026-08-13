# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""La navbar retire les modules épinglés 'off' (#1028)."""
import pathlib

from api import main as hub


def test_lit_les_epingles_off(tmp_path, monkeypatch):
    f = tmp_path / "pins.toml"
    f.write_text('"glances" = "off"\n"billets" = "on"\n"vault" = "off"\n')
    monkeypatch.setattr(hub, "_PINS_FILE", f)
    assert hub._epingles_off() == {"glances", "vault"}


def test_fichier_absent_ne_vide_pas_le_menu(tmp_path, monkeypatch):
    # Rendre un ensemble vide laisse le menu complet : le pire cas est de
    # revenir au comportement d'avant, jamais de couper la navigation.
    monkeypatch.setattr(hub, "_PINS_FILE", tmp_path / "jamais.toml")
    assert hub._epingles_off() == set()


def test_fichier_casse_ne_coupe_pas_la_navigation(tmp_path, monkeypatch):
    f = tmp_path / "pins.toml"
    f.write_text("ceci n'est pas du toml [[[")
    monkeypatch.setattr(hub, "_PINS_FILE", f)
    assert hub._epingles_off() == set()


def test_seul_off_compte(tmp_path, monkeypatch):
    f = tmp_path / "pins.toml"
    f.write_text('"a" = "on"\n"b" = "off"\n')
    monkeypatch.setattr(hub, "_PINS_FILE", f)
    assert hub._epingles_off() == {"b"}
