# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2897 — le menu suit le profil actif : `menu_off` du profil masque des entrees de menu.

Sur l'ebin (profil minimal) /ksm/ et /premier-pas-maitre/ restaient au menu : seul un pin
operateur (pins.toml) en retirait une entree, jamais ce que le profil exclut."""
from api import main as hub


def _profil(tmp_path, monkeypatch, nom="minimal", corps='menu_off = ["ksm", "premier-pas-maitre"]\n'):
    (tmp_path / "active").write_text(nom + "\n")
    (tmp_path / f"{nom}.toml").write_text(f'name = "{nom}"\n{corps}')
    monkeypatch.setattr(hub, "_PROFILS_DIR", tmp_path)


def test_lit_menu_off_du_profil_actif(tmp_path, monkeypatch):
    _profil(tmp_path, monkeypatch)
    assert hub._menu_off_du_profil() == {"ksm", "premier-pas-maitre"}


def test_sans_cle_ou_sans_fichier_le_menu_reste_complet(tmp_path, monkeypatch):
    _profil(tmp_path, monkeypatch, corps="")
    assert hub._menu_off_du_profil() == set()
    monkeypatch.setattr(hub, "_PROFILS_DIR", tmp_path / "absent")
    assert hub._menu_off_du_profil() == set()


def test_fichier_casse_ne_coupe_pas_la_navigation(tmp_path, monkeypatch):
    _profil(tmp_path, monkeypatch, corps="pas du toml [[[")
    assert hub._menu_off_du_profil() == set()


def test_nom_de_profil_actif_hostile_refuse(tmp_path, monkeypatch):
    (tmp_path / "active").write_text("../../etc/passwd\n")
    monkeypatch.setattr(hub, "_PROFILS_DIR", tmp_path)
    assert hub._menu_off_du_profil() == set()


def test_le_menu_masque_les_entrees_du_profil(tmp_path, monkeypatch):
    _profil(tmp_path, monkeypatch)
    items = [{"id": "ksm", "name": "KSM"}, {"id": "premier-pas-maitre", "name": "PP"}, {"id": "hub", "name": "Hub"},
             {"id": "nac", "name": "NAC"}]
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: items)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())
    monkeypatch.setattr(hub, "_check_module_installed", lambda w: True)
    monkeypatch.setattr(hub, "_check_module_active", lambda w: True)
    ids = {i["id"] for c in hub._compute_menu_sync()["categories"] for i in c["items"]}
    assert "ksm" not in ids and "premier-pas-maitre" not in ids and {"hub", "nac"} <= ids
