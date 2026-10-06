# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Une entrée de menu peut nommer le dossier www de son module (#2024).

Le hub n'acceptait une entrée que si /usr/share/secubox/www/<id>/ existait : « Voix »
(voicestudio-usager), dont la page usager.html vit dans www/voicestudio/, n'apparaissait jamais
au menu ni dans le registre du Hall."""
from api import main as hub


def _menu(monkeypatch, entrees, installes):
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: entrees)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())
    monkeypatch.setattr(hub, "_check_module_installed", lambda m: m in installes)
    monkeypatch.setattr(hub, "_check_module_active", lambda m: m in installes)
    res = hub._compute_menu_sync()
    return {i["id"]: i for cat in res["categories"] for i in cat.get("items", cat.get("modules", []))}


def test_une_entree_avec_cle_www_suit_le_dossier_de_son_module(monkeypatch):
    vus = _menu(monkeypatch, [
        {"id": "voicestudio", "name": "VoiceStudio", "category": "mind", "order": 614},
        {"id": "voicestudio-usager", "www": "voicestudio", "name": "Voix", "category": "mind", "order": 615},
    ], {"voicestudio"})
    assert "voicestudio-usager" in vus and vus["voicestudio-usager"]["active"] is True


def test_sans_cle_www_le_dossier_reste_l_id(monkeypatch):
    vus = _menu(monkeypatch, [
        {"id": "absent", "name": "Absent", "category": "mind", "order": 1},
    ], {"voicestudio"})
    assert "absent" not in vus                      # pas de dossier : toujours écarté


def test_la_cle_www_n_ouvre_pas_un_module_absent(monkeypatch):
    vus = _menu(monkeypatch, [
        {"id": "voicestudio-usager", "www": "voicestudio", "name": "Voix", "category": "mind", "order": 615},
    ], set())
    assert "voicestudio-usager" not in vus          # le module d'origine n'est pas installé
