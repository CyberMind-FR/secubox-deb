# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3042 — un module AUTONOME sert sa page lui-même, sans dossier www/.

gk2 : metanews (Go) répond 200 sur admin.<domaine>/<id>/ mais n'ont pas de
/usr/share/secubox/www/<id>/ : le hub les écartait du menu, donc du registre du Hall (« aucune source »).
La clé `"autonome": true` de menu.d le dit — le fichier menu.d est livré par le paquet, sa présence prouve
l'installation ; l'activité reste jugée sur l'unité / la socket du module."""
import json
from pathlib import Path

from api import main as hub

PAQUETS = Path(__file__).resolve().parents[2]


def _menu(monkeypatch, entrees, installes, actifs):
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: entrees)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())
    monkeypatch.setattr(hub, "_menu_off_du_profil", lambda: set())
    monkeypatch.setattr(hub, "_check_module_installed", lambda m: m in installes)
    monkeypatch.setattr(hub, "_check_module_active", lambda m: m in actifs)
    res = hub._compute_menu_sync()
    return {i["id"]: i for cat in res["categories"] for i in cat.get("items", [])}


def test_un_module_autonome_est_au_menu_sans_dossier_www(monkeypatch):
    vus = _menu(monkeypatch, [
        {"id": "metanews", "name": "MetaNews", "category": "mind", "order": 28, "autonome": True},
        {"id": "sans-page", "name": "API seule", "category": "mind", "order": 29},
    ], installes=set(), actifs={"metanews"})
    assert "metanews" in vus and vus["metanews"]["installed"] is True and vus["metanews"]["active"] is True
    assert "sans-page" not in vus      # sans dossier ni clé : toujours écarté


def test_un_module_autonome_arrete_reste_au_menu_mais_inactif(monkeypatch):
    vus = _menu(monkeypatch, [{"id": "autonome-dodo", "name": "Autonome endormi", "category": "mesh", "order": 29, "autonome": True}],
                installes=set(), actifs=set())
    assert vus["autonome-dodo"]["active"] is False


def test_metanews_se_declare_autonome():
    for chemin in ("secubox-metanews/menu.d/28-metanews.json",):
        assert json.loads((PAQUETS / chemin).read_text(encoding="utf-8")).get("autonome") is True, chemin
