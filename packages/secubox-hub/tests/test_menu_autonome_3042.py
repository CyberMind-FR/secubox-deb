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


def _menu(monkeypatch, entrees, installes, actifs, domaine="gk9.secubox.in"):
    monkeypatch.setattr(hub, "hote_box", lambda p: f"{p}.{domaine}" if domaine and p else "")
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


def test_un_module_autonome_porte_un_lien_externe_vers_son_vhost(monkeypatch):
    vus = _menu(monkeypatch, [
        {"id": "metanews", "name": "MetaNews", "category": "mind", "order": 28, "autonome": True, "path": "/metanews/"},
        {"id": "radio", "name": "Radio", "category": "mind", "order": 60},
    ], installes={"radio"}, actifs={"metanews", "radio"})
    assert vus["metanews"]["externe"] == "https://metanews.gk9.secubox.in/"     # dérivé du domaine de la box, jamais codé en dur
    assert "externe" not in vus["radio"]


def test_la_cle_hote_choisit_le_prefixe_et_sans_domaine_pas_de_lien(monkeypatch):
    vus = _menu(monkeypatch, [{"id": "metanews", "name": "MetaNews", "category": "mind", "order": 28, "autonome": True, "hote": "news"}],
                installes=set(), actifs=set())
    assert vus["metanews"]["externe"] == "https://news.gk9.secubox.in/"
    vus = _menu(monkeypatch, [{"id": "metanews", "name": "MetaNews", "category": "mind", "order": 28, "autonome": True}],
                installes=set(), actifs=set(), domaine="")
    assert "externe" not in vus["metanews"]


def test_la_barre_laterale_ouvre_un_lien_externe_dans_un_onglet():
    js = (PAQUETS / "secubox-hub" / "www" / "shared" / "sidebar.js").read_text(encoding="utf-8")
    assert "item.externe" in js and 'target="_blank" rel="noopener"' in js
    assert "'v2.45.0'" in js
