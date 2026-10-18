# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2905 — une page servie par un autre module est jugee sur CE module.

gk2 : Centres, Flotte (annuaire) et Releases (secubox-release) rouges « a l'arret » alors que
annuaire.sock et release.sock repondent : le hub cherchait une socket ou une unite portant l'id de la page."""
import json
from pathlib import Path

from api import main as hub

PAQUETS = Path(__file__).resolve().parents[2]


def _menu(monkeypatch, items, actifs):
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: items)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())
    monkeypatch.setattr(hub, "_menu_off_du_profil", lambda: set())
    monkeypatch.setattr(hub, "_check_module_installed", lambda w: True)
    sondes = []
    monkeypatch.setattr(hub, "_check_module_active", lambda w: (sondes.append(w), w in actifs)[1])
    cats = hub._compute_menu_sync()["categories"]
    return {i["id"]: i for c in cats for i in c["items"]}, sondes


def test_la_cle_unite_designe_le_module_qui_porte_la_page(monkeypatch):
    items = [{"id": "centers", "name": "Centres", "unite": "annuaire"}, {"id": "nac", "name": "NAC"}]
    out, sondes = _menu(monkeypatch, items, actifs={"annuaire"})
    assert out["centers"]["active"] is True
    assert "annuaire" in sondes and "centers" not in sondes
    assert out["nac"]["active"] is False and "nac" in sondes     # sans cle : l'id, comme avant


def test_les_pages_de_annuaire_et_de_release_portent_la_cle():
    attendu = {"570-centers.json": ("secubox-annuaire/menu.d", "annuaire"),
               "595-fleet.json": ("secubox-annuaire/menu.d", "annuaire"),
               "590-releases.json": ("secubox-repo/composants/release/menu.d", "release")}
    for nom, (dossier, unite) in attendu.items():
        d = json.loads((PAQUETS / dossier / nom).read_text())
        assert d.get("unite") == unite, nom
