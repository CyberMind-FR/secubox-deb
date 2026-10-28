# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3233 — page NetBoot multi-cartes : un onglet par carte (board/<carte>/), son live, sa clé USB, ses boxes ; les boxes
Globalscale vues sur le LAN sans profil, avec un profil prérempli."""
import importlib
import os
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parents[1] / "common"))


def _api(tmp_path):
    from fastapi.testclient import TestClient
    sys.modules.pop("api.lot", None)
    sys.modules.pop("api.main", None)
    main = importlib.import_module("api.main")
    main.BOARD_DIR = ICI / "board"
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    return main, TestClient(main.app)


def test_boards_porte_le_live_de_chaque_carte(tmp_path):
    _, c = _api(tmp_path)
    cartes = {b["model"]: b for b in c.get("/boards").json()["boards"]}
    assert (cartes["mochabin"]["live_nom"], cartes["mochabin"]["titre"], cartes["mochabin"]["console"]) \
        == ("mochabin-live", "MOCHAbin", "ttyS0,115200")
    assert (cartes["espressobin-v7"]["live_nom"], cartes["espressobin-v7"]["titre"], cartes["espressobin-v7"]["console"]) \
        == ("espressobin-live", "ESPRESSObin v7", "ttyMV0,115200")


def test_vues_lit_les_baux_globalscale_du_lan(tmp_path):
    main, c = _api(tmp_path)
    baux = tmp_path / "dnsmasq.leases"
    baux.write_text("1793219012 f0:ad:4e:08:ab:71 192.168.42.161 * *\n"
                    "1793219013 F0:AD:4E:27:88:9A 192.168.42.162 ebin-2 01:f0:ad:4e:27:88:9a\n"
                    "1793219014 aa:bb:cc:dd:ee:ff 192.168.42.50 tv *\n"
                    "ligne illisible\n"
                    "1793219015 f0:ad:4e:00:00:01 999.1.1.1 x *\n")
    main.BAUX_DHCP = baux
    assert c.get("/vues").json() == {"vues": [
        {"mac": "f0:ad:4e:08:ab:71", "ip": "192.168.42.161", "nom": None, "expire": 1793219012},
        {"mac": "f0:ad:4e:27:88:9a", "ip": "192.168.42.162", "nom": "ebin-2", "expire": 1793219013},
    ]}


def test_vues_ignore_un_lien_symbolique(tmp_path):
    main, c = _api(tmp_path)
    vrai = tmp_path / "vrai"
    vrai.write_text("1793219012 f0:ad:4e:08:ab:71 192.168.42.161 * *\n")
    lien = tmp_path / "lien"
    os.symlink(vrai, lien)
    main.BAUX_DHCP = lien
    assert c.get("/vues").json() == {"vues": []}


def test_vues_exige_une_session(tmp_path):
    main, c = _api(tmp_path)
    main.app.dependency_overrides.clear()
    assert c.get("/vues").status_code in (401, 403)


# ── page ───────────────────────────────────────────────────────────────────────────────────────────────────────
playwright = pytest.importorskip("playwright.sync_api")
from test_netboot_aurora_2597 import API, LIVE_EBIN, LIVES, navigateur, ouvre  # noqa: E402,F401

BOARDS = {"boards": [
    {"model": "espressobin-ultra", "live_nom": None, "titre": None, "console": None},
    {"model": "espressobin-v7", "live_nom": "espressobin-live", "titre": "ESPRESSObin v7", "console": "ttyMV0,115200"},
    {"model": "mochabin", "live_nom": "mochabin-live", "titre": "MOCHAbin", "console": "ttyS0,115200"}]}
VUES = {"vues": [{"mac": "f0:ad:4e:08:ab:71", "ip": "192.168.42.161", "nom": None, "expire": 1793219012},
                 {"mac": "02:00:5e:00:53:01", "ip": "192.168.42.20", "nom": "gk-test", "expire": 1793219012}]}
PROFILS = {"profiles": [{"id": "02005e005301", "model": "mochabin", "image": "secubox-2.39.0", "boot_level": "B2",
                         "srv": "192.0.2.10"}]}


@pytest.fixture
def page_cartes(navigateur):
    lives = {"lives": LIVES["lives"] + LIVE_EBIN["lives"]}
    routes = {**API, "/boards": (200, BOARDS), "/live": (200, lives), "/vues": (200, VUES), "/profiles": (200, PROFILS)}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netboot/", routes)
    p.wait_for_selector("#cartes [role=tab]", state="attached")
    yield p, err, appels
    ctx.close()


def test_un_onglet_par_carte_et_le_haut_de_page_est_le_serveur(page_cartes):
    p, err, _ = page_cartes
    onglets = p.eval_on_selector_all("#cartes [role=tab]", "els => els.map(e => e.textContent.trim())")
    assert onglets == ["espressobin-ultra", "ESPRESSObin v7", "MOCHAbin"]
    assert "Ce serveur" in p.inner_text("body")
    assert err == []


def test_l_onglet_espressobin_montre_son_live_sa_cle_et_sa_box(page_cartes):
    p, err, _ = page_cartes
    p.click("#cartes [role=tab]:has-text('ESPRESSObin v7')")
    texte = p.inner_text("#lives")
    assert "setenv ethact neta@30000" in texte and "autoflash.scr" in texte and "mochabin-live" not in texte
    assert "f0:ad:4e:08:ab:71" in texte and "sans profil" in texte
    p.click("#lives button:has-text('Profil ESPRESSObin v7')")
    assert p.input_value("#fProf input[name=id]") == "f0:ad:4e:08:ab:71"
    assert p.input_value("#fProf input[name=model]") == "espressobin-v7"
    assert err == []


def test_une_carte_sans_live_donne_la_commande_de_construction(page_cartes):
    p, _, _ = page_cartes
    p.click("#cartes [role=tab]:has-text('espressobin-ultra')")
    texte = p.inner_text("#lives")
    assert "Pas encore de live" in texte and "build-live-leger.sh --carte espressobin-ultra" in texte


def test_la_box_profilee_est_rangee_sous_son_modele_avec_son_bail(page_cartes):
    p, _, _ = page_cartes
    p.click("#cartes [role=tab]:has-text('MOCHAbin')")
    texte = p.inner_text("#lives")
    assert "02005e005301" in texte and "192.168.42.20" in texte          # profil + bail DHCP : en ligne
    assert "f0:ad:4e:08:ab:71" in texte                                   # vue sans profil, proposée partout
