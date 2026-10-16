# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2802 — /appstore/ : un panneau de cumuls par categorie (modele /apercu/), calcule d'apres l'etat reel, cliquable pour filtrer."""
import pytest
from test_appstore_aurora_2571 import navigateur, ouvre, SRC  # noqa: F401

pytest.importorskip("playwright.sync_api")


def test_les_cumuls_comptent_installes_sur_total_par_categorie(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/appstore/")
    p.wait_for_selector("#cumuls .cumul")
    lignes = {p.locator("#cumuls .cumul").nth(i).locator("b").inner_text(): p.locator("#cumuls .cumul").nth(i) for i in range(p.locator("#cumuls .cumul").count())}
    assert lignes["media"].locator(".n").inner_text() == "1 / 2"
    assert lignes["network"].locator(".n").inner_text() == "1 / 3"
    assert err == []
    ctx.close()


def test_une_categorie_dit_ce_qui_reste_a_installer(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/appstore/")
    p.wait_for_selector("#cumuls .cumul")
    txt = p.inner_text("#cumuls")
    assert "À installer : secubox-relais" in txt          # seul module `available` du reseau
    assert "secubox-galerie" not in txt                  # verrouille par le niveau : pas « installable »
    ctx.close()


def test_cliquer_un_cumul_filtre_la_liste_et_recliquer_l_enleve(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/appstore/")
    p.wait_for_selector("#cumuls .cumul")
    p.click("#cumuls .cumul:has(b:text-is('network'))")
    assert p.input_value("#fCat") == "network" and p.locator("#grille .carte").count() == 3
    assert p.get_attribute("#cumuls .cumul:has(b:text-is('network'))", "aria-pressed") == "true"
    p.click("#cumuls .cumul:has(b:text-is('network'))")
    assert p.input_value("#fCat") == "" and p.locator("#grille .carte").count() == 5
    ctx.close()


def test_le_panneau_n_utilise_que_le_dom_sur(navigateur):
    assert "innerHTML" not in SRC and "insertAdjacentHTML" not in SRC
