# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2759 — onglet Protocoles de nDPId : « Regrouper par » pour les protocoles ET une table complète des applications.

Vrai navigateur sur les données de démonstration de la page (13 protocoles, 10 applications)."""
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "protocoles.html"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.route("http://sbx.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/protocoles.html?demo=1&embed=1")
    p.wait_for_selector("#tab tr")
    return ctx, p, erreurs


def entiers(p, corps, col):
    return [int(t.replace(" ", "").replace(" ", "").replace("\xa0", "") or 0) for t in p.locator(f"{corps} tr td:nth-child({col})").all_inner_texts()]


def test_le_detail_des_protocoles_reste_celui_d_avant(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        assert p.locator("#tab tr").count() == 13 and p.locator("#grpP").input_value() == ""
        assert p.locator("#tabA tr").count() == 10, "table complète des applications"
        assert not err
    finally:
        ctx.close()


def test_protocoles_par_transport_deux_groupes_et_aucun_protocole_perdu(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        p.select_option("#grpP", "chiffre")
        p.wait_for_selector("#tab tr.grp")
        assert p.locator("#tab tr.grp").count() == 2
        assert sum(entiers(p, "#tab", 2)) == 13, "la colonne « Protocoles » additionne tous les protocoles"
        assert "Groupe" in p.locator("#entP").inner_text()
        assert not err
    finally:
        ctx.close()


def test_protocoles_par_categorie_additionne_tout(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        p.select_option("#grpP", "cat")
        p.wait_for_selector("#tab tr.grp")
        assert p.locator("#tab tr.grp").count() >= 3
        assert sum(entiers(p, "#tab", 2)) == 13
        flux = sum(entiers(p, "#tab", 3))
        assert flux == 18420 + 9310 + 4120 + 61200 + 210 + 48 + 340 + 2100 + 150 + 75 + 5400 + 880 + 320
    finally:
        ctx.close()


def test_un_clic_sur_un_groupe_revient_au_detail_filtre(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        p.select_option("#grpP", "chiffre")
        p.wait_for_selector("#tab tr.grp")
        p.locator("#tab tr.grp", has_text="Chiffré").click()
        p.wait_for_function("document.querySelectorAll('#tab tr.grp').length === 0")
        assert p.locator("#grpP").input_value() == ""
        lignes = p.locator("#tab tr").all_inner_texts()
        assert 0 < len(lignes) < 13 and all("Chiffré" in t for t in lignes)
    finally:
        ctx.close()


def test_applications_filtre_et_tri(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        p.fill("#filtreA", "you")
        assert p.locator("#tabA tr").count() == 1 and "YouTube" in p.locator("#tabA tr").inner_text()
        p.fill("#filtreA", "")
        assert p.locator("#tabA tr").count() == 10
        p.locator('#entA th[data-k="nom"]').click()
        noms = [t.split("\t")[0] for t in p.locator("#tabA tr").all_inner_texts()]
        assert noms == sorted(noms, key=str.casefold) or noms == sorted(noms, key=str.casefold, reverse=True) or noms[0] <= noms[-1]
        assert not err
    finally:
        ctx.close()


def test_applications_par_categorie_additionne_tout_et_clic_revient_au_detail(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        p.select_option("#grpA", "cat")
        p.wait_for_selector("#tabA tr.grp")
        assert sum(entiers(p, "#tabA", 2)) == 10, "dix applications réparties"
        p.locator("#tabA tr.grp").first.click()
        p.wait_for_function("document.querySelectorAll('#tabA tr.grp').length === 0")
        assert 0 < p.locator("#tabA tr").count() <= 10 and p.locator("#grpA").input_value() == ""
    finally:
        ctx.close()


def test_telephone_pas_de_debordement_horizontal(navigateur):
    ctx, p, err = ouvre(navigateur, {"width": 390, "height": 800})
    try:
        p.select_option("#grpP", "cat")
        p.select_option("#grpA", "cat")
        assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    finally:
        ctx.close()
