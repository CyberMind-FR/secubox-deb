# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2757 — onglet Flux de nDPId : « Regrouper par » (protocole, application, source, destination, niveau de risque).

Vrai navigateur sur les données de démonstration de la page (12 flux, adresses RFC 5737)."""
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "flux.html"


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
    p.goto("http://sbx.test/flux.html?demo=1&embed=1")
    p.wait_for_selector("#flux tr")
    return ctx, p, erreurs


def lignes(p):
    return p.locator("#flux tr").all_inner_texts()


def groupe(p, mode):
    p.select_option("#grp", mode)
    p.wait_for_selector("#flux tr.grp")


def test_sans_regroupement_le_detail_reste_celui_d_avant(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        assert len(lignes(p)) == 12 and p.locator("#grp").input_value() == ""
        assert p.locator("#entetes th").count() == 7 and not err
    finally:
        ctx.close()


def test_par_protocole_une_ligne_par_protocole(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        groupe(p, "proto")
        l = p.locator("#flux tr.grp")
        assert l.count() == 10
        tls = p.locator("#flux tr.grp", has_text="TLS")
        cellules = tls.locator("td").all_inner_texts()
        assert cellules[1].strip() == "3", "trois flux TLS"
        assert "Flux" in p.locator("#entetes").inner_text() and p.locator("#entetes th").count() == 5
        assert not err
    finally:
        ctx.close()


def test_les_octets_d_un_groupe_sont_la_somme_de_ses_flux(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        groupe(p, "proto")
        cel = p.locator("#flux tr.grp", has_text="TLS").locator("td").all_inner_texts()
        # YouTube 84 620 000 + Microsoft365 14 300 000 + Google 2 550 000 = 101 470 000 o = 96,8 Mo
        assert "96,8" in cel[2] and "Mo" in cel[2], cel
    finally:
        ctx.close()


def test_par_source_regroupe_les_flux_d_un_meme_hote(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        groupe(p, "sip")
        assert p.locator("#flux tr.grp").count() == 7
        assert p.locator("#flux tr.grp", has_text="192.0.2.11").locator("td").all_inner_texts()[1].strip() == "2"
    finally:
        ctx.close()


def test_par_niveau_de_risque_et_risque_maximal(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        groupe(p, "niv")
        assert p.locator("#flux tr.grp").count() == 3
        eleve = p.locator("#flux tr.grp", has_text="Élevé").locator("td").all_inner_texts()
        assert eleve[1].strip() == "2" and "83" in eleve[4], "IRC 83 et Telnet 76 : maximum 83"
    finally:
        ctx.close()


def test_un_clic_sur_un_groupe_revient_au_detail_de_ce_groupe(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        groupe(p, "proto")
        p.locator("#flux tr.grp", has_text="TLS").click()
        p.wait_for_function("document.querySelectorAll('#flux tr.grp').length === 0")
        assert p.locator("#grp").input_value() == ""
        assert len(lignes(p)) == 3 and all("TLS" in t for t in lignes(p))
    finally:
        ctx.close()


def test_le_filtre_en_cours_s_applique_avant_le_regroupement(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        p.select_option("#frisque", "eleve")
        groupe(p, "proto")
        assert p.locator("#flux tr.grp").count() == 2
    finally:
        ctx.close()


def test_le_compte_dit_groupes_et_flux(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        groupe(p, "app")
        txt = p.locator("#compte").inner_text()
        assert "groupe" in txt and "12" in txt
    finally:
        ctx.close()


def test_le_tri_d_un_regroupement_est_possible(navigateur):
    ctx, p, err = ouvre(navigateur)
    try:
        groupe(p, "proto")
        p.locator('#entetes th[data-k="n"] button').click()
        p.locator('#entetes th[data-k="n"] button').click()
        premiers = p.locator("#flux tr.grp").first.locator("td").all_inner_texts()
        assert premiers[1].strip() == "1" or premiers[1].strip() == "3"
        ordre = [int(r.locator("td").nth(1).inner_text().strip()) for r in [p.locator("#flux tr.grp").nth(i) for i in range(10)]]
        assert ordre == sorted(ordre) or ordre == sorted(ordre, reverse=True)
    finally:
        ctx.close()


def test_telephone_pas_de_debordement_horizontal(navigateur):
    ctx, p, err = ouvre(navigateur, {"width": 390, "height": 800})
    try:
        groupe(p, "proto")
        assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    finally:
        ctx.close()
