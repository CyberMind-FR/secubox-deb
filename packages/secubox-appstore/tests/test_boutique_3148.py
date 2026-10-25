# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3148 — /appstore/boutique.html : vitrine client Aurora, mêmes routes que la page d'administration."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "appstore"
PAGE = WWW / "boutique.html"
SRC = PAGE.read_text(encoding="utf-8")
FICHES = json.loads((WWW / "boutique-fiches.json").read_text(encoding="utf-8"))


def test_page_autonome_sans_dialogue_natif_ni_innerhtml():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert not re.findall(r"<script[^>]+src=", SRC)
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "insertAdjacentHTML", "http://", "https://"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet:'boutique'" in SRC and "demo" in SRC.lower()
    assert "sbx_token" in SRC and "Authorization" in SRC


def test_installation_par_la_route_existante_et_sans_autre_ecriture():
    assert "'/module/'+encodeURIComponent(a.id)+'/action/install'" in SRC
    assert len(re.findall(r"ecrire\(", SRC)) == 2        # définition + installation : aucune autre écriture
    for lecture in ("/catalog", "/groupes", "/jobs", "/appstore/boutique-fiches.json"):
        assert lecture in SRC


def test_fiches_valides_et_noms_de_paquets_connus():
    assert FICHES
    for nom, f in FICHES.items():
        assert nom.startswith("secubox-") and isinstance(f, dict)
        if not f.get("cacher"):
            assert f["nom"] and f["resume"] and f["categorie"] and f["detail"]
            assert "<" not in json.dumps(f)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def mod(name, cat, inst=False, tier_locked=False, installable=True):
    return {"name": name, "category": cat, "description": "SecuBox — " + name, "installed": inst, "running": inst,
            "version": "1.0", "tier_locked": tier_locked, "installable": installable}


CATALOG = {"modules": [mod("secubox-jellyfin", "media", True), mod("secubox-peertube", "misc"),
                       mod("secubox-core", "system"), mod("secubox-coffre", "media", installable=False),
                       mod("secubox-galerie", "media", tier_locked=True), mod("secubox-radio", "media"),
                       mod("secubox-streamlit", "media")]}
GROUPES = {"groupes": [{"id": "g", "label": "Cinéma", "description": "d",
                        "membres": [{"name": "secubox-jellyfin"}, {"name": "secubox-peertube"}]}]}


def ouvre(navigateur, statut=200, install=(202, {"status": "accepted"}), taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1200, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def tout(r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/appstore/boutique.html":
            return r.fulfill(status=200, content_type="text/html", body=SRC)
        if u == "/appstore/boutique-fiches.json":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(FICHES))
        appels.append((r.request.method, u))
        if r.request.method == "POST":
            return r.fulfill(status=install[0], content_type="application/json", body=json.dumps(install[1]))
        if statut != 200:
            return r.fulfill(status=statut, content_type="application/json", body="{}")
        corps = {"/api/v1/appstore/catalog": CATALOG, "/api/v1/appstore/groupes": GROUPES, "/api/v1/appstore/jobs": {"jobs": {}}}.get(u)
        r.fulfill(status=200 if corps is not None else 404, content_type="application/json", body=json.dumps(corps or {}))
    p.route("http://sbx.test/**", tout)
    p.goto("http://sbx.test/appstore/boutique.html")
    p.wait_for_selector(".pastille:not([hidden]), #session:not([hidden]), #erreur:not([hidden])")
    return ctx, p, erreurs, appels


def test_filtrage_habillage_et_pas_de_debordement(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur, taille={"width": 400, "height": 800})
    p.click("[role=tab]:text-is(\"Apps\")")
    noms = p.eval_on_selector_all(".app .txt b", "e=>e.map(x=>x.textContent)")
    assert "Jellyfin" in noms and "PeerTube" in noms and "Radio" in noms     # fiche ou catégorie grand public
    assert not any(n in noms for n in ("Core", "Coffre", "Galerie", "Streamlit"))   # système, non publié, verrouillé, caché
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert not erreurs
    ctx.close()


def test_obtenir_lance_l_installation_et_refus_explique(navigateur):
    ctx, p, _, appels = ouvre(navigateur)
    p.click("[role=tab]:text-is(\"Apps\")")
    p.locator(".app", has_text="PeerTube").locator("button.get").click()
    p.wait_for_selector(".get.busy")
    assert ("POST", "/api/v1/appstore/module/secubox-peertube/action/install") in appels
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, install=(403, {"detail": "x"}))
    p.click("[role=tab]:text-is(\"Apps\")")
    p.locator(".app", has_text="PeerTube").locator("button.get").click()
    p.wait_for_selector(".toast.on:has-text('Réservé à l’administrateur')")
    ctx.close()


def test_session_absente_annoncee(navigateur):
    ctx, p, _, _ = ouvre(navigateur, statut=401)
    assert p.is_visible("#session")
    ctx.close()


def test_fiche_xss_inerte(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur)
    p.click("[role=tab]:text-is(\"Apps\")")
    p.locator(".app", has_text="Jellyfin").click()
    assert p.is_visible("dialog[open] .sheet")
    assert not erreurs
    ctx.close()
