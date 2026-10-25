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
BESOINS = json.loads((WWW / "boutique-besoins.json").read_text(encoding="utf-8"))


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
    for lecture in ("/catalog", "/groupes", "/jobs"):
        assert lecture in SRC


def test_donnees_lues_par_url_relative():
    """Le vhost boutique.<domaine> sert /boutique-*.json à la racine : jamais de chemin /appstore/ en dur."""
    assert "fetch('boutique-fiches.json'" in SRC and "fetch('boutique-besoins.json'" in SRC
    assert "/appstore/boutique-fiches.json" not in SRC and "/appstore/boutique-besoins.json" not in SRC


def test_besoins_valides():
    assert BESOINS
    for cle, b in BESOINS.items():
        assert b["nom"] and b["resume"] and b["categorie"] and b["detail"] and b["solutions"]
        for sol in b["solutions"]:
            assert sol.get("paquet", "secubox-x").startswith("secubox-")
            assert sol.get("nom") or sol.get("paquet")
            for classe, texte in sol["traits"]:
                assert classe in ("", "oui", "att") and texte
        assert "<" not in json.dumps(b) and "http" not in json.dumps(b)
    assert {s["paquet"] for s in BESOINS["visio"]["solutions"] if "paquet" in s} == {"secubox-jitsi", "secubox-meet"}
    assert FICHES["secubox-meet"]["nom"] == "La Suite Meet" and FICHES["secubox-jitsi"]["nom"] == "Jitsi Meet"


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


CATALOG = {"modules": [mod("secubox-jitsi", "communication", True), mod("secubox-meet", "communication"),
                       mod("secubox-jellyfin", "media", True), mod("secubox-peertube", "misc"),
                       mod("secubox-core", "system"), mod("secubox-coffre", "media", installable=False),
                       mod("secubox-galerie", "media", tier_locked=True), mod("secubox-radio", "media"),
                       mod("secubox-streamlit", "media")]}
GROUPES = {"groupes": [{"id": "g", "label": "Cinéma", "description": "d",
                        "membres": [{"name": "secubox-jellyfin"}, {"name": "secubox-peertube"}]}]}


def ouvre(navigateur, statut=200, install=(202, {"status": "accepted"}), taille=None, besoins=True):
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
        if u == "/appstore/boutique-besoins.json":
            if not besoins:
                return r.fulfill(status=404, content_type="text/plain", body="")
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(BESOINS))
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


def test_besoin_visio_dans_la_liste_sans_ses_solutions(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur)
    p.click("[role=tab]:text-is(\"Apps\")")
    noms = p.eval_on_selector_all(".app .txt b", "e=>e.map(x=>x.textContent)")
    assert "Visio" in noms and "Jellyfin" in noms
    assert "Jitsi Meet" not in noms and "La Suite Meet" not in noms
    ligne = p.locator(".app", has_text="Visio")
    assert "Appels vidéo privés · 2 solutions" in ligne.inner_text()
    assert ligne.locator("button.get").inner_text() == "Ouvrir"          # Jitsi est installé
    p.click("[role=tab]:text-is(\"Installées\")")
    noms = p.eval_on_selector_all(".app .txt b", "e=>e.map(x=>x.textContent)")
    assert "Jitsi Meet" in noms and "Visio" not in noms
    assert not erreurs
    ctx.close()


def test_recherche_trouve_le_besoin_par_ses_solutions(navigateur):
    ctx, p, _, _ = ouvre(navigateur)
    p.fill("#q", "bigblue")
    noms = p.eval_on_selector_all(".app .txt b", "e=>e.map(x=>x.textContent)")
    assert noms == ["Visio"]
    ctx.close()


def test_fiche_du_besoin_trois_solutions_et_installation(navigateur):
    ctx, p, erreurs, appels = ouvre(navigateur, taille={"width": 400, "height": 800})
    p.click("[role=tab]:text-is(\"Apps\")")
    p.locator(".app", has_text="Visio").click()
    f = p.locator("dialog[open] .sheet")
    txt = f.text_content()
    for attendu in ("Un besoin, plusieurs solutions", "Solutions libres pour ce besoin", "Plusieurs solutions peuvent cohabiter."):
        assert attendu in txt
    assert f.locator(".sol").count() == 3
    jitsi = f.locator(".sol", has_text="Jitsi Meet")
    assert "choisie" in jitsi.get_attribute("class") and "Installée" in jitsi.inner_text()
    assert jitsi.locator("button.get").inner_text() == "Ouvrir"
    bbb = f.locator(".sol", has_text="BigBlueButton").locator("button.get")
    assert bbb.inner_text() == "Bientôt" and bbb.is_disabled()
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth")
    f.locator(".sol", has_text="La Suite Meet").locator("button.get", has_text="Obtenir").click()
    p.wait_for_selector("dialog[open] .sol button.get.busy")
    assert ("POST", "/api/v1/appstore/module/secubox-meet/action/install") in appels
    assert not erreurs
    ctx.close()


def test_sans_fichier_de_besoins_la_page_fonctionne(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur, besoins=False)
    p.click("[role=tab]:text-is(\"Apps\")")
    noms = p.eval_on_selector_all(".app .txt b", "e=>e.map(x=>x.textContent)")
    assert "Visio" not in noms and "Jitsi Meet" in noms and "La Suite Meet" in noms and "Jellyfin" in noms
    assert not erreurs
    ctx.close()
