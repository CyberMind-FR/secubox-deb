# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2679 — /publish/ (assistant de publication) au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "composants" / "publish" / "www" / "publish" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script[^>]+src="', SRC) == []        # le menu commun est injecté, hors embed et démo
    assert "'/shared/sidebar.js'" in SRC and "!EMB && !DEMO" in SRC
    for interdit in ("hybrid-dark", "crt-", "fonts.googleapis", "confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "gk2"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'publish'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert 'role="tablist"' in SRC and 'aria-current="step"' in SRC and "focus-visible" in SRC


def test_assertions_de_l_ancienne_page_conservees():
    """Reprise de test_publication_1823.test_la_page_ne_peint_plus_de_coche_sans_lire_la_reponse."""
    assert "Status').textContent = '✅';\n                document.getElementById('create" not in SRC
    assert "'.gk2.secubox.in'" not in SRC
    assert "/isp/travail/" in SRC and "/chaine" in SRC
    assert "if (!result.success)" in SRC and "t.etat === 'publie'" in SRC


def test_routes_et_corps_a_l_identique():
    for r in ("API + path", "'/overview'", "METABLOGIZER_API + '/sites'", "METABLOGIZER_API + '/access'",
              "'/quick-publish'", "/streamlit/deploy?name=", "/streamlit/stop?name=", "'/droplet/publish'",
              "/metablogizer/publish/", "/site/${encodeURIComponent(name)}/publish", "/unpublish", "/cert", "/exposure",
              "API + '/isp/upload'", "/bundle/${name}/qrcode", "/api/v1/publish/bundle/${name}.zip", "/api/v1/metablogizer/health/",
              "{ wan: true }", "content_type: 'app'", "content_type: 'site'", "data: { title }", "{ file: name }",
              "formData.append('auto_publish'", "formData.append('domain'", "formData.append('file'", "formData.append('name'"):
        assert r in SRC, r
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + token()" in SRC
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


OVERVIEW = {"apps": [{"name": "alpha", "running": True, "port": 8501}, {"name": "beta", "running": False}],
            "projects": [{"name": "proj", "template": "basic", "created": "2026-01-02"}],
            "files": [{"name": "doc.html", "size": "3 Ko", "published": False}],
            "sites": [{"name": "blog", "domain": "blog.box.test", "published": True},
                      {"name": "brouillon", "domain": "brouillon.box.test", "published": False}]}
CHAINE = {"maillons": {"vhost": {"ok": True, "detail": "vhost présent"}, "cert": {"ok": False, "detail": "pas de certificat"},
                       "route": {"ok": True}}}
BASE = {("GET", "/overview"): (200, OVERVIEW)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script(f"localStorage.setItem('sbx_token', '{jeton}')")
    p = ctx.new_page()
    erreurs, appels, charges = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialog natif : " + d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            charges.append(chemin)
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "publish":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        mod, chemin = ("publish", u.split("/api/v1/publish", 1)[1]) if u.startswith("/api/v1/publish") else ("metablogizer", u.split("/api/v1/metablogizer", 1)[1])
        appels.append((r.request.method, mod, chemin, r.request.post_data, r.request.headers.get("authorization")))
        cle = (r.request.method, chemin if mod == "publish" else mod + ":" + chemin)
        statut, corps = routes.get(cle, (404, {}) if r.request.method == "GET" else (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/**", api)
    p.goto(url)
    p.charges = charges
    return ctx, p, erreurs, appels


def prete(p):
    p.wait_for_selector("#appsTable td.mono", state="attached")


def test_tuiles_listes_et_onglets_accessibles(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/publish/", BASE, jeton="tok123")
    prete(p)
    assert [p.inner_text(i) for i in ("#tApps", "#tProjets", "#tFichiers", "#tSites")] == ["2", "1", "1", "2"]
    assert p.inner_text("#etat") == "PRÊT"
    assert all(p.get_attribute(s, "title") for s in (".tuile >> nth=0", ".tuile >> nth=3"))
    assert "EN MARCHE" in p.inner_text("#appsTable") and "ARRÊTÉE" in p.inner_text("#appsTable")
    # l'API est appelée avec le jeton en Bearer
    assert ("GET", "publish", "/overview", None, "Bearer tok123") in appels
    # onglets : rôle tab, aria-selected, flèches
    assert p.get_attribute("#tab-apps", "aria-selected") == "true" and p.is_hidden("#sites")
    p.focus("#tab-apps"); p.keyboard.press("ArrowRight")
    assert p.get_attribute("#tab-projects", "aria-selected") == "true" and p.is_visible("#projectsTable")
    p.keyboard.press("End")
    assert p.get_attribute("#tab-sites", "aria-selected") == "true" and "blog.box.test" in p.inner_text("#sitesTable")
    p.click(".tuile[data-onglet=files]")
    assert p.is_visible("#filesTable") and "BROUILLON" in p.inner_text("#filesTable")
    assert err == []
    ctx.close()


def test_menu_commun_charge_seulement_hors_embed_et_demo(navigateur):
    for url, attendu in (("http://sbx.test/publish/", True), ("http://sbx.test/publish/?embed=1", False), ("http://sbx.test/publish/?demo=1", False)):
        ctx, p, _, _ = ouvre(navigateur, url, BASE)
        p.wait_for_timeout(300)
        assert ("shared/sidebar.js" in p.charges) is attendu, url
        ctx.close()


def test_actions_des_listes_memes_appels(navigateur):
    routes = {**BASE, ("POST", "/metablogizer/publish/brouillon"): (200, {"error": "refus"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/publish/", routes, jeton="t")
    prete(p)
    p.get_by_role("button", name="Déployer beta").click()
    p.wait_for_timeout(200)
    assert any(a[:3] == ("POST", "publish", "/streamlit/deploy") for a in appels)
    # arrêt : confirmation dans la ligne, aucun appel avant
    p.get_by_role("button", name="Arrêter alpha").click()
    assert not [a for a in appels if a[2] == "/streamlit/stop"]
    p.locator("#appsTable").get_by_text("Annuler").click()
    assert not [a for a in appels if a[2] == "/streamlit/stop"]
    p.get_by_role("button", name="Arrêter alpha").click(); p.locator("tbody").get_by_text("Confirmer").click()
    p.wait_for_timeout(200)
    assert ("POST", "publish", "/streamlit/stop", None, "Bearer t") in [a for a in appels]
    p.click("#tab-projects"); p.get_by_role("button", name="Déployer proj").click()
    p.click("#tab-files"); p.get_by_role("button", name="Publier doc.html").click()
    p.wait_for_timeout(200)
    assert any(a[2] == "/droplet/publish" and json.loads(a[3]) == {"file": "doc.html"} for a in appels)
    # site brouillon : l'API publish refuse (error) -> repli sur metablogizer
    p.click("#tab-sites"); p.get_by_role("button", name="Publier brouillon").click()
    p.wait_for_timeout(300)
    assert any(a[:3] == ("POST", "metablogizer", "/site/brouillon/publish") for a in appels)
    assert any(a[2] == "/metablogizer/publish/brouillon" for a in appels)
    # dépublication confirmée
    p.get_by_role("button", name="Dépublier blog").click(); p.locator("tbody").get_by_text("Confirmer").click()
    p.wait_for_timeout(200)
    assert any(a[:3] == ("POST", "metablogizer", "/site/blog/unpublish") for a in appels)
    assert err == []
    ctx.close()


def test_sante_des_sites(navigateur):
    routes = {**BASE, ("GET", "metablogizer:/health/blog.box.test"): (200, {"http": 301, "https": 200, "waf": "inspected"}),
              ("GET", "metablogizer:/health/brouillon.box.test"): (200, {"http": 404, "https": 503, "waf": "blocked"})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/publish/", routes)
    prete(p); p.click("#tab-sites")
    assert p.inner_text("#healthGreen").startswith("—")
    p.click("#btnTousSites")
    p.wait_for_function("document.getElementById('healthRed').textContent.startsWith('1')")
    assert p.inner_text("#healthGreen").startswith("1") and "inspecté" in p.inner_text("#sitesTable") and "bloqué" in p.inner_text("#sitesTable")
    assert err == []
    ctx.close()


def test_creation_rapide_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/publish/", BASE)
    prete(p)
    p.click("#btnApp")                                       # nom vide : message dans la page, aucun appel
    assert "nom" in p.inner_text("#rCreation") and not [a for a in appels if a[2] == "/quick-publish"]
    p.fill("#appName", "neuf"); p.select_option("#appTemplate", "dashboard"); p.click("#btnApp")
    p.wait_for_function("document.getElementById('rCreation').textContent.includes('création demandée')")
    p.fill("#siteName", "mon-site"); p.fill("#siteTitle", "Titre"); p.click("#btnSite")
    p.wait_for_function("document.getElementById('rCreation').textContent.includes('mon-site')")
    corps = [json.loads(a[3]) for a in appels if a[2] == "/quick-publish"]
    assert corps == [{"content_type": "app", "name": "neuf", "template": "dashboard"},
                     {"content_type": "site", "name": "mon-site", "data": {"title": "Titre"}}]
    ctx.close()


def depose(p, nom="mon-blog.zip"):
    p.set_input_files("#fileInput", {"name": nom, "mimeType": "application/zip", "buffer": b"PK\x03\x04" + b"0" * 2000})


def test_assistant_publication_complete(navigateur):
    travail = {"etat": "publie", "domain": "mon-blog.box.test", "url": "https://mon-blog.box.test",
               "etapes": [{"cle": "a", "libelle": "Extraction", "etat": "ok"}, {"cle": "b", "libelle": "Vhost", "etat": "ok"}]}
    routes = {**BASE, ("POST", "/isp/upload"): (200, {"success": False, "etat": "en_cours", "travail": "ab12", "name": "mon-blog", "files_count": 7, "content_type": "static"}),
              ("GET", "/isp/travail/ab12"): (200, travail), ("GET", "metablogizer:/site/mon-blog/chaine"): (200, CHAINE),
              ("GET", "/bundle/mon-blog/qrcode"): (200, {"qrcode": "data:image/png;base64,iVBORw0KGgo="}),
              ("POST", "metablogizer:/site/mon-blog/cert"): (200, {"ok": True})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/publish/", routes, jeton="tk")
    prete(p)
    assert p.get_attribute("#pas li[data-pas='1']", "aria-current") == "step"
    p.set_input_files("#fileInput", {"name": "lisezmoi.txt", "mimeType": "text/plain", "buffer": b"x"})
    assert "Choisir un fichier" in p.inner_text("#rDepot") and p.is_hidden("#etape2")
    depose(p)
    assert p.is_visible("#etape2") and p.get_attribute("#pas li[data-pas='2']", "aria-current") == "step"
    assert p.input_value("#ispName") == "mon-blog" and p.inner_text("#detectedType") == "hugo" and "Ko" in p.inner_text("#fileSize")
    p.fill("#ispDomain", "mon-blog.box.test"); p.uncheck("#ispAutoPublish")
    p.click("#btnPublier")
    assert p.is_visible("#etape3")
    p.wait_for_selector("#etape4:not([hidden])", timeout=8000)
    assert p.get_attribute("#pas li[data-pas='4']", "aria-current") == "step"
    up = [a for a in appels if a[2] == "/isp/upload"][0]
    assert up[4] == "Bearer tk"
    for champ in ('name="file"', 'filename="mon-blog.zip"', 'name="name"', "mon-blog", 'name="domain"', "mon-blog.box.test", 'name="auto_publish"', "false"):
        assert champ in up[3], champ
    assert p.inner_text("#resultUrl") == "https://mon-blog.box.test" and p.inner_text("#summaryFiles") == "7"
    assert p.get_attribute("#downloadLink", "href") == "/api/v1/publish/bundle/mon-blog.zip"
    # chaîne : vhost OK, certificat à faire (bouton visible), route OK
    p.wait_for_function("document.getElementById('certStatus').textContent === 'À FAIRE'")
    assert p.inner_text("#vhostStatus") == "OK" and p.is_hidden("#createVhostBtn") and p.is_visible("#createCertBtn")
    p.click("#createCertBtn")
    p.wait_for_function("document.getElementById('rChaine').textContent.includes('demandé')")
    assert any(a[:3] == ("POST", "metablogizer", "/site/mon-blog/cert") for a in appels)
    # QR et commandes
    p.click("#btnQr"); p.wait_for_selector("#qrCodeContainer:not([hidden])")
    assert p.get_attribute("#btnQr", "aria-expanded") == "true"
    p.click("#btnCmd"); assert "metactl publish mon-blog" in p.inner_text("#cliCommands")
    # autre publication
    p.click("#btnAutre")
    assert p.is_visible("#etape1") and p.is_hidden("#qrCodeContainer") and p.input_value("#ispName") == ""
    assert err == []
    ctx.close()


def test_assistant_route_waf_et_exposition(navigateur):
    routes = {**BASE, ("POST", "/isp/upload"): (200, {"success": True, "name": "page", "domain": "page.box.test", "url": "https://page.box.test"}),
              ("GET", "metablogizer:/site/page/chaine"): (404, {})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/publish/", routes)
    prete(p); depose(p, "page.html"); p.click("#btnPublier")
    p.wait_for_selector("#etape4:not([hidden])")
    p.wait_for_function("document.getElementById('rChaine').textContent.includes('site absent')")
    p.click("#createWafBtn")
    p.wait_for_function("document.getElementById('rChaine').textContent.includes('Ajouter')")
    exp = [a for a in appels if a[2] == "/site/page/exposure"][0]
    assert json.loads(exp[3]) == {"wan": True}
    assert err == []
    ctx.close()


def test_assistant_echec_du_serveur(navigateur):
    routes = {**BASE, ("POST", "/isp/upload"): (400, {"detail": "Nom invalide"})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/publish/", routes)
    prete(p); depose(p); p.click("#btnPublier")
    p.wait_for_selector("#etapeErr:not([hidden])")
    assert p.inner_text("#errorMessage") == "Nom invalide" and p.is_hidden("#etape4")
    assert p.locator("#pas li.echec").count() == 1
    p.click("#btnRetry"); assert p.is_visible("#etape1")
    # succès faux sans travail : jamais d'écran de succès
    routes[("POST", "/isp/upload")] = (200, {"success": False, "message": "Publication refusée par le test"})
    depose(p); p.click("#btnPublier")
    p.wait_for_selector("#etapeErr:not([hidden])")
    assert "refusée par le test" in p.inner_text("#errorMessage") and p.is_hidden("#etape4")
    assert err == []
    ctx.close()


def test_assistant_travail_en_echec(navigateur):
    routes = {**BASE, ("POST", "/isp/upload"): (200, {"success": False, "etat": "en_cours", "travail": "zz", "name": "x"}),
              ("GET", "/isp/travail/zz"): (200, {"etat": "echec", "detail": "certificat refusé", "etapes": [{"libelle": "Certificat", "etat": "echec", "detail": "ACME"}]})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/publish/", routes)
    prete(p); depose(p); p.click("#btnPublier")
    p.wait_for_selector("#etapeErr:not([hidden])", timeout=8000)
    assert "certificat refusé" in p.inner_text("#errorMessage")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    routes = {("GET", "/overview"): (401, {"detail": "jeton requis"})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/publish/", routes)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tApps", "#tProjets", "#tFichiers", "#tSites")] == ["—"] * 4 and err == []
    assert p.url == "http://sbx.test/publish/"                 # plus de redirection vers /login.html
    ctx.close()


def test_demonstration_annoncee_et_aucune_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/publish/?demo=1", {})
    prete(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tSites") == "2"
    p.get_by_role("button", name="Déployer explorateur-demo").click()
    p.fill("#appName", "x"); p.click("#btnApp")
    assert "inerte" in p.inner_text("#rCreation")
    p.click("#tab-sites"); p.click("#btnTousSites")
    p.wait_for_function("document.getElementById('healthGreen').textContent.startsWith('1')")
    depose(p, "demo.zip"); p.click("#btnPublier")
    p.wait_for_selector("#etape4:not([hidden])")
    p.click("#createCertBtn")
    assert "inerte" in p.inner_text("#rChaine")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/publish/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    prete(p)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    depose(p, "demo.zip"); assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    p.click("#btnPublier"); p.wait_for_selector("#etape4:not([hidden])")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    p.click("#tab-sites"); assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


def test_focus_visible_et_zone_de_depot_au_clavier(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/publish/?demo=1", {})
    prete(p)
    p.focus("#dropZone")
    assert p.evaluate("getComputedStyle(document.activeElement).outlineStyle") != "none"
    with p.expect_file_chooser():
        p.keyboard.press("Enter")
    assert err == []
    ctx.close()
