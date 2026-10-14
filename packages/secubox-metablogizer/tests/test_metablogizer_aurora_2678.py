# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2678 — console MetaBlogizer (index.html, site.html) au profil Aurora : tests statiques + vrai navigateur, API simulée.

Les pages `index.html` et `site.html` sont des pages d'ADMINISTRATION (liées entre elles, derrière le menu). `empty-site.html`,
elle, est servie aux VISITEURS par nginx (`error_page 404`) : c'est du contenu publié, elle n'est pas passée à Aurora.
"""
import json
import re
import time
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "metablogizer"
INDEX = (WWW / "index.html").read_text(encoding="utf-8")
SITE = (WWW / "site.html").read_text(encoding="utf-8")
VISITEUR = (WWW / "empty-site.html").read_text(encoding="utf-8")
PAGES = {"index": INDEX, "site": SITE}


@pytest.mark.parametrize("nom", ["index", "site"])
def test_page_autonome_sans_dialogue_natif(nom):
    src = PAGES[nom]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in src
    assert re.findall(r'<script src="([^"]+)"', src) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in src and "crt-light" not in src and "googleapis" not in src and "hybrid-skin" not in src
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "oninput=", "onerror="):
        assert interdit not in src
    assert "lorem" not in src.lower() and "Math.random" not in src and "setItem" not in src
    assert "sbxVue" in src and "demo" in src.lower() and "embed" in src
    assert "localStorage.getItem('sbx_token')" in src


def test_index_routes_a_l_identique():
    for r in ("'/sites'", "'/status'", "'/deploys'", "'/sites/refresh'", "'/republish-all'", "'/site'", "/publish/wizard?flux=1",
              "'/upload'", "/publish/export/", "'/publish' : '/unpublish'", "'/deploy'", "'DELETE'", "/screenshot"):
        assert r in INDEX, r
    assert "{ name: nom, domain: domaine }" in INDEX and "fd.append('name', nom)" in INDEX and "fd.append('file', f)" in INDEX
    assert "vue-mosaique" in INDEX and "'mosaique'" in INDEX and "site.html?name=" in INDEX


def test_site_routes_a_l_identique():
    for r in ("'/chaine'", "'/unpublish'", "'/publish'", "'/exposure'", "'/cert'", "'/vhost'", "'/dns'", "'/upload'", "'/snapshot'", "'PUT'", "/screenshot"):
        assert r in SITE, r
    for champ in ("domain:", "title:", "description:", "category:", "tags:", "source_url:", "gitea_repo:", "aliases:"):
        assert champ in SITE
    assert "{ wan }" in SITE and "edit" in SITE and "httpOnly" in SITE


def test_page_visiteur_non_touchee():
    # Gabarit de contenu publié (nginx error_page 404) : son style est le choix de l'auteur du site, pas d'Aurora.
    assert "--cyan: #00d4ff" in VISITEUR and "--fond: #0b1014" in VISITEUR and "sbxVue" not in VISITEUR


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
ISO = lambda s: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - s))  # noqa: E731
STATUS = {"site_count": 3, "published_count": 2}
SITES = {"available": True, "reason": None, "cache_age_seconds": 120, "sites": [
    {"name": "alpha", "domain": "alpha.example.org", "published": True, "version": "v1.2.0", "last_updated": ISO(7200), "size": "12M", "category": "blog"},
    {"name": "beta", "domain": "beta.example.org", "published": False, "version": "", "last_updated": "", "size": "4K"},
    {"name": "gamma", "domain": "gamma.example.org", "published": True, "version": "v0.1", "last_updated": ISO(90000), "size": "2M", "screenshot_captured_at": "2026-10-01"},
]}
DEPLOYS = {"deploys": [{"source": "webhook", "site": "alpha", "from": "aaaaaaaa11", "to": "bbbbbbbb22", "duration_ms": 1500, "timestamp": NOW - 600},
                       {"source": "manual", "site": "gamma", "from": "cccccccc33", "to": "dddddddd44", "duration_ms": 800, "domain_changed": True, "timestamp": NOW - 3 * 86400}]}
API = {("GET", "/status"): (200, STATUS), ("GET", "/sites"): (200, SITES), ("GET", "/deploys"): (200, DEPLOYS)}

MAILLONS = {k: {"ok": True, "detail": "ok " + k} for k in ("contenu", "domaine", "vhost", "route", "dns", "cert")}
MAILLONS["dns"] = {"ok": False, "detail": "ne résout pas"}
MAILLONS["cert"] = {"ok": True, "detail": "valide", "jours_restants": 60}
CHAINE = {"published": True, "intention": True, "exposition": "lan", "domain": "alpha.example.org", "wildcard": False, "maillons": MAILLONS}
FICHE = {"name": "alpha", "domain": "alpha.example.org", "published": True, "version": "v1.2.0", "last_updated": ISO(7200), "title": "Alpha", "description": "d",
         "category": "blog", "tags": ["a", "b"], "aliases": ["www.alpha.example.org"], "source_url": "https://example.org/a.git", "gitea_repo": "javascript:alert(1)"}
API_SITE = {("GET", "/site/alpha"): (200, FICHE), ("GET", "/site/alpha/chaine"): (200, CHAINE)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900}, accept_downloads=True)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin == "metablogizer/index.html":
            r.fulfill(status=200, content_type="text/html", body=INDEX)
        elif chemin == "metablogizer/site.html":
            r.fulfill(status=200, content_type="text/html", body=SITE)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/metablogizer", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        defaut = (404, {}) if r.request.method == "GET" else (200, {"success": True})
        statut, corps = routes.get((r.request.method, chemin), defaut)
        if isinstance(corps, str):
            r.fulfill(status=statut, content_type="application/x-ndjson", body=corps)
        else:
            r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/metablogizer/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def pret(p):
    p.wait_for_selector("#mosaique .vignette")


def vignette(p, nom):
    return p.locator("#mosaique .vignette").filter(has_text=nom)


def test_tuiles_mosaique_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", API)
    pret(p)
    assert [p.inner_text(i) for i in ("#tTotal", "#tPublies", "#tDomaine", "#tDeploys")] == ["3", "2", "3/3", "1"]
    assert p.inner_text("#etat") == "EN SERVICE"
    assert vignette(p, "alpha").count() == 1 and "non publié" in vignette(p, "beta").inner_text()
    assert "maj il y a 2 min" in p.inner_text("#cCache")
    p.click("#tab-sites")
    p.wait_for_selector("#bSites tr")
    t = p.inner_text("#bSites")
    assert "alpha" in t and "v1.2.0" in t and "12M" in t and "2 h" in t and "1970" not in t
    p.click("#tab-deploys")
    d = p.inner_text("#bDeploys")
    assert "webhook" in d and "aaaaaaaa → bbbbbbbb" in d and "1500 ms" in d and "domaine modifié" in d
    assert err == []
    ctx.close()


def test_tri_et_filtre_cote_client(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", API)
    pret(p)
    p.click("#tab-sites"); p.wait_for_selector("#bSites tr")
    p.click("th button[data-tri=name]"); p.click("th button[data-tri=name]")
    assert p.locator("#bSites tr").first.inner_text().startswith("gamma")
    p.fill("#fSites", "bet")
    assert p.locator("#bSites tr").count() == 1 and p.inner_text("#cSites") == "1 / 3"
    assert [a for a in appels if a[0] != "GET"] == []
    ctx.close()


def test_publier_envoie_le_meme_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", API)
    pret(p)
    vignette(p, "beta").get_by_text("hors ligne").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('publié')")
    assert ("POST", "/site/beta/publish", None) in appels
    assert err == []
    ctx.close()


def test_depublier_se_confirme_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", API)
    pret(p)
    vignette(p, "alpha").get_by_text("en ligne").click()
    assert not [a for a in appels if a[0] == "POST"]
    assert "Retirer" in vignette(p, "alpha").inner_text()
    vignette(p, "alpha").get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "POST"]
    vignette(p, "alpha").get_by_text("en ligne").click()
    vignette(p, "alpha").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('retiré')")
    assert ("POST", "/site/alpha/unpublish", None) in appels and err == []
    ctx.close()


def test_supprimer_se_confirme_dans_la_ligne(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", API)
    pret(p); p.click("#tab-sites"); p.wait_for_selector("#bSites tr")
    ligne = p.locator("#bSites tr").filter(has_text="beta")
    ligne.get_by_title("Supprimer le site").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    ligne.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('supprimé')")
    assert ("DELETE", "/site/beta", None) in appels
    ctx.close()


def test_mise_a_jour_git(navigateur):
    routes = {**API, ("POST", "/site/alpha/deploy"): (200, {"success": True, "updated": True, "from": "aaaaaaaa11", "to": "bbbbbbbb22"})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", routes)
    pret(p); p.click("#tab-sites"); p.wait_for_selector("#bSites tr")
    p.locator("#bSites tr").filter(has_text="alpha").get_by_title("Mettre à jour — git pull").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('aaaaaaaa → bbbbbbbb')")
    assert ("POST", "/site/alpha/deploy", None) in appels
    ctx.close()


def test_televerser_le_contenu_d_un_site(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", {**API, ("POST", "/site/alpha/upload"): (200, {"success": True, "kind": "zip"})})
    pret(p); p.click("#tab-sites"); p.wait_for_selector("#bSites tr")
    with p.expect_file_chooser() as fc:
        p.locator("#bSites tr").filter(has_text="alpha").get_by_title("Charger un contenu").click()
    fc.value.set_files({"name": "s.zip", "mimeType": "application/zip", "buffer": b"PK"})
    p.wait_for_function("document.getElementById('toast').textContent.includes('(zip)')")
    assert [a[:2] for a in appels if a[1].endswith("/upload")] == [("POST", "/site/alpha/upload")]
    ctx.close()


def test_creer_un_site_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", API)
    pret(p)
    p.click("#btnNouveau"); p.fill("#nNom", "neuf"); p.fill("#nDomaine", "neuf.example.org"); p.click("#btnCreer")
    p.wait_for_function("document.getElementById('toast').textContent.includes('créé')")
    assert json.loads([a for a in appels if a[:2] == ("POST", "/site")][0][2]) == {"name": "neuf", "domain": "neuf.example.org"}
    ctx.close()


def test_republier_tout(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", {**API, ("POST", "/republish-all"): (200, {"success": True, "sites_published": 3})})
    pret(p); p.click("#btnRepublier")
    p.wait_for_function("document.getElementById('toast').textContent.includes('3 sites publiés')")
    assert ("POST", "/republish-all", None) in appels
    ctx.close()


def test_assistant_suit_le_flux_du_serveur(navigateur):
    flux = "\n".join(json.dumps(m) for m in [
        {"type": "debut", "etapes": [{"cle": "git", "libelle": "Dépôt"}, {"cle": "nginx", "libelle": "Service"}]},
        {"type": "etape", "cle": "git", "etat": "ok"},
        {"type": "etape", "cle": "nginx", "etat": "ko", "detail": "nginx -t refuse"},
        {"type": "fin", "ok": False}]) + "\n"
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", {**API, ("POST", "/publish/wizard"): (200, flux)})
    pret(p); p.click("#tab-sites")
    p.click("#wizGo")
    assert "nom et fichier requis" in p.inner_text("#wizResultat")
    p.fill("#wizNom", "zem"); p.fill("#wizDomaine", "zem.example.org")
    p.set_input_files("#wizFichier", {"name": "s.zip", "mimeType": "application/zip", "buffer": b"PK"})
    p.click("#wizGo")
    p.wait_for_function("document.getElementById('wizResultat').textContent.includes('Publication incomplète')")
    assert "Service" in p.inner_text("#wizResultat") and p.locator("#wizEtapes span.ok").count() == 1 and p.locator("#wizEtapes span.fail").count() == 1
    assert not p.is_disabled("#wizGo") and p.is_disabled("#wizSauvegarde")
    assert [a[:2] for a in appels if a[1] == "/publish/wizard"] == [("POST", "/publish/wizard")] and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tPublies", "#tDomaine", "#tDeploys")] == ["—"] * 4 and err == []
    ctx.close()


def test_cache_absent_n_est_pas_une_flotte_vide(navigateur):
    absent = {**API, ("GET", "/sites"): (200, {"available": False, "reason": "cache not written yet", "sites": []})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/metablogizer/index.html", absent)
    p.wait_for_function("document.getElementById('etat').textContent === 'CACHE ABSENT'")
    assert "indisponible" in p.inner_text("#mosaique") and "Aucun site publié" not in p.inner_text("#mosaique")
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/metablogizer/index.html?demo=1", {})
    pret(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    vignette(p, "brouillon").get_by_text("hors ligne").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.click("#btnRepublier")
    p.click("#tab-sites"); p.fill("#wizNom", "x"); p.click("#wizGo")
    assert "inerte" in p.inner_text("#wizResultat")
    assert appels == [] and err == []
    ctx.close()


def test_vue_mosaique_du_hall_est_en_lecture(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metablogizer/index.html?vue=mosaique", API)
    pret(p)
    for sel in (".tuiles", ".onglets", "#btnRepublier", "#btnNouveau", "#sidebar", ".vignette .pied"):
        assert not p.locator(sel).first.is_visible(), sel
    assert p.is_visible("#mosaique") and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metablogizer/index.html?embed=1", API, taille={"width": 420, "height": 800})
    pret(p)
    for onglet in ("#tab-sites", "#tab-deploys", "#tab-mosaique"):
        p.click(onglet)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), onglet
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


# ----- site.html -----

def site(navigateur, routes=None, taille=None, query="?name=alpha"):
    return ouvre(navigateur, "http://sbx.test/metablogizer/site.html" + query, {**API_SITE, **(routes or {})}, taille)


def test_site_fiche_et_chaine_viennent_de_l_api(navigateur):
    ctx, p, err, _ = site(navigateur)
    p.wait_for_function("document.getElementById('m-cert').textContent.includes('✓')")
    assert p.inner_text("#siteNom") == "alpha" and p.inner_text("#etat") == "PUBLIÉ"
    assert p.inner_text("#m-dns .v") == "✗" and "ne résout pas" in p.inner_text("#m-dns")
    assert "alpha.example.org" in p.inner_text("#etatUrl") and p.inner_text("#etatExposition") == "LAN seulement"
    m = p.inner_text("#meta")
    assert "v1.2.0" in m and "www.alpha.example.org" in m and "Alpha" in m
    assert p.is_hidden("#lienGitea") and p.get_attribute("#lienSource", "href") == "https://example.org/a.git"   # javascript: refusé
    assert p.get_attribute("#btnPublier", "class").endswith("warn") and err == []
    ctx.close()


def test_site_depublier_se_confirme_dans_la_page(navigateur):
    ctx, p, err, appels = site(navigateur)
    p.wait_for_function("document.getElementById('m-cert').textContent.includes('✓')")
    p.click("#btnPublier")
    assert p.is_visible("#confirmeDepub") and not [a for a in appels if a[0] == "POST"]
    p.click("#btnConfirmer")
    p.wait_for_function("document.getElementById('journal').textContent.includes('Dépublication —')")
    assert ("POST", "/site/alpha/unpublish", None) in appels and err == []
    ctx.close()


def test_site_exposition_corps_et_vhost(navigateur):
    ctx, p, _, appels = site(navigateur)
    p.wait_for_function("document.getElementById('m-cert').textContent.includes('✓')")
    p.click("#btnExposition")
    p.wait_for_function("document.getElementById('journal').textContent.includes('Exposition WAN —')")
    assert json.loads([a for a in appels if a[1] == "/site/alpha/exposure"][0][2]) == {"wan": True}
    p.click("#btnVhost")
    p.wait_for_function("document.getElementById('journal').textContent.includes('Application du vhost —')")
    assert ("POST", "/site/alpha/vhost", None) in appels
    ctx.close()


def test_site_enregistrer_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = site(navigateur, {("PUT", "/site/alpha"): (200, {"site": {**FICHE, "title": "Neuf"}})})
    p.wait_for_function("document.getElementById('f-title').value === 'Alpha'")
    p.fill("#f-title", "Neuf"); p.fill("#f-category", ""); p.fill("#f-tags", "x, y"); p.fill("#f-aliases", "a.example.org\nb.example.org")
    p.click("#btnSauver")
    p.wait_for_function("document.getElementById('saveStatut').textContent.includes('Enregistré')")
    corps = json.loads([a for a in appels if a[0] == "PUT"][0][2])
    assert corps == {"domain": "alpha.example.org", "title": "Neuf", "description": "d", "category": None, "tags": ["x", "y"],
                     "source_url": "https://example.org/a.git", "gitea_repo": "javascript:alert(1)", "aliases": ["a.example.org", "b.example.org"]}
    ctx.close()


def test_site_validation_refusee(navigateur):
    ctx, p, _, _ = site(navigateur, {("PUT", "/site/alpha"): (422, {"detail": {"errors": ["domaine invalide"]}})})
    p.wait_for_function("document.getElementById('f-title').value === 'Alpha'")
    p.click("#btnSauver")
    p.wait_for_function("document.getElementById('saveStatut').textContent.includes('domaine invalide')")
    ctx.close()


def test_site_televerser_et_vignette(navigateur):
    ctx, p, _, appels = site(navigateur, {("POST", "/site/alpha/upload"): (200, {"success": True}), ("POST", "/site/alpha/snapshot"): (200, {"ok": True})})
    p.wait_for_function("document.getElementById('m-cert').textContent.includes('✓')")
    p.click("#btnUpload")
    assert "Choisir" in p.inner_text("#uploadStatut")
    p.set_input_files("#f-file", {"name": "s.zip", "mimeType": "application/zip", "buffer": b"PK"})
    p.click("#btnUpload")
    p.wait_for_function("document.getElementById('uploadStatut').textContent.includes('déposé')")
    p.click("#btnSnapshot")
    p.wait_for_function("document.getElementById('snapshotStatut').textContent.includes('rafraîchie')")
    assert ("POST", "/site/alpha/upload", appels[[a[1] for a in appels].index("/site/alpha/upload")][2]) in appels
    assert ("POST", "/site/alpha/snapshot", None) in appels
    ctx.close()


def test_site_sans_session_et_sans_nom(navigateur):
    ctx, p, err, _ = site(navigateur, {k: (401, {}) for k in API_SITE})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and err == []
    ctx.close()
    ctx, p, err, _ = site(navigateur, query="")
    p.wait_for_selector("#erreur:not([hidden])")
    assert "name" in p.inner_text("#erreur") and err == []
    ctx.close()


def test_site_demonstration_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/metablogizer/site.html?demo=1", {})
    p.wait_for_selector("#m-cert .v")
    assert p.is_visible("#demo") and p.inner_text("#siteNom") == "atelier"
    p.click("#btnVhost"); p.click("#btnDns"); p.click("#btnSauver")
    p.wait_for_function("document.getElementById('saveStatut').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_site_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = site(navigateur, taille={"width": 420, "height": 800}, query="?name=alpha&embed=1")
    p.wait_for_function("document.getElementById('m-cert').textContent.includes('✓')")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
