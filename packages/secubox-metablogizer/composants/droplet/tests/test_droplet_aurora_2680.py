# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2680 — Droplet (index.html, admin) et depot.html (PUBLIC) au profil Aurora : statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "droplet"
IDX = (WWW / "index.html").read_text(encoding="utf-8")
DEP = (WWW / "depot.html").read_text(encoding="utf-8")
NGINX = (Path(__file__).resolve().parents[1] / "nginx" / "depot-vhost.conf").read_text(encoding="utf-8")


# ───────────────────────── statique : index.html ─────────────────────────
def test_index_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in IDX
    assert re.findall(r'<script src="([^"]+)"', IDX) == []          # le menu est injecté par le script, hors démo et hors embed
    assert "fonts.googleapis" not in IDX and "hybrid-dark" not in IDX and "crt-" not in IDX
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in IDX
    assert "lorem" not in IDX.lower()
    assert "sbxVue" in IDX and "onglet: 'droplet'" in IDX and "demo" in IDX.lower() and "embed" in IDX
    assert "/shared/sidebar.js" in IDX and "if (EMBED)" in IDX


def test_index_routes_et_contrat_a_l_identique():
    # ancienne page : GET /status, GET /list, POST /upload (FormData file/name/domain), GET /job/<id>, POST /remove {name}
    for r in ("const API = '/api/v1/droplet'", "lire('/status')", "lire('/list')", "API + '/upload'", "lire('/job/'", "API + '/remove'"):
        assert r in IDX
    assert "method: 'POST'" in IDX and "JSON.stringify({ name: nom })" in IDX and "'Content-Type': 'application/json'" in IDX
    assert "corps.append('file', f[0])" in IDX and "corps.append('name', nom)" in IDX and "corps.append('domain', domaine)" in IDX
    assert 'accept=".zip,.html,.tar.gz"' in IDX
    assert "localStorage.getItem('sbx_token')" in IDX and "'Bearer ' + t" in IDX
    assert "setItem" not in IDX


# ───────────────────────── statique : depot.html (public) ─────────────────────────
def test_depot_public_aucun_menu_jeton_ni_ressource_distante():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in DEP
    assert "<script src=" not in DEP and "<link" not in DEP and "@import" not in DEP
    assert not re.search(r'(src|href)="https?://', DEP)
    assert "sidebar" not in DEP and "sbx_token" not in DEP and "localStorage" not in DEP and "Authorization" not in DEP
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "eval("):
        assert interdit not in DEP
    assert "lorem" not in DEP.lower()
    assert 'name="robots" content="noindex, nofollow"' in DEP
    assert "sbxVue" in DEP and "onglet: 'depot'" in DEP and "demo" in DEP.lower() and "embed" in DEP


def test_depot_contrat_inchange_et_formulaire_sans_script():
    # le formulaire dépose même sans script
    assert re.search(r'<form id="f" method="post" enctype="multipart/form-data"\s+action="/api/v1/droplet/depot"', DEP)
    assert 'name="fichiers" multiple' in DEP and 'name="mot"' in DEP and 'maxlength="2000"' in DEP
    assert "fetch(API + '/depot/reglages')" in DEP and "x.open('POST', API + '/depot')" in DEP
    assert "corps.append('fichiers', f, f.name)" in DEP and "corps.append('mot'" in DEP
    assert "XMLHttpRequest" in DEP and "x.upload.addEventListener('progress'" in DEP
    assert "setRequestHeader" not in DEP                      # aucun en-tête posé, comme avant
    assert "d.alerte.ok === false" in DEP and "'Référence : ' + d.depot" in DEP


def test_depot_vhost_public_sert_la_page_et_trois_routes_seulement():
    assert "try_files /droplet/depot.html =404" in NGINX
    assert re.findall(r"location (?:= )?(\S+) \{", NGINX) == ["/", "/api/v1/droplet/depot", "/api/v1/droplet/depot/reglages", "/"]
    assert "location / { return 404; }" in NGINX


# ───────────────────────── navigateur ─────────────────────────
playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes, taille=None, page_src=IDX, nom="droplet", seuil=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, distants = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == nom:
            r.fulfill(status=200, content_type="text/html", body=page_src)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/droplet", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data_buffer, r.request.headers))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/droplet/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


STATUS = {"upload_dir": "/srv/droplet", "default_domain": "example.org", "sites_count": 2, "apps_count": 1}
LISTE = {"droplets": [{"name": "atelier", "domain": "atelier.example.org", "type": "static", "enabled": True},
                      {"name": "tdb", "domain": "tdb.example.org", "type": "streamlit", "enabled": False}]}
API = {"/status": (200, STATUS), "/list": (200, LISTE)}


def attend_liste(p):
    p.wait_for_function("document.querySelectorAll('#bListe td.act').length > 0")


def test_index_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/droplet/", API)
    attend_liste(p)
    assert [p.inner_text(i) for i in ("#tTotal", "#tSites", "#tApps")] == ["2", "2", "1"]
    assert p.inner_text("#etat") == "ACTIF"
    t = p.inner_text("#bListe")
    assert "atelier" in t and "tdb.example.org" in t and "Activé" in t and "Désactivé" in t
    assert p.get_attribute("#bListe a", "href") == "https://atelier.example.org"
    assert all(p.get_attribute(s, "title") for s in (".tuile >> nth=0", ".tuile >> nth=1", ".tuile >> nth=2"))
    assert err == []
    ctx.close()


def test_index_mesure_absente_est_un_tiret(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/droplet/", {"/status": (200, {}), "/list": (200, {"droplets": []})})
    p.wait_for_function("document.getElementById('etat').textContent == 'ACTIF'")
    assert [p.inner_text(i) for i in ("#tTotal", "#tSites", "#tApps")] == ["0", "—", "—"]    # 0 est une mesure, l'absence est « — »
    assert "Aucun droplet" in p.inner_text("#bListe") and err == []
    ctx.close()


def test_index_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/droplet/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tSites", "#tApps")] == ["—"] * 3 and err == []
    assert "login.html" in p.get_attribute("#session a", "href")
    ctx.close()


def test_index_jeton_bearer_dans_les_lectures(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/droplet/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')"); p.reload()
    attend_liste(p)
    lectures = [a for a in appels if a[0] == "GET"]
    assert lectures[-1][3].get("authorization") == "Bearer jeton-test"
    ctx.close()


def test_index_retrait_demande_confirmation_puis_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/droplet/", {**API, "/remove": (200, {"success": True})})
    attend_liste(p)
    p.locator("#bListe tr").first.get_by_text("Retirer").click()
    assert not [a for a in appels if a[1] == "/remove"]            # pas encore : il faut confirmer
    p.locator("#bListe tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('retiré')")
    post = [a for a in appels if a[1] == "/remove"][0]
    assert post[0] == "POST" and json.loads(post[2]) == {"name": "atelier"}
    assert post[3]["content-type"] == "application/json"
    ctx.close()


def test_index_retrait_annule_ou_refuse(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/droplet/", {**API, "/remove": (200, {"success": False, "message": "introuvable"})})
    attend_liste(p)
    p.locator("#bListe tr").first.get_by_text("Retirer").click()
    p.locator("#bListe tr").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[1] == "/remove"]
    p.locator("#bListe tr").first.get_by_text("Retirer").click()
    p.locator("#bListe tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('introuvable')")
    ctx.close()


def test_index_publication_multipart_a_l_identique_et_suivi(navigateur, tmp_path):
    routes = {**API, "/upload": (200, {"status": "started", "job_id": "42_ab"}),
              "/job/42_ab": (200, {"status": "complete", "success": True, "vhost": "site.example.org", "url": "https://site.example.org"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/droplet/", routes)
    attend_liste(p)
    p.click("#btnEnvoi")
    assert "fichier" in p.inner_text("#rEnvoi")                    # pas de fichier : message dans la page
    z = tmp_path / "site.zip"; z.write_bytes(b"PK-contenu")
    p.set_input_files("#fichier", str(z))
    assert p.inner_text("#zoneTitre") == "site.zip"
    p.click("#btnEnvoi")
    assert "nom" in p.inner_text("#rEnvoi")
    p.fill("#nom", "site"); p.fill("#domaine", "site.example.org")
    p.click("#btnEnvoi")
    p.wait_for_function("document.getElementById('rEnvoi').textContent.includes('Publié')")
    up = [a for a in appels if a[1] == "/upload"][0]
    corps = up[2].decode("latin-1")
    assert up[0] == "POST" and up[3]["content-type"].startswith("multipart/form-data")
    assert 'name="file"; filename="site.zip"' in corps and 'name="name"' in corps and "site" in corps and 'name="domain"' in corps
    assert "content-type" in up[3] and "authorization" not in up[3]          # pas de jeton posé : aucun n'existe dans ce navigateur
    assert p.get_attribute("#rEnvoi a", "href") == "https://site.example.org"
    assert [a for a in appels if a[1] == "/job/42_ab"]
    assert err == []
    ctx.close()


def test_index_domaine_vide_n_est_pas_envoye(navigateur, tmp_path):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/droplet/", {**API, "/upload": (200, {"detail": "Invalid file type"})})
    attend_liste(p)
    z = tmp_path / "a.zip"; z.write_bytes(b"x")
    p.set_input_files("#fichier", str(z)); p.fill("#nom", "a"); p.click("#btnEnvoi")
    p.wait_for_function("document.getElementById('rEnvoi').textContent.includes('Invalid file type')")
    assert 'name="domain"' not in [a for a in appels if a[1] == "/upload"][0][2].decode("latin-1")
    ctx.close()


def test_index_demonstration_annoncee_et_actions_inertes(navigateur, tmp_path):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/droplet/?demo=1", {})
    attend_liste(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert [p.inner_text(i) for i in ("#tTotal", "#tSites", "#tApps")] == ["3", "2", "1"]
    p.locator("#bListe tr").first.get_by_text("Retirer").click()
    p.locator("#bListe tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('inerte')")
    z = tmp_path / "d.zip"; z.write_bytes(b"x")
    p.set_input_files("#fichier", str(z)); p.fill("#nom", "d"); p.click("#btnEnvoi")
    p.wait_for_function("document.getElementById('rEnvoi').textContent.includes('inerte')")
    assert appels == [] and err == []
    assert p.evaluate("document.querySelectorAll('script[src]').length") == 0           # pas de menu en démonstration
    ctx.close()


def test_index_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/droplet/?embed=1", API, taille={"width": 420, "height": 800})
    attend_liste(p)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


def test_index_menu_commun_charge_hors_embed(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/droplet/", API)
    attend_liste(p)
    assert p.evaluate("document.querySelectorAll('script[src=\"/shared/sidebar.js\"]').length") == 1
    ctx.close()


# ── depot.html ──
REGL = {"/depot/reglages": (200, {"actif": True, "taille_max": 5368709120, "fichiers_max": 5})}
DEPOT_OK = {**REGL, "/depot": (201, {"ok": True, "depot": "20261014-abc", "alerte": {"ok": True}})}


def depot(navigateur, routes, url="http://sbx.test/depot/", **kw):
    return ouvre(navigateur, url, routes, page_src=DEP, nom="depot", **kw)


def fichiers(tmp_path, *noms):
    out = []
    for n in noms:
        f = tmp_path / n; f.write_bytes(b"x" * 2048); out.append(str(f))
    return out


def test_depot_plafonds_demandes_au_serveur_et_tuiles(navigateur):
    ctx, p, err, appels = depot(navigateur, REGL)
    p.wait_for_function("document.getElementById('ouverture').textContent == 'OUVERT'")
    assert p.inner_text("#tTaille") == "5.0 Gio" and p.inner_text("#tMax") == "5"
    assert "5.0 Gio par fichier, 5 fichiers" in p.inner_text("#indice")
    assert [a[:2] for a in appels] == [("GET", "/depot/reglages")]
    assert "authorization" not in appels[0][3]                       # page publique : jamais de jeton
    assert all(p.get_attribute(f".tuile >> nth={i}", "title") for i in range(3))
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


def test_depot_reglages_absents_tirets_et_page_utilisable(navigateur, tmp_path):
    ctx, p, err, _ = depot(navigateur, {})
    p.wait_for_timeout(300)
    assert p.inner_text("#tTaille") == "—" and p.inner_text("#tMax") == "—" and p.inner_text("#ouverture") == "—"
    p.set_input_files("#fichiers", fichiers(tmp_path, "a.txt"))
    assert not p.is_disabled("#envoyer") and err == []
    ctx.close()


def test_depot_ferme(navigateur):
    ctx, p, _, _ = depot(navigateur, {"/depot/reglages": (200, {"actif": False, "taille_max": 0, "fichiers_max": 20})})
    p.wait_for_function("document.getElementById('ouverture').textContent == 'FERMÉ'")
    assert p.is_disabled("#fichiers") and "fermé" in p.inner_text("#etat")
    ctx.close()


def test_depot_selection_retrait_et_plafond_de_fichiers(navigateur, tmp_path):
    ctx, p, err, _ = depot(navigateur, REGL)
    p.wait_for_function("document.getElementById('ouverture').textContent == 'OUVERT'")
    assert p.is_disabled("#envoyer")
    p.set_input_files("#fichiers", fichiers(tmp_path, "a.txt", "<b>b<i>.txt"))
    assert p.inner_text("#tSel") == "2" and "2 fichier(s)" in p.inner_text("#total")
    assert p.locator("#liste b").count() == 0                          # le nom est du texte, jamais du balisage
    p.locator("#liste li").first.get_by_role("button").click()
    assert p.inner_text("#tSel") == "1"
    p.set_input_files("#fichiers", fichiers(tmp_path, "c1", "c2", "c3", "c4", "c5", "c6"))
    assert p.inner_text("#tSel") == "5" and "Maximum 5" in p.inner_text("#etat") and err == []
    ctx.close()


def test_depot_envoi_multipart_sans_entete_ni_jeton(navigateur, tmp_path):
    ctx, p, err, appels = depot(navigateur, DEPOT_OK)
    p.wait_for_function("document.getElementById('ouverture').textContent == 'OUVERT'")
    p.evaluate("localStorage.setItem('sbx_token','ne-doit-pas-partir')")
    p.set_input_files("#fichiers", fichiers(tmp_path, "a.txt", "b.txt"))
    p.fill("#mot", "bonjour")
    p.click("#envoyer")
    p.wait_for_selector("#message.bien")
    post = [a for a in appels if a[0] == "POST"][0]
    corps = post[2].decode("latin-1")
    assert post[1] == "/depot" and post[3]["content-type"].startswith("multipart/form-data")
    assert corps.count('name="fichiers"; filename=') == 2 and 'name="mot"' in corps and "bonjour" in corps
    assert "authorization" not in post[3]
    t = p.inner_text("#message")
    assert "Dépôt reçu." in t and "Référence : 20261014-abc" in t and "va en être averti" in t
    assert p.inner_text("#tSel") == "0" and p.input_value("#mot") == "" and err == []
    ctx.close()


def test_depot_alerte_en_echec_et_refus_serveur(navigateur, tmp_path):
    ctx, p, _, _ = depot(navigateur, {**REGL, "/depot": (201, {"ok": True, "depot": "x1", "alerte": {"ok": False}})})
    p.set_input_files("#fichiers", fichiers(tmp_path, "a.txt")); p.click("#envoyer")
    p.wait_for_selector("#message.bien")
    assert "pas pu être prévenu" in p.inner_text("#message")
    ctx.close()
    ctx, p, _, _ = depot(navigateur, {**REGL, "/depot": (429, {"detail": "quota horaire atteint"})})
    p.set_input_files("#fichiers", fichiers(tmp_path, "a.txt")); p.click("#envoyer")
    p.wait_for_selector("#message.mal")
    assert "quota horaire atteint" in p.inner_text("#message") and not p.is_disabled("#envoyer")
    ctx.close()


def test_depot_demonstration_inerte(navigateur, tmp_path):
    ctx, p, err, appels = depot(navigateur, {}, url="http://sbx.test/depot/?demo=1")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tTaille") == "2.0 Gio" and p.inner_text("#ouverture") == "OUVERT"
    p.set_input_files("#fichiers", fichiers(tmp_path, "a.txt")); p.click("#envoyer")
    p.wait_for_selector("#message.demo-msg")
    assert "inerte" in p.inner_text("#message") and appels == [] and err == []
    ctx.close()


def test_depot_telephone_sans_debordement(navigateur, tmp_path):
    ctx, p, err, _ = depot(navigateur, REGL, url="http://sbx.test/depot/?embed=1", taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('ouverture').textContent == 'OUVERT'")
    p.set_input_files("#fichiers", fichiers(tmp_path, "un-nom-de-fichier-vraiment-tres-long-" + "x" * 80 + ".tar.gz"))
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()
