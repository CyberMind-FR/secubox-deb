# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /meshname/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants" / "meshname" / "www" / "meshname" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'meshname'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC
    assert SRC.count("<style>") == 1 and SRC.count("</style>") == 1   # le CSS est bien dans une balise style


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/enable?enabled='", "'/nodes'", "'/mappings'", "'/discover/import'", "'DELETE', '/nodes/'", "'DELETE', '/mappings/'",
              "'/service'", "'/discover'", "'/resolve/'"):
        assert r in SRC
    assert "[hostname]" in SRC                     # /discover/import prend une liste de noms d'hôte
    assert "{ name, ip, services }" in SRC and "{ hostname, ip, ttl }" in SRC
    assert "/stats" not in SRC                     # redondant avec /service : une route de moins


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


SERVICE = {"enabled": True, "mesh_domain": "mesh.local", "avahi_available": True, "dnsmasq_available": False, "nodes_count": 2,
           "mappings_count": 1, "local_hostname": "gk2", "local_ips": ["192.0.2.1", "198.51.100.7"]}
NODES = {"nodes": [{"name": "serveur1", "ip": "192.0.2.10", "services": ["http", "ssh"], "added": "2026-10-10T10:00:00"},
                   {"name": "<b>x</b>", "ip": "192.0.2.11", "services": [], "added": None}], "mesh_domain": "mesh.local"}
MAPPINGS = {"mappings": [{"hostname": "wiki.exemple.org", "ip": "192.0.2.10", "ttl": 3600, "added": "2026-10-10T10:00:00"}]}
HOSTS = {"hosts": [{"name": "n", "type": "_ssh._tcp", "hostname": "serveur1.local", "ip": "192.0.2.10", "port": "22"},
                   {"name": "p", "type": "_http._tcp", "hostname": "passerelle.local", "ip": "192.0.2.77", "port": "80"}]}
API = {"/service": (200, SERVICE), "/nodes": (200, NODES), "/mappings": (200, MAPPINGS), "/discover": (200, HOSTS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "meshname":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/meshname", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin + ("?" + r.request.url.split("?", 1)[1] if "?" in r.request.url else ""), r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {"detail": "introuvable"}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/meshname/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meshname/", API)
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tNoeuds", "#tMappages", "#tDomaine", "#tAvahi", "#tDnsmasq")] == ["2", "1", "mesh.local", "Actif", "Inactif"]
    assert p.inner_text("#etat") == "ACTIVÉ — DNSMASQ ARRÊTÉ"           # activé mais dnsmasq arrêté : dit, pas tu
    assert "serveur1.mesh.local" in p.inner_text("#bNoeuds") and "http, ssh" in p.inner_text("#bNoeuds")
    assert "wiki.exemple.org" in p.inner_text("#bMappages") and "3600 s" in p.inner_text("#bMappages")
    assert "192.0.2.1, 198.51.100.7" in p.inner_text("#kIps") and p.inner_text("#kNom") == "gk2"
    # une donnée d'API n'est jamais interprétée comme du HTML
    assert p.locator("#bNoeuds b").count() == 0 and "<b>x</b>" in p.inner_text("#bNoeuds")
    assert err == [] and not ecritures(_)
    ctx.close()


def test_retirer_un_noeud_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meshname/", API)
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    p.locator("#bNoeuds tr").first.get_by_text("Retirer").click()
    assert p.is_visible("#cNoeuds") and "serveur1.mesh.local" in p.inner_text("#cNoeuds")
    assert not ecritures(appels)                                       # pas avant la confirmation
    p.locator("#cNoeuds").get_by_text("Annuler").click()
    assert not p.is_visible("#cNoeuds") and not ecritures(appels)
    p.locator("#bNoeuds tr").first.get_by_text("Retirer").click()
    p.get_by_text("Confirmer le retrait").click()
    p.wait_for_function("document.getElementById('rNoeuds').textContent.includes('retiré')")
    assert ecritures(appels) == [("DELETE", "/nodes/serveur1", None)]
    # idem pour un mappage
    p.locator("#bMappages tr").first.get_by_text("Retirer").click()
    assert len(ecritures(appels)) == 1
    p.get_by_text("Confirmer le retrait").click()
    p.wait_for_function("document.getElementById('rMappages').textContent.includes('retiré')")
    assert ("DELETE", "/mappings/wiki.exemple.org", None) in appels and err == []
    ctx.close()


def test_ajouter_noeud_et_mappage_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meshname/", API)
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    p.click("#addNoeud")
    p.fill("#fNoeud [name=name]", "capteur"); p.fill("#fNoeud [name=ip]", "192.0.2.50"); p.fill("#fNoeud [name=services]", "mqtt, , http")
    p.click("#fNoeud button[type=submit]")
    p.wait_for_function("document.getElementById('rNoeuds').textContent.includes('enregistré')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/nodes"][0]
    assert json.loads(post[2]) == {"name": "capteur", "ip": "192.0.2.50", "services": ["mqtt", "http"]}
    p.click("#addMappage")
    p.fill("#fMappage [name=hostname]", "svc.exemple.org"); p.fill("#fMappage [name=ip]", "192.0.2.60"); p.fill("#fMappage [name=ttl]", "600")
    p.click("#fMappage button[type=submit]")
    p.wait_for_function("document.getElementById('rMappages').textContent.includes('enregistré')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/mappings"][0]
    assert json.loads(post[2]) == {"hostname": "svc.exemple.org", "ip": "192.0.2.60", "ttl": 600}
    assert err == []
    ctx.close()


def test_remplacer_un_nom_existant_demande_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/meshname/", API)
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    p.click("#addNoeud")
    p.fill("#fNoeud [name=name]", "serveur1"); p.fill("#fNoeud [name=ip]", "192.0.2.99")
    p.click("#fNoeud button[type=submit]")
    assert "existe déjà" in p.inner_text("#cNoeuds") and not ecritures(appels)
    p.get_by_text("Confirmer le remplacement").click()
    p.wait_for_function("document.getElementById('rNoeuds').textContent.includes('enregistré')")
    assert json.loads(ecritures(appels)[0][2]) == {"name": "serveur1", "ip": "192.0.2.99", "services": []}
    ctx.close()


def test_desactiver_confirme_activer_direct_et_erreur_affichee(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/meshname/", {**API, "/enable": (500, {"detail": "écriture refusée"})})
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    assert p.inner_text("#bascule") == "Désactiver"
    p.click("#bascule")
    assert not ecritures(appels) and "cesseront de se résoudre" in p.inner_text("#cService")
    p.get_by_text("Confirmer la désactivation").click()
    p.wait_for_function("document.getElementById('rService').textContent.includes('Échec')")
    assert ecritures(appels) == [("POST", "/enable?enabled=false", None)] and "écriture refusée" in p.inner_text("#rService")
    ctx.close()


def test_decouverte_et_import(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meshname/", {**API, "/discover/import": (200, {"success": True, "imported": ["passerelle"]})})
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    p.click("#decouvrir")
    p.wait_for_selector("#bDecouv td.act")
    assert "passerelle.local" in p.inner_text("#bDecouv")
    # serveur1 existe déjà : l'import ajouterait un doublon, donc confirmation
    p.locator("#bDecouv tr").nth(0).get_by_text("Importer").click()
    assert "existe déjà" in p.inner_text("#cDecouv") and not ecritures(appels)
    p.locator("#cDecouv").get_by_text("Annuler").click()
    p.locator("#bDecouv tr").nth(1).get_by_text("Importer").click()
    p.wait_for_function("document.getElementById('rDecouv').textContent.includes('Importé')")
    assert ecritures(appels) == [("POST", "/discover/import", '["passerelle.local"]')] and err == []
    ctx.close()


def test_resolution(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/meshname/", {**API, "/resolve/serveur1.mesh.local": (200, {"hostname": "serveur1.mesh.local", "ip": "192.0.2.10", "source": "mesh"})})
    p.fill("#resolNom", "serveur1.mesh.local"); p.click("#fResol button")
    p.wait_for_function("document.getElementById('rResol').textContent.includes('192.0.2.10')")
    assert "nœud du maillage" in p.inner_text("#rResol")
    p.fill("#resolNom", "inconnu.mesh.local"); p.click("#fResol button")
    p.wait_for_function("document.getElementById('rResol').textContent.includes('Introuvable')")
    assert not ecritures(appels)
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meshname/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tNoeuds", "#tMappages", "#tDomaine", "#tAvahi", "#tDnsmasq")] == ["—"] * 5
    assert p.is_disabled("#bascule") and err == []
    ctx.close()


def test_jeton_envoye(navigateur):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    vus = []
    p.route("http://sbx.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC) if r.request.url.endswith("/meshname/") else r.fulfill(status=404, body=""))
    p.route("http://sbx.test/api/v1/meshname/**", lambda r, *_: (vus.append(r.request.headers.get("authorization")), r.fulfill(status=200, content_type="application/json", body="{}")))
    p.add_init_script("localStorage.setItem('sbx_token','abc')")
    p.goto("http://sbx.test/meshname/")
    p.wait_for_function("document.getElementById('maj').textContent.startsWith('Relevé')")
    assert vus and all(v == "Bearer abc" for v in vus)
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meshname/?demo=1", {})
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tNoeuds") == "3" and "192.0.2." in p.inner_text("#bNoeuds")
    p.click("#bascule"); p.get_by_text("Confirmer la désactivation").click()
    p.wait_for_function("document.getElementById('rService').textContent.includes('inerte')")
    p.locator("#bNoeuds tr").first.get_by_text("Retirer").click(); p.get_by_text("Confirmer le retrait").click()
    p.wait_for_function("document.getElementById('rNoeuds').textContent.includes('inerte')")
    p.click("#decouvrir"); p.wait_for_selector("#bDecouv td.act")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meshname/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    p.click("#addNoeud"); p.click("#addMappage")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    assert p.evaluate("getComputedStyle(document.querySelector('.app')).borderRadius") == "16px"   # la feuille de style s'applique
    ctx.close()
