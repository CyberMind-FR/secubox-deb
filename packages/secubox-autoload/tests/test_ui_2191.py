# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2191 / #2597 : la page d'administration Auto-Load au profil Aurora, dans un vrai navigateur, API simulée : rendu, génération d'un jeton, confirmations intégrées, échappement, session, démonstration, téléphone."""
import json
import re
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
PAGE = ICI / "www" / "autoload" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")
playwright = pytest.importorskip("playwright.sync_api")

PIEGE = '<img src=x onerror="window.__pwn=1">'
BOXES = [{"id": 1, "client": "boulangerie-dupont", "profil": "lite", "lot": "lot-1", "serie": None, "statut": "en cours", "progression": 72, "etape": "installation", "maj_le": 1_800_000_000},
         {"id": 2, "client": PIEGE, "profil": "isp", "lot": None, "serie": None, "statut": "terminé", "progression": 100, "etape": "application", "maj_le": 1_800_000_100},
         {"id": 3, "client": "atelier-martin", "profil": "lite", "lot": None, "serie": None, "statut": "en attente", "progression": 0, "etape": None, "maj_le": None}]
JETONS = [{"id": 1, "client": "boulangerie-dupont", "profil": "lite", "lot": "lot-1", "serie": None, "etat": "reclame", "abonnement": "actif", "formule": "pme_12m",
           "abonnement_expire_le": 1_830_000_000, "emis_le": 1, "expire_le": 2, "reclame_le": 3},
          {"id": 3, "client": "atelier-martin", "profil": "lite", "lot": None, "serie": None, "etat": "emis", "abonnement": "suspendu", "formule": None,
           "abonnement_expire_le": None, "emis_le": 1, "expire_le": 2, "reclame_le": None}]
PRE = [{"empreinte": "a" * 64, "client": "boulangerie-dupont", "box": "essai-vm-lite", "profil": "lite", "mode": "auto", "paquets": 3, "recu_le": 1_800_000_050, "refuse": False, "motif": None}]
RAPPORTS = [{"id": 5, "client": "boulangerie-dupont", "profil": "lite", "paquets": 3, "recu_le": 1_800_000_900, "envoye": True}]
RAPPORT = {"client": "boulangerie-dupont", "profil": "lite", "paquets": ["secubox-core", PIEGE], "domaine": "c.secubox.in", "comptes": ["admin"], "tunnel_adresse": "10.64.0.2/32",
           "debut": 1_800_000_000, "fin": 1_800_000_900, "etapes": ["plan"]}
DETAIL = {"box": "boulangerie-dupont", "profil": "lite", "mode": "auto", "paquets": ["secubox-core", PIEGE], "comptes": ["admin"], "secrets": ["jeton"], "reseau": {"mode": "routeur", "domaine": "c.secubox.in"}}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, appels, surcharges=None, query="", taille=None, jeton="JETON-ADMIN"):
    surcharges = surcharges or {}
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (appels.append(("dialog", d.message)), d.dismiss()))

    def api(route, *_):
        req = route.request
        chemin = req.url.split("/api/v1/autoload", 1)[1].split("?")[0]
        corps = json.loads(req.post_data) if req.post_data else None
        appels.append((req.method, chemin, corps, req.headers.get("authorization")))
        cle = (req.method, chemin)
        if cle in surcharges:
            code, rep = surcharges[cle]
        elif cle == ("GET", "/boxes"):
            code, rep = 200, BOXES
        elif cle == ("GET", "/jetons"):
            code, rep = 200, JETONS
        elif cle == ("GET", "/prerapports"):
            code, rep = 200, PRE
        elif cle == ("GET", "/rapports"):
            code, rep = 200, RAPPORTS
        elif cle == ("GET", "/rapports/5"):
            code, rep = 200, RAPPORT
        elif cle == ("GET", "/prerapports/" + "a" * 64):
            code, rep = 200, DETAIL
        elif cle == ("POST", "/jetons"):
            code, rep = 200, {"id": 9, "valeur": "gk2_FACTICE" + "0123456789abcdef" * 2, "expire_le": 1_900_000_000}
        else:
            code, rep = 200, {"ok": True}
        route.fulfill(status=code, content_type="application/json", body=json.dumps(rep))
    p.route("http://sbx.test/api/v1/autoload/**", api)
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/autoload/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=HTML))
    if jeton:
        p.add_init_script(f"localStorage.setItem('sbx_token','{jeton}')")
    p.goto("http://sbx.test/autoload/" + query)
    return ctx, p, erreurs


def appels_ecriture(appels):
    return [a for a in appels if a[0] == "POST"]


def test_tuiles_tableaux_et_progression_viennent_de_l_api(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.wait_for_selector("#bBoxes tr td.nom, #bBoxes tr .nom", state="attached")
    assert [p.inner_text(i) for i in ("#tAttente", "#tPrep", "#tCours", "#tFin", "#tRev", "#tPre")] == ["1", "0", "1", "1", "0", "1"]
    assert p.locator("#bBoxes tr").count() == 3 and "boulangerie-dupont" in p.inner_text("#bBoxes") and "72 %" in p.inner_text("#bBoxes")
    assert p.locator(".barre > i.ok").count() == 1 and p.evaluate("document.querySelector('.barre > i').style.width") == "72%"
    # box en attente : aucune progression mesurée -> « — », pas « 0 % »
    assert "0 %" not in p.locator("#bBoxes tr").nth(2).inner_text()
    assert p.inner_text("#etat") == "EN LIGNE"
    assert any(a[0] == "GET" and a[3] == "Bearer JETON-ADMIN" for a in appels)      # le jeton d'admin part sur chaque lecture
    assert not erreurs and not [a for a in appels if a[0] == "dialog"]
    ctx.close()


def test_les_valeurs_du_serveur_sont_echappees(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.wait_for_selector("#bBoxes tr")
    assert p.evaluate("window.__pwn") is None and p.locator("#bBoxes img").count() == 0
    assert "<img" in p.inner_text("#bBoxes")                               # affiché comme du texte
    p.click("#o-prerapports"); p.click("#bPre >> text=Voir")
    p.wait_for_selector("#detail:not([hidden])")
    assert p.locator("#detail img").count() == 0 and p.evaluate("window.__pwn") is None and "secubox-core" in p.inner_text("#detail")
    assert not erreurs
    ctx.close()


def test_generation_du_jeton_envoie_les_memes_corps_et_montre_la_valeur_une_fois(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.click("#o-jetons")
    p.fill("#fClient", "client-042"); p.select_option("#fProfil", "isp"); p.select_option("#fMois", "24")
    p.fill("#fLot", "lot-test"); p.fill("#fEmail", "gerant@boulangerie.example")
    p.click("#btnGenerer")
    p.wait_for_selector("#jetonGenere:not([hidden])")
    assert p.inner_text("#mjValeur") == "gk2_FACTICE" + "0123456789abcdef" * 2 and "client-042" in p.inner_text("#mjClient") and "24 mois" in p.inner_text("#mjClient")
    posts = appels_ecriture(appels)
    assert posts[0][1:3] == ("/jetons", {"client": "client-042", "profil": "isp", "duree_jours": 90, "lot": "lot-test"})
    assert posts[1][1:3] == ("/clients/client-042/abonnement", {"statut": "actif", "mois": 24, "formule": "isp_24m"})
    assert posts[2][1:3] == ("/clients/client-042/contact", {"email": "gerant@boulangerie.example"})
    p.click("#fermeJeton")
    assert p.is_hidden("#jetonGenere") and p.inner_text("#mjValeur") == ""   # la valeur ne reste plus dans la page
    assert p.input_value("#fClient") == ""
    assert "gk2_FACTICE" not in p.evaluate("JSON.stringify(Object.assign({}, localStorage))")      # rien dans localStorage
    assert not erreurs
    ctx.close()


def test_une_erreur_de_generation_reste_affichee(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels, {("POST", "/jetons"): (422, {"detail": "client : minuscules, chiffres et tirets"})})
    p.click("#o-jetons"); p.fill("#fClient", "client-042"); p.click("#btnGenerer")
    p.wait_for_function("document.getElementById('rJetons').textContent.includes('minuscules')")
    p.wait_for_timeout(3300)                                               # plus long qu'un message transitoire
    assert "minuscules" in p.inner_text("#rJetons") and p.is_hidden("#jetonGenere") and not p.is_disabled("#btnGenerer")
    ctx.close()


def test_une_erreur_d_abonnement_apres_un_jeton_reussi_est_dite(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels, {("POST", "/clients/client-042/abonnement"): (422, {"detail": "formule invalide"})})
    p.click("#o-jetons"); p.fill("#fClient", "client-042"); p.click("#btnGenerer")
    p.wait_for_selector("#jetonGenere:not([hidden])")
    assert "jeton généré" in p.inner_text("#rJetons").lower() and "formule invalide" in p.inner_text("#rJetons")   # le jeton reste affiché : il ne se retrouvera plus
    ctx.close()


def test_revocation_suspension_et_refus_demandent_une_confirmation_dans_la_page(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.click("#o-jetons"); p.wait_for_selector("#bJetons tr")
    p.locator("#bJetons tr").first.get_by_text("Révoquer").click()
    assert p.is_visible("#conf") and "boulangerie-dupont" in p.inner_text("#confTexte") and "tunnel" in p.inner_text("#confTexte")
    assert not appels_ecriture(appels)                                     # pas d'écriture avant confirmation
    p.click("#confNon"); assert p.is_hidden("#conf") and not appels_ecriture(appels)
    p.locator("#bJetons tr").first.get_by_text("Révoquer").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rJetons').textContent.includes('révoqué')")
    assert ("POST", "/jetons/1/revoquer", {"motif": "révoqué depuis le panneau"}, "Bearer JETON-ADMIN") in appels
    p.locator("#bJetons tr").first.get_by_text("Suspendre").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rJetons').textContent.includes('suspendu')")
    assert any(a[:3] == ("POST", "/clients/boulangerie-dupont/abonnement", {"statut": "suspendu"}) for a in appels_ecriture(appels))
    p.locator("#bJetons tr").nth(1).get_by_text("Réactiver").click()          # sans confirmation, comme l'ancienne page
    p.wait_for_function("document.getElementById('rJetons').textContent.includes('réactivé')")
    assert any(a[:3] == ("POST", "/clients/atelier-martin/abonnement", {"statut": "actif", "mois": 12}) for a in appels_ecriture(appels))
    p.click("#o-prerapports"); p.wait_for_selector("#bPre tr")
    p.locator("#bPre tr").first.get_by_text("Refuser").click()
    assert "essai-vm-lite" in p.inner_text("#confTexte"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPre').textContent.includes('refusé')")
    assert ("POST", f"/prerapports/{'a' * 64}/refuser", {"motif": "refusé depuis le panneau"}, "Bearer JETON-ADMIN") in appels
    assert not [a for a in appels if a[0] == "dialog"] and not erreurs
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    appels = []
    refus = {("GET", c): (401, {"detail": "Token Bearer ou session manquant"}) for c in ("/boxes", "/jetons", "/prerapports", "/rapports")}
    ctx, p, erreurs = ouvre(navigateur, appels, refus, jeton=None)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tAttente", "#tPrep", "#tCours", "#tFin", "#tRev", "#tPre")] == ["—"] * 6 and not erreurs
    ctx.close()


def test_la_derniere_reponse_reste_affichee_quand_la_relecture_echoue(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.wait_for_selector("#bBoxes tr .nom")
    p.unroute("http://sbx.test/api/v1/autoload/**")
    p.route("http://sbx.test/api/v1/autoload/**", lambda r, *_: r.fulfill(status=500, content_type="application/json", body='{"detail":"hs"}'))
    p.click("#rafraichir")
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.locator("#bBoxes tr").count() == 3                             # double cache : on garde ce qu'on avait
    ctx.close()


def test_les_rapports_finaux_se_listent_et_se_lisent_echappes(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.click("#o-rapports"); p.wait_for_selector("#bRap tr")
    assert "envoyé" in p.inner_text("#bRap") and "boulangerie-dupont" in p.inner_text("#bRap")
    p.click("#bRap >> text=Voir"); p.wait_for_selector("#detail:not([hidden])")
    assert "Rapport final" in p.inner_text("#detail") and "15 min" in p.inner_text("#detail")
    assert p.locator("#detail img").count() == 0 and p.evaluate("window.__pwn") is None and not erreurs
    ctx.close()


def test_la_liste_des_pre_rapports_montre_le_nom_de_box_saisi_et_le_client_du_jeton(navigateur):
    """#2314 : le nom saisi pour la box est ce que l'opérateur reconnaît ; le client du jeton reste visible à côté."""
    ctx, p, erreurs = ouvre(navigateur, [])
    p.click("#o-prerapports"); p.wait_for_selector("#bPre tr")
    en_tete = p.inner_text("#t-prerapports thead").lower()
    ligne = p.inner_text("#bPre tr")
    assert "box (nom saisi)" in en_tete and "client (jeton)" in en_tete
    assert "essai-vm-lite" in ligne and "boulangerie-dupont" in ligne and ligne.index("essai-vm-lite") < ligne.index("boulangerie-dupont")
    assert not erreurs
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels, query="?demo=1&embed=1")
    p.wait_for_selector("#bBoxes tr .nom")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-jetons"); p.locator("#bJetons tr").first.get_by_text("Révoquer").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rJetons').textContent.includes('inerte')")
    p.fill("#fClient", "client-demo"); p.click("#btnGenerer")
    p.wait_for_function("document.getElementById('rJetons').textContent.includes('inerte')")
    assert appels == [] and not erreurs and p.is_hidden("#jetonGenere")
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, erreurs = ouvre(navigateur, [], query="?embed=1", taille={"width": 420, "height": 800})
    p.wait_for_selector("#bBoxes tr .nom")
    for o in ("#o-boxes", "#o-jetons", "#o-prerapports", "#o-rapports"):
        p.click(o)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), o
    assert not p.is_visible("#sidebar") and not erreurs
    ctx.close()


def test_la_hauteur_est_annoncee_a_l_hote(navigateur):
    ctx = navigateur.new_context(viewport={"width": 900, "height": 700})
    p = ctx.new_page()

    def serveur(r, *_):
        if r.request.url.startswith("http://sbx.test/autoload/"):
            r.fulfill(status=200, content_type="text/html", body=HTML)
        elif r.request.url.endswith("/hote.html"):
            r.fulfill(status=200, content_type="text/html", body="<iframe src='/autoload/?embed=1&demo=1' width=900 height=300></iframe><script>window.m=[];addEventListener('message',e=>m.push(e.data))</script>")
        else:
            r.fulfill(status=200, content_type="application/javascript", body="")
    p.route("http://sbx.test/**", serveur)
    p.goto("http://sbx.test/hote.html")
    p.wait_for_function("window.m.length>0", timeout=5000)
    msg = p.evaluate("window.m[window.m.length-1]")
    assert msg["onglet"] == "autoload" and msg["sbxVue"] > 100
    ctx.close()


# ── statiques ────────────────────────────────────────────────────────────────────────────────────────────
def test_page_autonome_aurora_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML
    assert re.findall(r'<script src="([^"]+)"', HTML) == ["/shared/sidebar.js"]
    assert re.findall(r'<link[^>]+href="([^"]+)"', HTML) == ["/shared/sidebar-light.css"]
    assert "hybrid-dark" not in HTML and "hybrid-skin" not in HTML and "fonts.googleapis" not in HTML and "Courier" not in HTML
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "Math.random"):
        assert interdit not in HTML
    assert "lorem" not in HTML.lower()
    assert not re.search(r"\bon[a-z]+\s*=\s*[\"']", HTML)                    # aucun gestionnaire en ligne
    assert "localStorage.getItem('sbx_token')" in HTML and "setItem" not in HTML and "sessionStorage" not in HTML
    assert "sbxVue" in HTML and "onglet: 'autoload'" in HTML and "ResizeObserver" in HTML and "demo" in HTML and "embed" in HTML
    assert "--fond:#060d1b" in HTML.replace(" ", "")


def test_routes_d_ecriture_a_l_identique_de_l_ancienne_page():
    for r in ("'/jetons'", "'/jetons/' + Number(j.id) + '/revoquer'", "'/clients/' + encodeURIComponent(client) + '/abonnement'", "'/clients/' + encodeURIComponent(client) + '/contact'",
              "'/prerapports/' + encodeURIComponent(p.empreinte) + '/refuser'", "'/boxes'", "'/prerapports'", "'/rapports'",
              "motif: 'révoqué depuis le panneau'", "motif: 'refusé depuis le panneau'", "{ statut: 'actif', mois: 12 }", "{ statut: 'suspendu' }",
              "formule: prof + '_' + mois + 'm'", "duree_jours: Number($('fValidite').value)"):
        assert r in HTML, r
    assert HTML.count("method: 'POST'") == 1 and "'DELETE'" not in HTML and "'PUT'" not in HTML
    # aucune route que l'API n'a pas
    assert "/series" not in HTML and "/lots/" not in HTML and "/enrol" not in HTML


def test_le_menu_pointe_la_page_et_est_installe():
    m = json.loads((ICI / "menu.d" / "906-autoload.json").read_text())
    assert m["id"] == "autoload" and m["path"] == "/autoload/" and (ICI / "www" / "autoload" / "index.html").is_file()
    rules = (ICI / "debian" / "rules").read_text()
    assert "usr/share/secubox/www/autoload" in rules and "usr/share/secubox/menu.d" in rules
