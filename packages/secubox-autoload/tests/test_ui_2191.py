# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2191 : la page d'administration Auto-Load dans un vrai navigateur, API simulée : rendu, génération d'un jeton, erreurs persistantes, confirmations, échappement."""
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
PRE = [{"empreinte": "a" * 64, "client": "boulangerie-dupont", "profil": "lite", "mode": "auto", "paquets": 3, "recu_le": 1_800_000_050, "refuse": False, "motif": None}]
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


def ouvre(navigateur, appels, surcharges=None):
    surcharges = surcharges or {}
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (appels.append(("dialog", d.message)), d.accept()))

    def api(route):
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
            code, rep = 200, {"id": 9, "valeur": "gk2_" + "0123456789abcdef" * 2, "expire_le": 1_900_000_000}
        else:
            code, rep = 200, {"ok": True}
        route.fulfill(status=code, content_type="application/json", body=json.dumps(rep))
    p.route("http://sbx.test/api/v1/autoload/**", api)
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=HTML))
    p.add_init_script("localStorage.setItem('sbx_token','JETON-ADMIN')")
    p.goto("http://sbx.test/")
    return ctx, p, erreurs


def test_rendu_des_statistiques_des_box_et_progression(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.wait_for_selector("#lignesBoxes tr")
    assert p.locator("#lignesBoxes tr").count() == 3
    assert "boulangerie-dupont" in p.inner_text("#lignesBoxes") and "72 %" in p.inner_text("#lignesBoxes")
    valeurs = p.locator("#stats .stat-card .value").all_inner_texts()
    assert valeurs == ["1", "0", "1", "1", "0", "1"]                       # attente, préparation, en cours, terminées, révoquées, pré-rapports
    assert p.locator(".barre > i.ok").count() == 1 and p.evaluate("document.querySelector('.barre > i').style.width") == "72%"
    assert any(a[0] == "GET" and a[3] == "Bearer JETON-ADMIN" for a in appels if a[0] != "dialog")      # le jeton d'admin part sur chaque appel
    assert not erreurs
    ctx.close()


def test_les_valeurs_du_serveur_sont_echappees(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.wait_for_selector("#lignesBoxes tr")
    assert p.evaluate("window.__pwn") is None and p.locator("#lignesBoxes img").count() == 0
    assert "<img" in p.inner_text("#lignesBoxes")                         # affiché comme du texte
    p.click("button[data-tab=prerapports]")
    p.click("button[data-act=voir-pre]")
    p.wait_for_selector("#modalPre.show")
    assert p.locator("#detailPre img").count() == 0 and p.evaluate("window.__pwn") is None
    ctx.close()


def test_generation_du_jeton_pose_l_abonnement_et_montre_la_valeur_une_fois(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.click("button[data-tab=jetons]")
    p.fill("#fClient", "client-042")
    p.select_option("#fProfil", "isp")
    p.select_option("#fMois", "24")
    p.fill("#fLot", "lot-test")
    p.fill("#fEmail", "gerant@boulangerie.example")
    p.click("#btnGenerer")
    p.wait_for_selector("#modalJeton.show")
    assert p.inner_text("#mjValeur") == "gk2_" + "0123456789abcdef" * 2 and "client-042" in p.inner_text("#mjClient") and "24 mois" in p.inner_text("#mjClient")
    posts = [a for a in appels if a[0] == "POST"]
    assert posts[0][1:3] == ("/jetons", {"client": "client-042", "profil": "isp", "duree_jours": 90, "lot": "lot-test"})
    assert posts[1][1:3] == ("/clients/client-042/abonnement", {"statut": "actif", "mois": 24, "formule": "isp_24m"})
    assert posts[2][1:3] == ("/clients/client-042/contact", {"email": "gerant@boulangerie.example"})
    p.click("button[data-act=fermer-modal]")
    assert p.locator("#modalJeton.show").count() == 0
    assert p.input_value("#fClient") == ""                                 # le formulaire est vidé : la valeur n'est plus nulle part
    assert not erreurs
    ctx.close()


def test_une_erreur_reste_affichee_jusqu_a_sa_fermeture(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels, {("POST", "/jetons"): (422, {"detail": "client : minuscules, chiffres et tirets"})})
    p.click("button[data-tab=jetons]")
    p.fill("#fClient", "client-042")
    p.click("#btnGenerer")
    p.wait_for_selector("#erreur.show")
    p.wait_for_timeout(3600)                                               # plus longtemps qu'un toast transitoire (3 s)
    assert p.locator("#erreur.show").count() == 1 and "minuscules" in p.inner_text("#erreurTexte")
    assert p.locator("#modalJeton.show").count() == 0 and not p.is_disabled("#btnGenerer")
    p.click("button[data-act=fermer-erreur]")
    assert p.locator("#erreur.show").count() == 0
    ctx.close()


def test_une_erreur_d_abonnement_apres_un_jeton_reussi_est_dite(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels, {("POST", "/clients/client-042/abonnement"): (422, {"detail": "formule invalide"})})
    p.click("button[data-tab=jetons]")
    p.fill("#fClient", "client-042")
    p.click("#btnGenerer")
    p.wait_for_selector("#erreur.show")
    assert "jeton généré" in p.inner_text("#erreurTexte").lower() and "formule invalide" in p.inner_text("#erreurTexte")
    assert p.locator("#modalJeton.show").count() == 1                      # le jeton reste affiché : il ne se retrouvera plus
    ctx.close()


def test_revocation_et_suspension_demandent_confirmation(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.click("button[data-tab=jetons]")
    p.click("button[data-act=revoquer][data-id='1']")
    p.wait_for_timeout(300)
    assert ("POST", "/jetons/1/revoquer", {"motif": "révoqué depuis le panneau"}, "Bearer JETON-ADMIN") in appels
    assert any(a[0] == "dialog" and "tunnel" in a[1] for a in appels)
    p.click("button[data-act=suspendre][data-client='boulangerie-dupont']")
    p.wait_for_timeout(300)
    assert any(a[:3] == ("POST", "/clients/boulangerie-dupont/abonnement", {"statut": "suspendu"}) for a in appels if a[0] != "dialog")
    p.click("button[data-act=reactiver][data-client='atelier-martin']")
    p.wait_for_timeout(300)
    assert any(a[:3] == ("POST", "/clients/atelier-martin/abonnement", {"statut": "actif", "mois": 12}) for a in appels if a[0] != "dialog")
    ctx.close()


def test_refus_d_un_pre_rapport(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.click("button[data-tab=prerapports]")
    p.wait_for_selector("#lignesPre tr")
    p.click("button[data-act=refuser-pre]")
    p.wait_for_timeout(300)
    assert ("POST", f"/prerapports/{'a' * 64}/refuser", {"motif": "refusé depuis le panneau"}, "Bearer JETON-ADMIN") in appels
    ctx.close()


def test_sans_session_la_page_le_dit_sans_erreur_fatale(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels, {("GET", "/boxes"): (401, {"detail": "Token Bearer ou session manquant"}), ("GET", "/jetons"): (401, {}), ("GET", "/prerapports"): (401, {})})
    p.wait_for_selector("#toast.show")
    assert "Connexion requise" in p.inner_text("#toast") and p.locator("#erreur.show").count() == 0 and not erreurs
    ctx.close()


def test_la_derniere_reponse_reste_affichee_quand_la_relecture_echoue(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.wait_for_selector("#lignesBoxes tr")
    p.unroute("http://sbx.test/api/v1/autoload/**")
    p.route("http://sbx.test/api/v1/autoload/**", lambda r: r.fulfill(status=500, content_type="application/json", body='{"detail":"hs"}'))
    p.click("button[data-act=rafraichir]")
    p.wait_for_selector("#erreur.show")
    assert p.locator("#lignesBoxes tr").count() == 3                        # double cache : on garde ce qu'on avait
    ctx.close()


def test_les_rapports_finaux_se_listent_et_se_lisent_echappes(navigateur):
    appels = []
    ctx, p, erreurs = ouvre(navigateur, appels)
    p.click("button[data-tab=rapports]")
    p.wait_for_selector("#lignesRap tr")
    assert "envoyé" in p.inner_text("#lignesRap") and "boulangerie-dupont" in p.inner_text("#lignesRap")
    p.click("button[data-act=voir-rap]")
    p.wait_for_selector("#modalPre.show")
    assert "Rapport final" in p.inner_text("#detailPre") and "15 min" in p.inner_text("#detailPre")
    assert p.locator("#detailPre img").count() == 0 and p.evaluate("window.__pwn") is None and not erreurs
    ctx.close()


# ── statiques ────────────────────────────────────────────────────────────────────────────────────────────
def test_conformite_a_la_charte_des_panneaux():
    assert 'class="hybrid-dark"' in HTML and "/shared/hybrid-skin.css" in HTML and "/shared/sidebar.js" in HTML and 'id="sidebar"' in HTML
    assert "Courier Prime" in HTML and "--cyan:#00d4ff" in HTML.replace(" ", "")
    assert "localStorage.getItem('sbx_token')" in HTML
    assert not re.search(r"\bon(click|change|submit)\s*=", HTML)            # aucune interpolation dans un gestionnaire en ligne : data-* et écouteur délégué
    assert "http://" not in HTML.replace("http://www.w3.org", "")
    assert "window.top !== window.self" in HTML and "sbx-embed" in HTML
    assert "@media (max-width:768px)" in HTML and "function esc(" in HTML and "errorToast" in HTML
    assert "Math.random" not in HTML


def test_le_menu_pointe_la_page_et_est_installe():
    m = json.loads((ICI / "menu.d" / "906-autoload.json").read_text())
    assert m["id"] == "autoload" and m["path"] == "/autoload/" and (ICI / "www" / "autoload" / "index.html").is_file()
    rules = (ICI / "debian" / "rules").read_text()
    assert "usr/share/secubox/www/autoload" in rules and "usr/share/secubox/menu.d" in rules
