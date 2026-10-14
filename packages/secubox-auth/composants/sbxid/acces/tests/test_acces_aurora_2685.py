# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2685 — /acces/ au profil Aurora : tests statiques + vrai navigateur, API simulée (données factices).

Servie sous http://localhost (contexte sécurisé : WebCrypto et IndexedDB, nécessaires au parcours réel)."""
import json
import re
import time
from pathlib import Path

import pytest

DIR = Path(__file__).resolve().parents[1] / "www" / "acces"
SRC = (DIR / "index.html").read_text(encoding="utf-8")
BASE = "http://localhost:8099"
NOW = int(time.time())


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == []
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", 'onclick="'):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower() and "hybrid-dark" not in SRC
    assert "sbxVue" in SRC and "onglet: 'acces'" in SRC and "DEMO" in SRC and "embed" in SRC
    assert "from './appareil.js'" in SRC and "./moi.js" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("poste('/file/refuser', { did: d.did, motif: '' })", "poste('/profils/bbs/synchroniser', { adopter: [nom] })",
              "poste('/profils/bbs/synchroniser', { adopter: [] })", "poste('/profils/rattacher', { did, compte })",
              "poste('/profils/rattacher', { did, compte: cible.value })", "poste('/profils/promouvoir', { did: a.did, profil: pr })",
              "poste('/profils/revoquer', { did: a.did })", "api('/file')", "api('/profils')", "api('/invitation/url')",
              "api('/profils/inventaire')", "API + '/invitation/qr'", "'/invitation/url'"):
        assert r in SRC, r
    assert "new URL('/identite/#admin'" in SRC            # « Admettre » mène toujours au Gestionnaire d'identité
    assert "setItem" not in SRC and "Math.random" not in SRC
    assert "empreinte" in SRC and "qrcode" not in SRC.lower()   # l'empreinte n'est jamais mise en QR


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


ADMIS = [
    {"did": "did:a", "nom": "cedre83", "appareil": "Firefox", "empreinte": "AA11", "compte": "cedre83", "compte_appareil": "cedre83", "profil": "admin", "derniere_connexion": NOW - 60},
    {"did": "did:b", "nom": "ana", "appareil": "Chromium", "empreinte": "BB22", "compte": None, "compte_appareil": "ana", "profil": "guest", "derniere_connexion": NOW - 99999},
]
FILE = {"en_attente": [{"did": "did:dem", "nom": "<b>Visiteur</b>", "appareil": "Safari", "message": "salut", "empreinte": "CC33 DD44"}]}
PROFILS = {"admis": ADMIS, "profils": ["guest", "user", "admin"], "compte_par_defaut": "ana", "bbs": {},
           "comptes": [{"handle": "cedre83", "role": "admin"}, {"handle": "ana", "role": "user"}]}
INV = {"resume": {"total": 2, "par_etat": {"acceptee": 2}}, "profils": ["guest"], "privileges": {}, "appareils": []}
API = {("GET", "/file"): (200, FILE), ("GET", "/profils"): (200, PROFILS), ("GET", "/invitation/url"): (200, {"url": "https://acces.example.org/acces/", "sbxos": "/sbxos/"}),
       ("GET", "/profils/inventaire"): (200, INV)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, demandes = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif: " + d.message), d.dismiss()))
    p.on("request", lambda r: demandes.append(r.url))

    def fichier(r, *_):
        chemin = r.request.url.split(BASE + "/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.startswith("acces/"):
            f = DIR / (chemin[len("acces/"):] or "index.html")
            if f.is_file():
                r.fulfill(status=200, content_type={".html": "text/html", ".js": "application/javascript"}.get(f.suffix, "text/plain"), body=f.read_text(encoding="utf-8"))
            else:
                r.fulfill(status=404, body="")
        else:
            r.fulfill(status=404, body="")
    p.route(BASE + "/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/acces", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get((r.request.method, chemin), (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route(BASE + "/api/v1/acces/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels, demandes


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_vue_admin_tuiles_et_profileur_viennent_de_l_api(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, BASE + "/acces/?embed=1", API)
    p.wait_for_selector("#profils .ligne .nom")
    assert [p.inner_text(f"#tuiles .tuile:nth-child({i}) .v") for i in (1, 2, 3, 4)] == ["1", "2", "0", "1"]
    assert p.locator("#tuiles .tuile[title]").count() == 4 and p.inner_text("#etat") == "ADMINISTRATION"
    assert "<b>Visiteur</b>" in p.inner_text("#file") and p.locator("#file b").count() == 0   # texte, jamais balisage
    assert err == []
    ctx.close()


def test_revoquer_confirme_dans_la_page_puis_envoie_le_meme_corps(navigateur):
    routes = {**API, ("POST", "/profils/revoquer"): (200, {})}
    ctx, p, err, appels, _ = ouvre(navigateur, BASE + "/acces/?embed=1", routes)
    p.wait_for_selector("#profils .ligne .nom")
    p.locator("#profils .ligne", has_text="BB22").get_by_role("button", name="Révoquer").click()
    p.wait_for_selector("#confirmation:not([hidden])")
    assert "Révoquer l’accès" in p.inner_text("#confirmation") and not ecritures(appels)
    p.locator("#confirmation").get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('confirmation').hidden")
    assert [(a[0], a[1], json.loads(a[2])) for a in ecritures(appels)] == [("POST", "/profils/revoquer", {"did": "did:b"})]
    assert err == []
    ctx.close()


def test_annuler_ne_revoque_rien(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, BASE + "/acces/?embed=1", API)
    p.wait_for_selector("#profils .ligne .nom")
    p.locator("#profils .ligne", has_text="BB22").get_by_role("button", name="Révoquer").click()
    p.locator("#confirmation").get_by_role("button", name="Annuler").click()
    p.wait_for_function("document.getElementById('confirmation').hidden")
    assert not ecritures(appels) and err == []
    ctx.close()


def test_rattachement_groupe_demande_confirmation_et_poste_chaque_appareil(navigateur):
    routes = {**API, ("POST", "/profils/rattacher"): (200, {})}
    ctx, p, err, appels, _ = ouvre(navigateur, BASE + "/acces/?embed=1", routes)
    p.wait_for_selector("#profils .ligne .nom")
    p.locator("#profils .ligne", has_text="BB22").locator("input.choix").check()
    p.get_by_role("button", name="Rattacher la sélection").click()
    p.wait_for_selector("#confirmation:not([hidden])")
    assert not ecritures(appels)
    p.locator("#confirmation").get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('confirmation').hidden")
    assert [json.loads(a[2]) for a in ecritures(appels)] == [{"did": "did:b", "compte": "ana"}] and err == []
    ctx.close()


def test_refuser_une_demande_garde_le_meme_appel(navigateur):
    routes = {**API, ("POST", "/file/refuser"): (200, {})}
    ctx, p, err, appels, _ = ouvre(navigateur, BASE + "/acces/?embed=1", routes)
    p.wait_for_selector("#file .bloc")
    p.locator("#file").get_by_role("button", name="Refuser").click()
    p.wait_for_timeout(300)
    assert [json.loads(a[2]) for a in ecritures(appels)][0] == {"did": "did:dem", "motif": ""} and err == []
    ctx.close()


def test_visiteur_sans_session_voit_le_formulaire_de_demande(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, BASE + "/acces/?embed=1", {})
    p.wait_for_selector("#vue .champ")
    assert not p.is_visible("#admin") and p.inner_text("#etat") == "NON ADMIS"
    assert not ecritures(appels) and err == []
    ctx.close()


def test_demonstration_annoncee_aucune_requete_ni_ecriture(navigateur):
    ctx, p, err, appels, demandes = ouvre(navigateur, BASE + "/acces/?demo=1&embed=1", {})
    p.wait_for_selector("#profils .ligne .nom")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#profils .ligne", has_text="4F2A").get_by_role("button", name="Révoquer").click()
    p.locator("#confirmation").get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.body.textContent.includes('inerte')")
    assert appels == [] and not [u for u in demandes if "/api/" in u] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, BASE + "/acces/?demo=1&embed=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#profils .ligne .nom")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()


def test_encadree_annonce_la_hauteur_du_cadre(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1000, "height": 700})
    p = ctx.new_page()

    def fichier(r, *_):
        chemin = r.request.url.split(BASE + "/", 1)[1].split("?")[0]
        if chemin == "parent":
            r.fulfill(status=200, content_type="text/html", body='<script>window.__m=[];addEventListener("message",e=>__m.push(e.data))</script>'
                      '<iframe src="/acces/?demo=1" style="width:900px;height:3500px"></iframe>')
        elif chemin.startswith("acces/"):
            f = DIR / (chemin[len("acces/"):] or "index.html")
            r.fulfill(status=200 if f.is_file() else 404, content_type={".html": "text/html", ".js": "application/javascript"}.get(f.suffix, "text/plain"),
                      body=f.read_text(encoding="utf-8") if f.is_file() else "")
        else:
            r.fulfill(status=200, content_type="application/javascript", body="")
    p.route(BASE + "/**", fichier)
    p.goto(BASE + "/parent")
    p.wait_for_function("window.__m.some(m => m.onglet === 'acces' && m.sbxVue > 300)")
    h = p.evaluate("window.__m.filter(m => m.onglet === 'acces').pop().sbxVue")
    assert 300 < h < 3000
    ctx.close()
