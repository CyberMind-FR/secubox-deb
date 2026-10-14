# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2685 — /identite/ au profil Aurora : tests statiques + vrai navigateur, API simulée (données factices).

Le contrat ne change pas : mêmes routes, méthodes, corps et en-têtes que l'ancienne page ; seule la peau est refaite."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "identite" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
NOW = int(time.time())


def test_page_autonome_sans_dialogue_natif_ni_balisage_de_donnees():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    # seul le menu commun, injecté dynamiquement hors mode encadré, charge un script externe
    assert re.findall(r'<script src="([^"]+)"', SRC) == []
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", 'onclick="', "document.write"):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower() and "hybrid-dark" not in SRC
    assert "sbxVue" in SRC and "onglet: 'identite'" in SRC and "DEMO" in SRC and "embed" in SRC


def test_routes_et_methodes_a_l_identique():
    attendu = [
        "'/moi'", "'/roles'", "'/elevation/etat'", "'/elevation/defi', {method:'POST'", "'/elevation', {method:'POST'",
        "'/appareils/' + d.device_uuid, {method:'PATCH'", "/revoquer', {method:'POST'", "/certificat/preparer', {method:'POST'",
        "/certificat/signer', {method:'POST'", "'/admin/personnes', {method:'POST'", "/roles', {method:'PUT'", "/statut', {method:'POST'",
        "'?comptes_services=' + svc, {method:'DELETE'", "/comptes/reinitialiser', {method:'POST'", "/comptes/travail",
        "/lier`, {method:'POST'", "/liens/${svc}/${encodeURIComponent(x.identifiant)}`, {method:'DELETE'",
        "/accepter', {method:'POST'", "/refuser', {method:'POST'", "/oublier', {method:'POST'",
        "'/admin/communautes', {method:'POST'", "/membres/${s.dataset.role}`, {method:'PUT'", "/membres/${b.dataset.retire}`, {method:'DELETE'",
        "'/admin/autorisations', {method:'POST'", "'/admin/autorisations/' + b.dataset.revoque, {method:'DELETE'",
        "/salons/${b.dataset.ferme}`, {method:'POST'", "/archiver`, {method:'POST'", "'/mesh'", "'/appareils/inviter', {method:'POST'",
        "'/invitations', {method:'POST'", "'/invitations/' + i.invite_uuid, {method:'DELETE'",
    ]
    for r in attendu:
        assert r in SRC, r
    assert "const API = '/api/v1/sbxid'" in SRC
    # les en-têtes d'origine : seulement Content-Type, ni jeton ni Accept ajoutés
    assert "headers:{'Content-Type':'application/json'}" in SRC
    assert "Authorization" not in SRC and "sbx_token" not in SRC


def test_aucun_secret_stocke_ni_serie_inventee():
    assert "setItem" not in SRC and "localStorage" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


DEV = [
    {"device_uuid": "d1", "name": "Téléphone", "trust": "trusted", "last_seen_at": NOW - 300, "revoked_at": None, "did": "did:sbx:dev:un", "agent": "Firefox", "ip": "192.0.2.14",
     "certificate": {"expires": "2027-10-14T00:00:00Z"}},
    {"device_uuid": "d2", "name": "Portable", "trust": "verified", "last_seen_at": NOW - 9000, "revoked_at": None, "did": "did:sbx:dev:deux"},
]
MOI = {"identite": {"pseudo": "cedre83", "user_uuid": "3f9c1a52-7d4e-4b8a-9a31-0c5e2f6d8b17", "home_node": "n1", "epoch": 3, "tier": "standard", "status": "active",
                    "roles": ["member"], "capabilities": ["hall.read", "admin.users"], "communities": [], "etat": "member"},
       "liens": [], "appareils": DEV, "appareil_courant": "d1", "systeme": False, "par_compte": False,
       "connexions": {"session_compte": "cedre83", "compte_systeme": False, "appareil_courant": "Téléphone", "rattachements": [], "liens": [], "services": []}}
ROLES = {"roles": [{"id": "guest", "label": "Invité", "derive": False, "capacites": ["hall.read"]},
                   {"id": "member", "label": "Membre", "derive": False, "capacites": ["hall.read", "admin.users"]}], "capacites": ["hall.read", "admin.users"]}
PERS = {"personnes": [{"pseudo": "cedre83", "user_uuid": "3f9c1a52-7d4e-4b8a-9a31-0c5e2f6d8b17", "roles": ["member"], "tier": "standard", "appareils": 2, "status": "active"},
                      {"pseudo": "ana", "user_uuid": "8a1d4c70-2b6e-4f93-b5a8-71e0c9d34f26", "roles": ["guest"], "tier": "free", "appareils": 1, "status": "active"}]}
DEMANDES = {"en_attente": [{"did": "did:sbx:dev:dem", "nom": "<img src=x onerror=window.__xss=1>", "appareil": "Firefox", "demandee_le": NOW - 60, "empreinte": "AB12 CD34"}], "closes": [], "revoques": []}
API = {
    ("GET", "/moi"): (200, MOI), ("GET", "/roles"): (200, ROLES), ("GET", "/elevation/etat"): (200, {"lie": False}),
    ("GET", "/admin/personnes"): (200, PERS), ("GET", "/admin/journal"): (200, {"evenements": [{"at": NOW - 5, "event": "x.y", "actor": "cedre83", "detail": "d"}]}),
    ("GET", "/admin/demandes"): (200, DEMANDES), ("GET", "/admin/communautes"): (200, {"communautes": []}),
    ("GET", "/admin/capacites"): (200, {"modules": {"hall": ["hall.read"]}}), ("GET", "/mesh"): (200, {"node": {"did": "did:n", "pubkey": "pk"}, "personnes_hebergees": 0, "migrations": [], "etat": "ok"}),
    ("GET", "/invitations"): (200, {"invitations": []}),
}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif: " + d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "identite":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/sbxid", 1)[1].split("?")[0]
        q = r.request.url.split("?", 1)[1] if "?" in r.request.url else ""
        appels.append((r.request.method, chemin, r.request.post_data, q, r.request.headers))
        statut, corps = routes.get((r.request.method, chemin), (404, {}) if r.request.method == "GET" else (200, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/sbxid/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_et_identite_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/identite/", API)
    p.wait_for_function("document.getElementById('etat').textContent === 'IDENTIFIÉ·E'")
    assert [p.inner_text(i) for i in ("#tApp", "#tCap", "#tPers", "#tDem")] == ["2", "2", "2", "1"]
    assert "cedre83" in p.inner_text("#moi-corps") and "hall.read" in p.inner_text("#moi-corps")
    assert p.get_attribute("#cDem", "title") and all(p.get_attribute(f"#{i}", "title") is None for i in ("tApp",))
    assert p.locator(".tuile[title]").count() == 4
    assert err == []
    ctx.close()


def test_donnees_inconnues_jamais_interpretees_comme_balisage(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/identite/#admin", API)
    p.wait_for_selector("#adm-demandes .dev")
    assert "<img src=x" in p.inner_text("#adm-demandes")          # affiché comme texte
    assert p.locator("#adm-demandes img").count() == 0
    assert p.evaluate("window.__xss") is None and err == []
    ctx.close()


def test_en_tetes_d_origine_seulement_content_type(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/identite/", API)
    p.wait_for_function("document.getElementById('etat').textContent === 'IDENTIFIÉ·E'")
    h = [a for a in appels if a[1] == "/moi"][0][4]
    assert h.get("content-type") == "application/json" and "authorization" not in h
    ctx.close()


def test_revoquer_demande_une_confirmation_dans_la_page(navigateur):
    routes = {**API, ("POST", "/appareils/d2/revoquer"): (200, {"sessions_coupees": 2})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/identite/#appareils", routes)
    ligne = p.locator("#devs .dev", has_text="Portable")
    ligne.get_by_role("button", name="Révoquer").click()
    assert not ecritures(appels)                                    # pas encore : il faut confirmer
    assert "Révoquer « Portable » ?" in ligne.inner_text()
    ligne.get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('2 session')")
    assert [(a[0], a[1]) for a in ecritures(appels)] == [("POST", "/appareils/d2/revoquer")]
    assert err == []
    ctx.close()


def test_annuler_ne_revoque_rien(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/identite/#appareils", API)
    ligne = p.locator("#devs .dev", has_text="Portable")
    ligne.get_by_role("button", name="Révoquer").click()
    ligne.get_by_role("button", name="Annuler").click()
    p.wait_for_selector("#devs .dev button:has-text('Renommer')")
    assert not ecritures(appels) and err == []
    ctx.close()


def test_creer_une_personne_et_changer_un_role_envoient_les_memes_corps(navigateur):
    routes = {**API, ("POST", "/admin/personnes"): (200, {"pseudo": "zoe"}), ("PUT", "/admin/personnes/8a1d4c70-2b6e-4f93-b5a8-71e0c9d34f26/roles"): (200, {})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/identite/#admin", routes)
    p.wait_for_selector("#people tbody tr")
    p.fill("#np-pseudo", "zoe")
    p.select_option("#np-role", "guest")
    p.fill("#np-email", "zoe@example.org")
    p.click("#f-personne button")
    p.wait_for_function("document.getElementById('toast').textContent.includes('zoe')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/admin/personnes"][0]
    assert json.loads(post[2]) == {"pseudo": "zoe", "role": "guest", "email": "zoe@example.org"}
    p.wait_for_selector("#people tbody tr")
    p.check('input[data-u="8a1d4c70-2b6e-4f93-b5a8-71e0c9d34f26"][data-r="member"]')
    p.wait_for_function("document.getElementById('toast').textContent.includes('Rôles')")
    put = [a for a in appels if a[0] == "PUT"][0]
    assert json.loads(put[2]) == {"roles": ["guest", "member"]} and err == []
    ctx.close()


def test_refuser_une_demande_passe_par_la_confirmation_de_la_page(navigateur):
    routes = {**API, ("POST", "/admin/demandes/did%3Asbx%3Adev%3Adem/refuser"): (200, {})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/identite/#admin", routes)
    p.wait_for_selector("#adm-demandes .dev")
    p.locator("#adm-demandes").get_by_role("button", name="Refuser").click()
    assert not ecritures(appels)
    p.locator("#adm-demandes").get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('refusée')")
    assert [(a[0], a[1], a[2]) for a in ecritures(appels)] == [("POST", "/admin/demandes/did%3Asbx%3Adev%3Adem/refuser", "{}")]
    assert err == []
    ctx.close()


def test_salon_ouvert_a_tous_se_reserve_apres_confirmation_dans_la_page(navigateur):
    routes = {**API, ("GET", "/admin/communautes"): (200, {"communautes": [{"community_uuid": "k1"}]}),
              ("GET", "/admin/communautes/k1"): (200, {"community_uuid": "k1", "name": "Atelier", "visibility": "private", "description": "", "members": [], "grants": []}),
              ("GET", "/admin/communautes/k1/salons"): (200, {"salons": [{"id": 7, "titre": "Projets", "ouvert": False, "prive": False, "profondeur": 0}]}),
              ("POST", "/admin/communautes/k1/salons/7"): (200, {})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/identite/#communautes", routes)
    p.wait_for_selector("details.kom")
    p.evaluate("document.querySelector('details.kom').open = true")
    p.wait_for_selector("[data-salon]")
    p.click("[data-salon] button:has-text('Ouvrir à la communauté')")
    assert "le réserver le rend privé" in p.inner_text("[data-salon]") and not ecritures(appels)
    p.locator("[data-salon]").get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('réservé')")
    assert json.loads(ecritures(appels)[0][2]) == {"ouvrir": True, "reserver": True} and err == []
    ctx.close()


def test_archiver_une_communaute_demande_confirmation(navigateur):
    routes = {**API, ("GET", "/admin/communautes"): (200, {"communautes": [{"community_uuid": "k1"}]}),
              ("GET", "/admin/communautes/k1"): (200, {"community_uuid": "k1", "name": "Atelier", "visibility": "private", "description": "", "members": [], "grants": []}),
              ("GET", "/admin/communautes/k1/salons"): (200, {"salons": []}), ("POST", "/admin/communautes/k1/archiver"): (200, {})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/identite/#communautes", routes)
    p.wait_for_selector("details.kom")
    p.evaluate("document.querySelector('details.kom').open = true")
    p.click("[data-archive]")
    assert not ecritures(appels)
    p.locator("[data-archive-zone]").get_by_role("button", name="Annuler").click()
    assert not ecritures(appels) and p.locator("[data-archive]").count() == 1
    p.click("[data-archive]")
    p.locator("[data-archive-zone]").get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('archivée')")
    assert [(a[0], a[1]) for a in ecritures(appels)] == [("POST", "/admin/communautes/k1/archiver")] and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/identite/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tApp", "#tCap", "#tPers", "#tDem")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_aucune_requete_ni_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/identite/?demo=1#appareils", {})
    p.wait_for_function("document.getElementById('etat').textContent === 'IDENTIFIÉ·E'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    ligne = p.locator("#devs .dev", has_text="Portable")
    ligne.get_by_role("button", name="Révoquer").click()
    ligne.get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.click("#b-ajout")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    assert appels == [] and err == []
    assert p.locator("nav#sidebar").count() == 0                   # pas de menu commun en démonstration
    ctx.close()


@pytest.mark.parametrize("vue", ["moi", "appareils", "admin", "communautes", "mesh"])
def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur, vue):
    ctx, p, err, _ = ouvre(navigateur, f"http://sbx.test/identite/?embed=1&demo=1#{vue}", {}, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('etat').textContent === 'IDENTIFIÉ·E'")
    p.wait_for_timeout(500)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert p.locator(f"#v-{vue}.on").count() == 1 and err == []
    ctx.close()


def test_encadree_annonce_la_hauteur_du_cadre_a_l_hote(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1000, "height": 700})
    p = ctx.new_page()

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "parent":
            r.fulfill(status=200, content_type="text/html", body='<script>window.__m=[];addEventListener("message",e=>__m.push(e.data))</script>'
                      '<iframe id="f" src="/identite/?demo=1" style="width:900px;height:3000px"></iframe>')
        elif chemin.rstrip("/") == "identite":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test/parent")
    p.wait_for_function("window.__m.length > 0 && window.__m.some(m => m.onglet === 'identite' && m.sbxVue > 100)")
    h = p.evaluate("window.__m.filter(m => m.onglet === 'identite').pop().sbxVue")
    assert 100 < h < 2500                                          # la hauteur du cadre, pas celle (3000) de l'iframe
    ctx.close()
