# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2674 — console sysop du BBS (www/bbs/index.html) au profil Aurora : statique + navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "bbs" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "hybrid-skin" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'bbs'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_et_corps_identiques_a_l_ancienne_console():
    for r in ("/status", "/integrity", "/threads", "/users", "/invites", "/settings", "/admin/salons", "/admin/passerelles",
              "/admin/moderation", "'/invite'", "'/backup'", "'/reindex'", "/users/delete", "/users/password", "/users/local",
              "'/users/' + (desactiver ? 'disable' : 'enable')", "'/admin/salons/' + id + '/prive'", "'/membres'",
              "'/communautes'", "'/invitation'"):
        assert r in SRC, r
    assert "{ id: id }" in SRC and "{ id: id, password: champ.value }" in SRC
    assert "{ instance: $('mastoInstance').value, invitation: $('mastoInvitation').value }" in SRC
    assert "{ slug: v('slSlug'), titre: v('slTitre'), desc: v('slDesc'), parent: +$('slParent').value }" in SRC
    assert "{ prive: prive }" in SRC and "{ membre: m, action: action }" in SRC and "{ communaute: uuid, action: action }" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer '" in SRC
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
USERS = {"users": [
    {"id": 1, "handle": "alice", "role": "sysop", "source": "local", "desactive": False, "derniere_connexion": NOW - 60, "sessions": 2},
    {"id": 2, "handle": "bob", "role": "membre", "source": "secubox", "desactive": False, "derniere_connexion": 0, "sessions": 0}]}
SALONS = {"salons": [
    {"id": 7, "slug": "general", "titre": "Général", "desc": "", "profondeur": 0, "fils": 3, "prive": False, "public": True, "membres": [], "communautes": []},
    {"id": 8, "slug": "atelier", "titre": "Atelier", "desc": "", "profondeur": 0, "fils": 1, "prive": True, "public": False,
     "membres": [{"id": 1, "handle": "alice"}], "communautes": []}],
    "comptes": [{"id": 1, "handle": "alice"}, {"id": 2, "handle": "bob"}], "communautes": [{"uuid": "u-1", "nom": "Cellule"}]}
API = {
    "/status": (200, {"titre": "BBS test", "version": "1.2.3", "salons": 2, "stats": {"Threads": 20, "Posts": 134, "Members": 7, "Files": 0, "Billets": 4}}),
    "/integrity": (200, {"integrite": {"Indexed": 20, "OnDisk": 20, "Diverging": 0, "Missing": 0, "Details": []}}),
    "/threads": (200, {"fils": [{"Title": "Fil <b>un</b>", "Visibility": "public", "Published": True, "Source": "", "Author": "alice", "Posts": 4}]}),
    "/users": (200, USERS), "/invites": (200, {"invites": [{"emetteur": "alice", "beneficiaire": "", "utilisee": False, "emise_le": NOW}]}),
    "/settings": (200, {"instance": "https://social.example.org", "invitation": ""}),
    "/admin/salons": (200, SALONS), "/admin/passerelles": (200, {"passerelles": []}), "/admin/moderation": (200, {"journal": []}),
    "/invite": (200, {"code": "CODE-ABC"}), "/backup": (200, {"archive": "/var/backups/bbs.tgz"}), "/reindex": (200, {"ok": True}),
}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script("localStorage.setItem('sbx_token','%s')" % jeton)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif"), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "bbs":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/bbs", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {"error": "inconnu"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/bbs/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_fils_et_integrite_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/bbs/", API, jeton="tok123")
    p.wait_for_selector("#fils .ligne")
    assert [p.inner_text(i) for i in ("#tFils", "#tMessages", "#tMembres", "#tFichiers", "#tBillets", "#tInteg")] == ["20", "134", "7", "0", "4", "OK"]
    assert p.inner_text("#etat") == "EN LIGNE" and "BBS test" in p.inner_text("#subline") and "v1.2.3" in p.inner_text("#subline")
    assert "<b>un</b>" in p.inner_text("#fils")            # donnée affichée en texte, jamais interprétée
    assert all(a[3] == "Bearer tok123" for a in appels)
    assert all(p.get_attribute(s, "title") for s in (".tuile >> nth=0", ".tuile >> nth=5"))
    assert err == []
    ctx.close()


def test_ecart_d_integrite_signale(navigateur):
    routes = {**API, "/integrity": (200, {"integrite": {"Indexed": 19, "OnDisk": 20, "Diverging": 1, "Missing": 0, "Details": ["fil-x"]}})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/bbs/", routes)
    p.wait_for_selector("#integrite .ligne.bad")
    assert p.inner_text("#tInteg") == "ÉCART" and "fil-x" in p.inner_text("#integrite") and "ÉCART" in p.inner_text("#etat")
    ctx.close()


def test_invitation_sauvegarde_et_reconstruction(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/bbs/", API)
    p.wait_for_selector("#fils .ligne")
    p.click("#inviter")
    p.wait_for_selector("#carteInvitation:not([hidden])")
    assert p.inner_text("#codeInvitation") == "CODE-ABC"
    p.click("#sauvegarder")
    p.wait_for_function("document.getElementById('toast').textContent.includes('archive écrite')")
    p.click("#reconstruire")
    assert not [a for a in appels if a[1] == "/reindex"]          # il faut confirmer dans la page
    p.click("#confOk")
    p.wait_for_function("document.getElementById('toast').textContent.includes('index reconstruit')")
    assert [(a[0], a[1], a[2]) for a in ecritures(appels)] == [("POST", "/invite", None), ("POST", "/backup", None), ("POST", "/reindex", None)]
    assert err == []
    ctx.close()


def test_reconstruction_annulee(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/bbs/", API)
    p.wait_for_selector("#fils .ligne")
    p.click("#reconstruire"); p.click("#confNon")
    assert not p.is_visible("#conf") and not ecritures(appels)
    ctx.close()


def test_onglet_sysop_comptes_et_actions(navigateur):
    routes = {**API, "/users/disable": (200, {"ok": True}), "/users/password": (200, {"ok": True}), "/users/local": (200, {"ok": True}),
              "/users/delete": (200, {"ok": True}), "/settings": (200, {"instance": "https://social.example.org", "invitation": ""})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/bbs/", routes)
    p.wait_for_selector("#fils .ligne")
    p.click(".onglet[data-vue=sysop]")
    assert p.get_attribute(".onglet[data-vue=sysop]", "aria-selected") == "true"
    p.wait_for_selector("#comptes tbody tr")
    p.wait_for_function("document.getElementById('mastoInstance').value !== ''")
    assert p.input_value("#mastoInstance") == "https://social.example.org"
    ligne_a = p.locator("#comptes tbody tr").nth(0)
    ligne_b = p.locator("#comptes tbody tr").nth(1)
    ligne_a.get_by_text("Désactiver", exact=True).click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('désactivé')")
    ligne_a.get_by_text("Réinitialiser").click()                 # champ vide : refusé sans appel
    assert not [a for a in appels if a[1] == "/users/password"]
    p.fill("#pw-1", "nouveau-mdp"); ligne_a.get_by_text("Réinitialiser").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('réinitialisé')")
    p.fill("#pw-2", "local-mdp"); ligne_b.get_by_text("Reprendre en local").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('repris en local')")
    # suppression : confirmation dans la page, avec saisie du pseudonyme
    ligne_a.get_by_text("Supprimer", exact=True).click()
    assert p.is_disabled("#confOk")
    p.fill("#confSaisie", "alic"); assert p.is_disabled("#confOk")
    p.fill("#confSaisie", "alice"); p.click("#confOk")
    p.wait_for_function("document.getElementById('toast').textContent.includes('supprimé')")
    p.click("#enregistrer")
    p.wait_for_function("document.getElementById('toast').textContent.includes('réglages enregistrés')")
    corps = {(a[1]): json.loads(a[2]) for a in ecritures(appels)}
    assert corps["/users/disable"] == {"id": 1} and corps["/users/password"] == {"id": 1, "password": "nouveau-mdp"}
    assert corps["/users/local"] == {"id": 2, "password": "local-mdp"} and corps["/users/delete"] == {"id": 1}
    assert corps["/settings"] == {"instance": "https://social.example.org", "invitation": ""}
    assert err == []
    ctx.close()


def test_suppression_annulee_n_appelle_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/bbs/", API)
    p.click(".onglet[data-vue=sysop]"); p.wait_for_selector("#comptes tbody tr")
    p.locator("#comptes tbody tr").nth(0).get_by_text("Supprimer", exact=True).click(); p.click("#confNon")
    assert not ecritures(appels)
    ctx.close()


def test_onglet_salons_creation_et_gestes(navigateur):
    ok = (200, {"ok": True})
    routes = {**API, "/admin/salons": (200, SALONS), "/admin/salons/8/prive": ok, "/admin/salons/8/membres": ok,
              "/admin/salons/8/communautes": ok, "/admin/salons/8/invitation": (200, {"lien": "/s/abc"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/bbs/", routes)
    p.click(".onglet[data-vue=salons]"); p.wait_for_selector("#salonsPrives tbody tr")
    assert "Atelier" in p.inner_text("#salonsArbre") and p.locator("#slParent option").count() == 3
    p.click("#creerSalon")                                        # identifiant et titre requis
    assert not [a for a in appels if a[0] == "POST"]
    p.fill("#slSlug", "nouveau"); p.fill("#slTitre", "Nouveau"); p.select_option("#slParent", "7")
    p.click("#creerSalon")
    p.wait_for_function("document.getElementById('toast').textContent.includes('salon créé')")
    ligne = p.locator("#salonsPrives tbody tr").nth(1)
    ligne.get_by_text("Convier").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('convié')")
    ligne.get_by_text("Ouvrir", exact=True).click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('ouvert à la communauté')")
    ligne.get_by_text("Rouvrir").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('salon rouvert')")
    ligne.get_by_text("Émettre un lien").click()
    p.wait_for_selector("#lienSalon:not([hidden])")
    assert "/bbs/s/abc" in p.inner_text("#lienSalon")
    corps = {a[1]: json.loads(a[2]) for a in ecritures(appels) if a[0] == "POST"}
    assert corps["/admin/salons"] == {"slug": "nouveau", "titre": "Nouveau", "desc": "", "parent": 7}
    assert corps["/admin/salons/8/membres"] == {"membre": 1, "action": "ajouter"}
    assert corps["/admin/salons/8/communautes"] == {"communaute": "u-1", "action": "ajouter"}
    assert corps["/admin/salons/8/prive"] == {"prive": False} and corps["/admin/salons/8/invitation"] == {}
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"error": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/bbs/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tFils", "#tMessages", "#tMembres", "#tFichiers", "#tBillets", "#tInteg")] == ["—"] * 6
    assert err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/bbs/?demo=1", {})
    p.wait_for_selector("#fils .ligne")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tFils") == "20"
    p.click("#inviter")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.click("#sauvegarder")
    p.click(".onglet[data-vue=sysop]"); p.wait_for_selector("#comptes tbody tr")
    p.locator("#comptes tbody tr").nth(0).get_by_text("Désactiver", exact=True).click()
    p.click(".onglet[data-vue=salons]"); p.wait_for_selector("#salonsPrives tbody tr")
    p.fill("#slSlug", "x"); p.fill("#slTitre", "X"); p.click("#creerSalon")
    p.click("#reconstruire"); p.click("#confOk")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    for vue in ("exploitation", "sysop", "salons"):
        ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/bbs/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
        p.wait_for_selector("#fils .ligne")
        p.click(".onglet[data-vue=%s]" % vue)
        p.wait_for_timeout(300)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), vue
        assert not p.is_visible("#sidebar") and err == []
        ctx.close()
