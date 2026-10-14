# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /nextcloud/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "nextcloud" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "crt-engine" not in SRC and "crt-light" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'nextcloud'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC


def test_routes_d_ecriture_a_l_identique():
    ecritures = [
        ("'/user', { method: 'POST', body: JSON.stringify({ uid, display_name: dn, password: pw })",),
        ("'/user/' + encodeURIComponent(uid) + '/' + op, { method: 'POST' }",),
        ("'/user/' + encodeURIComponent(uid) + '/quota', { method: 'POST', body: JSON.stringify({ quota })",),
        ("'/user/password', { method: 'POST', body: JSON.stringify({ uid, password: pw })",),
        ("'/user/' + encodeURIComponent(uid), { method: 'DELETE' }",),
        ("'/backup', { method: 'POST' }",),
        ("'/backup/' + encodeURIComponent(name), { method: 'DELETE' }",),
        ("'/restore/' + encodeURIComponent(name), { method: 'POST' }",),
        ("'/occ', { method: 'POST', body: JSON.stringify({ command: cmd })",),
        ("'/config', { method: 'POST', body: JSON.stringify(body)",),
        ("'/start', { method: 'POST' }",), ("'/stop', { method: 'POST' }",), ("'/restart', { method: 'POST' }",),
        ("'/install', { method: 'POST' }",), ("'/uninstall', { method: 'POST' }",),
    ]
    for (e,) in ecritures:
        assert "await api(" + e in SRC, e
    # aucune route nouvelle : ni mise à jour ni SSL, que l'ancienne page n'appelait pas
    assert "'/update'" not in SRC and "/ssl/" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"module": "nextcloud", "running": True, "reachable": True, "installed": True, "version": "29.0.7", "user_count": 4,
          "web_url": "http://192.0.2.10:8080", "domain": "cloud.example.org"}
STORAGE = {"used": "41G", "total": "220G", "used_pct": 19, "data": "37G", "ts": NOW - 120}
CONN = {"base_url": "http://192.0.2.10:8080", "webdav": "http://192.0.2.10:8080/remote.php/dav/files/<username>/", "caldav": "http://192.0.2.10:8080/c",
        "carddav": "http://192.0.2.10:8080/d", "davx5_url": "http://192.0.2.10:8080/remote.php/dav",
        "ios_app": "https://apps.apple.com/app/nextcloud/id1125420102", "android_app": "javascript:alert(1)"}
USERS = {"users": [{"uid": "alice", "displayname": "Alice <b>", "enabled": True, "quota": "10 GB"},
                   {"uid": "bob", "displayname": "Bob", "enabled": False, "quota": ""}]}
BACKUPS = {"backups": [{"name": "20261012-0300", "size": "1840M", "timestamp": NOW - 90000}]}
CONFIG = {"http_port": 8080, "domain": "cloud.example.org", "memory_limit": "1G", "upload_max": "512M", "admin_user": "admin",
          "redis_enabled": True, "ssl_enabled": False, "ssl_domain": "", "backup_enabled": True, "backup_keep": 7}
API = {"/status": (200, STATUS), "/storage": (200, STORAGE), "/connections": (200, CONN), "/users": (200, USERS), "/backups": (200, BACKUPS),
       "/logs": (200, {"logs": ["ligne un", "ligne deux"]}), "/config": (200, CONFIG)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "nextcloud":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/nextcloud", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/nextcloud/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def charge(navigateur, routes=API, url="http://sbx.test/nextcloud/", **kw):
    ctx, p, err, appels = ouvre(navigateur, url, routes, **kw)
    p.wait_for_function("document.getElementById('maj').textContent !== '—'")
    return ctx, p, err, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = charge(navigateur)
    assert [p.inner_text(i) for i in ("#tEtat", "#tComptes", "#tDonnees", "#tStock", "#tVersion")] == ["En marche", "4", "37G", "19 %", "29.0.7"]
    assert p.inner_text("#etat") == "EN MARCHE" and "192.0.2.10:8080" in p.inner_text("#sousTitre")
    # la valeur d'API est du texte : jamais interprétée comme du HTML
    assert "Alice <b>" in p.inner_text("#bComptes") and p.locator("#bComptes b").count() == 0
    assert "DÉSACTIVÉ" in p.inner_text("#bComptes") and "défaut" in p.inner_text("#bComptes")
    assert "20261012-0300" in p.inner_text("#bSauv") and "ligne deux" in p.inner_text("#sJournal")
    assert "41G" in p.inner_text("#kUsed") and "220G" in p.inner_text("#kTotal")
    assert p.input_value("#fConfig [name=memory_limit]") == "1G"
    # un lien d'application non https n'est jamais posé
    assert p.is_visible("#lIos") and not p.is_visible("#lAndroid")
    assert ecritures(appels) == [] and err == []
    # exactement les sept lectures de l'ancienne page, une fois chacune
    assert sorted(a[1] for a in appels) == sorted(["/status", "/storage", "/connections", "/users", "/backups", "/logs", "/config"])
    ctx.close()


def test_mesures_absentes_en_tirets(navigateur):
    froid = {**API, "/status": (200, {**STATUS, "version": "", "user_count": 0}), "/storage": (200, {"used": "", "total": "", "used_pct": 0, "data": "", "ts": 0})}
    ctx, p, err, _ = charge(navigateur, froid)
    assert p.inner_text("#tComptes") == "—" and p.inner_text("#tDonnees") == "—" and p.inner_text("#tStock") == "—" and p.inner_text("#tVersion") == "—"
    assert err == []
    ctx.close()


def test_arret_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = charge(navigateur)
    p.click("#bArreter")
    assert ecritures(appels) == [] and p.is_visible("#z-conteneur .conf")
    p.click("#z-conteneur .conf button:text-is(\"Annuler\")")
    assert ecritures(appels) == []
    p.click("#bArreter"); p.click("#z-conteneur .conf button:text-is(\"Confirmer\")")
    p.wait_for_function("document.getElementById('r-conteneur').textContent.includes('Arrêt')")
    assert ("POST", "/stop", None) in appels and err == []
    ctx.close()


def test_suppression_de_compte_exige_l_identifiant(navigateur):
    ctx, p, err, appels = charge(navigateur)
    p.locator("#bComptes tr").first.get_by_text("Supprimer").click()
    ok = p.locator("#z-comptes .conf button:text-is(\"Confirmer\")")
    assert ok.is_disabled()
    p.fill("#z-comptes .conf input", "alice")
    ok.click()
    p.wait_for_function("document.getElementById('r-comptes').textContent.includes('supprimé')")
    assert ("DELETE", "/user/alice", None) in appels and err == []
    ctx.close()


def test_creer_un_compte_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = charge(navigateur)
    p.click("#addUser")
    p.fill("#fUser [name=uid]", "carol"); p.fill("#fUser [name=display_name]", "Carol"); p.fill("#fUser [name=password]", "S3cret-pour-test")
    p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('r-comptes').textContent.includes('créé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/user"][0]
    assert json.loads(post[2]) == {"uid": "carol", "display_name": "Carol", "password": "S3cret-pour-test"}
    assert "S3cret-pour-test" not in p.content() and p.input_value("#fUser [name=password]") == ""
    ctx.close()


def test_quota_mot_de_passe_et_bascule(navigateur):
    ctx, p, _, appels = charge(navigateur)
    p.locator("#bComptes tr").first.get_by_text("Quota").click()
    p.fill("#fQuota [name=quota]", "5GB"); p.click("#fQuota button[type=submit]")
    p.wait_for_function("document.getElementById('r-comptes').textContent.includes('Quota appliqué')")
    assert ("POST", "/user/alice/quota", json.dumps({"quota": "5GB"}, separators=(",", ":"))) in appels
    p.locator("#bComptes tr").nth(1).get_by_text("Activer").click()
    p.wait_for_function("document.getElementById('r-comptes').textContent.includes('activé')")
    assert ("POST", "/user/bob/enable", None) in appels
    p.locator("#bComptes tr").first.get_by_text("Mot de passe").click()
    p.fill("#fMdp [name=password]", "Nouveau-Mdp-1"); p.click("#fMdp button[type=submit]")
    assert not [a for a in appels if a[1] == "/user/password"]       # confirmation d'abord
    p.click("#z-comptes .conf button:text-is(\"Confirmer\")")
    p.wait_for_function("document.getElementById('r-comptes').textContent.includes('réinitialisé')")
    post = [a for a in appels if a[1] == "/user/password"][0]
    assert json.loads(post[2]) == {"uid": "alice", "password": "Nouveau-Mdp-1"}
    ctx.close()


def test_occ_et_sauvegardes_et_config(navigateur):
    routes = {**API, "/occ": (200, {"success": True, "output": "versionstring: 29.0.7"})}
    ctx, p, err, appels = charge(navigateur, routes)
    p.fill("#cmdOcc", "status"); p.press("#cmdOcc", "Enter")
    p.click("#z-occ .conf button:text-is(\"Confirmer\")")
    p.wait_for_function("document.getElementById('sOcc').textContent.includes('versionstring')")
    assert ("POST", "/occ", json.dumps({"command": "status"}, separators=(",", ":"))) in appels
    # une commande qui coupe le service demande de saisir « occ »
    p.fill("#cmdOcc", "maintenance:mode --on"); p.press("#cmdOcc", "Enter")
    assert p.locator("#z-occ .conf button:text-is(\"Confirmer\")").is_disabled()
    assert len([a for a in appels if a[1] == "/occ"]) == 1
    p.click("#z-occ .conf button:text-is(\"Annuler\")")
    p.locator("#bSauv tr").first.get_by_text("Restaurer").click()
    p.fill("#z-sauv .conf input", "20261012-0300"); p.click("#z-sauv .conf button:text-is(\"Confirmer\")")
    p.wait_for_function("document.getElementById('r-sauv').textContent.includes('Restauration')")
    assert ("POST", "/restore/20261012-0300", None) in appels
    p.fill("#fConfig [name=domain]", "nuage.example.org"); p.click("#fConfig button[type=submit]")
    p.wait_for_function("document.getElementById('r-config').textContent.includes('enregistrée')")
    corps = json.loads([a for a in appels if a[0] == "POST" and a[1] == "/config"][0][2])
    assert corps == {"http_port": 8080, "domain": "nuage.example.org", "memory_limit": "1G", "upload_max": "512M"} and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = charge(navigateur, refus)
    assert p.is_visible("#session") and "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tComptes", "#tDonnees", "#tStock", "#tVersion")] == ["—"] * 4
    assert "login.html" in p.get_attribute("#session a", "href") and err == []
    assert p.url.startswith("http://sbx.test/nextcloud")           # plus de redirection vers la connexion
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = charge(navigateur, {}, url="http://sbx.test/nextcloud/?demo=1")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert "alice" in p.inner_text("#bComptes") and "192.0.2.10" in p.inner_text("#sousTitre")
    p.click("#bRedemarrer"); p.click("#z-conteneur .conf button:text-is(\"Confirmer\")")
    p.wait_for_function("document.getElementById('r-conteneur').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    for url in ("http://sbx.test/nextcloud/?embed=1", "http://sbx.test/nextcloud/?demo=1&embed=1"):
        ctx, p, err, _ = charge(navigateur, API, url=url, taille={"width": 420, "height": 800})
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        assert not p.is_visible("#sidebar") and err == []
        ctx.close()
