# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /gitea/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "gitea" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'gitea'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("ecrire('POST', '/install')", "'/user/' + encodeURIComponent(nom)", "ecrire('DELETE'", "ecrire('POST', '/user'",
              "ecrire('POST', '/backup')", "action('/start'", "action('/stop'", "action('/restart'"):
        assert r in SRC
    assert "{ username: f.username.value, email: f.email.value, password: f.password.value, admin: f.admin.checked }" in SRC
    # aucune écriture que l'ancienne page n'avait
    posts = set(re.findall(r"ecrire\('(?:POST|DELETE)', '([^']+)'", SRC)) | {"/start", "/stop", "/restart"}
    assert posts <= {"/install", "/user", "/user/", "/backup", "/start", "/stop", "/restart"}
    assert "/webhooks" not in SRC and "/restore" not in SRC and "/migrate" not in SRC and "/quotas" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "gitea", "version": "1.22.6", "enabled": True, "domain": "git.example.test",
          "components": {"gitea": {"name": "gitea", "installed": True, "running": True, "ip": "192.0.2.40"}},
          "repo_count": 0, "user_count": 2, "storage": "412M", "http_port": 3000, "ssh_port": 2222, "running": True, "installed": True}
ACCESS = {"domain": "git.example.test", "http": {"url": "http://192.0.2.40:3000", "clone_template": "http://192.0.2.40:3000/OWNER/REPO.git"},
          "ssh": {"port": 2222, "clone_template": "git@192.0.2.40:2222/OWNER/REPO.git"}, "web_interface": "http://192.0.2.40:3000",
          "api": "http://192.0.2.40:3000/api/v1", "running": True}
REPOS = {"repos": [{"name": "<img src=x onerror=window.__xss=1>", "owner": "demo", "size": "12M", "clone_http": "http://192.0.2.40:3000/demo/a.git"},
                   {"name": "infra", "owner": "demo", "size": "3M", "clone_http": "javascript:alert(1)"}], "count": 2}
USERS = {"users": [{"id": "1", "name": "demo", "email": "demo@example.test", "is_admin": True},
                   {"id": "2", "name": "equipe", "email": "equipe@example.test", "is_admin": False}], "count": 2}
BACKUPS = {"backups": [{"name": "gitea_20261012.tar.gz", "size": "210M", "timestamp": 1791774000}]}
API = {"/status": (200, STATUS), "/access": (200, ACCESS), "/repos": (200, REPOS), "/users": (200, USERS), "/backups": (200, BACKUPS),
       "/logs": (200, {"logs": ["ligne un", "ligne deux"]})}


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
        elif chemin.rstrip("/") == "gitea":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/gitea", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True, "message": "ok"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/gitea/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/gitea/", API)
    p.wait_for_function("document.getElementById('tUsers').textContent === '2'")
    # 0 est une mesure : « 0 », pas un tiret
    assert [p.inner_text(i) for i in ("#tEtat", "#tDepots", "#tUsers", "#tStock", "#tVer")] == ["En marche", "0", "2", "412M", "1.22.6"]
    assert p.inner_text("#etat") == "EN MARCHE" and p.inner_text("#kIp") == "192.0.2.40"
    p.click("#o-acces")
    assert p.inner_text("#uSsh") == "ssh://git@192.0.2.40:2222/OWNER/REPO.git"      # pas de git@hôte:port/ (invalide)
    assert p.inner_text("#uHttp") == "http://192.0.2.40:3000/OWNER/REPO.git"
    p.click("#o-depots"); p.wait_for_selector("#bDepots tr td.act")
    # nom hostile rendu en texte, jamais en HTML ; lien javascript: refusé
    assert "<img" in p.inner_text("#bDepots") and p.evaluate("window.__xss") is None
    assert p.locator("#bDepots a").count() == 1 and p.get_attribute("#bDepots a", "href") == "http://192.0.2.40:3000/demo/a"
    p.click("#o-users"); p.wait_for_selector("#bUsers tr td.act")
    assert "equipe@example.test" in p.inner_text("#bUsers") and "ADMIN" in p.inner_text("#bUsers")
    assert err == []
    ctx.close()


def test_jeton_envoye_en_bearer(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/gitea/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_timeout(300)
    assert any(a[3] == "Bearer jeton-test" for a in appels)
    ctx.close()


def test_supprimer_un_utilisateur_confirme_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/gitea/", {**API, "/user/equipe": (200, {"success": True})})
    p.click("#o-users"); p.wait_for_selector("#bUsers tr td.act")
    p.locator("#bUsers tr").nth(1).get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bUsers tr").nth(1).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rUsers').textContent.includes('supprimé')")
    assert ("DELETE", "/user/equipe", None) in [a[:3] for a in appels] and err == []
    ctx.close()


def test_creer_un_utilisateur_envoie_le_meme_corps_sans_afficher_le_mot_de_passe(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/gitea/", API)
    p.click("#o-users"); p.click("#addUser")
    p.fill("#fUser [name=username]", "alice"); p.fill("#fUser [name=email]", "alice@example.test"); p.fill("#fUser [name=password]", "S3cr3t-x")
    p.check("#fUser [name=admin]"); p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('rUsers').textContent.includes('créé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/user"][0]
    assert json.loads(post[2]) == {"username": "alice", "email": "alice@example.test", "password": "S3cr3t-x", "admin": True}
    assert "S3cr3t-x" not in p.inner_text("body") and err == []
    ctx.close()


def test_arret_du_conteneur_demande_confirmation_puis_poste(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/gitea/", API)
    p.click("#o-actions"); p.wait_for_selector("#gSvc button")
    p.locator("#gSvc").get_by_text("Arrêter").click()
    assert not [a for a in appels if a[1] == "/stop"]
    p.locator("#gSvc").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('arrêté')")
    assert ("POST", "/stop", None) in [a[:3] for a in appels]
    p.click("#btnBak"); p.wait_for_function("document.getElementById('rBak').textContent.includes('créée')")
    assert ("POST", "/backup", None) in [a[:3] for a in appels]
    p.click("#btnListeBak"); p.wait_for_selector("#bBak tr td.mono")
    assert "gitea_20261012" in p.inner_text("#bBak")
    p.click("#btnLogs"); p.wait_for_function("document.getElementById('journal').textContent.includes('ligne deux')")
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/gitea/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEtat", "#tDepots", "#tUsers", "#tStock", "#tVer")] == ["—"] * 5
    assert p.url.startswith("http://sbx.test/gitea/") and err == []     # plus de redirection vers /login.html
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/gitea/?demo=1", {})
    p.wait_for_function("document.getElementById('tUsers').textContent === '2'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-actions"); p.locator("#gSvc").get_by_text("Arrêter").click(); p.locator("#gSvc").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('inerte')")
    p.click("#btnBak"); p.wait_for_function("document.getElementById('rBak').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/gitea/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tUsers').textContent === '2'")
    for t in ("o-acces", "o-depots", "o-users", "o-actions"):
        p.click("#" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
