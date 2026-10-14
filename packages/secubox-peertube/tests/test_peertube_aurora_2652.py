# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2652 — /peertube/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "peertube" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == []          # le menu est injecté hors embed/démo
    assert "/shared/sidebar.js" in SRC
    assert "hybrid-dark" not in SRC and "crt-" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'peertube'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "setItem" not in SRC


def test_toutes_les_routes_de_l_ancienne_page_sont_conservees():
    for r in ("'/status'", "'/version'", "/videos?count=20", "'/imports'", "'/channels'", "'/users'", "/federation/following",
              "/federation/followers", "/transcoding/settings", "/transcoding/backlog", "/transcoding/jobs", "/storage/stats",
              "'/plugins'", "/logs?lines=", "'/playlist/jobs'", "/admin/op/"):
        assert r in SRC, r
    for r in ("'POST', '/import'", "'POST', '/playlist/import'", "'POST', '/channel'", "'DELETE', '/channel/'", "'POST', '/user'",
              "'DELETE', '/user/'", "'POST', '/federation/follow'", "'POST', '/transcoding/settings'", "'POST', '/plugin/install'",
              "'DELETE', '/plugin/'", "'POST', '/admin/reset-password'", "'POST', '/upgrade'", "'/container/restart'",
              "'/container/uninstall'", "'/container/install'", "/container/stop", "/container/start", "/cancel"):
        assert r in SRC, r
    assert "target: 'latest'" in SRC and "name_prefix" in SRC and "npm_name" in SRC and "display_name" in SRC


def test_onglets_accessibles_et_huit_sections():
    assert "role', 'tablist'" in SRC or 'role="tablist"' in SRC
    assert "'role', 'tab'" in SRC and "aria-selected" in SRC and "focus-visible" in SRC and 'role="tabpanel"' in SRC
    for nom in ("Vidéos", "Import", "Chaînes", "Utilisateurs", "Fédération", "Transcodage", "Extensions", "Journaux"):
        assert nom in SRC


def test_aucun_identifiant_initial_ni_secret_affiche():
    assert "gisatejewumefatibedu" not in SRC
    assert "res.password" not in SRC and "New password" not in SRC
    assert "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"container_status": "running", "runtime": "lxc", "video_count": 0, "disk_usage": "1,2 Go", "federation_enabled": True,
          "public_url": "https://videos.example.org/"}
API = {
    "/status": (200, STATUS),
    "/version": (200, {"installed": "7.1.1", "latest": "7.2.0", "upgrade_available": True}),
    "/videos": (200, {"videos": [{"id": 1, "name": "Vidéo fictive", "views": 7}]}),
    "/channels": (200, {"channels": [{"id": 3, "name": "atelier", "displayName": "Atelier", "followersCount": 2, "videosCount": 5}]}),
    "/imports": (200, {"imports": []}),
    "/playlist/jobs": (200, {"jobs": [{"id": "j1", "title": "Liste", "total": 4, "done": 1, "errors": 0, "status": "running"}]}),
    "/users": (200, {"users": [{"id": 9, "username": "alice", "email": "alice@example.org", "role": 1, "videosCount": 0}]}),
    "/federation/following": (200, {"following": [{"following": {"host": "video.example.com"}, "state": "accepted"}]}),
    "/federation/followers": (200, {"followers": []}),
    "/transcoding/settings": (200, {"enabled": True, "threads": 3, "hls_enabled": True, "webtorrent_enabled": False, "resolutions": {"1440p": True}}),
    "/transcoding/backlog": (200, {"available": True, "unplayable": 2, "states": [{"label": "En attente", "videos": 2, "without_hls": 2}]}),
    "/transcoding/jobs": (200, {"jobs": []}),
    "/storage/stats": (200, {"stats": {"total": "1,2 Go"}}),
    "/plugins": (200, {"plugins": [{"name": "peertube-plugin-x", "version": "1.0", "npmName": "peertube-plugin-x"}]}),
    "/logs": (200, {"logs": "ligne de journal"}),
}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "peertube":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/peertube", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(r.request.method + " " + chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/peertube/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def prete(p):
    p.wait_for_function("document.getElementById('etat').textContent !== 'Chargement…'")


def onglet(p, nom):
    p.click(f"#o-{nom}")
    assert p.get_attribute(f"#o-{nom}", "aria-selected") == "true"


def corps(appels, methode, chemin):
    return [json.loads(a[2]) if a[2] else None for a in appels if a[0] == methode and a[1] == chemin]


def test_tuiles_viennent_de_l_api_et_zero_est_une_mesure(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p)
    p.wait_for_selector("#listeVideos .video")
    assert p.inner_text("#etat") == "EN MARCHE"
    assert [p.inner_text(i) for i in ("#tStatut", "#tRuntime", "#tVideos", "#tStockage", "#tFed")] == ["En marche", "lxc", "0", "1,2 Go", "Activée"]
    assert p.is_visible("#ouvrir") and p.get_attribute("#ouvrir", "href") == "https://videos.example.org/"
    assert "Vidéo fictive" in p.inner_text("#listeVideos")
    assert p.get_attribute("#cStatut", "title")
    assert all(a[3] is None for a in appels)           # pas de jeton stocké : pas d'en-tête Authorization
    assert err == []
    ctx.close()


def test_jeton_envoye_en_bearer(navigateur):
    ctx = navigateur.new_context()
    ctx.add_init_script("localStorage.setItem('sbx_token','abc')")
    ctx.close()
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_function("window.__n = (window.__n||0)+1, true")
    p.wait_for_timeout(300)
    assert any(a[3] == "Bearer jeton-test" for a in appels)
    ctx.close()


def test_navigation_clavier_des_onglets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p)
    p.focus("#o-videos"); p.keyboard.press("ArrowRight")
    assert p.get_attribute("#o-import", "aria-selected") == "true" and p.is_visible("#p-import") and not p.is_visible("#p-videos")
    p.keyboard.press("End")
    assert p.get_attribute("#o-logs", "aria-selected") == "true"
    for nom in ("videos", "import", "chaines", "users", "fed", "tc", "plug", "logs"):
        onglet(p, nom)
    assert err == []
    ctx.close()


def test_import_playlist_et_video_simple_corps_identiques(navigateur):
    routes = {**API, "POST /playlist/import": (200, {"success": True, "total": 4, "already_done": 1})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", routes)
    prete(p); onglet(p, "import"); p.wait_for_selector("#impChaine option[value='3']", state="attached")
    p.fill("#impUrl", "https://video.example.net/playlist?list=PL1"); p.fill("#impNom", "Pre")
    p.click("#btnImport")
    p.wait_for_function("document.getElementById('rImport').textContent.includes('4 vidéo')")
    assert corps(appels, "POST", "/playlist/import") == [{"target_url": "https://video.example.net/playlist?list=PL1", "privacy": 3, "name_prefix": "Pre", "channel_id": 3}]
    p.fill("#impUrl", "https://video.example.net/watch?v=1"); p.fill("#impNom", "Seule")
    p.click("#btnImport")
    p.wait_for_function("document.getElementById('rImport').textContent.includes('Import en file')")
    assert corps(appels, "POST", "/import") == [{"target_url": "https://video.example.net/watch?v=1", "privacy": 3, "name": "Seule", "channel_id": 3}]
    ctx.close()


def test_liste_fausse_playlist_retombe_sur_import_simple(navigateur):
    routes = {**API, "POST /playlist/import": (200, {"success": False, "is_playlist": False})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", routes)
    prete(p); onglet(p, "import"); p.wait_for_selector("#impChaine option[value='3']", state="attached")
    p.fill("#impUrl", "https://video.example.net/watch?v=1&list=RD1"); p.click("#btnImport")
    p.wait_for_function("document.getElementById('rImport').textContent.includes('Import en file')")
    assert len(corps(appels, "POST", "/import")) == 1
    ctx.close()


def test_arret_d_une_liste_demande_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p); onglet(p, "import"); p.wait_for_selector("#bListes button")
    p.click("#bListes button")
    assert p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rListes').textContent.includes('arrêt')")
    assert ("POST", "/playlist/jobs/j1/cancel") in [(a[0], a[1]) for a in appels]
    ctx.close()


def test_chaine_creation_et_suppression(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p); onglet(p, "chaines"); p.wait_for_selector("#bChaines td.act")
    p.fill("#chNom", "nouvelle"); p.fill("#chAff", "Nouvelle"); p.fill("#chDesc", "d")
    p.click("#fChaine button[type=submit]")
    p.wait_for_function("document.getElementById('rChaine').textContent.includes('créée')")
    assert corps(appels, "POST", "/channel") == [{"name": "nouvelle", "display_name": "Nouvelle", "description": "d"}]
    p.click("#bChaines button"); p.click("#confNon")
    assert not [a for a in appels if a[0] == "DELETE"]
    p.click("#bChaines button"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rChaine').textContent.includes('supprimée')")
    assert ("DELETE", "/channel/atelier") in [(a[0], a[1]) for a in appels]
    ctx.close()


def test_utilisateur_creation_et_mot_de_passe_court_refuse(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p); onglet(p, "users"); p.wait_for_selector("#bUsers td.act")
    assert "Modérateur" in p.inner_text("#bUsers")
    p.fill("#usNom", "bob"); p.fill("#usMail", "bob@example.org"); p.fill("#usPass", "court")
    p.click("#fUser button[type=submit]")
    assert "8 caractères" in p.inner_text("#rUser") and not corps(appels, "POST", "/user")
    p.fill("#usPass", "longmotdepasse"); p.select_option("#usRole", "0")
    p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('rUser').textContent.includes('créé')")
    assert corps(appels, "POST", "/user") == [{"username": "bob", "email": "bob@example.org", "password": "longmotdepasse", "role": 0}]
    assert p.input_value("#usPass") == ""
    ctx.close()


def test_reinitialisation_admin_n_affiche_jamais_le_mot_de_passe(navigateur):
    routes = {**API, "POST /admin/reset-password": (200, {"success": True, "id": "op1"}),
              "/admin/op/op1": (200, {"status": "done", "password": "SECRET-GENERE-123"})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", routes)
    prete(p); onglet(p, "users")
    p.click("#btnReset"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rReset').textContent.includes('réinitialisé')")
    assert corps(appels, "POST", "/admin/reset-password") == [{"password": None}]
    assert "SECRET-GENERE-123" not in p.content() and "SECRET-GENERE-123" not in p.inner_text("body")
    ctx.close()


def test_federation_suivre_des_hotes(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p); onglet(p, "fed"); p.wait_for_selector("#lSuivies .ligne")
    assert "video.example.com" in p.inner_text("#lSuivies") and "Aucun abonné" in p.inner_text("#lAbonnes")
    p.fill("#fwHotes", "a.example.org, b.example.org ,")
    p.click("#fFollow button[type=submit]")
    p.wait_for_function("document.getElementById('rFollow').textContent.includes('envoyée')")
    assert corps(appels, "POST", "/federation/follow") == [{"hosts": ["a.example.org", "b.example.org"]}]
    ctx.close()


def test_transcodage_lit_et_enregistre(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p); onglet(p, "tc"); p.wait_for_selector("#backlog .ligne")
    assert p.input_value("#tcThreads") == "3" and p.is_checked("#res1440") and not p.is_checked("#tcWebTorrent")
    assert "2 vidéos sans playlist HLS" in p.inner_text("#backlog") and "1,2 Go" in p.inner_text("#stockage")
    p.uncheck("#res240"); p.click("#fTc button[type=submit]")
    p.wait_for_function("document.getElementById('rTc').textContent.includes('enregistrés')")
    c = corps(appels, "POST", "/transcoding/settings")[0]
    assert c["threads"] == 3 and c["hls_enabled"] is True and c["webtorrent_enabled"] is False
    assert c["resolutions"]["240p"] is False and c["resolutions"]["1440p"] is True and len(c["resolutions"]) == 7
    ctx.close()


def test_extensions_installer_et_desinstaller(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p); onglet(p, "plug"); p.wait_for_selector("#bPlug td.act")
    p.fill("#plNpm", "peertube-plugin-y"); p.click("#fPlug button[type=submit]")
    p.wait_for_function("document.getElementById('rPlug').textContent.includes('installée')")
    assert corps(appels, "POST", "/plugin/install") == [{"npm_name": "peertube-plugin-y"}]
    p.click("#bPlug button"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPlug').textContent.includes('désinstallée')")
    assert ("DELETE", "/plugin/peertube-plugin-x") in [(a[0], a[1]) for a in appels]
    ctx.close()


def test_journaux_et_maintenance_mise_a_niveau(navigateur):
    routes = {**API, "POST /upgrade": (200, {"success": True, "id": "up1"}), "/admin/op/up1": (200, {"status": "done", "backup": "/data/b.sql"})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", routes)
    prete(p); onglet(p, "logs")
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne de journal')")
    p.select_option("#logLignes", "200")
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne')")
    assert any(a[1] == "/logs" for a in appels)
    p.wait_for_selector("#btnUpgrade:not([hidden])")
    assert "7.2.0" in p.inner_text("#btnUpgrade")
    p.click("#btnUpgrade"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rMaint').textContent.includes('terminée')")
    assert corps(appels, "POST", "/upgrade") == [{"target": "latest"}]
    p.click("#btnRestart"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rMaint').textContent.includes('redémarré')")
    assert ("POST", "/container/restart") in [(a[0], a[1]) for a in appels]
    ctx.close()


def test_arret_du_service_via_le_bouton_principal(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p)
    assert p.inner_text("#btnToggle") == "Arrêter"
    p.click("#btnToggle")
    p.wait_for_function("document.getElementById('toast').textContent.includes('arrêté')")
    assert ("POST", "/container/stop") in [(a[0], a[1]) for a in appels]
    ctx.close()


def test_non_installe_propose_l_installation_avec_confirmation(navigateur):
    routes = {**API, "/status": (200, {"container_status": "not_installed"}), "POST /container/install": (200, {"success": True, "message": "ok"})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/peertube/", routes)
    prete(p)
    assert p.is_visible("#accueil") and p.inner_text("#etat") == "NON INSTALLÉ" and p.inner_text("#tVideos") == "—"
    p.click("#btnInstall")
    assert not [a for a in appels if a[1] == "/container/install"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('toast').textContent.includes('ok')")
    assert ("POST", "/container/install") in [(a[0], a[1]) for a in appels]
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/peertube/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tStatut", "#tRuntime", "#tVideos", "#tStockage", "#tFed")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/peertube/?demo=1", {})
    p.wait_for_selector("#listeVideos .video")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tVideos") == "42"
    onglet(p, "chaines"); p.wait_for_selector("#bChaines td.act")
    p.fill("#chNom", "x"); p.fill("#chAff", "X"); p.click("#fChaine button[type=submit]")
    p.wait_for_function("document.getElementById('rChaine').textContent.includes('inerte')")
    for nom in ("import", "users", "fed", "tc", "plug", "logs"):
        onglet(p, nom)
    p.wait_for_function("document.getElementById('journal').textContent.includes('démonstration')")
    assert appels == [] and err == []
    assert not p.evaluate("!!document.querySelector('script[src*=\"sidebar\"]')")
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/peertube/?embed=1", API, taille={"width": 420, "height": 800})
    prete(p)
    for nom in ("videos", "import", "chaines", "users", "fed", "tc", "plug", "logs"):
        onglet(p, nom)
        p.wait_for_timeout(120)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), nom
    assert not p.is_visible("#sidebar") and err == []
    assert not p.evaluate("!!document.querySelector('script[src*=\"sidebar\"]')")
    ctx.close()


def test_menu_commun_charge_hors_embed_et_hors_demo(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/peertube/", API)
    prete(p)
    assert p.evaluate("!!document.querySelector('script[src=\"/shared/sidebar.js\"]')")
    ctx.close()
