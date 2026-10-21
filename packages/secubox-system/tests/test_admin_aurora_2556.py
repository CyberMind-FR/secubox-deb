# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /admin/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants" / "admin" / "www" / "admin" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert re.findall(r'<link[^>]+href="([^"]+)"', SRC) == ["/shared/sidebar-light.css"]
    assert "crt-engine" not in SRC and "hybrid-dark" not in SRC and "googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'admin'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    # Même route, même méthode, même corps que l'ancienne page.
    assert "'/service/' + encodeURIComponent(nom) + '/' + action" in SRC
    assert "ecrire('POST', '/reboot', { confirm: true, reason })" in SRC
    assert "ecrire('POST', '/shutdown', { confirm: true, reason })" in SRC
    assert "ecrire('POST', '/update', { confirm: true, packages: [] })" in SRC
    for r in ("'/status'", "'/services'", "'/storage'", "'/logs?'", "'/processes?'", "'/updates'"):
        assert r in SRC
    assert SRC.count("ecrire('POST'") == 4 and "DELETE" not in SRC and "'PUT'" not in SRC
    assert "sbx_token" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def svc(name, active, sub, desc, sbx=False):
    return {"name": name, "unit": name + ".service", "load": "loaded", "active": active, "sub": sub, "description": desc,
            "is_running": active == "active" and sub == "running", "is_secubox": sbx}


STATUS = {"hostname": "gk-test", "kernel": "6.1.0-test", "debian_version": "12.7", "cpu_percent": 12.5, "memory_percent": 47.0, "memory_used": "1.8 GB",
          "memory_total": "3.8 GB", "disk_percent": 38.5, "disk_used": "11.6 GB", "disk_total": "30.2 GB", "load_avg": [0.42, 0.51, 0.47],
          "uptime_seconds": 90061, "uptime_human": "1 day, 1:01:01", "boot_time": "2026-10-10T07:12:30"}
SERVICES = {"services": [svc("secubox-waf-ng", "active", "running", "WAF", True), svc("secubox-off", "inactive", "dead", "Arrêté", True),
                         svc("nginx", "active", "running", "nginx"), svc("<b>x</b>", "failed", "failed", "<img src=x onerror=window.PWN=1>")],
            "count": 4, "secubox_count": 2, "running_count": 2}
STORAGE = {"partitions": [{"device": "/dev/sda1", "mountpoint": "/", "fstype": "ext4", "total_human": "30.2 GB", "used_human": "11.6 GB", "percent": 38.5},
                          {"device": "/dev/sdb1", "mountpoint": "/data", "fstype": "ext4", "total_human": "900 GB", "used_human": "800 GB", "percent": 91.0}]}
PROCS = {"total": 90, "processes": [{"pid": 7, "name": "sbxwaf", "cmd": "sbxwaf", "cpu_percent": 6.4, "memory_percent": 1.9, "status": "running", "user": "waf", "threads": 12}]}
LOGS = {"logs": ["ligne un", "ligne deux"], "count": 2}
UPD = {"available": 2, "packages": [{"name": "libx", "old_version": "1.0", "new_version": "1.1"}, {"name": "outil", "old_version": "2", "new_version": "3"}]}
API = {"/status": (200, STATUS), "/services": (200, SERVICES), "/storage": (200, STORAGE), "/processes": (200, PROCS), "/logs": (200, LOGS), "/updates": (200, UPD),
       # #3002 : la mise à niveau tourne en arrière-plan, la page suit /update/status jusqu'à « idle »
       "/update/status": (200, {"phase": "idle", "derniere": "appliquer", "ok": True, "appliques": 2, "count": 0, "en_cours": False})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "admin":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/admin", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.url))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/admin/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/admin/", API)
    p.wait_for_selector("#lSbx .ligne")
    assert p.inner_text("#tCpu") == "12,5 %" and p.inner_text("#tMem") == "47 %" and p.inner_text("#tDisque") == "38,5 %"
    assert p.inner_text("#tServ") == "2 / 4" and p.inner_text("#tCharge") == "0,42" and p.inner_text("#tMaj") == "—"
    assert p.inner_text("#etat") == "EN LIGNE" and p.inner_text("#hote") == "gk-test"
    assert "1 j 1 h 01 min" in p.inner_text("#kUptime") and "2026-10-10 07:12:30" in p.inner_text("#kBoot")
    assert "secubox-waf-ng" in p.inner_text("#lSbx") and "ACTIF" in p.inner_text("#lSbx") and "ARRÊTÉ" in p.inner_text("#lSbx")
    # une partition > 90 % passe au rouge
    assert p.locator("#dApercu .barre b.hors").count() == 1
    # données d'API jamais interprétées comme HTML
    p.click("#o-services")
    assert "<b>x</b>" in p.inner_text("#bServ") and p.evaluate("window.PWN") is None and "ÉCHEC" in p.inner_text("#bServ")
    assert err == []
    ctx.close()


def test_onglets_journaux_stockage_processus_mises_a_jour(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/admin/", API)
    p.wait_for_selector("#lSbx .ligne")
    p.click("#o-journaux"); p.wait_for_function("document.getElementById('journal').textContent.includes('ligne deux')")
    j = [a for a in appels if a[1] == "/logs"][0][3]
    assert "lines=100" in j and "unit=" not in j
    p.select_option("#lUnite", "nginx.service"); p.select_option("#lPrio", "err")
    p.wait_for_function("document.getElementById('lUnite').value === 'nginx.service'")
    p.wait_for_timeout(200)
    j = [a for a in appels if a[1] == "/logs"][-1][3]
    assert "unit=nginx.service" in j and "priority=err" in j
    p.click("#o-stockage"); assert "/dev/sdb1 monté sur /data" in p.inner_text("#dStock")
    p.click("#o-processus"); p.wait_for_selector("#bProc td.nom")
    assert "sbxwaf" in p.inner_text("#bProc") and "6,4 %" in p.inner_text("#bProc")
    assert p.inner_text("#nProc") == "1 sur 90 processus"
    p.click("#o-maj"); p.click("#bVerif"); p.wait_for_selector("#bMaj td.mono")
    assert p.inner_text("#tMaj") == "2" and "libx" in p.inner_text("#bMaj") and not p.is_disabled("#bMajTout")
    assert err == []
    ctx.close()


def test_la_selection_du_journal_survit_a_l_actualisation(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/admin/", API)
    p.wait_for_selector("#lSbx .ligne")
    p.click("#o-journaux"); p.wait_for_selector("#lUnite option[value='nginx.service']", state="attached")
    p.select_option("#lUnite", "nginx.service")
    p.click("#rafraichir"); p.wait_for_timeout(300)
    assert p.input_value("#lUnite") == "nginx.service"   # l'ancienne page la remettait à « toutes les unités »
    ctx.close()


def test_action_de_service_confirmee_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/admin/", API)
    p.click("#o-services"); p.wait_for_selector("#bServ tr td.act")
    p.locator("#bServ tr", has_text="nginx").get_by_text("Redémarrer").click()
    assert p.is_visible("#conf") and "nginx" in p.inner_text("#confTitre")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('réussi')")
    assert ("POST", "/service/nginx/restart", None) in [a[:3] for a in appels]
    # démarrer un service arrêté : direct, sans corps
    p.locator("#bServ tr", has_text="secubox-off").get_by_text("Démarrer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('start')")
    assert ("POST", "/service/secubox-off/start", None) in [a[:3] for a in appels]
    ctx.close()


def test_redemarrage_extinction_et_mise_a_jour_envoient_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/admin/", API)
    p.wait_for_selector("#lSbx .ligne")
    p.click("#bReboot"); p.fill("#confMotif", "maintenance"); p.click("#confNon")
    assert not [a for a in appels if a[0] == "POST"] and not p.is_visible("#conf")
    p.click("#bReboot"); p.fill("#confMotif", "maintenance"); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Redémarrage')")
    assert json.loads([a for a in appels if a[1] == "/reboot"][0][2]) == {"confirm": True, "reason": "maintenance"}
    p.click("#bShutdown"); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Extinction')")
    assert json.loads([a for a in appels if a[1] == "/shutdown"][0][2]) == {"confirm": True, "reason": ""}
    p.click("#o-maj"); p.click("#bVerif"); p.wait_for_selector("#bMaj td.mono")
    p.click("#bMajTout"); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('terminée')")
    assert json.loads([a for a in appels if a[1] == "/update"][0][2]) == {"confirm": True, "packages": []}
    ctx.close()


def test_echec_d_action_et_erreur_de_commande_dites(navigateur):
    routes = {**API, "/service/nginx/restart": (200, {"success": False, "stderr": "Unit not found"}),
              "/updates": (200, {"available": 0, "packages": [], "error": "Update check timeout"})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/admin/", routes)
    p.click("#o-services"); p.wait_for_selector("#bServ tr td.act")
    p.locator("#bServ tr", has_text="nginx").get_by_text("Redémarrer").click(); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Unit not found')")
    # l'API répond 200 + « error » : la page ne dit pas « à jour », elle dit l'échec
    p.click("#o-maj"); p.click("#bVerif")
    p.wait_for_function("document.getElementById('bMaj').textContent.includes('timeout')")
    assert p.inner_text("#tMaj") == "—" and "à jour" not in p.inner_text("#bMaj")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/admin/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tCpu", "#tMem", "#tDisque", "#tServ", "#tCharge", "#tMaj")] == ["—"] * 6
    assert not [a for a in appels if a[0] != "GET"] and err == []     # plus de redirection forcée vers /login.html
    assert p.url.startswith("http://sbx.test/admin/")
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/admin/?demo=1", {})
    p.wait_for_selector("#lSbx .ligne")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#hote") == "gk-demo"
    p.click("#bReboot"); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.click("#o-processus"); p.click("#o-maj"); p.click("#bVerif")
    assert appels == [] and err == []
    ctx.close()


@pytest.mark.parametrize("onglet", ["apercu", "services", "journaux", "stockage", "processus", "maj"])
def test_telephone_sans_debordement(navigateur, onglet):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/admin/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#lSbx .ligne")
    p.click("#o-" + onglet)
    if onglet == "maj":
        p.click("#bVerif")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
