# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /system/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "system" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'system'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    ecritures = [
        "'/service_control', { service: nom, action }", "'/restart_services'", "'/reload_firewall'", "'/sync_time'", "'/clear_cache'",
        "'/backup'", "'/reboot'", "'/shutdown'", "'/apply_updates'", "'/settings', { hostname:", "'/kiosk/enable?mode='", "'/kiosk/disable'",
        "'/board/detect'", "'DELETE', '/sessions/'", "'/sessions/revoke-all'",
    ]
    for r in ecritures:
        assert r in SRC, r
    for lecture in ("/info", "/resources", "/services", "/network", "/security", "/packages", "/board", "/kiosk/status",
                    "/sessions", "/sessions/summary", "/secubox_logs", "/logs?lines=", "/check_updates"):
        assert lecture in SRC, lecture
    assert "filename" not in SRC.replace("pas « filename »", "")  # l'API rend « file », pas « filename »


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


INFO = {"hostname": "gk2", "board": "MOCHAbin", "arch": "aarch64", "kernel": "6.1.0", "uptime_formatted": "2d 3h 4m", "local_time": "13/10/2026 09:00:00"}
RES = {"cpu_percent": 12.5, "memory_percent": 40.0, "memory_used": 3.2e9, "memory_total": 8e9, "disk_percent": 85.0, "disk_used": 2.1e11, "disk_total": 2.5e11, "load_avg": [0.5, 0.4, 0.3]}
SERV = {"services": [{"name": "nginx", "active": True, "status": "active", "enabled": True}, {"name": "secubox-dpi", "active": False, "status": "failed", "enabled": True}]}
NET = {"interfaces": [{"name": "eth0", "addresses": ["192.0.2.1", "192.0.2.2"], "up": True, "speed": 1000}]}
SEC = {"firewall": "Active", "ssh_status": "Running", "apparmor": "Disabled"}
PKG = {"packages": [{"name": "secubox-core", "version": "1.0.0-1"}]}
BOARD = {"board_type": "mochabin", "profile": "full", "cpu_model": "ARM", "cpu_cores": 4, "cpu_threads": 4,
         "interfaces": {"wan": ["eth0"], "lan": ["lan0"], "sfp": []}, "interface_details": [{"name": "eth0", "addresses": ["192.0.2.1"], "carrier": True, "speed": 1000}]}
KIOSK = {"enabled": False, "mode": "disabled", "service_active": False}
SESS = {"sessions": [{"id": "s/1", "username": "admin", "expires_in_formatted": "1h 2m"}], "total": 1}
SUMM = {"active_count": 1, "by_user": {"admin": 1}, "users_online": ["admin"]}
JOUR = {"logs": [{"emoji": "🟠", "category": "Web", "message": "<img src=x onerror=window.__xss=1>", "count": 3, "priority": "3"}], "total_entries": 9}
API = {"/info": INFO, "/resources": RES, "/services": SERV, "/network": NET, "/security": SEC, "/packages": PKG, "/board": BOARD,
       "/kiosk/status": KIOSK, "/sessions": SESS, "/sessions/summary": SUMM, "/secubox_logs": JOUR}


def ouvre(navigateur, url, statut=200, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token', %s)" % json.dumps(jeton))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "system":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/system", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        if statut != 200:
            r.fulfill(status=statut, content_type="application/json", body='{"detail":"jeton requis"}')
        elif r.request.method == "GET":
            corps = API.get(chemin) if chemin != "/check_updates" else {"packages": ["secubox-core"], "count": 1}
            r.fulfill(status=200 if corps is not None else 404, content_type="application/json", body=json.dumps(corps or {}))
        else:
            reponse = {"success": True, "file": "/var/lib/secubox/backup-1.tar.gz", "size": 2048} if chemin == "/backup" else {"success": True}
            r.fulfill(status=200, content_type="application/json", body=json.dumps(reponse))
    p.route("http://sbx.test/api/v1/system/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/system/", jeton="abc")
    p.wait_for_selector("#bServ tr td.mono", state="attached")
    assert p.inner_text("#tServ") == "1 / 2" and p.inner_text("#tCpu") == "12,5 %" and p.inner_text("#tDisk") == "85,0 %"
    assert p.inner_text("#tLoad") == "0,50" and p.inner_text("#tSess") == "1" and p.inner_text("#etat") == "EN LIGNE"
    assert "ÉCHEC" in p.inner_text("#bServ") and "192.0.2.1, 192.0.2.2" in p.inner_text("#bNet")
    assert p.inner_text("#kNoyau") == "6.1.0" and "mochabin" in p.inner_text("#bType") and "DÉSACTIVÉ" in p.inner_text("#kkEtat")
    assert "secubox-core" in p.inner_text("#bPaq") and "admin" in p.inner_text("#bSess")
    # le contenu du journal est du texte, jamais du HTML
    assert "<img" in p.inner_text("#journal") and p.evaluate("window.__xss") is None and "×3" in p.inner_text("#journal")
    assert all(a[3] == "Bearer abc" for a in appels)
    assert err == []
    ctx.close()


def test_action_ecriture_et_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/system/")
    p.wait_for_selector("#bServ tr td.mono", state="attached")
    p.locator("#bServ tr").first.get_by_text("Arrêter").click()
    assert not [a for a in appels if a[1] == "/service_control"]          # pas encore : il faut confirmer
    assert "Arrêter nginx" in p.inner_text("#cServices")
    p.locator("#cServices").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rServices').textContent.includes('arrêté')")
    post = [a for a in appels if a[1] == "/service_control"][0]
    assert post[0] == "POST" and json.loads(post[2]) == {"service": "nginx", "action": "stop"}
    # démarrer un service ne demande pas de confirmation
    p.locator("#bServ tr").nth(1).get_by_text("Démarrer").click()
    p.wait_for_function("document.getElementById('rServices').textContent.includes('démarré')")
    assert json.loads([a for a in appels if a[1] == "/service_control"][1][2]) == {"service": "secubox-dpi", "action": "start"}
    assert err == []
    ctx.close()


def test_reglages_sauvegarde_et_session(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/system/")
    p.wait_for_selector("#bServ tr td.mono", state="attached")
    p.fill("#newHost", "boite"); p.select_option("#newTz", "UTC"); p.click("#fReglages button[type=submit]")
    p.wait_for_function("document.getElementById('rReglages').textContent.includes('enregistrés')")
    assert json.loads([a for a in appels if a[1] == "/settings"][0][2]) == {"hostname": "boite", "timezone": "UTC"}
    p.click("#aBackup")
    p.wait_for_function("document.getElementById('rRapide').textContent.includes('backup-1.tar.gz')")
    p.locator("#bSess tr").first.get_by_text("Révoquer").click()
    p.locator("#cSess").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSess').textContent.includes('révoquée')")
    assert ("DELETE", "/sessions/s%2F1") in [(a[0], a[1]) for a in appels]
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/system/", statut=401)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tServ", "#tCpu", "#tMem", "#tDisk", "#tLoad", "#tSess", "#kHote")] == ["—"] * 7 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/system/?demo=1")
    p.wait_for_selector("#bServ tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#aFw")
    p.wait_for_function("document.getElementById('rRapide').textContent.includes('inerte')")
    p.click("#aCheck")
    p.wait_for_function("document.getElementById('rPaq').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/system/?embed=1", taille={"width": 420, "height": 800})
    p.wait_for_selector("#bServ tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
