# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /glances/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "glances" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'glances'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_lues_et_ecritures_a_l_identique():
    for r in ("/status", "/stats", "/processes", "/sensors", "/config", "/logs?lines=100", "/history?hours="):
        assert r in SRC
    # les trois écritures de l'ancienne page : démarrer, arrêter, enregistrer la configuration
    assert "ecrire('POST', '/config', corps)" in SRC and "actionService('stop'" in SRC and "actionService('start'" in SRC
    assert "'/' + action" in SRC and "/restart" not in SRC
    for cle in ("refresh_interval", "history_size", "process_top_n", "disk_paths", "enable_history", "sensors_enabled", "network_interfaces: []"):
        assert cle in SRC
    assert len(re.findall(r"ecrire\('", SRC)) == 2 and "'DELETE'" not in SRC and "'PUT'" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _historique(n=30):
    t0 = datetime.now() - timedelta(minutes=n)
    return [{"cpu": 10.0 + i, "memory": 40.0, "disk": 50.0, "net_rx": 1000 * i, "net_tx": 500 * i, "load": 0.5,
             "timestamp": (t0 + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S")} for i in range(n)]


STATUS = {"running": True, "version": "Glances v4.2.1"}
STATS = {"cpu": {"percent": 23.4, "per_core": [30.0, 16.8], "count": 2, "count_logical": 2, "freq_current": 0, "freq_max": 0},
         "memory": {"percent": 41.7, "used": 1073741824, "total": 2147483648, "available": 1000000000, "cached": 100, "buffers": 50},
         "swap": {"percent": 0, "used": 0, "total": 0}, "disk": {"percent": 58.3, "used": 10737418240, "total": 21474836480, "free": 1},
         "network": {"rx_rate": 2097152, "tx_rate": 1024}, "load": {"avg_1": 0.84, "avg_5": 0.72, "avg_15": 0.65}, "uptime": {"seconds": 90061}}
PROCS = {"processes": [{"pid": 7, "name": "<img src=x onerror=window.__xss=1>", "cpu_percent": 5.0, "memory_percent": 1.0, "status": "running", "user": "root", "threads": 2},
                       {"pid": 9, "name": "nginx", "cpu_percent": 9.0, "memory_percent": 2.5, "status": "sleeping", "user": "www-data", "threads": 1}], "total": 120}
SENS = {"temperatures": [{"name": "cpu_thermal", "current": 97.0, "high": 85, "critical": 95}, {"name": "phy", "current": 50.0, "high": None, "critical": None}],
        "fans": [], "battery": None}
CONFIG = {"refresh_interval": 5, "history_size": 720, "process_top_n": 20, "disk_paths": ["/", "/data"], "enable_history": True, "sensors_enabled": False}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/processes": (200, PROCS), "/sensors": (200, SENS), "/history": (200, {"history": _historique(), "count": 30, "hours": 1}),
       "/config": (200, CONFIG), "/logs": (200, {"lines": ["ligne un", "ligne <b>deux</b>"], "count": 2})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "glances":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/glances", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get("POST " + chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/glances/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_viennent_de_l_api_et_tiret_si_absent(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/glances/", API)
    p.wait_for_function("document.getElementById('tCpu').textContent !== '—'")
    assert p.inner_text("#tCpu") == "23,4 %" and p.inner_text("#tMem") == "41,7 %" and p.inner_text("#tDisk") == "58,3 %"
    assert p.inner_text("#tRx") == "2,0 Mio/s" and p.inner_text("#tTx") == "1,0 Kio/s" and p.inner_text("#tLoad") == "0,84"
    assert "1,0 Gio / 2,0 Gio" in p.inner_text("#sMem")
    assert "MHz" not in p.inner_text("#sCpu") and p.inner_text("#kFreq") == "—"      # fréquence 0 = absente, pas « 0 MHz »
    assert p.inner_text("#etat") == "EN MARCHE" and "1 j 1 h 1 min" in p.inner_text("#kUp")
    assert p.locator("#gCpu polyline").count() == 1 and p.locator("#gNet polyline").count() == 2
    assert err == []
    ctx.close()


def test_processus_et_capteurs_sans_injection(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/glances/", API)
    p.click("#o-processus")
    p.wait_for_selector("#bProc tr td.nom")
    assert p.locator("#bProc tr").count() == 2 and "nginx" in p.inner_text("#bProc")
    assert "<img" in p.inner_text("#bProc") and p.evaluate("window.__xss") is None   # le nom est du texte
    assert p.locator("#bProc tr").first.inner_text().startswith("nginx")              # tri CPU décroissant
    p.click("#t-processus th button[data-k=name]")      # 1er clic : décroissant par nom
    p.click("#t-processus th button[data-k=name]")      # 2e clic : croissant
    assert p.locator("#bProc tr").first.inner_text().startswith("<img")
    p.fill("#fProc", "ngi")
    assert p.locator("#bProc tr").count() == 1
    p.click("#o-capteurs")
    p.wait_for_selector("#temps .capteur")
    assert p.locator("#temps .capteur.hors").count() == 1 and "97,0 °C" in p.inner_text("#temps")
    assert "Aucun ventilateur" in p.inner_text("#fans") and p.is_hidden("#pBat")
    assert err == []
    ctx.close()


def test_configuration_lue_et_enregistree_avec_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/glances/", API)
    p.click("#o-config")
    p.wait_for_function("document.getElementById('cfgProc').value === '20'")
    assert p.input_value("#cfgDisks") == "/, /data" and not p.is_checked("#cfgSens")
    assert "ligne <b>deux</b>" in p.inner_text("#journal")
    p.fill("#cfgRefresh", "10"); p.fill("#cfgDisks", "/, /data, ")
    p.click("#fCfg button[type=submit]")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('enregistrée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/config"][0]
    assert json.loads(post[2]) == {"refresh_interval": 10, "history_size": 720, "process_top_n": 20, "disk_paths": ["/", "/data"],
                                   "enable_history": True, "sensors_enabled": False, "network_interfaces": []}
    assert err == []
    ctx.close()


def test_arret_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/glances/", API)
    p.wait_for_function("document.getElementById('tCpu').textContent !== '—'")
    p.click("#bArreter")
    assert "Arrêter Glances" in p.inner_text("#rSvc") and not [a for a in appels if a[1] == "/stop"]
    p.get_by_text("Annuler").click()
    assert p.is_hidden("#rSvc") and not [a for a in appels if a[1] == "/stop"]
    p.click("#bArreter"); p.get_by_text("Confirmer l’arrêt").click()
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('arrêté')")
    assert ("POST", "/stop", None) in appels
    p.click("#bDemarrer")
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('démarré')")
    assert ("POST", "/start", None) in appels and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/glances/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tCpu", "#tMem", "#tDisk", "#tRx", "#tTx", "#tLoad")] == ["—"] * 6
    assert "/login.html" not in p.url and err == []         # plus de redirection brutale hors de la page
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/glances/?demo=1", {})
    p.wait_for_function("document.getElementById('tCpu').textContent !== '—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bArreter")
    assert "inerte" in p.inner_text("#rSvc")
    p.click("#o-config"); p.click("#fCfg button[type=submit]")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/glances/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tCpu').textContent !== '—'")
    for t in ("o-processus", "o-capteurs", "o-config", "o-tableau"):
        p.click("#" + t)
        p.wait_for_timeout(150)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
