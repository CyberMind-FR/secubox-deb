# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2644 — /eye-remote/ (tableau de bord et console série) au profil Aurora : statique + vrai navigateur, API simulée."""
import json
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "eye-remote"
PAGES = {"eye-remote/index.html": WWW / "index.html", "eye-remote/terminal.html": WWW / "terminal.html"}
IDX = PAGES["eye-remote/index.html"].read_text(encoding="utf-8")
TERM = PAGES["eye-remote/terminal.html"].read_text(encoding="utf-8")


@pytest.mark.parametrize("src", [IDX, TERM], ids=["index", "terminal"])
def test_page_autonome_sans_dialogue_natif(src):
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in src
    assert "<script src=" not in src                       # menu injecté dynamiquement, aucune dépendance
    assert "cdn.jsdelivr" not in src and "fonts.googleapis" not in src and "hybrid-dark" not in src and "crt-" not in src
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in src
    assert "lorem" not in src.lower()
    assert "sbxVue" in src and "onglet:" in src and "demo" in src.lower() and "embed" in src
    assert "localStorage.getItem('sbx_token')" in src and "'Bearer '" in src
    assert "/shared/sidebar.js" in src


def test_index_routes_a_l_identique_et_lecture_seule():
    for r in ("API + '/health'", "API + '/metrics'", "/api/v1/hub/dashboard", "const API = '/api/v1/eye-remote'",
              "cpu_percent", "mem_percent", "cpu_temp", "uptime_seconds", "disk_percent", "load_1m", "/eye-remote/terminal.html"):
        assert r in IDX
    assert "POST" not in IDX and "DELETE" not in IDX and "method:" not in IDX
    for cmd in ("ssh pi@10.55.0.2", "screen /dev/ttyACM0 115200", "ip link set usb0 up", "systemctl restart pizero-metrics"):
        assert cmd in IDX


def test_terminal_memes_routes_et_websocket():
    for r in ("/paired-devices", "/serial/devices", "/serial/console/", "token=${encodeURIComponent(params.token)}",
              "&baud=${params.baud}", "&device=${encodeURIComponent(params.device)}", "binaryType = 'arraybuffer'",
              "serial_token_", "sessionStorage", "TextEncoder", "reconnectDelay: 3000", "maxReconnectAttempts: 5",
              "scrollback: 10000", "event.code !== 1000 && event.code !== 1008", "read/write", "read-only"):
        assert r in TERM
    # le jeton d'appareil n'est jamais écrit dans la page ni dans le stockage persistant
    assert "localStorage.setItem" not in TERM and 'type="password"' in TERM


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


PI = {"cpu_percent": 23.4, "mem_percent": 41.2, "cpu_temp": 52.4, "uptime_seconds": 93784, "disk_percent": 37.0, "load_1m": 0.42, "hostname": "pizero-test"}
HUB = {"cpu_percent": 18, "memory_percent": 46, "disk_percent": 61, "load_avg": [0.7], "hostname": "box-test", "uptime": "3 j", "kernel": "6.1.0-test", "cpu_temp": 49, "wifi_rssi": -58}
DEVICES = {"devices": [{"device_id": "dev-001", "hostname": "pizero-test", "peer_ip": "10.55.0.2", "name": "Eye test"}], "count": 1}
PORTS = [{"path": "/dev/ttyACM0", "readable": True, "writable": True}, {"path": "/dev/ttyUSB0", "readable": True, "writable": False}]

WS_FACTICE = """
window.__ws = [];
class FW { constructor(u){ this.url=u; this.sent=[]; this.readyState=0; window.__ws.push(this);
  setTimeout(()=>{ this.readyState=1; this.onopen && this.onopen({}); }, 10); }
  send(d){ this.sent.push(Array.from(d)); }
  close(c,r){ this.readyState=3; this.onclose && this.onclose({code:c, reason:r}); } }
FW.OPEN = 1; window.WebSocket = FW;
"""


def ouvre(navigateur, chemin, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.add_init_script(WS_FACTICE)
    if jeton:
        p.add_init_script("try{localStorage.setItem('sbx_token','%s')}catch(e){}" % jeton)

    def fichier(r, *_):
        ch = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if ch.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if ch.endswith(".css") else "application/javascript", body="")
        elif ch in PAGES:
            r.fulfill(status=200, content_type="text/html", body=PAGES[ch].read_text(encoding="utf-8"))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        url = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        appels.append((r.request.method, url, r.request.headers.get("authorization")))
        statut, corps = routes.get(url, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", api)
    p.goto("http://sbx.test/" + chemin)
    return ctx, p, erreurs, appels


ROUTES_OK = {
    "/api/v1/eye-remote/health": (200, {"status": "ok", "service": "secubox-eye-remote"}),
    "/api/v1/eye-remote/metrics": (200, PI),
    "/api/v1/hub/dashboard": (200, HUB),
}
TUILES = ("#tLiaison", "#tCpu", "#tMem", "#tTemp", "#tDisque", "#tUptime")


def test_index_les_mesures_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "eye-remote/index.html", ROUTES_OK, jeton="jeton-test")
    p.wait_for_function("document.getElementById('tCpu').textContent !== '—'")
    assert [p.inner_text(i) for i in TUILES] == ["Connectée", "23%", "41%", "52°", "37%", "26 h 3 min"]
    assert p.inner_text("#etat") == "CONNECTÉ"
    assert p.inner_text("#piHote") == "pizero-test" and p.inner_text("#piDisque") == "37%" and p.inner_text("#piCharge") == "0.42"
    p.wait_for_function("document.getElementById('mbHote').textContent === 'box-test'")
    assert p.inner_text("#mbKernel") == "6.1.0-test" and "ATTENTION" in p.inner_text("#etatRond")   # disque à 61 % > 50
    assert p.locator("#sparkCpu div").count() >= 1
    assert ("GET", "/api/v1/eye-remote/health", "Bearer jeton-test") in appels
    assert ("GET", "/api/v1/eye-remote/metrics", "Bearer jeton-test") in appels
    assert all(a[0] == "GET" for a in appels) and err == []
    # chaque tuile porte sa définition
    assert all(p.get_attribute(f".tuile:nth-child({i})", "title") for i in range(1, 7))
    ctx.close()


def test_index_liaison_coupee_mesures_en_tirets(navigateur):
    routes = {**ROUTES_OK, "/api/v1/eye-remote/health": (503, {})}
    ctx, p, err, appels = ouvre(navigateur, "eye-remote/index.html", routes)
    p.wait_for_function("document.getElementById('etat').textContent === 'DÉCONNECTÉ'")
    assert [p.inner_text(i) for i in TUILES] == ["Coupée", "—", "—", "—", "—", "—"]
    assert not [a for a in appels if a[1].endswith("/metrics")]   # pas de mesures sans liaison
    assert err == []
    ctx.close()


def test_index_mesure_absente_est_un_tiret_pas_zero(navigateur):
    routes = {**ROUTES_OK, "/api/v1/eye-remote/metrics": (200, {"cpu_percent": 0, "hostname": "x"}), "/api/v1/hub/dashboard": (404, {})}
    ctx, p, err, _ = ouvre(navigateur, "eye-remote/index.html", routes)
    p.wait_for_function("document.getElementById('tCpu').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tCpu", "#tMem", "#tTemp", "#tUptime")] == ["0%", "—", "—", "—"]   # 0 est une mesure
    assert p.inner_text("#piCharge") == "—" and p.inner_text("#mbHote") == "—" and err == []
    ctx.close()


def test_index_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in ROUTES_OK}
    ctx, p, err, _ = ouvre(navigateur, "eye-remote/index.html", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in TUILES] == ["—"] * 6 and err == []
    ctx.close()


def test_index_demonstration_annoncee_sans_aucun_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "eye-remote/index.html?demo=1", {})
    p.wait_for_function("document.getElementById('tCpu').textContent !== '—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tLiaison") == "Connectée" and p.inner_text("#mbHote") == "mochabin-demo"
    assert appels == [] and err == []
    ctx.close()


def test_index_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "eye-remote/index.html?embed=1", ROUTES_OK, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('mbHote').textContent === 'box-test'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


# ----------------------------- Terminal -----------------------------

ROUTES_TERM = {"/api/v1/eye-remote/paired-devices": (200, DEVICES), "/api/v1/eye-remote/serial/devices": (200, PORTS)}


def ouvre_connexion(navigateur, url="eye-remote/terminal.html", routes=None, **kw):
    ctx, p, err, appels = ouvre(navigateur, url, routes or ROUTES_TERM, **kw)
    p.wait_for_function("document.getElementById('select-device').value === 'dev-001'")
    p.click("#btn-connect")
    p.wait_for_selector("#connect-dialog:not([hidden])")
    p.wait_for_function("document.getElementById('input-device-id').value === 'dev-001'")
    return ctx, p, err, appels


def pousse(p, texte):
    p.evaluate("(s) => { const w = window.__ws[0]; w.onmessage({ data: new TextEncoder().encode(s).buffer }); }", texte)


def test_terminal_boite_de_connexion_liste_appareils_et_ports(navigateur):
    ctx, p, err, appels = ouvre_connexion(navigateur, jeton="jeton-test")
    assert "pizero-test (10.55.0.2)" in p.inner_text("#input-device-id")
    assert "/dev/ttyUSB0 (non accessible)" in p.inner_text("#input-port")
    assert p.is_enabled("#input-device-id") and p.get_attribute("#input-token", "type") == "password"
    assert ("GET", "/api/v1/eye-remote/paired-devices", "Bearer jeton-test") in appels
    assert ("GET", "/api/v1/eye-remote/serial/devices", "Bearer jeton-test") in appels
    p.keyboard.press("Escape")                                   # Échap ferme la fenêtre
    assert p.is_hidden("#connect-dialog") and err == []
    ctx.close()


def test_terminal_connexion_reception_et_saisie(navigateur):
    ctx, p, err, _ = ouvre_connexion(navigateur)
    p.fill("#input-token", "secret-appareil")
    p.select_option("#input-baud", "230400")
    p.click("#btn-dialog-connect")
    p.wait_for_function("window.__ws.length === 1 && document.getElementById('status-text').textContent === 'Connecté'")
    url = p.evaluate("window.__ws[0].url")
    assert url == "ws://sbx.test/api/v1/eye-remote/serial/console/dev-001?token=secret-appareil&baud=230400&device=%2Fdev%2FttyACM0"
    assert p.is_hidden("#connect-dialog") and p.input_value("#input-token") == "" and p.is_enabled("#btn-disconnect")
    assert "secret-appareil" not in p.inner_text("body")        # le jeton n'est jamais affiché
    # réception : couleurs ANSI, retour chariot, effacement de fin de ligne
    pousse(p, "pi@eye:~ $ \x1b[1;32mok\x1b[0m\r\nread/write\r\nfaux\rvrai\x1b[K\r\n")
    p.wait_for_function("document.getElementById('terminal').innerText.includes('vrai')")
    txt = p.inner_text("#terminal")
    assert "pi@eye:~ $ ok" in txt and "faux" not in txt and "vrai" in txt
    assert p.locator("#terminal span.f2.b", has_text="ok").first.inner_text() == "ok"
    assert p.inner_text("#mode-value") == "R/W"
    # saisie : octets envoyés tels quels
    p.click("#terminal")
    p.keyboard.type("ls")
    p.keyboard.press("Enter")
    p.keyboard.press("ArrowUp")
    p.keyboard.press("Control+c")
    p.wait_for_function("window.__ws[0].sent.length >= 5")
    envoye = p.evaluate("window.__ws[0].sent")
    assert envoye == [[108], [115], [13], [27, 91, 65], [3]]
    # déconnexion volontaire : code 1000, pas de reprise
    p.click("#btn-disconnect")
    p.wait_for_function("document.getElementById('status-text').textContent === 'Déconnecté'")
    assert p.is_disabled("#btn-disconnect") and p.is_enabled("#btn-connect")
    assert "Connexion fermee" in p.inner_text("#terminal") and "Reconnexion" not in p.inner_text("#terminal")
    assert err == []
    ctx.close()


def test_terminal_saisie_ignoree_hors_connexion_et_effacer(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "eye-remote/terminal.html", ROUTES_TERM)
    p.click("#terminal")
    p.keyboard.type("abc")
    assert p.evaluate("window.__ws.length") == 0
    assert "Connecter" in p.inner_text("#terminal")
    p.click("#btn-clear")
    p.wait_for_function("document.getElementById('terminal').innerText.trim() === ''")
    assert err == []
    ctx.close()


def test_terminal_fermeture_inattendue_programme_la_reprise(navigateur):
    ctx, p, err, _ = ouvre_connexion(navigateur)
    p.fill("#input-token", "t")
    p.click("#btn-dialog-connect")
    p.wait_for_function("document.getElementById('status-text').textContent === 'Connecté'")
    p.evaluate("window.__ws[0].onclose({code: 1006})")
    p.wait_for_function("document.getElementById('terminal').innerText.includes('Reconnexion dans 3s')")
    assert "tentative 1/5" in p.inner_text("#terminal")
    assert p.evaluate("sessionStorage.getItem('serial_token_dev-001')") == "t"
    ctx.close()


def test_terminal_sans_session_bandeau(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in ROUTES_TERM}
    ctx, p, err, _ = ouvre(navigateur, "eye-remote/terminal.html", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and err == []
    ctx.close()


def test_terminal_demonstration_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "eye-remote/terminal.html?demo=1", {})
    p.wait_for_function("document.getElementById('select-device').textContent.includes('Eye Remote démo')")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btn-connect")
    p.fill("#input-token", "x")
    p.click("#btn-dialog-connect")
    p.wait_for_function("document.getElementById('terminal').innerText.includes('inerte')")
    assert p.evaluate("window.__ws.length") == 0 and appels == [] and err == []
    assert p.evaluate("sessionStorage.length") == 0
    ctx.close()


def test_terminal_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "eye-remote/terminal.html?embed=1", ROUTES_TERM, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('select-device').value === 'dev-001'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    p.click("#btn-connect")
    p.wait_for_selector("#connect-dialog:not([hidden])")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
