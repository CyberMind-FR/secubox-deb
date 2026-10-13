# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /netdiag/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "netdiag" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert re.findall(r'<link rel="stylesheet" href="([^"]+)"', SRC) == ["/shared/sidebar-light.css"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC and "lorem" not in SRC.lower()
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "oninput="):
        assert interdit not in SRC
    assert "sbxVue" in SRC and "onglet: 'netdiag'" in SRC and "demo" in SRC and "embed" in SRC


def test_routes_d_ecriture_identiques_et_lectures():
    # Mêmes routes et mêmes corps que l'ancienne page.
    for r in ("'/ping', { host, count }", "'/traceroute', { host, max_hops }", "'/dns', { domain, record_type }",
              "'/whois', { target }", "'/mtr', { host, count }", "'/portscan', { host, ports }"):
        assert r in SRC
    for r in ("'/status'", "'/interfaces'", "'/routes'", "'/arp'", "'/connections'", "'/ports'"):
        assert r in SRC
    assert "/nmap" not in SRC and "/bandwidth" not in SRC   # jamais appelées par l'ancienne page
    assert len(re.findall(r"appel\('POST'", SRC)) == 1       # un seul point d'écriture, partagé par les six outils


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "netdiag", "tools_count": 8, "tools_available": {"ping": True, "traceroute": True, "dig": True, "whois": True, "mtr": False, "nmap": True, "ss": True, "ip": True, "iperf3": True}}
IFACES = {"success": True, "count": 2, "interfaces": [
    {"name": "lo", "mac": "", "mtu": 65536, "state": "UNKNOWN", "type": "loopback", "addresses": [{"address": "127.0.0.1", "prefix": 8}]},
    {"name": "eth0", "mac": "02:00:5e:00:53:01", "mtu": 1500, "state": "UP", "type": "ether", "addresses": [{"address": "192.0.2.10", "prefix": 24}]}]}
ROUTES = {"success": True, "count": 3, "ipv4": [{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "metric": 100, "scope": "global"},
                                              {"dst": "192.0.2.0/24", "dev": "eth0", "metric": 0, "scope": "link"}],
          "ipv6": [{"dst": "2001:db8::/64", "dev": "eth0", "metric": 256, "protocol": "kernel"}]}
ARP = {"success": True, "count": 1, "entries": [{"ip": "192.0.2.1", "mac": "02:00:5e:00:53:fe", "interface": "eth0", "state": ["REACHABLE"]}]}
CONNS = {"success": True, "count": 3, "connections": [
    {"proto": "tcp", "state": "ESTAB", "local": "192.0.2.10:22", "remote": "198.51.100.7:51514", "process": "users:((\"<img src=x onerror=window.PWNED=1>\",pid=8))"},
    {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:22", "remote": "0.0.0.0:*", "process": ""},
    {"proto": "udp", "state": "UNCONN", "local": "192.0.2.10:123", "remote": "0.0.0.0:*", "process": ""}]}
PORTS = {"success": True, "count": 2, "ports": [{"proto": "tcp", "state": "LISTEN", "local_addr": "0.0.0.0", "local_port": 22, "process": None},
                                              {"proto": "udp", "state": "UNCONN", "local_addr": "192.0.2.10", "local_port": 123, "process": None}]}
API = {"/status": (200, STATUS), "/interfaces": (200, IFACES), "/routes": (200, ROUTES), "/arp": (200, ARP), "/connections": (200, CONNS), "/ports": (200, PORTS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "netdiag":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/netdiag", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (200, {"success": True, "output": "ok"}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/netdiag/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netdiag/", API)
    p.wait_for_selector("#bPorts tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tOutils", "#tIf", "#tRoutes", "#tArp", "#tConn", "#tEstab", "#tListen")] == ["8/9", "1/2", "3", "1", "3", "1", "2"]
    assert "mtr" in p.inner_text("#sOutils") and p.inner_text("#etat") == "EN LIGNE"
    p.click("#o-routes")
    assert "default" in p.inner_text("#bR4") and "192.0.2.1" in p.inner_text("#bR4")
    assert "2001:db8::/64" in p.inner_text("#bR6")
    ligne0 = [td.inner_text() for td in p.locator("#bR4 tr").nth(1).locator("td").all()]
    assert ligne0[3] == "0"                      # une métrique à 0 est une mesure, pas « - »
    assert "REACHABLE" in p.inner_text("#bArp")
    p.click("#o-interfaces")
    assert "eth0" in p.inner_text("#lIf") and "192.0.2.10/24" in p.inner_text("#lIf") and "UNKNOWN" in p.inner_text("#lIf")
    p.click("#o-connexions")
    assert "198.51.100.7:51514" in p.inner_text("#bConn") and p.locator("#bPorts tr").count() == 2
    assert err == []
    ctx.close()


def test_donnees_d_api_jamais_interpretees_comme_html(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netdiag/", API)
    p.wait_for_selector("#bPorts tr td.mono", state="attached")
    p.click("#o-connexions")
    assert "<img" in p.inner_text("#bConn") and p.evaluate("window.PWNED") is None
    ctx.close()


def test_filtre_des_connexions(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/netdiag/", API)
    p.wait_for_selector("#bPorts tr td.mono", state="attached")
    p.click("#o-connexions"); p.fill("#filtre", "udp")
    assert p.locator("#bConn tr").count() == 1 and "1 sur 3" in p.inner_text("#nConn")
    ctx.close()


def test_outil_envoie_le_meme_corps_et_le_jeton(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netdiag/", {**API, "/ping": (200, {"success": True, "output": "64 bytes from 192.0.2.1", "stats": {"packets_transmitted": 4, "packets_received": 4, "packet_loss": 0.0, "rtt_min": 0.1, "rtt_avg": 0.2, "rtt_max": 0.3}})})
    p.evaluate("localStorage.setItem('sbx_token','tok123')")
    p.fill("#fPing [name=host]", "192.0.2.1"); p.fill("#fPing [name=count]", "3")
    p.click("#fPing button[type=submit]")
    p.wait_for_function("document.getElementById('sortie').textContent.includes('Perte')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/ping" and json.loads(post[2]) == {"host": "192.0.2.1", "count": 3} and post[3] == "Bearer tok123"
    assert "RTT : min=0.1 ms" in p.inner_text("#sortie") and err == []
    for form, champ, valeur, chemin, corps in (("fTrace", "host", "192.0.2.1", "/traceroute", {"host": "192.0.2.1", "max_hops": 30}),
                                              ("fDns", "domain", "example.com", "/dns", {"domain": "example.com", "record_type": "A"}),
                                              ("fWhois", "target", "example.com", "/whois", {"target": "example.com"}),
                                              ("fMtr", "host", "192.0.2.1", "/mtr", {"host": "192.0.2.1", "count": 10}),
                                              ("fScan", "host", "192.168.1.1", "/portscan", {"host": "192.168.1.1", "ports": "1-1024"})):
        p.fill(f"#{form} [name={champ}]", valeur); p.click(f"#{form} button[type=submit]")
        p.wait_for_timeout(150)
        envoi = [a for a in appels if a[0] == "POST" and a[1] == chemin][0]
        assert json.loads(envoi[2]) == corps
    ctx.close()


def test_refus_serveur_affiche_le_detail_et_saisie_vide_sans_dialogue(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netdiag/", {**API, "/portscan": (403, {"detail": "Port scanning only allowed on local network addresses"})})
    p.click("#fScan button[type=submit]")                       # saisie vide : message dans la page, aucun appel
    assert "Saisie manquante" in p.inner_text("#sortie") and not [a for a in appels if a[0] == "POST"]
    p.fill("#fScan [name=host]", "198.51.100.5"); p.click("#fScan button[type=submit]")
    p.wait_for_function("document.getElementById('sortie').textContent.includes('Erreur')")
    assert "local network" in p.inner_text("#sortie") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netdiag/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tOutils", "#tIf", "#tRoutes", "#tArp", "#tConn", "#tListen")] == ["—"] * 6
    assert "netdiag" in p.url and err == []                       # plus de redirection vers /login.html
    ctx.close()


def test_demonstration_annoncee_et_outils_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netdiag/?demo=1", {})
    p.wait_for_selector("#bPorts tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tOutils") == "8/9"
    p.fill("#fPing [name=host]", "192.0.2.1"); p.click("#fPing button[type=submit]")
    assert "inerte" in p.inner_text("#sortie") and appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netdiag/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bPorts tr td.mono", state="attached")
    for t in ("outils", "interfaces", "routes", "connexions"):
        p.click(f"#o-{t}")
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
