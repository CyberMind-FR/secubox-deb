# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3821 — le nom de nœud (<nœud>.<zone>, ex. gk2.secubox.in) montre le dé SecuBox en plein écran sur « / ».

Vérifié : la décision de `webos-noeud` (route absente, reprise d'une cible qui rend 404, existant explicite qui gagne,
garde du mot de passe par défaut, retour arrière), le vhost rendu servi par un VRAI nginx (« / » exact seul, le reste
404 ou relayé à l'ancienne cible), la route posée par le vrai `secubox-waf-route`, et la page (Aurora, sans ressource
extérieure, rendue à 1400 et 420 px)."""
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
RACINE = PKG.parents[1]
SCRIPT = PKG / "sbin" / "webos-noeud"
PAGE = PKG / "www" / "noeud" / "index.html"
WAF_ROUTE = RACINE / "packages" / "secubox-core" / "usr" / "sbin" / "secubox-waf-route"
DOM = "gk2.secubox.in"


def charger():
    loader = SourceFileLoader("webos_noeud", str(SCRIPT))
    mod = module_from_spec(spec_from_loader("webos_noeud", loader))
    loader.exec_module(mod)
    return mod


@pytest.fixture
def box(tmp_path, monkeypatch):
    """Une box en miniature : arbres nginx, table sbxwaf, réglages, état, audit ; commandes enregistrées."""
    m = charger()
    for d in ("etc/nginx/sites-enabled", "etc/nginx/conf.d", "etc/secubox/waf", "var/log/secubox"):
        (tmp_path / d).mkdir(parents=True)
    routes = tmp_path / "etc/secubox/waf/haproxy-routes.json"
    routes.write_text(json.dumps({"hall.gk2.secubox.in": ["192.168.1.200", 9080]}))
    (tmp_path / "etc/secubox/haproxy.toml").write_text('[vhosts.hall]\ndomain = "hall.gk2.secubox.in"\n')
    monkeypatch.setattr(m, "CONF", str(tmp_path / "etc/nginx/conf.d/secubox-noeud.conf"))
    monkeypatch.setattr(m, "DOSSIERS_NGINX", (str(tmp_path / "etc/nginx/sites-enabled"), str(tmp_path / "etc/nginx/conf.d")))
    monkeypatch.setattr(m, "FORMAT_HOTES", str(tmp_path / "etc/nginx/conf.d/secubox-hosts-log.conf"))
    monkeypatch.setattr(m, "ROUTES", str(routes))
    monkeypatch.setenv("SBX_WAF_ROUTES", str(routes))
    monkeypatch.setattr(m, "REGLAGES", str(tmp_path / "etc/secubox/webos.toml"))
    monkeypatch.setattr(m, "HAPROXY_TOML", str(tmp_path / "etc/secubox/haproxy.toml"))
    monkeypatch.setattr(m, "ETAT_DIR", str(tmp_path / "var/lib/secubox-webos-noeud"))
    monkeypatch.setattr(m, "ETAT", str(tmp_path / "var/lib/secubox-webos-noeud/etat.json"))
    monkeypatch.setattr(m, "AUDIT", str(tmp_path / "var/log/secubox/audit.log"))
    monkeypatch.setattr(m, "domaine", lambda: DOM)
    monkeypatch.setattr(m, "mot_de_passe_change", lambda: True)
    m.appels = []
    m.nginx_ok = True
    m.sonde = None

    def executer(argv, delai=60):
        m.appels.append(list(argv))
        if argv[:2] == ["nginx", "-t"] and not m.nginx_ok:
            raise subprocess.CalledProcessError(1, argv, "", "emerg")
        if argv[0] == "secubox-waf-route":       # le VRAI outil de secubox-core, sur la table de la box miniature
            return subprocess.run([sys.executable, "-I", str(WAF_ROUTE), *argv[1:]], check=True, timeout=delai,
                                  capture_output=True, text=True)
        if argv[:3] == ["haproxyctl", "vhost", "add"]:  # haproxyctl écrit sa table
            with open(m.HAPROXY_TOML, "a") as fh:
                fh.write(f'[vhosts.x]\ndomain = "{argv[3]}"\nbackend = "{argv[4]}"\n')
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(m, "executer", executer)
    monkeypatch.setattr(m, "sonder", lambda ip, port, dom: m.sonde)
    m.racine = tmp_path
    return m


def table(m):
    return json.loads(Path(m.ROUTES).read_text())


def conf(m):
    p = Path(m.CONF)
    return p.read_text() if p.exists() else None


def audits(m):
    p = Path(m.AUDIT)
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


# ── Décisions ────────────────────────────────────────────────────────────────────────────────────────────────

def test_nom_jamais_route_route_vhost_et_haproxy_poses(box):
    assert box.appliquer() == 0
    c = conf(box)
    assert re.search(r"server_name gk2\.secubox\.in;", c) and "listen 9080;" in c
    assert "location = / {" in c and "location / {\n        return 404;" in c
    assert table(box)[DOM] == ["192.168.1.200", 9080]           # adresse des voisines du même port (secubox-waf-route)
    assert ["haproxyctl", "vhost", "add", DOM, "sbxwaf_inspector", "true"] in box.appels   # derrière le WAF
    assert ["nginx", "-t"] in box.appels and ["systemctl", "reload", "nginx"] in box.appels
    assert [a["action"] for a in audits(box)] == ["route", "vhost-haproxy"]
    # deuxième passage : rien ne bouge, rien n'est rechargé
    box.appels.clear()
    assert box.appliquer() == 0
    assert ["systemctl", "reload", "nginx"] not in box.appels and not any(a[0] == "haproxyctl" for a in box.appels)


def test_nouvelle_exposition_refusee_tant_que_le_mot_de_passe_par_defaut(box, monkeypatch):
    monkeypatch.setattr(box, "mot_de_passe_change", lambda: False)
    assert box.appliquer() == 0
    assert conf(box) is not None                                 # le vhost local seul
    assert DOM not in table(box)
    assert not any(a[0] in ("secubox-waf-route", "haproxyctl") for a in box.appels)
    assert audits(box)[0]["action"] == "exposition_refusee"


def test_gk2_ancienne_cible_qui_rend_404_reprise_sans_masquer_ses_chemins(box):
    t = table(box)
    t[DOM] = ["192.168.1.200", 8000]
    Path(box.ROUTES).write_text(json.dumps(t))
    box.sonde = 404
    assert box.appliquer() == 0
    c = conf(box)
    assert "proxy_pass http://192.168.1.200:8000;" in c and "return 404;" not in c
    assert table(box)[DOM] == ["192.168.1.200", 9080]
    etat = json.loads(Path(box.ETAT).read_text())
    assert etat == {"domaine": DOM, "route_reprise": True, "route_precedente": ["192.168.1.200", 8000]}
    assert "reste des chemins relayé à 192.168.1.200:8000" in audits(box)[0]["detail"]
    assert ["haproxyctl", "vhost", "add", DOM, "sbxwaf_inspector", "true"] in box.appels
    # passage suivant (route déjà à nous) : le relais est gardé
    assert box.appliquer() == 0 and conf(box) == c
    # retrait du paquet : vhost retiré, route rendue à son ancienne cible
    assert box.retirer("paquet retiré") == 0
    assert conf(box) is None and table(box)[DOM] == ["192.168.1.200", 8000]


def test_route_qui_sert_deja_la_racine_gagne(box):
    t = table(box)
    t[DOM] = ["127.0.0.1", 8900]
    Path(box.ROUTES).write_text(json.dumps(t))
    for code in (200, 301, 401, None):                           # sert quelque chose, ou injoignable : on ne touche à rien
        box.sonde = code
        assert box.appliquer() == 0
        assert conf(box) is None and table(box)[DOM] == ["127.0.0.1", 8900]
    assert box.appels == []


@pytest.mark.parametrize("nom", ["gk2.secubox.in", ".gk2.secubox.in"])
def test_server_name_explicite_gagne_et_retire_le_notre(box, nom):
    assert box.appliquer() == 0 and conf(box)
    site = box.racine / "etc/nginx/sites-enabled/mon-site.conf"
    site.write_text(f"server {{\n  listen 9080;\n  server_name autre.example\n     {nom};\n}}\n")
    assert box.appliquer() == 0
    assert conf(box) is None
    # un sous-domaine ou un commentaire ne compte pas
    site.write_text("server { server_name hall.gk2.secubox.in; } # server_name gk2.secubox.in;\n")
    assert box.appliquer() == 0 and conf(box)


def test_desactive_par_reglage(box):
    assert box.appliquer() == 0 and conf(box)
    Path(box.REGLAGES).write_text("[noeud]\naccueil = false\n")
    assert box.appliquer() == 0 and conf(box) is None


def test_nginx_refuse_rien_ne_change(box):
    box.nginx_ok = False
    assert box.appliquer() == 1
    assert conf(box) is None and DOM not in table(box)
    assert audits(box)[-1]["result"] == "echec"


def test_table_illisible_abandon(box):
    Path(box.ROUTES).write_text("{tronqué")
    assert box.appliquer() == 1
    assert conf(box) is None and Path(box.ROUTES).read_text() == "{tronqué"


def test_fichier_qui_n_est_pas_le_notre_jamais_retire(box):
    Path(box.CONF).write_text("server { listen 9080; server_name x.example; }\n")
    assert box.retirer_conf() is False and Path(box.CONF).exists()


# ── Le vhost rendu, servi par un vrai nginx ──────────────────────────────────────────────────────────────────

def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Ancienne(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        corps = b'{"status": "ok"}' if self.path == "/api/v1/health" else b'{"detail": "Not Found"}'
        self.send_response(200 if self.path == "/api/v1/health" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Hote-Recu", self.headers.get("Host", ""))
        self.end_headers()
        self.wfile.write(corps)

    def log_message(self, *a):
        pass


def get(url, hote):
    req = urllib.request.Request(url, headers={"Host": hote})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


@pytest.mark.skipif(not shutil.which("nginx"), reason="nginx absent")
@pytest.mark.parametrize("avec_repli", [False, True])
def test_vrai_nginx_ne_sert_que_la_racine_exacte(tmp_path, avec_repli):
    m = charger()
    www = tmp_path / "www"
    (www / "noeud").mkdir(parents=True)
    shutil.copy(PAGE, www / "noeud" / "index.html")
    os.symlink(PKG / "www" / "hall", www / "hall")
    m.WWW, m.PORT = str(www), port_libre()
    serveur = None
    repli = None
    if avec_repli:
        serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Ancienne)
        threading.Thread(target=serveur.serve_forever, daemon=True).start()
        repli = ("127.0.0.1", serveur.server_address[1])
    (tmp_path / "logs").mkdir()
    (tmp_path / "noeud.conf").write_text(m.rendre(DOM, repli, journal_hotes=False))
    (tmp_path / "nginx.conf").write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/logs/error.log;\nevents {{}}\n"
        f"http {{\n include /etc/nginx/mime.types;\n access_log off;\n client_body_temp_path {tmp_path}/cb;\n"
        f" proxy_temp_path {tmp_path}/px;\n fastcgi_temp_path {tmp_path}/fc;\n uwsgi_temp_path {tmp_path}/uw;\n"
        f" scgi_temp_path {tmp_path}/sc;\n include {tmp_path}/noeud.conf;\n}}\n")
    base = ["nginx", "-p", str(tmp_path), "-c", str(tmp_path / "nginx.conf"), "-e", str(tmp_path / "logs/error.log")]
    subprocess.run(base + ["-t"], check=True, timeout=30, capture_output=True)
    subprocess.run(base, check=True, timeout=30, capture_output=True)
    try:
        url = f"http://127.0.0.1:{m.PORT}"
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", m.PORT), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        code, h, corps = get(url + "/", DOM)
        assert code == 200 and h["Content-Type"].startswith("text/html") and b"<sbx-dice" in corps
        csp = h["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "connect-src" not in csp
        assert get(url + "/?x=1", DOM)[0] == 200
        code, h, corps = get(url + "/_noeud/sbx-dice.js", DOM)
        assert code == 200 and b"customElements.define('sbx-dice'" in corps
        for i in range(6):
            code, h, corps = get(url + f"/_noeud/dice/face-{i}.jpg", DOM)
            assert code == 200 and h["Content-Type"] == "image/jpeg" and corps[:2] == b"\xff\xd8"
        # rien d'autre n'est servi par l'accueil : ni /index.html, ni une API, ni le dossier du Hall
        for chemin in ("/index.html", "/api/v1/health", "/_noeud/", "/_noeud/../hall/index.html", "/sbx-dice.js"):
            code, h, corps = get(url + chemin, DOM)
            assert b"<sbx-dice" not in corps, chemin
            if avec_repli and chemin == "/api/v1/health":
                assert code == 200 and corps == b'{"status": "ok"}' and h["X-Hote-Recu"] == DOM
            else:
                assert code == 404, (chemin, code)
    finally:
        subprocess.run(base + ["-s", "stop"], check=False, timeout=30, capture_output=True)
        if serveur:
            serveur.shutdown()


# ── La page ──────────────────────────────────────────────────────────────────────────────────────────────────

SRC = PAGE.read_text(encoding="utf-8")


def test_page_aurora_sans_ressource_exterieure_ni_donnee():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert "--fond:#060d1b" in SRC and '"IBM Plex Sans"' in SRC
    for interdit in ("http://", "https://", "fetch(", "XMLHttpRequest", "innerHTML", "@import", "url(", "eval(",
                     "localStorage.setItem", "gk2"):
        assert interdit not in SRC, interdit
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/_noeud/sbx-dice.js"]
    assert "textContent" in SRC and 'role="img"' in SRC


def test_paquet_livre_page_et_script_sans_recopier_le_de():
    rules = (PKG / "debian/rules").read_text()
    assert "sbin/webos-noeud $(CURDIR)/debian/secubox-webos/usr/sbin/webos-noeud" in rules
    assert "www/noeud/index.html $(CURDIR)/debian/secubox-webos/usr/share/secubox/www/noeud/index.html" in rules
    assert "usr/share/secubox/www/noeud/dice" not in rules and "noeud/sbx-dice.js" not in rules
    assert "/usr/sbin/webos-noeud appliquer" in (PKG / "debian/postinst").read_text()
    assert "/usr/sbin/webos-noeud retirer" in (PKG / "debian/prerm").read_text()
    assert "rm -rf /var/lib/secubox-webos-noeud" in (PKG / "debian/postrm").read_text()
    assert "[noeud]\naccueil = true" in (PKG / "etc/webos.toml.example").read_text()
    script = SCRIPT.read_text()
    assert "shell=True" not in script and "waf_bypass" not in script
    assert os.access(SCRIPT, os.X_OK)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.parametrize("largeur,hauteur", [(1400, 900), (420, 860)])
def test_rendu_plein_ecran_sans_debordement(largeur, hauteur):
    fichiers = {"/": (PAGE, "text/html"), "/_noeud/sbx-dice.js": (PKG / "www/hall/sbx-dice.js", "application/javascript")}
    for i in range(6):
        fichiers[f"/_noeud/dice/face-{i}.jpg"] = (PKG / f"www/hall/dice/face-{i}.jpg", "image/jpeg")
    externes = []

    def servir(route):
        chemin = route.request.url.split("gk2.secubox.in", 1)[1].split("?")[0] or "/"
        if chemin not in fichiers:
            externes.append(route.request.url)
            return route.fulfill(status=404, body="")
        f, t = fichiers[chemin]
        route.fulfill(status=200, body=f.read_bytes(), content_type=t)

    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        try:
            p = b.new_page(viewport={"width": largeur, "height": hauteur})
            p.route("**/*", servir)
            p.goto("http://gk2.secubox.in/")
            p.wait_for_function("document.querySelector('sbx-dice canvas') && "
                                "document.querySelector('sbx-dice').getAttribute('data-raf-ms') !== null", timeout=15000)
            assert p.inner_text("h1") == "gk2" and p.inner_text("#zone") == DOM
            assert p.evaluate("document.documentElement.scrollWidth") <= largeur
            taille = int(p.get_attribute("sbx-dice", "size"))
            assert taille >= min(largeur, hauteur) * 0.35          # le dé occupe la page
            a1 = p.evaluate("document.querySelector('sbx-dice')._ay")
            p.wait_for_timeout(300)
            assert p.evaluate("document.querySelector('sbx-dice')._ay") > a1   # il tourne
            sortie = os.environ.get("SBX_NOEUD_CAPTURES")
            if sortie:
                p.screenshot(path=f"{sortie}/de-noeud-{largeur}.png")
        finally:
            b.close()
    assert externes == []
