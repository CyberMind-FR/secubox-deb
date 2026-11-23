# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3821 — le nom de nœud (<nœud>.<zone>, ex. gk2.secubox.in) montre le dé SecuBox en plein écran sur « / ».

Vérifié : la décision de `secubox-noeud` (secubox-core depuis #3883) (route absente, reprise d'une cible qui rend 404, existant explicite qui gagne,
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
import threading
import time
from pathlib import Path

import pytest

from banc_noeud import DOM, HALL, PAGE, PKG, SCRIPT, audits, box_noeud, charger, conf, get, port_libre, table  # noqa: F401


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
    # #3824 : seule la santé est relayée ; le reste rend 404 tant que relais_api n'est pas ouvert
    assert "location = /api/v1/health {\n        proxy_pass http://192.168.1.200:8000;" in c
    assert "location / {\n        return 404;" in c and c.count("proxy_pass") == 1
    assert table(box)[DOM] == ["192.168.1.200", 9080]
    etat = json.loads(Path(box.ETAT).read_text())
    assert etat == {"domaine": DOM, "route_reprise": True, "route_precedente": ["192.168.1.200", 8000]}
    assert "santé relayée à 192.168.1.200:8000 ; autres chemins fermés" in audits(box)[0]["detail"]
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


@pytest.mark.skipif(not shutil.which("nginx"), reason="nginx absent")
@pytest.mark.parametrize("avec_repli", [False, True])
def test_vrai_nginx_ne_sert_que_la_racine_exacte(tmp_path, avec_repli):
    m = charger()
    www = tmp_path / "www"
    (www / "noeud").mkdir(parents=True)
    shutil.copy(PAGE, www / "noeud" / "index.html")
    # ce que livre secubox-core (#3883) : le dé à côté de la page, AUCUN www/hall (box sans secubox-webos)
    shutil.copy(HALL / "sbx-dice.js", www / "noeud" / "sbx-dice.js")
    shutil.copytree(HALL / "dice", www / "noeud" / "dice")
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
        # santé : relayée à l'ancienne cible, sinon rendue sur place (#3824)
        code, h, corps = get(url + "/api/v1/health", DOM)
        assert code == 200 and json.loads(corps) == {"status": "ok"}
        assert (h.get("X-Hote-Recu") == DOM) if avec_repli else ("X-Hote-Recu" not in h)
        # rien d'autre n'est servi par l'accueil : ni /index.html, ni une API, ni le dossier du Hall
        for chemin in ("/index.html", "/api/v1/admin/", "/_noeud/", "/_noeud/../hall/index.html", "/sbx-dice.js"):
            code, h, corps = get(url + chemin, DOM)
            assert b"<sbx-dice" not in corps, chemin
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


def test_paquet_livre_page_script_et_de_sans_le_hall():
    """#3883 : secubox-core livre le script, la page ET le dé (source : le Hall) ; le vhost ne lit plus www/hall."""
    rules = (PKG / "debian/rules").read_text()
    assert "sbin/secubox-noeud debian/secubox-core/usr/sbin/secubox-noeud" in rules
    assert "www/noeud/index.html debian/secubox-core/usr/share/secubox/www/noeud/index.html" in rules
    assert "../secubox-webos/www/hall/sbx-dice.js debian/secubox-core/usr/share/secubox/www/noeud/sbx-dice.js" in rules
    assert "../secubox-webos/www/hall/dice/*.jpg debian/secubox-core/usr/share/secubox/www/noeud/dice/" in rules
    assert "etc/noeud.toml.example debian/secubox-core/usr/share/secubox-core/noeud.toml.example" in rules
    assert (HALL / "sbx-dice.js").is_file() and len(list((HALL / "dice").glob("face-*.jpg"))) == 6
    vhost = charger().rendre(DOM, None, False)
    assert "/www/hall" not in vhost
    assert "alias /usr/share/secubox/www/noeud/sbx-dice.js;" in vhost and "alias /usr/share/secubox/www/noeud/dice/;" in vhost
    assert "/usr/sbin/secubox-noeud appliquer" in (PKG / "debian/postinst").read_text()
    assert "/usr/sbin/secubox-noeud retirer" in (PKG / "debian/prerm").read_text()
    assert "rm -rf /var/lib/secubox-noeud" in (PKG / "debian/postrm").read_text()
    assert "[noeud]\naccueil = true" in (PKG / "etc/noeud.toml.example").read_text()
    script = SCRIPT.read_text()
    assert "shell=True" not in script and "waf_bypass" not in script
    assert os.access(SCRIPT, os.X_OK)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.parametrize("largeur,hauteur", [(1400, 900), (420, 860)])
def test_rendu_plein_ecran_sans_debordement(largeur, hauteur):
    fichiers = {"/": (PAGE, "text/html"), "/_noeud/sbx-dice.js": (HALL / "sbx-dice.js", "application/javascript")}
    for i in range(6):
        fichiers[f"/_noeud/dice/face-{i}.jpg"] = (HALL / f"dice/face-{i}.jpg", "image/jpeg")
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


def test_mire_en_fond_sans_texte_ni_ressource_3886():
    """#3886 : la mire de télévision est en fond (SVG écrit dans la page, aria-hidden), sans texte d'erreur ni ressource externe."""
    import re
    page = (Path(__file__).resolve().parents[1] / "www" / "noeud" / "index.html").read_text(encoding="utf-8")
    svg = page[page.index('<svg class="mire"'):page.index("</svg>")]
    assert 'aria-hidden="true"' in svg and "<text" not in svg and "Désolé" not in page
    assert not re.search(r'(?:src|href)="https?://', page)
    assert page.index('<svg class="mire"') < page.index("<main>")


def test_chemin_inconnu_du_nom_public_rend_la_404_a_la_mire_3885(box):
    """#3885 : tout chemin inconnu du nom public rend la page 404 à la mire, servie en interne avec la CSP de l'accueil ;
    le vhost n'intercepte jamais les réponses relayées (pas de proxy_intercept_errors)."""
    assert box.appliquer() == 0
    c = conf(box)
    assert "error_page 404 /_noeud/404.html;" in c
    bloc = c[c.index("location = /_noeud/404.html {"):]
    bloc = bloc[:bloc.index("}")]
    assert "internal;" in bloc and "/noeud/404.html;" in bloc and "Content-Security-Policy" in bloc
    assert "proxy_intercept_errors" not in c
    page = (PKG / "www" / "noeud" / "404.html").read_text(encoding="utf-8")
    assert "404 · CETTE PAGE N’EXISTE PAS" in page or "404 · CETTE PAGE N'EXISTE PAS" in page
    assert "<script" not in page and not re.search(r'(?:src|href)="https?://', page)
    regles = (PKG / "debian" / "rules").read_text(encoding="utf-8")
    assert "www/noeud/404.html" in regles
