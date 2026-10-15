# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2730 — le HTML de l'assistant n'est plus servi « public, immutable » une heure.

CONSTAT (RPi400, 2026-10-15) : après la mise à jour du paquet et `premier-pasctl rejouer`, le navigateur et le kiosque relancé affichaient l'ANCIENNE page,
alors que la box servait la nouvelle. `location /` du site par défaut pose `expires 1h` + `Cache-Control: public, immutable` sur tout fichier statique :
`immutable` interdit de revérifier, même sur un rechargement simple. Pour la page de l'assistant (elle change à chaque version, et son écran dépend de
l'état de la box), c'est faux. On teste avec un VRAI nginx, en reprenant la `location /` du site."""
import http.client
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SNIPPET = PKG / "nginx" / "premier-pas.conf"
SITE = PKG.parents[1] / "common" / "nginx" / "secubox.conf"

pytestmark = pytest.mark.skipif(not shutil.which("nginx") and not Path("/usr/sbin/nginx").exists(), reason="nginx absent")
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"


@pytest.fixture
def serveur(tmp_path):
    www = tmp_path / "www"
    for d in ("premier-pas", "premier-pas-maitre", "hall"):
        (www / d).mkdir(parents=True)
        (www / d / "index.html").write_text(f"<title>{d}</title>")
    (www / "index.html").write_text("<title>racine</title>")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"""
daemon off; pid {tmp_path}/n.pid; error_log {tmp_path}/err.log;
events {{ worker_connections 16; }}
http {{
  access_log off;
  client_body_temp_path {tmp_path}/b; proxy_temp_path {tmp_path}/p; fastcgi_temp_path {tmp_path}/f; uwsgi_temp_path {tmp_path}/u; scgi_temp_path {tmp_path}/s;
  include /etc/nginx/mime.types;
  server {{
    listen 127.0.0.1:{port};
    root {www};
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    location / {{
        try_files $uri $uri/ /index.html;
        expires 1h;
        add_header Cache-Control "public, immutable";
    }}
    include {SNIPPET};
  }}
}}
""")
    ok = subprocess.run([NGINX, "-t", "-c", str(conf), "-p", str(tmp_path)], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    p = subprocess.Popen([NGINX, "-c", str(conf), "-p", str(tmp_path)], stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield port
    p.terminate()
    p.wait(timeout=5)


def get(port, chemin):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", chemin)
    r = c.getresponse()
    corps = r.read().decode()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, corps


@pytest.mark.parametrize("chemin", ["/premier-pas/", "/premier-pas/index.html", "/premier-pas-maitre/", "/premier-pas-maitre/index.html"])
def test_la_page_de_l_assistant_se_revalide_a_chaque_affichage(serveur, chemin):
    st, h, _ = get(serveur, chemin)
    assert st == 200
    assert h["cache-control"] == "no-cache", h["cache-control"]
    assert "expires" not in h and "immutable" not in h["cache-control"]
    assert "etag" in h, "no-cache + ETag : la revalidation reste peu coûteuse"


@pytest.mark.parametrize("chemin", ["/premier-pas/", "/premier-pas-maitre/"])
def test_les_en_tetes_de_securite_du_serveur_ne_sont_pas_perdus(serveur, chemin):
    """`add_header` dans une location REMPLACE ceux du serveur : le bloc doit les répéter."""
    _, h, _ = get(serveur, chemin)
    assert h["strict-transport-security"].startswith("max-age=31536000")
    assert h["x-frame-options"] == "SAMEORIGIN" and h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"


def test_le_reste_du_site_est_inchange(serveur):
    """Le défaut général de `location /` est une décision sur tout le site : on n'y touche pas ici."""
    _, h, corps = get(serveur, "/hall/index.html")
    assert h["cache-control"] == "public, immutable" and "hall" in corps


def test_une_page_inconnue_de_l_assistant_est_un_404_pas_la_racine(serveur):
    st, _, _ = get(serveur, "/premier-pas/inexistante.html")
    assert st == 404


def test_le_site_inclut_bien_les_snippets_de_secubox_d():
    """Le bloc n'a d'effet que si le site inclut /etc/nginx/secubox.d/*.conf."""
    assert "include /etc/nginx/secubox.d/*.conf;" in SITE.read_text()


def test_le_paquet_installe_le_bloc_et_recharge_nginx():
    rules = (PKG / "debian" / "rules").read_text()
    assert "nginx/premier-pas.conf" in rules and "etc/nginx/secubox.d/premier-pas.conf" in rules
    post = (PKG / "debian" / "postinst").read_text()
    assert "nginx -t" in post and "reload nginx" in post
