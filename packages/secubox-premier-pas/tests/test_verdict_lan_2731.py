# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2731 — la route d'ouverture distante reçoit le verdict LAN de nginx, même si secubox-proxy.conf ne le pose pas.

CONSTAT (RPi400, 2026-10-15) : « L'assistant distant s'ouvre depuis le réseau local de la box » sur un poste du LAN. La ligne `proxy_set_header
X-SecuBox-LAN $lan_client;` n'est ajoutée à snippets/secubox-proxy.conf que par le postinst de secubox-core, et seulement si le fichier GeoIP du Hub
existe alors. On teste avec un VRAI nginx et un faux backend qui rend les en-têtes qu'il reçoit."""
import http.client
import http.server
import json
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SESSION = (PKG / "nginx" / "premier-pas-session.conf").read_text()
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"

pytestmark = pytest.mark.skipif(not Path(NGINX).exists(), reason="nginx absent")


def libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def banc(tmp_path):
    """nginx devant un faux backend qui répond les en-têtes reçus. `lan` : valeur de $lan_client pour le client local."""
    recu = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            recu["x-secubox-lan"] = self.headers.get("X-SecuBox-LAN")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    procs = []

    def demarre(lan):
        port = libre()
        (tmp_path / "proxy.conf").write_text("proxy_set_header Host $host;\n")
        bloc = SESSION.replace("proxy_pass http://unix:/run/secubox/aggregator.sock;", f"proxy_pass http://127.0.0.1:{srv.server_port};") \
                      .replace("/etc/nginx/snippets/secubox-proxy.conf", str(tmp_path / "proxy.conf"))
        (tmp_path / "session.conf").write_text(bloc)
        (tmp_path / "nginx.conf").write_text(f"""
daemon off; pid {tmp_path}/n.pid; error_log {tmp_path}/err.log;
events {{ worker_connections 16; }}
http {{
  access_log off;
  client_body_temp_path {tmp_path}/b; proxy_temp_path {tmp_path}/p; fastcgi_temp_path {tmp_path}/f; uwsgi_temp_path {tmp_path}/u; scgi_temp_path {tmp_path}/s;
  geo $lan_client {{ default 0; 127.0.0.0/8 {lan}; }}
  server {{ listen 127.0.0.1:{port}; include {tmp_path}/session.conf; }}
}}
""")
        ok = subprocess.run([NGINX, "-t", "-c", str(tmp_path / "nginx.conf"), "-p", str(tmp_path)], capture_output=True, text=True)
        assert ok.returncode == 0, ok.stderr
        p = subprocess.Popen([NGINX, "-c", str(tmp_path / "nginx.conf"), "-p", str(tmp_path)], stderr=subprocess.DEVNULL)
        procs.append(p)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        return port

    yield demarre, recu
    for p in procs:
        p.terminate()
        p.wait(timeout=5)
    srv.shutdown()


def poste(port, entetes=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("POST", "/api/v1/premier-pas/session", body=b"", headers=entetes or {})
    r = c.getresponse()
    r.read()
    return r.status


def test_un_client_du_lan_recoit_le_verdict_1(banc):
    demarre, recu = banc
    assert poste(demarre(1)) == 200
    assert recu["x-secubox-lan"] == "1"


def test_un_client_hors_du_lan_recoit_le_verdict_0(banc):
    demarre, recu = banc
    assert poste(demarre(0)) == 200
    assert recu["x-secubox-lan"] == "0"


def test_un_client_ne_peut_pas_forger_le_verdict(banc):
    """Le client écrit « 1 » : nginx le REMPLACE par son propre verdict."""
    demarre, recu = banc
    poste(demarre(0), {"X-SecuBox-LAN": "1"})
    assert recu["x-secubox-lan"] == "0"


def test_seule_la_route_de_session_est_visee():
    assert "location = /api/v1/premier-pas/session" in SESSION
    assert "location /" not in SESSION.replace("location = /api/v1/premier-pas/session", "")


# ---------- le postinst ne pose ce bloc que s'il est sûr ----------

POST = (PKG / "debian" / "postinst").read_text()


def test_le_postinst_exige_le_fichier_geoip_du_hub_et_l_absence_de_la_ligne_et_nginx_t():
    assert "/etc/nginx/conf.d/secubox-lan-geo.conf" in POST
    # LA DIRECTIVE, pas la chaîne (#2743) : le commentaire de secubox-proxy.conf contient « X-SecuBox-LAN » et l'ancien garde concluait « déjà posée ».
    assert "proxy_set_header[[:space:]]+X-SecuBox-LAN" in POST and "/etc/nginx/snippets/secubox-proxy.conf" in POST
    assert "nginx -t" in POST
    assert 'rm -f "$SESSION_CONF"' in POST, "le bloc est retiré quand il n'est pas sûr (une variable inconnue casserait toute la configuration)"


def test_le_bloc_est_livre_hors_de_secubox_d_donc_jamais_actif_sans_le_postinst():
    rules = (PKG / "debian" / "rules").read_text()
    assert "usr/share/secubox/premier-pas/nginx/premier-pas-session.conf" in rules
    assert "etc/nginx/secubox.d/premier-pas-session.conf" not in rules
