# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126), C1 : l'identité d'une box est l'adresse source de la connexion au tunnel, posée par nginx. secubox-hub règle au niveau http
`real_ip_header X-Forwarded-For; real_ip_recursive on;` et secubox-realip ajoute des set_real_ip_from (dont 10.10.0.1 et 10.64.0.1) : un processus
local qui se connecte à l'écouteur avec un X-Forwarded-For forgé faisait réécrire $remote_addr, donc X-Real-IP (usurpation de n'importe quelle box).
Le server du canal neutralise l'héritage et lit $realip_remote_addr (la vraie adresse du pair), jamais $remote_addr."""
import contextlib
import http.server
import re
import shutil
import socket
import socketserver
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
TPL = (ICI / "nginx" / "pilotage-canal.conf.tpl").read_text()
SNIPPET = ICI.parents[1] / "common" / "nginx" / "secubox-proxy.conf"


def test_gabarit_neutralise_le_realip_herite():
    c = "\n".join(x for x in TPL.splitlines() if not x.lstrip().startswith("#"))
    assert "set_real_ip_from 255.255.255.255;" in c                       # remplace la liste héritée (tableau : le server l'emporte)
    assert "real_ip_recursive off;" in c
    assert c.count("proxy_set_header X-Real-IP $realip_remote_addr;") == 1
    assert c.count("proxy_set_header X-Forwarded-For $realip_remote_addr;") == 1
    assert "$remote_addr;" not in re.sub(r"\$binary_remote_addr", "", c)  # aucune lecture de l'adresse réécrite
    # la neutralisation précède tout allow/deny et tout proxy
    assert c.index("set_real_ip_from") < c.index("allow ") < c.index("proxy_pass")


class _Echo(socketserver.UnixStreamServer):
    pass


class _Gestionnaire(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        corps = (f"real={self.headers.get('X-Real-IP')};xff={self.headers.get('X-Forwarded-For')};"
                 f"tunnel={self.headers.get_all('X-SecuBox-Pilotage-Tunnel') or []}").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def address_string(self):
        return "local"

    def log_message(self, *a):
        pass


def _port_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def _nginx_reel(tmp_path, blocs: str, port: int):
    """Un vrai nginx dans l'environnement d'une box (realip configuré au niveau http, 127.0.0.1 « de confiance » comme 10.10.0.1), devant un
    écho sur socket Unix (tmp_path/canal.sock) qui renvoie les en-têtes reçus."""
    sock = tmp_path / "canal.sock"
    srv = _Echo(str(sock), _Gestionnaire)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"""
pid {tmp_path}/nginx.pid;
error_log {tmp_path}/err.log;
worker_processes 1;
events {{ worker_connections 16; }}
http {{
    access_log off;
    client_body_temp_path {tmp_path}/b; proxy_temp_path {tmp_path}/p; fastcgi_temp_path {tmp_path}/f; uwsgi_temp_path {tmp_path}/u; scgi_temp_path {tmp_path}/s;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    set_real_ip_from 127.0.0.1;
    set_real_ip_from 10.10.0.1;
    limit_conn_zone $binary_remote_addr zone=pilotage_canal:1m;
{blocs.replace("/run/secubox/pilotage-canal.sock", str(sock))}
}}
""")
    base = ["nginx", "-c", str(conf), "-p", str(tmp_path)]
    ok = subprocess.run(base + ["-t"], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    p = subprocess.Popen(base + ["-g", "daemon off;"], stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        yield
    finally:
        p.terminate()
        p.wait(10)
        srv.shutdown()
        srv.server_close()


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx absent")
def test_essai_reel_nginx_xff_forge_ne_change_pas_x_real_ip(tmp_path):
    port = _port_libre()
    bloc = "\n".join(x for x in TPL.splitlines() if not x.lstrip().startswith("#"))
    bloc = bloc.replace("__IP__", "127.0.0.1").replace("__SOURCE__", "127.0.0.0/8").replace("listen 127.0.0.1:8472;", f"listen 127.0.0.1:{port};")
    with _nginx_reel(tmp_path, bloc, port):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/canal/v1/requetes", headers={"X-Forwarded-For": "127.0.0.5", "X-Real-IP": "127.0.0.9",
                                                                                           "X-SecuBox-Pilotage-Tunnel": "0"})
        corps = urllib.request.urlopen(req, timeout=5).read().decode()
        # le vrai pair, jamais l'adresse forgée (127.0.0.5 est DANS la plage autorisée : sans le correctif la requête passe, usurpée) ; le marqueur
        # du tunnel est celui de nginx, une seule fois, jamais celui du client (L2 T0, M6)
        assert corps == "real=127.0.0.1;xff=127.0.0.1;tunnel=['1']", corps
        # une autre route du canal passe (200) ; tout ce qui n'est pas /canal/v1/ est refusé (403)
        assert urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/canal/v1/x"), timeout=5).status == 200
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/autre", timeout=5)
        assert e.value.code == 403


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx absent")
def test_essai_reel_nginx_le_snippet_commun_vide_le_marqueur(tmp_path):
    """M6 (L2 T0) : tout autre proxy inclut secubox-proxy.conf ; un client qui forge le marqueur du tunnel ne le fait jamais parvenir à l'amont."""
    port = _port_libre()
    bloc = f"""server {{
    listen 127.0.0.1:{port};
    location / {{
        proxy_pass http://unix:/run/secubox/pilotage-canal.sock;
        include {SNIPPET};
    }}
}}"""
    with _nginx_reel(tmp_path, bloc, port):
        h = {"X-SecuBox-Pilotage-Tunnel": "1", "X-Real-IP": "10.10.0.10"}
        corps = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/canal/v1/requetes", headers=h), timeout=5).read().decode()
        assert corps.endswith(";tunnel=[]"), corps
