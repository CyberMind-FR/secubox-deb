# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2301 : l'enrôlement HTTPS fonctionne avec l'ouvreur RÉEL. Trouvé par le test VirtualBox : `TypeError: OpenerDirector.open() got an unexpected keyword argument 'context'`
(les tests passaient parce que le faux ouvreur acceptait `context=`)."""
import json
import shutil
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from autoload_agent import client as C  # noqa: E402

OK = {"tunnel": {"endpoint": "e", "serveur_cle_pub": "k", "adresse": "a", "hub": "h"}, "client": "c1", "profil": "lite"}


def test_l_ouvreur_reel_lie_le_contexte_au_gestionnaire_https():
    ctx = ssl.create_default_context()
    o = C.ouvreur_sans_redirection(ctx)
    assert any(isinstance(h, __import__("urllib.request").request.HTTPSHandler) and h._context is ctx for h in o.handlers)
    with pytest.raises(TypeError):
        o.open("http://x.test/", context=ctx)          # la forme fautive reste refusée : c'est le client qui ne doit plus la produire


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")
def test_enrolement_https_de_bout_en_bout_avec_l_ouvreur_reel(tmp_path):
    cert, cle = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=infra.test", "-addext", "subjectAltName=DNS:infra.test",
                    "-keyout", str(cle), "-out", str(cert)], check=True, capture_output=True)

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            corps = json.dumps(OK).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    srv.socket = _tls(srv.socket, cert, cle)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ctx = ssl.create_default_context(cafile=str(cert))
        import urllib.request
        c = C.ClientInfra()                                       # ouvreur RÉEL, pas un faux
        req = urllib.request.Request(f"https://localhost:{srv.server_port}/api/v1/autoload/enrol", data=b"{}", method="POST")
        # localhost : le SAN du certificat de test est infra.test, on vérifie donc seulement la chaîne ; l'essentiel est que l'appel passe par l'ouvreur réel sans TypeError.
        ctx.check_hostname = False
        assert c._appel(req, ctx)["client"] == "c1"
    finally:
        srv.shutdown()


def _tls(sock, cert, cle):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(cle))
    return ctx.wrap_socket(sock, server_side=True)
