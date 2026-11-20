# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — lecteur du substrat SADE : sockets Unix, échecs sans exception, fixtures en adresses de documentation."""
import json
import os
import re
import shutil
import socketserver
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import substrat  # noqa: E402

DONNEES = Path(__file__).resolve().parent / "donnees" / "substrat"


class _Serveur(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        req, _ = super().get_request()
        return req, ("unix", 0)


class _Unix:
    def __init__(self):
        self.dossier = tempfile.mkdtemp(prefix="sbx")
        self.chemin = os.path.join(self.dossier, "s.sock")
        self.routes = {}
        self.vus = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.vus.append((self.path, dict(self.headers)))
                code, corps, pause = outer.routes.get(self.path, (404, {}, 0))
                time.sleep(pause)
                brut = corps if isinstance(corps, bytes) else json.dumps(corps).encode()
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(brut)))
                    self.end_headers()
                    self.wfile.write(brut)
                except OSError:
                    pass

        self.srv = _Serveur(self.chemin, H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def repond(self, chemin, code, corps):
        self.routes[chemin] = (code, corps, 0)

    def dort(self, chemin, secondes):
        self.routes[chemin] = (200, {}, secondes)

    def ferme(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.dossier, ignore_errors=True)


@pytest.fixture
def serveur_unix(monkeypatch):
    s = _Unix()
    monkeypatch.setitem(substrat.SOURCES, "waf", s.chemin)
    yield s
    s.ferme()


def test_socket_absent_rend_une_lecture_ko(tmp_path, monkeypatch):
    monkeypatch.setitem(substrat.SOURCES, "waf", str(tmp_path / "absent.sock"))
    assert substrat.lire("waf", "/bans") == {"ok": False, "donnees": None, "erreur": "socket absent"}


def test_source_inconnue_refusee():
    with pytest.raises(KeyError):
        substrat.lire("ailleurs", "/x")


def test_sources_declarees():
    assert set(substrat.SOURCES) == {"actord", "waf", "threatmesh"}
    assert substrat.SOURCES["waf"] == "/run/secubox/waf.sock"


def test_reponse_200_json(serveur_unix):
    serveur_unix.repond("/bans", 200, {"bans": []})
    assert substrat.lire("waf", "/bans") == {"ok": True, "donnees": {"bans": []}, "erreur": None}


def test_reponse_503_et_delai(serveur_unix):
    serveur_unix.repond("/bans", 503, {})
    r = substrat.lire("waf", "/bans")
    assert r["ok"] is False and r["donnees"] is None
    serveur_unix.dort("/lent", 2.0)
    assert substrat.lire("waf", "/lent", delai=0.2)["erreur"] == "délai"


def test_corps_non_json_et_trop_grand(serveur_unix, monkeypatch):
    serveur_unix.repond("/x", 200, b"pas du json")
    assert substrat.lire("waf", "/x")["erreur"] == "réponse illisible"
    monkeypatch.setattr(substrat, "CORPS_MAX", 10)
    serveur_unix.repond("/gros", 200, {"a": "b" * 50})
    assert substrat.lire("waf", "/gros")["erreur"] == "réponse trop grande"


def test_entetes_transmis(serveur_unix):
    serveur_unix.repond("/bans", 200, [])
    substrat.lire("waf", "/bans", entetes={"Authorization": "Bearer abc", "X-Sbx-Vue": "complete"})
    h = serveur_unix.vus[-1][1]
    assert h.get("Authorization") == "Bearer abc" and h.get("X-Sbx-Vue") == "complete"


def test_socket_mort_sans_exception(tmp_path, monkeypatch):
    chemin = tmp_path / "mort.sock"
    chemin.write_text("")  # existe mais n'écoute pas
    monkeypatch.setitem(substrat.SOURCES, "waf", str(chemin))
    r = substrat.lire("waf", "/bans")
    assert r["ok"] is False and r["erreur"]


@pytest.mark.parametrize("f", sorted(p.name for p in DONNEES.glob("*.json")))
def test_fixtures_json_et_adresses_de_documentation(f):
    texte = (DONNEES / f).read_text(encoding="utf-8")
    json.loads(texte)
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", texte):
        assert ip.startswith(("203.0.113.", "198.51.100.")), ip


def test_fixtures_attendues_presentes():
    attendues = {"actord_actors", "actord_proposals", "waf_bans", "waf_bans_history", "threatmesh_status",
                 "threatmesh_decisions"}
    assert attendues <= {p.stem for p in DONNEES.glob("*.json")}
