# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — l'annuaire publie les noms publics de la box (webos) comme offres « service » signées."""
import http.server
import json
import socketserver
import threading
from pathlib import Path

import pytest

from annuaire import offres

NOMS = {
    "domaine": "gk3.exemple.test",
    "noeud": "gk3",
    "noms": ["hall.gk3.exemple.test", "admin.gk3.exemple.test", "a.b.gk3.exemple.test",
             "hall.autre.test", "wpad.gk3.exemple.test"],
}


def test_services_des_noms_garde_un_seul_niveau_hors_exclus():
    res = offres.services_des_noms(NOMS)
    assert len(res) == 1
    o = res[0]
    assert o["name"] == "hall" and o["kind"] == "service"
    assert o["endpoint"] == "https://hall.gk3.exemple.test"
    assert o["scope"]["source"] == "sync" and o["scope"]["domaine"] == "gk3.exemple.test"
    assert o["scope"]["service"] == "hall" and o["scope"]["channel"] == "public"
    assert o["description"] == "hall (gk3)"


@pytest.mark.parametrize("entree", [None, {}, {"domaine": "x y"}, {"noms": "hall"}, "hall", []])
def test_services_des_noms_entrees_invalides(entree):
    assert offres.services_des_noms(entree) == []


def test_services_des_noms_plafonne_a_64():
    noms = {"domaine": "gk3.exemple.test", "noeud": "gk3",
            "noms": [f"s{i}.gk3.exemple.test" for i in range(100)]}
    assert len(offres.services_des_noms(noms)) == 64


class _Serveur(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture
def socket_webos(tmp_path):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/public/noms":
                corps = json.dumps(NOMS).encode()
                self.send_response(200)
            else:
                corps = b"[]"
                self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *a):
            pass

    chemin = str(tmp_path / "w.sock")
    srv = _Serveur(chemin, H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield chemin
    srv.shutdown()
    srv.server_close()


def test_lire_noms_webos_par_socket_unix(socket_webos):
    assert offres.lire_noms_webos(socket_webos) == NOMS


def test_lire_noms_webos_socket_absent(tmp_path):
    assert offres.lire_noms_webos(str(tmp_path / "absent.sock")) is None


def test_collecter_faits_contient_le_service(socket_webos, tmp_path):
    faits = offres.collecter_faits(tor_dir=tmp_path / "t", hall_index=tmp_path / "h.html",
                                   haproxy_toml=tmp_path / "p.toml", repo_marqueur=tmp_path / "r",
                                   webos_sock=socket_webos)
    assert [f["kind"] for f in faits] == ["service"]
    assert faits[0]["endpoint"] == "https://hall.gk3.exemple.test"


def test_collecter_faits_sans_socket(tmp_path):
    faits = offres.collecter_faits(tor_dir=tmp_path / "t", hall_index=tmp_path / "h.html",
                                   haproxy_toml=tmp_path / "p.toml", repo_marqueur=tmp_path / "r",
                                   webos_sock=str(tmp_path / "absent.sock"))
    assert faits == []


def test_minuterie_horaire():
    pkg = Path(__file__).resolve().parents[1]
    minuterie = (pkg / "systemd" / "secubox-annuaire-offres.timer").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=1h" in minuterie
