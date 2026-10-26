# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — `netmodes` est à socket dédiée : il appelle `netmodesctl` par sudo, impossible sous l'utilisateur `secubox`
de l'agrégateur (pas de sudo). Le relais transparent l'atteint sur /run/secubox/netmodes.sock."""
import importlib
import json
import re
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"
ROUTEUR_API = Path(__file__).resolve().parents[2] / "secubox-netmodes" / "api" / "routeur_api.py"


def test_netmodes_est_a_socket_dediee_et_pas_retire():
    assert "netmodes" in ag.DEDICATED_MODULES
    assert "netmodes" not in ag.RETIRED_MODULES


def test_netmodes_cite_dans_le_toml_n_est_pas_monte(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "netmodes", "waf"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert ag._load_config()["modules"] == ["hub", "waf"]


def test_le_script_de_migration_l_exclut_aussi():
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "netmodes" in ligne.split('"')[1].split()


# --- relecture finale I5 : délai du relais par module ------------------------------------------------------------------

class _FauxModule(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Module à socket dédiée minimal : répond 200 et un JSON à toute requête."""
    daemon_threads = True

    def __init__(self, chemin: str):
        class _Gestionnaire(BaseHTTPRequestHandler):
            def do_GET(self):
                sortie = json.dumps({"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(sortie)))
                self.end_headers()
                self.wfile.write(sortie)

            def address_string(self):                   # socket unix : pas d'adresse cliente
                return "unix"

            def log_message(self, *a):
                pass

        super().__init__(chemin, _Gestionnaire)


def test_relais_netmodes_attend_plus_que_son_controleur(tmp_path, monkeypatch):
    """Une application du mode routeur par le chemin public (Unbound, nginx -t, networkd, DHCP vérifié) dure jusqu'au
    délai de l'API netmodes (DELAI_CTL) : à 60 s, le relais rendait 502 pendant que la bascule continuait."""
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setattr(ag, "RUN_DIR", str(run))
    monkeypatch.setattr(ag, "CONFIG_FILE", tmp_path / "absent.toml")
    serveurs = []
    for nom in ("netmodes", "lyrion"):
        m = _FauxModule(str(run / f"{nom}.sock"))
        threading.Thread(target=m.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        serveurs.append(m)
    delais = []
    reel = httpx.AsyncClient

    class Espion(reel):
        def __init__(self, *a, **kw):
            delais.append(kw.get("timeout"))
            super().__init__(*a, **kw)

    monkeypatch.setattr(ag.httpx, "AsyncClient", Espion)
    try:
        client = TestClient(ag._build_app())
        assert client.get("/api/v1/netmodes/routeur/etat").status_code == 200
        assert client.get("/api/v1/lyrion/status").status_code == 200
    finally:
        for m in serveurs:
            m.shutdown()
            m.server_close()
    assert delais == [200.0, 60.0]                                  # netmodes allongé, les autres inchangés
    delai_ctl = int(re.search(r"^DELAI_CTL = (\d+)", ROUTEUR_API.read_text(encoding="utf-8"), re.M).group(1))
    assert ag.DELAIS_RELAIS_MODULE["netmodes"] > delai_ctl          # le relais laisse l'API répondre la première
